"""Where a VPN address is: the free DB-IP Lite databases kept on disk, checked against ipinfo.io,
with the admin's own names for known networks taking precedence over both.

No source knows where a person is. They know where an operator's address block comes out to the internet,
which for mobile operators is a handful of gateways for the whole country. So the answer also says how far
it can be trusted: both sources agree, they name different towns, or the address belongs to a mobile operator.
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import logging
import math
import os
import re
import shutil
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    import maxminddb
except ImportError:  # the old desktop program is built without it
    maxminddb = None

from . import __version__

log = logging.getLogger("vpnmon.geodb")

# DB-IP publishes the Lite databases on the 1st of every month under CC BY 4.0, no account needed.
DBIP_URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"
DBIP_PAGE = "https://db-ip.com"
DBIP_FILES = {"city": "dbip-city-lite.mmdb", "asn": "dbip-asn-lite.mmdb"}
VERSIONS_FILE = "dbip-versions.json"
DB_RETRY_SECONDS = 6 * 3600
MAX_DOWNLOAD_BYTES = 400 * 1024 * 1024
# Two answers closer than this are the same town: districts, suburbs and spellings differ between sources.
AGREE_KM = 60

# Mobile operators: their subscribers from all over the country share a few internet gateways.
MOBILE_ASNS = {
    29355: "Kcell", 21299: "Beeline", 206026: "Beeline", 48503: "Tele2/Altel", 29555: "Tele2/Altel",
    35104: "Jusan Mobile", 8359: "МТС", 31133: "МегаФон", 12958: "T2",
}
MOBILE_NAME_RE = re.compile(r"mobile|cellular|kcell|beeline|tele2|altel|megafon", re.IGNORECASE)


# ---------------------------------------------------------------------------------------------- answers
@dataclass
class GeoAnswer:
    loc: str             # "KZ / Almaty": the country code always comes first, alerts compare it
    org: str
    note: str = ""       # space-separated: label, conflict, mobile
    detail: str = ""     # one line per source, shown as a tooltip

    def as_dict(self) -> dict:
        return asdict(self)


def clean_city(name: str) -> str:
    """DB-IP adds the district: "Almaty (Medeū)" is Almaty."""
    return re.sub(r"\s*\(.*\)\s*$", "", name or "").strip()


def asn_of(org: str) -> int | None:
    m = re.match(r"AS(\d+)\b", org or "")
    return int(m.group(1)) if m else None


def parse_asns(items) -> set[int]:
    out = set()
    for item in items or ():
        m = re.fullmatch(r"(?:AS)?(\d+)", str(item).strip(), re.IGNORECASE)
        if m:
            out.add(int(m.group(1)))
    return out


def mobile_operator(asn: int | None, org: str, extra: set[int] = frozenset()) -> str:
    if asn is not None and asn in extra:
        return re.sub(r"^AS\d+\s*", "", org or "") or f"AS{asn}"
    if asn in MOBILE_ASNS:
        return MOBILE_ASNS[asn]
    m = MOBILE_NAME_RE.search(org or "")
    return re.sub(r"^AS\d+\s*", "", org) if m else ""


def distance_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    lat1, lon1, lat2, lon2 = map(math.radians, (*a, *b))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(h))


def _coords(value) -> tuple[float, float] | None:
    try:
        if isinstance(value, str):
            lat, lon = (float(x) for x in value.split(","))
        else:
            lat, lon = float(value[0]), float(value[1])
        return lat, lon
    except (TypeError, ValueError, IndexError):
        return None


def _place(*parts: str) -> str:
    out = []
    for p in parts:
        if p and p not in out:
            out.append(p)
    return ", ".join(out) or "—"


def merge_geo(local: dict | None, remote: dict | None, label: dict | None = None,
              extra_mobile: set[int] = frozenset()) -> GeoAnswer | None:
    """One answer from the local database, ipinfo.io and the admin's labels. None when nothing is known."""
    r = remote if remote and not remote.get("bogon") and not remote.get("error") else None
    if not (r or local or label):
        return None
    rc, rcity, rregion = (str(r.get(k) or "").strip() for k in ("country", "city", "region")) if r else ("", "", "")
    rorg = str(r.get("org") or "").strip() if r else ""
    lc, lcity, lregion = ((local.get("country") or ""), clean_city(local.get("city") or ""),
                          (local.get("region") or "")) if local else ("", "", "")
    lasn, lorg = (local.get("asn"), local.get("org") or "") if local else (None, "")

    country = rc or lc
    city = rcity or lcity
    asn = asn_of(rorg) or lasn
    org = rorg or (f"AS{lasn} {lorg}".strip() if lasn else lorg)
    notes, lines = [], []
    if r:
        lines.append(f"ipinfo.io: {_place(rc, rregion, rcity)}")
    if local:
        lines.append(f"DB-IP: {_place(lc, lregion, lcity)}")
    if r and local and rcity and lcity:
        a, b = _coords(r.get("loc")), _coords((local.get("lat"), local.get("lon")))
        far = distance_km(a, b) > AGREE_KM if a and b else rcity.lower() != lcity.lower()
        if rc and lc and rc != lc:
            far = True
        if far:
            notes.append("conflict")
            city = f"{rcity} или {lcity}" + (f" ({lc})" if lc != rc else "")
            lines.append("Источники называют разные города, поэтому город под вопросом.")
    mobile = mobile_operator(asn, org, extra_mobile)
    if mobile:
        notes.append("mobile")
        lines.append(f"Мобильный оператор ({mobile}): это город, где оператор выходит в интернет, "
                     f"а человек может быть в другом.")
    if label:
        notes = ["label"]
        city = label.get("label") or city
        country = (label.get("country") or country or "").upper()
        lines.insert(0, f"Своя подпись сети {label.get('cidr')}"
                        + (f": {label['comment']}" if label.get("comment") else ""))
    loc = " / ".join(p for p in (country, city) if p) or "—"
    return GeoAnswer(loc, org or "—", " ".join(notes), "\n".join(lines))


# ---------------------------------------------------------------------------------------------- labels
def normalize_cidr(text: str) -> str:
    """An address or a network as typed ("10.1.2.3", "10.1.2.0/24", "10.1.2.7/24") in canonical form."""
    return str(ipaddress.ip_network(str(text).strip(), strict=False))


class IpLabels:
    """The admin's names for networks; the most specific network wins."""

    def __init__(self, rows: list[dict] | None = None):
        nets = []
        for row in rows or ():
            try:
                nets.append((ipaddress.ip_network(row["cidr"], strict=False), row))
            except (KeyError, ValueError):
                continue
        self._nets = sorted(nets, key=lambda x: x[0].prefixlen, reverse=True)

    def match(self, ip: str) -> dict | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, row in self._nets:
            if addr.version == net.version and addr in net:
                return row
        return None


# ---------------------------------------------------------------------------------------------- local database
def month_of(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m")


def previous_month(month: str) -> str:
    y, m = (int(x) for x in month.split("-"))
    return f"{y - 1}-12" if m == 1 else f"{y}-{m - 1:02d}"


class NotPublished(Exception):
    """This month's file is not out yet (the first hours of a month)."""


def _http_open(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": f"CiscoAnyConnectMonitor/{__version__}"})
    try:
        return urllib.request.urlopen(req, timeout=60)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise NotPublished(url) from exc
        raise


class LocalGeoDB:
    """The DB-IP Lite city and ASN databases in a folder, replaced once a month."""

    def __init__(self, folder: Path, opener=None):
        self.folder = Path(folder)
        self._open_url = opener or _http_open
        self._lock = threading.RLock()
        self._readers: dict[str, object] = {}
        self._stamps: dict[str, tuple] = {}
        self.updating = False
        self.error = ""
        self.last_attempt = 0
        self.last_update = 0

    @property
    def supported(self) -> bool:
        return maxminddb is not None

    def path(self, kind: str) -> Path:
        return self.folder / DBIP_FILES[kind]

    # -- reading
    def _reader(self, kind: str):
        path = self.path(kind)
        try:
            st = path.stat()
        except OSError:
            self._close(kind)
            return None
        stamp = (st.st_mtime_ns, st.st_size)
        if kind not in self._readers or self._stamps.get(kind) != stamp:
            self._close(kind)
            try:
                self._readers[kind] = maxminddb.open_database(str(path), maxminddb.MODE_MMAP)
                self._stamps[kind] = stamp
            except Exception as exc:
                self.error = f"Не удалось открыть {path.name}: {exc}"
                return None
        return self._readers[kind]

    def _close(self, kind: str):
        reader = self._readers.pop(kind, None)
        self._stamps.pop(kind, None)
        if reader is not None:
            try:
                reader.close()
            except Exception:
                pass

    def close(self):
        with self._lock:
            for kind in list(self._readers):
                self._close(kind)

    def lookup(self, ip: str) -> dict | None:
        if not self.supported:
            return None
        with self._lock:
            city_db, asn_db = self._reader("city"), self._reader("asn")
            try:
                c = city_db.get(ip) if city_db else None
                a = asn_db.get(ip) if asn_db else None
            except (ValueError, TypeError):
                return None
        if not c and not a:
            return None
        out: dict = {}
        if c:
            subs = c.get("subdivisions") or [{}]
            loc = c.get("location") or {}
            out.update(country=(c.get("country") or {}).get("iso_code", ""),
                       region=(subs[0].get("names") or {}).get("en", ""),
                       city=((c.get("city") or {}).get("names") or {}).get("en", ""),
                       lat=loc.get("latitude"), lon=loc.get("longitude"))
        if a:
            out.update(asn=a.get("autonomous_system_number"), org=a.get("autonomous_system_organization", ""))
        return out

    # -- versions
    def _versions(self) -> dict:
        try:
            data = json.loads((self.folder / VERSIONS_FILE).read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def month(self, kind: str) -> str:
        """Which month's file is installed; "" when there is none."""
        if not self.path(kind).exists():
            return ""
        known = self._versions().get(kind)
        if known:
            return str(known)
        with self._lock:  # copied in by hand: judge by the build date inside the file
            reader = self._reader(kind) if self.supported else None
            return month_of(reader.metadata().build_epoch) if reader else "0000-00"

    def status(self) -> dict:
        files = {}
        for kind in DBIP_FILES:
            path = self.path(kind)
            files[kind] = {"month": self.month(kind), "size": path.stat().st_size if path.exists() else 0}
        return {
            "supported": self.supported,
            "available": bool(files["city"]["size"]),
            "files": files,
            "updating": self.updating,
            "error": self.error,
            "last_attempt": self.last_attempt,
            "last_update": self.last_update,
            "folder": str(self.folder),
        }

    # -- updating
    def update_due(self, now: float) -> bool:
        if not self.supported or self.updating or now - self.last_attempt < DB_RETRY_SECONDS:
            return False
        current = month_of(now)
        return any(self.month(kind) < current for kind in DBIP_FILES)

    def update(self, now: float | None = None) -> list[tuple[str, str]]:
        """Fetch this month's files, or last month's while this month's are not published yet.

        Returns what was installed. Raises when a download fails; the old files stay in place.
        """
        now = time.time() if now is None else now
        self.updating, self.last_attempt = True, now
        installed = []
        try:
            self.folder.mkdir(parents=True, exist_ok=True)
            current = month_of(now)
            for kind in DBIP_FILES:
                for month in (current, previous_month(current)):
                    if self.month(kind) >= month:
                        break
                    try:
                        self._download(kind, month)
                    except NotPublished:
                        continue
                    installed.append((kind, month))
                    break
            self.error = ""
            if installed:
                self.last_update = now
            return installed
        except Exception as exc:
            self.error = str(exc)[:300]
            raise
        finally:
            self.updating = False

    def _download(self, kind: str, month: str):
        url = DBIP_URL.format(kind=kind, month=month)
        packed = self.folder / f".{kind}.download.gz"
        unpacked = self.folder / f".{kind}.download.mmdb"
        try:
            with self._open_url(url) as resp, open(packed, "wb") as out:
                total = 0
                while chunk := resp.read(1 << 20):
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise RuntimeError(f"{url}: файл больше {MAX_DOWNLOAD_BYTES >> 20} МБ")
                    out.write(chunk)
            with gzip.open(packed, "rb") as src, open(unpacked, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            self._validate(unpacked, kind)
            with self._lock:  # Windows will not replace a file that is still mapped
                self._close(kind)
                os.replace(unpacked, self.path(kind))
                versions = self._versions() | {kind: month}
                (self.folder / VERSIONS_FILE).write_text(json.dumps(versions), encoding="utf-8")
            log.info("База DB-IP %s за %s установлена", kind, month)
        finally:
            for tmp in (packed, unpacked):
                try:
                    tmp.unlink()
                except OSError:
                    pass

    @staticmethod
    def _validate(path: Path, kind: str):
        reader = maxminddb.open_database(str(path), maxminddb.MODE_FILE)
        try:
            db_type = reader.metadata().database_type
        finally:
            reader.close()
        if "DBIP" not in db_type.upper() or kind not in db_type.lower():
            raise RuntimeError(f"Неожиданный файл базы: {db_type}")
