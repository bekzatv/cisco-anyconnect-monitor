from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request

IPINFO_URL = "https://ipinfo.io/{ip}/json"


def is_private_or_local_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False


def format_ip_summary(data: dict) -> tuple[str, str]:
    if not data:
        return ("", "")
    if data.get("bogon") or data.get("_private"):
        return ("LAN / Локальная", "Локальная сеть")
    country = str(data.get("country") or "").strip()
    city = str(data.get("city") or "").strip()
    org = str(data.get("org") or "").strip()
    loc_parts = [p for p in (country, city) if p]
    loc_str = " / ".join(loc_parts) if loc_parts else "—"
    org_str = org if org else "—"
    return (loc_str, org_str)


def fetch_ipinfo(ip: str, timeout: int = 12) -> dict:
    if is_private_or_local_ip(ip):
        return {
            "ip": ip,
            "bogon": True,
            "_private": True,
            "country": "LAN",
            "city": "Private IP",
            "org": "Local Network",
        }
    url = IPINFO_URL.format(ip=ip)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "CiscoAnyConnectMonitor/4.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            payload = response.read().decode(charset, errors="replace")
            return json.loads(payload)
    except urllib.error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"ipinfo.io returned HTTP {exc.code}: {details or exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not connect to ipinfo.io: {exc.reason}") from exc
