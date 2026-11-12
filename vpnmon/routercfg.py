"""Router configuration backups, address pool usage and AnyConnect licenses: parsing only."""

from __future__ import annotations

import difflib
import hashlib
import re

CONFIG_COMMAND = "show running-config"
POOL_COMMAND = "show ip local pool"
LICENSE_COMMAND = "show license"

# Lines that change without anyone changing the configuration.
_VOLATILE_RE = re.compile(
    r"^(! Last configuration change at|! NVRAM config last updated|! No configuration change since|"
    r"ntp clock-period )"
)
_DENIED_RE = re.compile(r"(% ?Invalid input|[Aa]uthorization failed|% ?Permission denied)")

# Passwords, keys and communities: the word, an optional encryption type, then the value.
_SECRET_WORDS = (
    r"secret|password|key-string|pre-shared-key|authentication-key|community|md5|wpa-psk ascii|"
    r"server-key|key"
)
# "ntp authentication-key 1 md5 VALUE": the key number and the hash type come before the value.
_SECRET_RE = re.compile(rf"(?<![\w-])((?:{_SECRET_WORDS})(?:\s+(?:\d{{1,2}}|md5|sha1|sha256))*\s+)(\S+)")
_KEEP_AFTER = {"chain", "config-key", "generate", "rsa", "pubkey-chain", "encryption", "exchange"}
MASK = "<скрыто>"


class ConfigUnavailable(RuntimeError):
    pass


def extract_config(output: str) -> str:
    """The configuration text out of a raw SSH reply to `show running-config`.

    Raises ConfigUnavailable when the reply is a refusal or is cut short: storing half a
    configuration would show a huge bogus change on the next backup.
    """
    text = output.replace("\r", "")
    lines = text.split("\n")
    if _DENIED_RE.search(text[:400]):
        raise ConfigUnavailable("роутер не выдал конфигурацию: у учётки мониторинга нет прав на "
                                "show running-config (нужен privilege 15)")
    start = next((i for i, x in enumerate(lines)
                  if x.startswith("Current configuration") or x.startswith("Building configuration")), None)
    if start is None:
        start = 1 if lines and lines[0].strip().startswith("show") else 0
    body = lines[start:]
    while body and (body[0].startswith("Building configuration") or body[0].startswith("Current configuration")
                    or not body[0].strip()):
        body = body[1:]
    end = max((i for i, x in enumerate(body) if x.strip() == "end"), default=None)
    if end is None:
        raise ConfigUnavailable("ответ роутера обрезан (нет строки end), копия не сохранена")
    body = [x.rstrip() for x in body[: end + 1] if not _VOLATILE_RE.match(x)]
    if len(body) < 5:
        raise ConfigUnavailable("роутер вернул пустую конфигурацию")
    return "\n".join(body) + "\n"


def config_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def mask_line(line: str) -> str:
    def repl(m: re.Match) -> str:
        if m.group(2).lower() in _KEEP_AFTER:
            return m.group(0)
        return m.group(1) + MASK

    return _SECRET_RE.sub(repl, line)


def mask_config(text: str) -> str:
    return "\n".join(mask_line(x) for x in text.split("\n"))


def config_diff(old: str, new: str, context: int = 2) -> list[str]:
    """Unified diff of two configurations with secrets masked (a changed password still shows)."""
    diff = difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=context)
    out = []
    for line in diff:
        if line.startswith(("---", "+++")):
            continue
        out.append(mask_line(line))
    return out


def diff_counts(old: str, new: str) -> tuple[int, int]:
    added = removed = 0
    for line in difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0):
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return added, removed


def vpn_pool_names(config: str) -> set[str]:
    """Pools that WebVPN contexts hand out to AnyConnect clients (`svc address-pool NAME`)."""
    return {m.group(1) for m in re.finditer(r'^\s*svc address-pool\s+"?([^"\s]+)"?', config, re.M)}


_POOL_LINE_RE = re.compile(
    r"^\s*(?:(\S+)\s+)?(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)(?:\s+(\d+))?\s*$"
)


def parse_ip_local_pools(output: str) -> list[dict]:
    """`show ip local pool`: one entry per pool, ranges of the same pool added up.

     Pool                     Begin           End             Free  In use   Blocked
     SSLVPN_POOL              10.20.30.1      10.20.30.100      93       7         0
                              10.20.31.1      10.20.31.50       50       0         0
    """
    pools: dict[str, dict] = {}
    current = ""
    for line in output.replace("\r", "").split("\n"):
        m = _POOL_LINE_RE.match(line)
        if not m:
            continue
        name = m.group(1) or current
        if not name:
            continue
        current = name
        free, used, blocked = int(m.group(4)), int(m.group(5)), int(m.group(6) or 0)
        p = pools.setdefault(name, {"name": name, "free": 0, "in_use": 0, "blocked": 0, "ranges": []})
        p["free"] += free
        p["in_use"] += used
        p["blocked"] += blocked
        p["ranges"].append(f"{m.group(2)}–{m.group(3)}")
    out = []
    for p in pools.values():
        p["total"] = p["free"] + p["in_use"] + p["blocked"]
        p["percent"] = round(100 * (p["in_use"] + p["blocked"]) / p["total"]) if p["total"] else 0
        out.append(p)
    return out


def parse_sslvpn_license(output: str) -> dict | None:
    """AnyConnect (SSL VPN) license count from `show license` on ISR G2 IOS 15.

    Index 5 Feature: SSL_VPN
            License State: Active, In Use
            License Count: 10/7/0  (Active/In-use/Violation)
    """
    text = output.replace("\r", "")
    m = re.search(r"Feature:\s*SSL_VPN\b(.*?)(?=\n\s*Index \d+|\Z)", text, re.S)
    if not m:
        return None
    count = re.search(r"License Count:\s*(\d+)(?:\s*/\s*(\d+))?", m.group(1))
    if not count or int(count.group(1)) <= 0:
        return None
    state = re.search(r"License State:\s*(.+)", m.group(1))
    return {
        "limit": int(count.group(1)),
        "in_use": int(count.group(2)) if count.group(2) else None,
        "state": state.group(1).strip() if state else "",
    }
