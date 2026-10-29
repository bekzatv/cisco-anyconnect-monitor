from __future__ import annotations

import base64
import json
import os
import sys
import threading
from pathlib import Path

if getattr(sys, "frozen", False):
    APP_DIR = Path(sys.executable).resolve().parent
    RESOURCE_DIR = Path(getattr(sys, "_MEIPASS", APP_DIR))
else:
    APP_DIR = Path(__file__).resolve().parent.parent
    RESOURCE_DIR = APP_DIR

# Data lives next to the program on a workstation; on a server it goes to its own folder
# (--data-dir sets VPNMON_DATA_DIR before this module is imported), so updates never touch it.
DATA_DIR = Path(os.environ.get("VPNMON_DATA_DIR") or APP_DIR).resolve()

ICON_FILE = RESOURCE_DIR / "assets" / "CiscoAnyConnectMonitor.ico"
WEB_STATIC_DIR = RESOURCE_DIR / "vpnmon" / "web"
SETTINGS_FILE = DATA_DIR / "settings.json"
IP_CACHE_FILE = DATA_DIR / "ip_cache.json"
HISTORY_LOG_FILE = DATA_DIR / "session_history.log"
STATS_DB_FILE = DATA_DIR / "connection_stats.db"
KNOWN_HOSTS_FILE = DATA_DIR / "known_hosts"
SERVER_LOG_FILE = DATA_DIR / "server.log"
BACKUP_DIR = DATA_DIR / "backups"
TLS_DIR = DATA_DIR / "tls"

_settings_lock = threading.Lock()


def load_settings() -> dict:
    try:
        data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def update_settings(changes: dict) -> dict:
    """Merge `changes` into settings.json so the desktop app and the server never wipe each other's keys."""
    with _settings_lock:
        data = load_settings()
        data.update(changes)
        SETTINGS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return data


# -----------------------------------------------------------------------------
# Password Storage Helper (Windows DPAPI + Base64 fallback)
# -----------------------------------------------------------------------------
def _dpapi(data: bytes, protect: bool) -> bytes | None:
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), buf)
    blob_out = DATA_BLOB()
    func = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    # 0x01 = CRYPTPROTECT_UI_FORBIDDEN
    if not func(ctypes.byref(blob_in), None, None, None, None, 0x01, ctypes.byref(blob_out)):
        return None
    result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    kernel32.LocalFree(blob_out.pbData)
    return result


def encode_password(plain: str) -> str:
    if not plain:
        return ""
    raw_bytes = plain.encode("utf-8")
    if sys.platform == "win32":
        try:
            encrypted = _dpapi(raw_bytes, protect=True)
            if encrypted is not None:
                return "dpapi:" + base64.b64encode(encrypted).decode("ascii")
        except Exception:
            pass
    # Fallback obfuscation so it always works across environments
    obf = bytes(b ^ 0x5A for b in raw_bytes)
    return "b64:" + base64.b64encode(obf).decode("ascii")


def decode_password(stored: str) -> str:
    if not stored:
        return ""
    if stored.startswith("dpapi:"):
        if sys.platform != "win32":
            return ""
        try:
            plain = _dpapi(base64.b64decode(stored[6:]), protect=False)
            return plain.decode("utf-8", errors="replace") if plain is not None else ""
        except Exception:
            return ""
    if stored.startswith("b64:"):
        try:
            obf = base64.b64decode(stored[4:])
            return bytes(b ^ 0x5A for b in obf).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return stored


DEFAULT_ROUTER_ID = "main"
ROUTER_FIELDS = ("id", "name", "host", "port", "username", "password_encoded", "disconnect_command", "enabled")


def get_routers(settings: dict | None = None) -> list[dict]:
    """Configured routers. Settings from v4.0 (single host/username at the top level) become router "main"."""
    s = settings if settings is not None else load_settings()
    routers = s.get("routers")
    if not isinstance(routers, list) or not routers:
        if not str(s.get("host", "")).strip():
            return []
        routers = [{
            "id": DEFAULT_ROUTER_ID,
            "name": str(s.get("router_name") or s.get("host", "")).strip(),
            "host": s.get("host", ""),
            "port": s.get("port", 22),
            "username": s.get("username", ""),
            "password_encoded": s.get("password_encoded", "") or (encode_password(s["password"]) if s.get("password") else ""),
            "disconnect_command": s.get("disconnect_command", ""),
            "enabled": True,
        }]
    out = []
    for r in routers:
        if not isinstance(r, dict) or not r.get("id"):
            continue
        try:
            port = int(r.get("port", 22))
        except (TypeError, ValueError):
            port = 22
        out.append({
            "id": str(r["id"]),
            "name": str(r.get("name") or r.get("host") or r["id"]).strip(),
            "host": str(r.get("host", "")).strip(),
            "port": port,
            "username": str(r.get("username", "")).strip(),
            "password_encoded": str(r.get("password_encoded", "")),
            "disconnect_command": str(r.get("disconnect_command", "")).strip(),
            "enabled": bool(r.get("enabled", True)),
        })
    return out


def save_routers(routers: list[dict]) -> dict:
    changes: dict = {"routers": [{k: r.get(k) for k in ROUTER_FIELDS} for r in routers]}
    if routers:
        # Keep the v4.0 top-level keys pointing at the first router: the desktop app reads them.
        first = routers[0]
        changes.update({
            "host": first["host"], "port": first["port"], "username": first["username"],
            "password_encoded": first["password_encoded"], "remember_password": True,
        })
        if first.get("disconnect_command"):
            changes["disconnect_command"] = first["disconnect_command"]
    return update_settings(changes)


def router_creds(router: dict) -> tuple[str, int, str, str]:
    return router["host"], int(router["port"]), router["username"], decode_password(router["password_encoded"])


def router_credentials(settings: dict | None = None) -> tuple[str, int, str, str]:
    s = settings if settings is not None else load_settings()
    password = decode_password(str(s.get("password_encoded", ""))) or str(s.get("password", ""))
    try:
        port = int(s.get("port", 22))
    except (TypeError, ValueError):
        port = 22
    return str(s.get("host", "")).strip(), port, str(s.get("username", "")).strip(), password
