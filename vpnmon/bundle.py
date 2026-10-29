"""Move the monitor to another machine: export a zip here, import it on the server.

Router passwords and the Telegram token are encrypted with Windows DPAPI for the current
user of this PC, so they can't be decrypted anywhere else and are left out; they are entered
again in the panel after the move. The panel password hash (PBKDF2) is portable and kept.
"""

from __future__ import annotations

import json
import shutil
import socket
import tempfile
import time
import zipfile
from pathlib import Path

from . import __version__
from .config import DATA_DIR, get_routers
from .storage import ConnectionStatsStore

MANIFEST = "manifest.json"
DB_NAME = "connection_stats.db"
# Only these names are ever written on import: nothing else from the archive reaches the disk.
DATA_FILES = ("known_hosts", "ip_cache.json", "session_history.log")
SECRET_KEYS = ("password", "password_encoded", "telegram_token_encoded")


def strip_secrets(settings: dict) -> dict:
    clean = {k: v for k, v in settings.items() if k not in SECRET_KEYS}
    if isinstance(settings.get("routers"), list):
        clean["routers"] = [{k: v for k, v in r.items() if k != "password_encoded"}
                            for r in settings["routers"] if isinstance(r, dict)]
    return clean


def export_bundle(dest: Path, data_dir: Path = DATA_DIR) -> dict:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    settings_path = data_dir / "settings.json"
    try:
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        settings = {}
    if "routers" not in settings:
        # Write the v4.0 single-router keys out as a routers list so the server sees router "main".
        routers = get_routers(settings)
        if routers:
            settings["routers"] = routers
    with tempfile.TemporaryDirectory() as tmp:
        db_copy = Path(tmp) / DB_NAME
        store = ConnectionStatsStore(data_dir / DB_NAME)
        store.backup_to(db_copy)
        sessions = _count(db_copy, "session_events")
        manifest = {
            "app": "CiscoAnyConnectMonitor",
            "version": __version__,
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source_host": socket.gethostname(),
            "source_dir": str(data_dir),
            "sessions": sessions,
            "routers": [{"id": r["id"], "name": r.get("name", ""), "host": r.get("host", "")}
                        for r in settings.get("routers", []) if isinstance(r, dict)],
            "needs_reentry": ["пароли устройств Cisco"]
                             + (["токен Telegram"] if settings.get("telegram_token_encoded") else []),
        }
        with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr(MANIFEST, json.dumps(manifest, ensure_ascii=False, indent=2))
            z.writestr("settings.json", json.dumps(strip_secrets(settings), ensure_ascii=False, indent=2))
            z.write(db_copy, DB_NAME)
            for name in DATA_FILES:
                if (data_dir / name).is_file():
                    z.write(data_dir / name, name)
    return manifest


def import_bundle(src: Path, data_dir: Path = DATA_DIR, force: bool = False,
                  lan: bool = False, port: int | None = None) -> dict:
    src, data_dir = Path(src), Path(data_dir)
    if (data_dir / DB_NAME).exists() and not force:
        raise RuntimeError(
            f"В {data_dir} уже есть база {DB_NAME}. Чтобы заменить её данными из архива, "
            f"запустите импорт с --force (текущая база будет сохранена с суффиксом .before-import)."
        )
    data_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(src) as z:
        names = set(z.namelist())
        if MANIFEST not in names or DB_NAME not in names:
            raise RuntimeError("Это не архив переноса Cisco AnyConnect Monitor")
        manifest = json.loads(z.read(MANIFEST).decode("utf-8"))
        stamp = time.strftime("%Y%m%d-%H%M%S")
        for name in (DB_NAME, "settings.json", *DATA_FILES):
            target = data_dir / name
            if name not in names:
                continue
            if target.exists():
                shutil.copy2(target, target.with_name(f"{target.name}.before-import-{stamp}"))
            if name == "settings.json":
                continue
            with z.open(name) as fsrc, open(target, "wb") as fdst:
                shutil.copyfileobj(fsrc, fdst)
        for leftover in ("-wal", "-shm"):
            (data_dir / f"{DB_NAME}{leftover}").unlink(missing_ok=True)
        incoming = json.loads(z.read("settings.json").decode("utf-8")) if "settings.json" in names else {}

    try:
        current = json.loads((data_dir / "settings.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        current = {}
    settings = current | strip_secrets(incoming)
    if lan:
        settings["web_bind"] = "0.0.0.0"
        settings["web_https"] = True
    if port:
        settings["web_port"] = int(port)
    (data_dir / "settings.json").write_text(json.dumps(settings, ensure_ascii=False, indent=2), encoding="utf-8")
    ConnectionStatsStore(data_dir / DB_NAME)  # applies schema migrations if the bundle is older
    return manifest | {"sessions_imported": _count(data_dir / DB_NAME, "session_events"), "data_dir": str(data_dir)}


def _count(db: Path, table: str) -> int:
    import sqlite3

    conn = sqlite3.connect(str(db))
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    except sqlite3.Error:
        return 0
    finally:
        conn.close()
