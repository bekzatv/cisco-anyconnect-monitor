"""Checks GitHub for a newer release. Nothing is downloaded or installed: the panel only says so."""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request

from . import REPOSITORY, __version__
from .cisco import version_tuple
from .storage import ConnectionStatsStore

log = logging.getLogger("vpnmon.updates")

RELEASES_API = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPOSITORY}/releases"
CHECK_EVERY_SECONDS = 24 * 3600
# After a failed check (no internet on the server is normal), try again later, not every minute.
RETRY_SECONDS = 6 * 3600


def is_newer(latest: str, current: str = __version__) -> bool:
    a, b = version_tuple(latest), version_tuple(current)
    if not a or not b:
        return False
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) > b + (0,) * (n - len(b))


def fetch_latest_release(timeout: int = 10) -> dict | None:
    """The latest published release, or None when the repository has no releases yet."""
    req = urllib.request.Request(RELEASES_API, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": f"CiscoAnyConnectMonitor/{__version__}",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    tag = str(data.get("tag_name") or "")
    return {
        "version": tag.lstrip("vV"),
        "url": str(data.get("html_url") or RELEASES_PAGE),
        "published": str(data.get("published_at") or "")[:10],
        "notes": str(data.get("body") or "").strip()[:2000],
    }


def update_state(store: ConnectionStatsStore) -> dict:
    """What the panel shows: the current version, the latest known release and when it was checked."""
    try:
        latest = json.loads(store.get_meta("update_latest", "") or "null")
    except ValueError:
        latest = None
    return {
        "current": __version__,
        "latest": latest,
        "available": bool(latest and is_newer(latest.get("version", ""))),
        "checked_ts": int(store.get_meta("update_checked_ts", "0") or 0),
        "error": store.get_meta("update_error", ""),
        "releases_url": RELEASES_PAGE,
    }


def check_for_update(store: ConnectionStatsStore, now: int | None = None, fetch=None) -> dict:
    """Ask GitHub now and remember the answer. Returns update_state() plus "is_new" for a first sighting."""
    now = now if now is not None else int(time.time())
    try:
        latest = (fetch or fetch_latest_release)()
    except Exception as exc:
        log.info("Проверка обновлений не удалась: %s", exc)
        store.set_meta("update_error", str(exc)[:300])
        store.set_meta("update_retry_ts", str(now + RETRY_SECONDS))
        return update_state(store) | {"is_new": False}
    store.set_meta("update_error", "")
    store.set_meta("update_checked_ts", str(now))
    store.set_meta("update_latest", json.dumps(latest, ensure_ascii=False) if latest else "")
    state = update_state(store)
    version = latest["version"] if latest else ""
    state["is_new"] = state["available"] and store.get_meta("update_notified") != version
    if state["is_new"]:
        store.set_meta("update_notified", version)
    return state


def check_due(store: ConnectionStatsStore, now: int) -> bool:
    checked = int(store.get_meta("update_checked_ts", "0") or 0)
    retry = int(store.get_meta("update_retry_ts", "0") or 0)
    return now - checked >= CHECK_EVERY_SECONDS and now >= retry
