from __future__ import annotations

import logging
import shutil
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .cisco import VpnSession, parse_cisco_age
from .config import STATS_DB_FILE

log = logging.getLogger("vpnmon.storage")

SCHEMA_VERSION = 5
DEFAULT_ROUTER_ID = "main"

# A session counts as a reconnect when it starts at most RECONNECT_MAX_GAP seconds after the
# previous session of the same login ended. A small overlap is allowed because the router may
# still list the dead session for a poll or two; long overlaps are parallel devices, not reconnects.
RECONNECT_MAX_GAP = 600
RECONNECT_MAX_OVERLAP = 120
DEFAULT_UNSTABLE_PER_DAY = 3


def format_duration_hm(seconds: int) -> str:
    if seconds <= 0:
        return "< 1 мин"
    minutes = max(1, seconds // 60)
    hours, rem_min = divmod(minutes, 60)
    if hours > 0:
        return f"{hours}ч {rem_min:02d}м"
    return f"{rem_min}м"


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def session_start_estimate(created_raw: str, observed_ts: int) -> tuple[int, int | None]:
    """Return (estimated start ts, match tolerance in seconds, or None when Created is unparseable)."""
    parsed = parse_cisco_age(created_raw)
    if parsed is None:
        return observed_ts, None
    age, resolution = parsed
    # Two polls of one session give starts a few seconds apart (command latency, rounding);
    # coarse formats like "1d02h" only move in whole hours.
    return observed_ts - age, max(120, resolution + 120)


@dataclass
class SnapshotDiff:
    connected: list[VpnSession] = field(default_factory=list)
    disconnected: list[dict] = field(default_factory=list)


class ConnectionStatsStore:
    """Persistent SQLite3 store for user VPN connection events and known user roster.

    One row in session_events is one real VPN session. first_seen_ts is the session start
    as reported by the router (poll time minus the Created age), last_seen_ts is the last
    poll where the session was still present.
    """

    # A session missing from one or two polls (router hiccup, app restart) is resumed
    # rather than counted again, as long as its start time matches.
    DEDUP_WINDOW_SECONDS = 18 * 3600

    def __init__(self, db_path: Path = STATS_DB_FILE):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        # `with sqlite3.connect()` only commits; the connection must be closed explicitly.
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self._lock:
            try:
                with self._connect() as conn:
                    conn.execute("PRAGMA journal_mode=WAL")
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS session_events (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            login TEXT NOT NULL,
                            context TEXT NOT NULL,
                            ip TEXT NOT NULL,
                            created_raw TEXT NOT NULL,
                            country TEXT DEFAULT '',
                            org TEXT DEFAULT '',
                            peak_connections INTEGER DEFAULT 1,
                            first_seen_ts INTEGER NOT NULL,
                            last_seen_ts INTEGER NOT NULL,
                            first_seen_iso TEXT NOT NULL,
                            last_seen_iso TEXT NOT NULL,
                            is_active INTEGER DEFAULT 1
                        )
                        """
                    )
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS known_users (
                            login TEXT PRIMARY KEY COLLATE NOCASE,
                            added_ts INTEGER NOT NULL,
                            added_iso TEXT NOT NULL,
                            source TEXT DEFAULT 'auto'
                        )
                        """
                    )
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS app_events (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ts INTEGER NOT NULL,
                            type TEXT NOT NULL,
                            login TEXT DEFAULT '',
                            ip TEXT DEFAULT '',
                            message TEXT NOT NULL
                        )
                        """
                    )
                    conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_session_events_login_ts "
                        "ON session_events (login, first_seen_ts)"
                    )
                    conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_session_events_first_ts "
                        "ON session_events (first_seen_ts)"
                    )
                    conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_session_events_active "
                        "ON session_events (is_active)"
                    )
                    conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_session_events_key "
                        "ON session_events (login, context, ip, last_seen_ts)"
                    )
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_app_events_ts ON app_events (ts)")
                    conn.commit()
                self._migrate()
            except Exception:
                log.exception("Не удалось инициализировать базу %s", self.db_path)

    # -------------------------------------------------------------------------
    # Migrations
    # -------------------------------------------------------------------------
    def _migrate(self):
        with self._connect() as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version >= SCHEMA_VERSION:
            return
        if version < 2:
            has_rows = False
            with self._connect() as conn:
                has_rows = conn.execute("SELECT 1 FROM session_events LIMIT 1").fetchone() is not None
            if has_rows:
                backup = self.db_path.with_name(self.db_path.name + f".before-v2-{int(time.time())}.bak")
                with self._connect() as conn:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                shutil.copy2(self.db_path, backup)
                log.info("Резервная копия базы перед миграцией: %s", backup)
            with self._connect() as conn:
                merged, removed = merge_duplicate_sessions(conn)
                conn.execute("PRAGMA user_version = 2")
                conn.commit()
            if removed:
                log.info("Миграция v2: склеено %s сессий, удалено %s дублей", merged, removed)
        if version < 3:
            # v3: several routers, client details, router user lists, scheduler state.
            with self._connect() as conn:
                _add_columns(conn, "session_events", {
                    "router": f"TEXT NOT NULL DEFAULT '{DEFAULT_ROUTER_ID}'",
                    "client_agent": "TEXT DEFAULT ''",
                    "client_os": "TEXT DEFAULT ''",
                    "client_version": "TEXT DEFAULT ''",
                    "tunnel_ip": "TEXT DEFAULT ''",
                    "rx_packets": "INTEGER DEFAULT 0",
                    "tx_packets": "INTEGER DEFAULT 0",
                    "details_ts": "INTEGER DEFAULT 0",
                })
                _add_columns(conn, "app_events", {"router": "TEXT DEFAULT ''"})
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS router_users (
                        router TEXT NOT NULL,
                        login TEXT NOT NULL COLLATE NOCASE,
                        privilege INTEGER DEFAULT 1,
                        first_synced_ts INTEGER NOT NULL,
                        synced_ts INTEGER NOT NULL,
                        PRIMARY KEY (router, login)
                    )
                    """
                )
                conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_session_events_router_active "
                    "ON session_events (router, is_active)"
                )
                conn.execute("PRAGMA user_version = 3")
                conn.commit()
        if version < 4:
            # v4: periods when the monitor itself was not running (PC off, power loss).
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS downtime (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        start_ts INTEGER NOT NULL,
                        end_ts INTEGER NOT NULL
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_downtime_end ON downtime (end_ts)")
                conn.execute("PRAGMA user_version = 4")
                conn.commit()
        if version < 5:
            # v5: the router's own log received over syslog.
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS syslog_messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts INTEGER NOT NULL,
                        router TEXT DEFAULT '',
                        source_ip TEXT NOT NULL,
                        severity INTEGER NOT NULL,
                        code TEXT DEFAULT '',
                        text TEXT NOT NULL,
                        kind TEXT DEFAULT ''
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_syslog_ts ON syslog_messages (ts)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_syslog_code ON syslog_messages (code, ts)")
                conn.execute("PRAGMA user_version = 5")
                conn.commit()

    # -------------------------------------------------------------------------
    # Known users
    # -------------------------------------------------------------------------
    def register_known_users(
        self, logins: list[str], source: str = "imported", now_ts: int | None = None
    ) -> int:
        if now_ts is None:
            now_ts = int(time.time())
        now_iso = _iso(now_ts)
        added = 0
        with self._lock:
            try:
                with self._connect() as conn:
                    for raw_login in logins:
                        login = raw_login.strip()
                        if not login:
                            continue
                        cur = conn.execute(
                            """
                            INSERT OR IGNORE INTO known_users (login, added_ts, added_iso, source)
                            VALUES (?, ?, ?, ?)
                            """,
                            (login, now_ts, now_iso, source),
                        )
                        if cur.rowcount and cur.rowcount > 0:
                            added += 1
                    conn.commit()
            except Exception:
                log.exception("register_known_users")
        return added

    def remove_known_users(self, logins: list[str]) -> int:
        if not logins:
            return 0
        removed = 0
        with self._lock:
            try:
                with self._connect() as conn:
                    for login in logins:
                        cur = conn.execute(
                            "DELETE FROM known_users WHERE login = ? COLLATE NOCASE",
                            (login.strip(),),
                        )
                        removed += cur.rowcount or 0
                    conn.commit()
            except Exception:
                log.exception("remove_known_users")
        return removed

    # -------------------------------------------------------------------------
    # Snapshots
    # -------------------------------------------------------------------------
    def record_snapshot(self, sessions: list[VpnSession], now_ts: int | None = None,
                        router: str = DEFAULT_ROUTER_ID) -> SnapshotDiff:
        """Store one poll of one router. Sessions of other routers are left untouched."""
        if now_ts is None:
            now_ts = int(time.time())
        now_iso = _iso(now_ts)
        diff = SnapshotDiff()

        with self._lock:
            try:
                with self._connect() as conn:
                    for s in sessions:
                        conn.execute(
                            """
                            INSERT OR IGNORE INTO known_users (login, added_ts, added_iso, source)
                            VALUES (?, ?, ?, 'vpn_session')
                            """,
                            (s.login, now_ts, now_iso),
                        )

                    active_rows = conn.execute(
                        "SELECT id, router, login, context, ip, created_raw, first_seen_ts, last_seen_ts, "
                        "country, org FROM session_events WHERE is_active = 1 AND router = ?",
                        (router,),
                    ).fetchall()
                    active_by_key: dict[tuple[str, str, str], list[sqlite3.Row]] = {}
                    for r in active_rows:
                        active_by_key.setdefault((r["context"], r["login"], r["ip"]), []).append(r)
                    seen_ids: set[int] = set()

                    for s in sessions:
                        start_ts, tolerance = session_start_estimate(s.created, now_ts)
                        candidates = [
                            r for r in active_by_key.get(s.key(), []) if r["id"] not in seen_ids
                        ]
                        row_id = _closest_row(candidates, start_ts, tolerance)

                        if row_id is None and tolerance is not None:
                            recent = conn.execute(
                                """
                                SELECT id, first_seen_ts FROM session_events
                                WHERE login = ? AND context = ? AND ip = ? AND router = ?
                                  AND last_seen_ts >= ? AND ABS(first_seen_ts - ?) <= ?
                                ORDER BY ABS(first_seen_ts - ?) LIMIT 1
                                """,
                                (
                                    s.login, s.context, s.ip, router,
                                    now_ts - self.DEDUP_WINDOW_SECONDS,
                                    start_ts, tolerance, start_ts,
                                ),
                            ).fetchone()
                            if recent and recent["id"] not in seen_ids:
                                row_id = recent["id"]

                        loc_val = s.country if s.country and s.country != "Загрузка..." else ""
                        org_val = s.org if s.org and s.org != "Загрузка..." else ""

                        if row_id is not None:
                            seen_ids.add(row_id)
                            conn.execute(
                                """
                                UPDATE session_events
                                SET last_seen_ts = ?,
                                    last_seen_iso = ?,
                                    is_active = 1,
                                    peak_connections = MAX(peak_connections, ?),
                                    country = CASE WHEN ? != '' THEN ? ELSE country END,
                                    org = CASE WHEN ? != '' THEN ? ELSE org END
                                WHERE id = ?
                                """,
                                (now_ts, now_iso, s.connections,
                                 loc_val, loc_val, org_val, org_val, row_id),
                            )
                            if tolerance is not None:
                                # Coarse ages ("1d02h") are floored, so the earliest estimate is the closest.
                                conn.execute(
                                    """
                                    UPDATE session_events
                                    SET first_seen_ts = ?, first_seen_iso = ?
                                    WHERE id = ? AND first_seen_ts > ?
                                    """,
                                    (start_ts, _iso(start_ts), row_id, start_ts),
                                )
                        else:
                            cur = conn.execute(
                                """
                                INSERT INTO session_events (
                                    router, login, context, ip, created_raw, country, org,
                                    peak_connections, first_seen_ts, last_seen_ts,
                                    first_seen_iso, last_seen_iso, is_active
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                                """,
                                (router, s.login, s.context, s.ip, s.created, loc_val, org_val,
                                 s.connections, start_ts, now_ts, _iso(start_ts), now_iso),
                            )
                            if cur.lastrowid:
                                seen_ids.add(cur.lastrowid)
                            diff.connected.append(s)

                    for r in active_rows:
                        if r["id"] not in seen_ids:
                            conn.execute(
                                "UPDATE session_events SET is_active = 0 WHERE id = ?",
                                (r["id"],),
                            )
                            diff.disconnected.append(dict(r))

                    conn.commit()
            except Exception:
                log.exception("record_snapshot")

        return diff

    def update_geo_for_ip(self, ip: str, country: str, org: str):
        if not ip or country == "Загрузка...":
            return
        with self._lock:
            try:
                with self._connect() as conn:
                    conn.execute(
                        """
                        UPDATE session_events
                        SET country = CASE WHEN country = '' OR country = '—' THEN ? ELSE country END,
                            org = CASE WHEN org = '' OR org = '—' THEN ? ELSE org END
                        WHERE ip = ?
                        """,
                        (country, org, ip),
                    )
                    conn.commit()
            except Exception:
                log.exception("update_geo_for_ip")

    # -------------------------------------------------------------------------
    # Event journal
    # -------------------------------------------------------------------------
    def add_event(self, event_type: str, message: str, login: str = "", ip: str = "",
                  now_ts: int | None = None, router: str = ""):
        ts = now_ts if now_ts is not None else int(time.time())
        with self._lock:
            try:
                with self._connect() as conn:
                    conn.execute(
                        "INSERT INTO app_events (ts, type, login, ip, message, router) VALUES (?, ?, ?, ?, ?, ?)",
                        (ts, event_type, login, ip, message, router),
                    )
                    conn.commit()
            except Exception:
                log.exception("add_event")

    def get_events(self, limit: int = 500, event_type: str = "", query: str = "",
                   since_ts: int = 0, until_ts: int | None = None) -> list[dict]:
        sql = "SELECT id, ts, type, login, ip, message, router FROM app_events WHERE ts >= ?"
        params: list = [since_ts]
        if until_ts is not None:
            sql += " AND ts < ?"
            params.append(until_ts)
        if event_type:
            sql += " AND type = ?"
            params.append(event_type)
        if query:
            sql += " AND (login LIKE ? OR ip LIKE ? OR message LIKE ?)"
            like = f"%{query}%"
            params += [like, like, like]
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            try:
                with self._connect() as conn:
                    return [dict(r) | {"iso": _iso(r["ts"])} for r in conn.execute(sql, params)]
            except Exception:
                log.exception("get_events")
                return []

    # -------------------------------------------------------------------------
    # Analytics
    # -------------------------------------------------------------------------
    def get_user_counts_map(self, days: int = 90, now_ts: int | None = None) -> dict[str, int]:
        if now_ts is None:
            now_ts = int(time.time())
        cutoff = now_ts - (days * 86400) if days > 0 else 0
        with self._lock:
            try:
                with self._connect() as conn:
                    rows = conn.execute(
                        """
                        SELECT login, COUNT(*) AS cnt
                        FROM session_events
                        WHERE first_seen_ts >= ?
                        GROUP BY login
                        """,
                        (cutoff,),
                    ).fetchall()
                    return {r["login"]: int(r["cnt"]) for r in rows}
            except Exception:
                log.exception("get_user_counts_map")
                return {}

    def get_user_countries(self, login: str, exclude_ip: str = "") -> set[str]:
        with self._lock:
            try:
                with self._connect() as conn:
                    rows = conn.execute(
                        """
                        SELECT DISTINCT country FROM session_events
                        WHERE login = ? COLLATE NOCASE AND ip != ? AND country NOT IN ('', '—')
                        """,
                        (login, exclude_ip),
                    ).fetchall()
                    return {r["country"].split(" / ")[0] for r in rows}
            except Exception:
                log.exception("get_user_countries")
                return set()

    def get_all_users_summary(self, days: int = 30, now_ts: int | None = None,
                              unstable_per_day: int = DEFAULT_UNSTABLE_PER_DAY) -> list[dict]:
        if now_ts is None:
            now_ts = int(time.time())
        cutoff_period = now_ts - (days * 86400) if days > 0 else 0
        cutoff_90d = now_ts - (90 * 86400)
        cutoff_30d = now_ts - (30 * 86400)
        cutoff_7d = now_ts - (7 * 86400)

        with self._lock:
            try:
                with self._connect() as conn:
                    known_rows = conn.execute(
                        "SELECT login, added_ts, added_iso, source FROM known_users"
                    ).fetchall()
                    known_map = {r["login"].lower(): dict(r) for r in known_rows}

                    agg_rows = conn.execute(
                        """
                        SELECT
                            MIN(login) AS login,
                            SUM(CASE WHEN first_seen_ts >= ? THEN 1 ELSE 0 END) AS connects_period,
                            SUM(CASE WHEN first_seen_ts >= ? THEN 1 ELSE 0 END) AS connects_90d,
                            SUM(CASE WHEN first_seen_ts >= ? THEN 1 ELSE 0 END) AS connects_30d,
                            SUM(CASE WHEN first_seen_ts >= ? THEN 1 ELSE 0 END) AS connects_7d,
                            COUNT(DISTINCT CASE WHEN first_seen_ts >= ? THEN ip END) AS unique_ips,
                            COUNT(DISTINCT CASE WHEN first_seen_ts >= ? THEN substr(first_seen_iso, 1, 10) END) AS active_days,
                            SUM(CASE WHEN first_seen_ts >= ? THEN MAX(60, last_seen_ts - first_seen_ts) ELSE 0 END) AS work_seconds,
                            MAX(last_seen_ts) AS last_seen_ts_max,
                            MAX(is_active) AS online
                        FROM session_events
                        GROUP BY lower(login)
                        """,
                        (cutoff_period, cutoff_90d, cutoff_30d, cutoff_7d,
                         cutoff_period, cutoff_period, cutoff_period),
                    ).fetchall()
                    last_rows = conn.execute(
                        """
                        SELECT lkey, ip, country, org, context, last_seen_iso FROM (
                            SELECT lower(login) AS lkey, ip, country, org, context, last_seen_iso,
                                   ROW_NUMBER() OVER (
                                       PARTITION BY lower(login) ORDER BY first_seen_ts DESC, id DESC
                                   ) AS rn
                            FROM session_events
                        ) WHERE rn = 1
                        """
                    ).fetchall()
                    reconnect_rows = conn.execute(
                        """
                        WITH s AS (
                            SELECT lower(login) AS lkey, first_seen_ts,
                                   substr(first_seen_iso, 1, 10) AS day,
                                   first_seen_ts - LAG(last_seen_ts) OVER (
                                       PARTITION BY lower(login) ORDER BY first_seen_ts, id
                                   ) AS gap
                            FROM session_events
                        ), per_day AS (
                            SELECT lkey, day, COUNT(*) AS cnt FROM s
                            WHERE gap BETWEEN ? AND ? AND first_seen_ts >= ?
                            GROUP BY lkey, day
                        )
                        SELECT lkey, SUM(cnt) AS reconnects, MAX(cnt) AS peak_day,
                               (SELECT p2.day FROM per_day p2 WHERE p2.lkey = per_day.lkey
                                ORDER BY p2.cnt DESC, p2.day DESC LIMIT 1) AS peak_date
                        FROM per_day GROUP BY lkey
                        """,
                        (-RECONNECT_MAX_OVERLAP, RECONNECT_MAX_GAP, cutoff_period),
                    ).fetchall()
                    client_rows = conn.execute(
                        """
                        SELECT lkey, client_agent, client_os, client_version FROM (
                            SELECT lower(login) AS lkey, client_agent, client_os, client_version,
                                   ROW_NUMBER() OVER (
                                       PARTITION BY lower(login) ORDER BY details_ts DESC, id DESC
                                   ) AS rn
                            FROM session_events WHERE client_agent != ''
                        ) WHERE rn = 1
                        """
                    ).fetchall()
                    router_rows = conn.execute(
                        "SELECT lower(login) AS lkey, GROUP_CONCAT(DISTINCT router) AS routers "
                        "FROM session_events WHERE first_seen_ts >= ? GROUP BY lower(login)",
                        (cutoff_period,),
                    ).fetchall()
            except Exception:
                log.exception("get_all_users_summary")
                return []

        agg_map = {r["login"].lower(): r for r in agg_rows}
        last_map = {r["lkey"]: r for r in last_rows}
        reconnect_map = {r["lkey"]: r for r in reconnect_rows}
        client_map = {r["lkey"]: r for r in client_rows}
        routers_map = {r["lkey"]: sorted((r["routers"] or "").split(",")) for r in router_rows}
        results: list[dict] = []
        for key in sorted(set(known_map) | set(agg_map)):
            r = agg_map.get(key)
            k = known_map.get(key)
            last_row = last_map.get(key)
            login_display = r["login"] if r else k["login"]

            connects_period = int(r["connects_period"] or 0) if r else 0
            last_seen_ts_max = int(r["last_seen_ts_max"] or 0) if r else 0
            days_idle = max(0, (now_ts - last_seen_ts_max) // 86400) if last_seen_ts_max else 9999
            work_seconds = int(r["work_seconds"] or 0) if r else 0
            is_active_in_period = connects_period > 0
            rc = reconnect_map.get(key)
            reconnects = int(rc["reconnects"]) if rc else 0
            peak_day = int(rc["peak_day"]) if rc else 0
            cl = client_map.get(key)

            results.append(
                {
                    "status": "ACTIVE" if is_active_in_period else "INACTIVE",
                    "status_label": "● Активен" if is_active_in_period else "○ Неактивен",
                    "login": login_display,
                    "online": bool(r["online"]) if r else False,
                    "source": k["source"] if k else "vpn_session",
                    "connects_period": connects_period,
                    "connects_30d": int(r["connects_30d"] or 0) if r else 0,
                    "connects_90d": int(r["connects_90d"] or 0) if r else 0,
                    "connects_7d": int(r["connects_7d"] or 0) if r else 0,
                    "active_days": int(r["active_days"] or 0) if r else 0,
                    "work_seconds": work_seconds,
                    "work_time": format_duration_hm(work_seconds) if connects_period > 0 else "0м",
                    "unique_ips": int(r["unique_ips"] or 0) if r else 0,
                    "last_connected": last_row["last_seen_iso"] if last_row else "Никогда",
                    "days_idle": days_idle,
                    "days_idle_str": "Никогда" if days_idle >= 9999 else f"{days_idle} дн.",
                    "last_ip": last_row["ip"] if last_row else "—",
                    "last_country": (last_row["country"] or "—") if last_row else "—",
                    "last_org": (last_row["org"] or "—") if last_row else "—",
                    "reconnects": reconnects,
                    "reconnects_peak_day": peak_day,
                    "reconnects_peak_date": rc["peak_date"] if rc else "",
                    "unstable": peak_day >= max(1, unstable_per_day),
                    "client_agent": cl["client_agent"] if cl else "",
                    "client_os": cl["client_os"] if cl else "",
                    "client_version": cl["client_version"] if cl else "",
                    "routers": routers_map.get(key, []),
                }
            )

        results.sort(key=lambda x: (-x["connects_period"], x["login"].lower()))
        return results

    def get_user_sessions_history(
        self, login: str, days: int = 90, now_ts: int | None = None
    ) -> list[dict]:
        if now_ts is None:
            now_ts = int(time.time())
        cutoff = now_ts - (days * 86400) if days > 0 else 0
        with self._lock:
            try:
                with self._connect() as conn:
                    rows = conn.execute(
                        """
                        SELECT
                            id, router, login, context, ip, created_raw, country, org,
                            peak_connections, first_seen_ts, last_seen_ts,
                            first_seen_iso, last_seen_iso, is_active,
                            client_agent, client_os, client_version, tunnel_ip, rx_packets, tx_packets
                        FROM session_events
                        WHERE login = ? COLLATE NOCASE AND first_seen_ts >= ?
                        ORDER BY first_seen_ts DESC, id DESC
                        """,
                        (login, cutoff),
                    ).fetchall()
                    out = [dict(r) for r in rows]
                    for i, d in enumerate(out):
                        d["duration_seconds"] = max(60, int(d["last_seen_ts"]) - int(d["first_seen_ts"]))
                        d["duration_str"] = format_duration_hm(d["duration_seconds"])
                        # Rows are newest first, so the previous session is the next row.
                        prev = out[i + 1] if i + 1 < len(out) else None
                        gap = int(d["first_seen_ts"]) - int(prev["last_seen_ts"]) if prev else None
                        d["gap_seconds"] = gap
                        d["reconnect"] = gap is not None and -RECONNECT_MAX_OVERLAP <= gap <= RECONNECT_MAX_GAP
                    return out
            except Exception:
                log.exception("get_user_sessions_history")
                return []

    def get_user_monthly_breakdown(
        self, login: str, days: int = 90, now_ts: int | None = None
    ) -> list[tuple[str, int]]:
        if now_ts is None:
            now_ts = int(time.time())
        cutoff = now_ts - (days * 86400) if days > 0 else 0
        with self._lock:
            try:
                with self._connect() as conn:
                    rows = conn.execute(
                        """
                        SELECT substr(first_seen_iso, 1, 7) AS ym, COUNT(*) AS cnt
                        FROM session_events
                        WHERE login = ? COLLATE NOCASE AND first_seen_ts >= ?
                        GROUP BY ym
                        ORDER BY ym DESC
                        """,
                        (login, cutoff),
                    ).fetchall()
                    return [(r["ym"], int(r["cnt"])) for r in rows]
            except Exception:
                log.exception("get_user_monthly_breakdown")
                return []

    def get_concurrency(self, days: int = 7, bucket_seconds: int = 3600,
                        now_ts: int | None = None) -> list[dict]:
        """Peak and distinct-user count of concurrent sessions per time bucket."""
        if now_ts is None:
            now_ts = int(time.time())
        start = now_ts - days * 86400
        start -= start % bucket_seconds
        with self._lock:
            try:
                with self._connect() as conn:
                    rows = conn.execute(
                        "SELECT login, first_seen_ts, last_seen_ts FROM session_events "
                        "WHERE last_seen_ts >= ? AND first_seen_ts <= ?",
                        (start, now_ts),
                    ).fetchall()
            except Exception:
                log.exception("get_concurrency")
                return []

        n = (now_ts - start) // bucket_seconds + 1
        users: list[set[str]] = [set() for _ in range(n)]
        # Sweep line over session intervals for the true peak inside each bucket.
        points: list[tuple[int, int]] = []
        for r in rows:
            a, b = max(start, int(r["first_seen_ts"])), int(r["last_seen_ts"])
            points.append((a, 1))
            points.append((b + 1, -1))
            for i in range((a - start) // bucket_seconds, min(n - 1, (b - start) // bucket_seconds) + 1):
                users[i].add(r["login"].lower())
        points.sort()
        peaks = [0] * n
        current = 0
        idx = 0
        for i in range(n):
            bucket_end = start + (i + 1) * bucket_seconds
            peak = current
            while idx < len(points) and points[idx][0] < bucket_end:
                current += points[idx][1]
                peak = max(peak, current)
                idx += 1
            peaks[i] = peak
        return [
            {"ts": start + i * bucket_seconds, "peak": peaks[i], "users": len(users[i])}
            for i in range(n)
        ]

    # -------------------------------------------------------------------------
    # Client details (AnyConnect version, OS, traffic)
    # -------------------------------------------------------------------------
    def update_client_details(self, router: str, context: str, login: str, ip: str, info: dict,
                              created_ts: int | None = None, now_ts: int | None = None) -> int:
        now_ts = now_ts if now_ts is not None else int(time.time())
        values = (
            info.get("agent", ""), info.get("os", ""), info.get("version", ""),
            info.get("tunnel_ip", ""), int(info.get("rx_packets") or 0), int(info.get("tx_packets") or 0),
            now_ts,
        )
        sql = (
            "UPDATE session_events SET client_agent = ?, client_os = ?, client_version = ?, "
            "tunnel_ip = ?, rx_packets = ?, tx_packets = ?, details_ts = ? "
            "WHERE router = ? AND context = ? AND login = ? AND ip = ? AND is_active = 1"
        )
        key = (router, context, login, ip)
        with self._lock:
            try:
                with self._connect() as conn:
                    cur = None
                    if created_ts is not None:
                        # Two parallel sessions of one login/IP: the router's Created time tells them apart.
                        cur = conn.execute(sql + " AND ABS(first_seen_ts - ?) <= 300", values + key + (created_ts,))
                    if cur is None or not cur.rowcount:
                        cur = conn.execute(sql, values + key)
                    conn.commit()
                    return cur.rowcount or 0
            except Exception:
                log.exception("update_client_details")
                return 0

    def mark_details_checked(self, router: str, context: str, login: str, ip: str,
                             now_ts: int | None = None):
        """Remember a failed lookup too, so a session without details isn't re-queried every poll."""
        with self._lock:
            try:
                with self._connect() as conn:
                    conn.execute(
                        "UPDATE session_events SET details_ts = ? WHERE router = ? AND context = ? "
                        "AND login = ? AND ip = ? AND is_active = 1",
                        (now_ts if now_ts is not None else int(time.time()), router, context, login, ip),
                    )
                    conn.commit()
            except Exception:
                log.exception("mark_details_checked")

    def sessions_needing_details(self, router: str, refresh_before_ts: int, limit: int = 5) -> list[dict]:
        with self._lock:
            try:
                with self._connect() as conn:
                    rows = conn.execute(
                        """
                        SELECT context, login, ip, MIN(details_ts) AS details_ts FROM session_events
                        WHERE router = ? AND is_active = 1 AND details_ts < ?
                        GROUP BY context, login, ip ORDER BY details_ts LIMIT ?
                        """,
                        (router, refresh_before_ts, limit),
                    ).fetchall()
                    return [dict(r) for r in rows]
            except Exception:
                log.exception("sessions_needing_details")
                return []

    def get_active_details(self, router: str) -> dict[tuple[str, str, str], dict]:
        with self._lock:
            try:
                with self._connect() as conn:
                    rows = conn.execute(
                        """
                        SELECT context, login, ip, client_agent, client_os, client_version,
                               tunnel_ip, rx_packets, tx_packets, details_ts
                        FROM session_events WHERE router = ? AND is_active = 1 AND details_ts > 0
                        ORDER BY details_ts
                        """,
                        (router,),
                    ).fetchall()
                    return {(r["context"], r["login"], r["ip"]): dict(r) for r in rows}
            except Exception:
                log.exception("get_active_details")
                return {}

    # -------------------------------------------------------------------------
    # Router user lists (for the cleanup report)
    # -------------------------------------------------------------------------
    def sync_router_users(self, router: str, entries: list[tuple[str, int]],
                          now_ts: int | None = None) -> dict:
        now_ts = now_ts if now_ts is not None else int(time.time())
        logins = {login.lower(): (login, priv) for login, priv in entries if login}
        with self._lock:
            with self._connect() as conn:
                before = {r["login"].lower() for r in conn.execute(
                    "SELECT login FROM router_users WHERE router = ?", (router,))}
                for login, priv in logins.values():
                    conn.execute(
                        """
                        INSERT INTO router_users (router, login, privilege, first_synced_ts, synced_ts)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT (router, login) DO UPDATE SET privilege = excluded.privilege,
                                                                  synced_ts = excluded.synced_ts
                        """,
                        (router, login, priv, now_ts, now_ts),
                    )
                removed = before - set(logins)
                for login in removed:
                    conn.execute("DELETE FROM router_users WHERE router = ? AND login = ?", (router, login))
                conn.commit()
        self.register_known_users([v[0] for v in logins.values()], source="router", now_ts=now_ts)
        self.set_meta(f"router_users_synced:{router}", str(now_ts))
        return {"total": len(logins), "added": len(set(logins) - before), "removed": len(removed)}

    def get_admin_logins(self, min_privilege: int = 15) -> set[str]:
        """Router admin accounts (privilege 15): device management, not VPN users."""
        with self._lock:
            try:
                with self._connect() as conn:
                    return {r["login"].lower() for r in conn.execute(
                        "SELECT login FROM router_users WHERE privilege >= ?", (min_privilege,))}
            except Exception:
                log.exception("get_admin_logins")
                return set()

    def get_router_user_activity(self, router: str) -> tuple[list[dict], int | None]:
        """Users from the router config with their last VPN activity on that router.

        Also returns when monitoring of the router started: "never logged in" only means
        "not since then", so the cleanup report must not count idle days before it.
        """
        with self._lock:
            try:
                with self._connect() as conn:
                    rows = conn.execute(
                        """
                        SELECT ru.login, ru.privilege, ru.first_synced_ts, ru.synced_ts,
                               (SELECT MAX(se.last_seen_ts) FROM session_events se
                                 WHERE se.router = ru.router AND se.login = ru.login COLLATE NOCASE) AS last_ts,
                               (SELECT MAX(se.is_active) FROM session_events se
                                 WHERE se.router = ru.router AND se.login = ru.login COLLATE NOCASE) AS online
                        FROM router_users ru WHERE ru.router = ?
                        ORDER BY ru.login COLLATE NOCASE
                        """,
                        (router,),
                    ).fetchall()
                    observed = conn.execute(
                        "SELECT MIN(last_seen_ts) FROM session_events WHERE router = ?", (router,)
                    ).fetchone()[0]
                    return [dict(r) for r in rows], (int(observed) if observed else None)
            except Exception:
                log.exception("get_router_user_activity")
                return [], None

    # -------------------------------------------------------------------------
    # Small key/value state (report schedule, sync times)
    # -------------------------------------------------------------------------
    def get_meta(self, key: str, default: str = "") -> str:
        with self._lock:
            try:
                with self._connect() as conn:
                    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
                    return row["value"] if row else default
            except Exception:
                log.exception("get_meta")
                return default

    def set_meta(self, key: str, value: str):
        with self._lock:
            try:
                with self._connect() as conn:
                    conn.execute(
                        "INSERT INTO meta (key, value) VALUES (?, ?) "
                        "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                        (key, value),
                    )
                    conn.commit()
            except Exception:
                log.exception("set_meta")

    # -------------------------------------------------------------------------
    # Router syslog
    # -------------------------------------------------------------------------
    def add_syslog(self, ts: int, router: str, source_ip: str, severity: int, code: str,
                   text: str, kind: str = ""):
        with self._lock:
            try:
                with self._connect() as conn:
                    conn.execute(
                        "INSERT INTO syslog_messages (ts, router, source_ip, severity, code, text, kind) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (ts, router, source_ip, severity, code, text, kind),
                    )
                    conn.commit()
            except Exception:
                log.exception("add_syslog")

    def get_syslog(self, limit: int = 500, query: str = "", max_severity: int = 7, router: str = "",
                   code_prefix: str = "", kind: str = "", hide: list[str] | None = None,
                   hide_text: list[str] | None = None) -> list[dict]:
        sql = "SELECT id, ts, router, source_ip, severity, code, text, kind FROM syslog_messages WHERE severity <= ?"
        params: list = [max_severity]
        if router:
            sql += " AND router = ?"
            params.append(router)
        if code_prefix:
            sql += " AND code LIKE ?"
            params.append(code_prefix + "%")
        if kind:
            sql += " AND kind = ?"
            params.append(kind)
        for prefix in hide or []:
            sql += " AND code NOT LIKE ?"
            params.append(prefix + "%")
        for fragment in hide_text or []:
            sql += " AND text NOT LIKE ?"
            params.append(f"%{fragment}%")
        if query:
            sql += " AND (text LIKE ? OR code LIKE ? OR source_ip LIKE ?)"
            like = f"%{query}%"
            params += [like, like, like]
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            try:
                with self._connect() as conn:
                    return [dict(r) | {"iso": _iso(r["ts"])} for r in conn.execute(sql, params)]
            except Exception:
                log.exception("get_syslog")
                return []

    def get_syslog_summary(self, since_ts: int) -> dict:
        with self._lock:
            try:
                with self._connect() as conn:
                    codes = conn.execute(
                        "SELECT code, MIN(severity) AS severity, COUNT(*) AS cnt, MAX(ts) AS last_ts "
                        "FROM syslog_messages WHERE ts >= ? GROUP BY code ORDER BY cnt DESC LIMIT 40",
                        (since_ts,),
                    ).fetchall()
                    sources = conn.execute(
                        "SELECT source_ip, router, COUNT(*) AS cnt, MAX(ts) AS last_ts FROM syslog_messages "
                        "GROUP BY source_ip, router ORDER BY last_ts DESC"
                    ).fetchall()
            except Exception:
                log.exception("get_syslog_summary")
                return {"codes": [], "sources": []}
        return {"codes": [dict(r) for r in codes], "sources": [dict(r) for r in sources]}

    def purge_syslog(self, days: int, now_ts: int | None = None) -> int:
        cutoff = (now_ts if now_ts is not None else int(time.time())) - days * 86400
        with self._lock:
            try:
                with self._connect() as conn:
                    cur = conn.execute("DELETE FROM syslog_messages WHERE ts < ?", (cutoff,))
                    conn.commit()
                    return cur.rowcount or 0
            except Exception:
                log.exception("purge_syslog")
                return 0

    # -------------------------------------------------------------------------
    # Monitor downtime
    # -------------------------------------------------------------------------
    def add_downtime(self, start_ts: int, end_ts: int):
        with self._lock:
            try:
                with self._connect() as conn:
                    conn.execute("INSERT INTO downtime (start_ts, end_ts) VALUES (?, ?)", (start_ts, end_ts))
                    conn.commit()
            except Exception:
                log.exception("add_downtime")

    def get_downtime(self, since_ts: int, until_ts: int | None = None) -> dict:
        """Downtime intervals overlapping [since, until), clipped to it, with their total."""
        until_ts = until_ts if until_ts is not None else int(time.time())
        with self._lock:
            try:
                with self._connect() as conn:
                    rows = conn.execute(
                        "SELECT start_ts, end_ts FROM downtime WHERE end_ts > ? AND start_ts < ? ORDER BY start_ts",
                        (since_ts, until_ts),
                    ).fetchall()
            except Exception:
                log.exception("get_downtime")
                rows = []
        intervals = [(max(r["start_ts"], since_ts), min(r["end_ts"], until_ts)) for r in rows]
        return {
            "intervals": [{"start": a, "end": b} for a, b in intervals],
            "total_seconds": sum(b - a for a, b in intervals),
            "count": len(intervals),
        }

    # -------------------------------------------------------------------------
    # Period statistics (weekly report)
    # -------------------------------------------------------------------------
    def get_period_stats(self, since_ts: int, until_ts: int) -> dict:
        """Per-user sessions and online time inside [since, until), clipped to the period."""
        with self._lock:
            try:
                with self._connect() as conn:
                    rows = conn.execute(
                        """
                        SELECT MIN(login) AS login,
                               SUM(CASE WHEN first_seen_ts >= ? THEN 1 ELSE 0 END) AS sessions,
                               SUM(MAX(60, MIN(last_seen_ts, ?) - MAX(first_seen_ts, ?))) AS seconds,
                               COUNT(DISTINCT router) AS routers
                        FROM session_events
                        WHERE last_seen_ts >= ? AND first_seen_ts < ?
                        GROUP BY lower(login)
                        """,
                        (since_ts, until_ts, since_ts, since_ts, until_ts),
                    ).fetchall()
                    known = [r["login"] for r in conn.execute(
                        "SELECT login FROM known_users ORDER BY login COLLATE NOCASE")]
                    started = conn.execute(
                        "SELECT COUNT(*) FROM session_events WHERE first_seen_ts >= ? AND first_seen_ts < ?",
                        (since_ts, until_ts),
                    ).fetchone()[0]
            except Exception:
                log.exception("get_period_stats")
                return {"users": [], "known": [], "sessions_started": 0}
        users = sorted(
            ({"login": r["login"], "sessions": int(r["sessions"] or 0), "seconds": int(r["seconds"] or 0)}
             for r in rows),
            key=lambda u: -u["seconds"],
        )
        return {"users": users, "known": known, "sessions_started": int(started or 0)}

    # -------------------------------------------------------------------------
    # Backups
    # -------------------------------------------------------------------------
    BACKUP_PREFIX = "connection_stats-"

    def backup_to(self, dest: Path) -> Path:
        """Write a consistent, compacted copy of the database (safe while the collector writes)."""
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".tmp")
        tmp.unlink(missing_ok=True)
        with self._lock:
            conn = sqlite3.connect(str(self.db_path), timeout=30, isolation_level=None)
            try:
                conn.execute("VACUUM INTO ?", (str(tmp),))
            finally:
                conn.close()
        tmp.replace(dest)
        return dest

    def daily_backup(self, backup_dir: Path, keep: int, today: str | None = None) -> Path | None:
        """Create today's backup if it doesn't exist yet and keep only the newest `keep` files."""
        if keep <= 0:
            return None
        today = today or datetime.now().strftime("%Y-%m-%d")
        dest = backup_dir / f"{self.BACKUP_PREFIX}{today}.db"
        created = None
        if not dest.exists():
            created = self.backup_to(dest)
        for old in self.list_backups(backup_dir)[keep:]:
            try:
                (backup_dir / old["name"]).unlink()
            except OSError:
                log.warning("Не удалось удалить старую копию %s", old["name"])
        return created

    def list_backups(self, backup_dir: Path) -> list[dict]:
        if not backup_dir.is_dir():
            return []
        files = sorted(backup_dir.glob(f"{self.BACKUP_PREFIX}*.db"), reverse=True)
        return [
            {"name": f.name, "size": f.stat().st_size, "mtime": int(f.stat().st_mtime)}
            for f in files
        ]

    def purge_older_than(self, days: int = 90, now_ts: int | None = None) -> int:
        if now_ts is None:
            now_ts = int(time.time())
        cutoff = now_ts - (days * 86400)
        with self._lock:
            try:
                with self._connect() as conn:
                    cur = conn.execute(
                        "DELETE FROM session_events WHERE first_seen_ts < ? AND is_active = 0",
                        (cutoff,),
                    )
                    conn.execute("DELETE FROM app_events WHERE ts < ?", (cutoff,))
                    conn.commit()
                    return cur.rowcount or 0
            except Exception:
                log.exception("purge_older_than")
                return 0


def _add_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]):
    existing = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    for name, ddl in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


def _closest_row(candidates: list[sqlite3.Row], start_ts: int, tolerance: int | None) -> int | None:
    if not candidates:
        return None
    if tolerance is None:
        return candidates[0]["id"]
    best = min(candidates, key=lambda r: abs(int(r["first_seen_ts"]) - start_ts))
    return best["id"] if abs(int(best["first_seen_ts"]) - start_ts) <= tolerance else None


def merge_duplicate_sessions(conn: sqlite3.Connection) -> tuple[int, int]:
    """Collapse rows written by versions <= 3.x, which inserted a new row on every poll.

    Old rows have first_seen_ts = poll time and created_raw = session age at that poll,
    so the real start is first_seen_ts - age. Rows with the same login/context/ip and
    matching start belong to one session. Returns (sessions kept, rows deleted).
    """
    cur = conn.execute(
        "SELECT id, login, context, ip, created_raw, country, org, peak_connections, "
        "first_seen_ts, last_seen_ts, is_active FROM session_events"
    )
    names = [d[0] for d in cur.description]
    rows = [dict(zip(names, r)) for r in cur.fetchall()]
    # Parallel sessions from one IP interleave by poll time, so order by the derived start.
    estimated = []
    for r in rows:
        start, tolerance = session_start_estimate(r["created_raw"], int(r["first_seen_ts"]))
        estimated.append((r["context"], r["login"].lower(), r["ip"], start, r["id"], tolerance, r))
    estimated.sort(key=lambda e: e[:5])

    groups: list[dict] = []
    current: dict | None = None
    for context, login_key, ip, start, _id, tolerance, r in estimated:
        key = (context, login_key, ip)
        same = (
            current is not None
            and current["key"] == key
            and tolerance is not None
            and abs(start - current["start"]) <= tolerance
        )
        if same:
            current["ids"].append(r["id"])
            current["start"] = min(current["start"], start)
            current["last"] = max(current["last"], int(r["last_seen_ts"]))
            current["peak"] = max(current["peak"], int(r["peak_connections"] or 1))
            current["active"] = current["active"] or bool(r["is_active"])
            current["country"] = current["country"] or (r["country"] or "")
            current["org"] = current["org"] or (r["org"] or "")
        else:
            current = {
                "key": key,
                "ids": [r["id"]],
                "start": start,
                "last": int(r["last_seen_ts"]),
                "peak": int(r["peak_connections"] or 1),
                "active": bool(r["is_active"]),
                "country": r["country"] or "",
                "org": r["org"] or "",
            }
            groups.append(current)

    removed = 0
    for g in groups:
        keep, *dupes = g["ids"]
        conn.execute(
            """
            UPDATE session_events
            SET first_seen_ts = ?, first_seen_iso = ?, last_seen_ts = ?, last_seen_iso = ?,
                peak_connections = ?, is_active = ?, country = ?, org = ?
            WHERE id = ?
            """,
            (g["start"], _iso(g["start"]), g["last"], _iso(g["last"]), g["peak"],
             1 if g["active"] else 0, g["country"], g["org"], keep),
        )
        for i in range(0, len(dupes), 500):
            chunk = dupes[i:i + 500]
            conn.execute(
                f"DELETE FROM session_events WHERE id IN ({','.join('?' * len(chunk))})", chunk
            )
        removed += len(dupes)
    return len(groups), removed
