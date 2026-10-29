from __future__ import annotations

import json
import logging
import queue
import socket
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import asdict
from datetime import datetime

from .cisco import (
    DEFAULT_DISCONNECT_COMMAND,
    ROUTER_USERS_COMMANDS,
    CiscoConnection,
    VpnSession,
    disconnect_on_shell,
    parse_cisco_age,
    parse_router_user_entries,
    parse_show_version,
    parse_session_details,
    send_cisco_command,
    session_details_on_shell,
)
from .config import (
    BACKUP_DIR,
    HISTORY_LOG_FILE,
    IP_CACHE_FILE,
    decode_password,
    get_routers,
    load_settings,
    router_creds,
)
from .geo import fetch_ipinfo, format_ip_summary, is_private_or_local_ip
from .storage import ConnectionStatsStore
from .syslog import FailureCounter, SyslogMessage, SyslogReceiver, classify, is_ignored

log = logging.getLogger("vpnmon.collector")

MIN_INTERVAL = 10
PURGE_EVERY_SECONDS = 24 * 3600
MAINTENANCE_EVERY_SECONDS = 60
# The heartbeat is written every MAINTENANCE_EVERY_SECONDS; a longer silence is downtime, not a restart.
DOWNTIME_MIN_SECONDS = 300
DETAILS_PER_POLL = 4  # client-detail lookups per poll, so polling isn't held up by a burst of logins
DETAIL_COMMAND = "show webvpn session user {login} context {context}"
VERSION_CHECK_SECONDS = 15 * 60
# IP phones register/unregister all day long and drown everything else in the router log.
DEFAULT_SYSLOG_IGNORE = ("IPPHONE-6-",)


class TelegramNotifier:
    def __init__(self):
        self._queue: queue.Queue[tuple[str, str, str]] = queue.Queue()
        threading.Thread(target=self._worker, name="telegram", daemon=True).start()

    @staticmethod
    def config(settings: dict) -> tuple[str, str] | None:
        if not settings.get("telegram_enabled"):
            return None
        token = decode_password(str(settings.get("telegram_token_encoded", "")))
        chat_id = str(settings.get("telegram_chat_id", "")).strip()
        return (token, chat_id) if token and chat_id else None

    def send(self, settings: dict, text: str):
        cfg = self.config(settings)
        if cfg:
            self._queue.put((cfg[0], cfg[1], text))

    @staticmethod
    def send_now(token: str, chat_id: str, text: str, timeout: int = 10):
        # Telegram rejects messages over 4096 characters.
        if len(text) > 4000:
            text = text[:3990] + "\n…"
        data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode()
        req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=data)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
        if not body.get("ok"):
            raise RuntimeError(body.get("description") or "Telegram API error")

    def _worker(self):
        while True:
            token, chat_id, text = self._queue.get()
            try:
                self.send_now(token, chat_id, text)
            except Exception as exc:
                log.warning("Telegram: не удалось отправить сообщение: %s", exc)


class RouterPoller:
    """Polls one router on its own thread over one long-lived SSH connection."""

    def __init__(self, collector: "Collector", router: dict):
        self.collector = collector
        self.router = router
        self.conn = CiscoConnection()
        self.sessions: list[VpnSession] = []
        self.status = "starting"  # starting | ok | error | not_configured | disabled
        self.last_error = ""
        self.last_poll_ts = 0
        self.last_success_ts = 0
        self._last_logged_error = ""
        self._first_poll_done = False
        self.clock_skew: int | None = None
        self._skews: list[int] = []
        self.version_info: dict = {}
        self._last_version_check = 0
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"poll-{router['id']}", daemon=True)

    @property
    def id(self) -> str:
        return self.router["id"]

    @property
    def label(self) -> str:
        return self.router["name"] or self.router["host"]

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()
        self.conn.close()

    def refresh_now(self):
        self._wake.set()

    def creds(self) -> tuple[str, int, str, str]:
        return router_creds(self.router)

    def _run(self):
        while not self._stop.is_set():
            settings = load_settings()
            interval = max(MIN_INTERVAL, _safe_int(settings.get("refresh_seconds"), 30))
            try:
                self.poll_once(settings)
                if self.status == "ok":
                    self.collect_details(settings)
            except Exception:
                log.exception("Опрос %s", self.label)
            self._wake.wait(interval)
            self._wake.clear()

    def poll_once(self, settings: dict):
        c = self.collector
        now = int(time.time())
        host, port, username, password = self.creds()
        if not self.router.get("enabled", True):
            self.status, self.last_error, self.sessions = "disabled", "", []
            c.bump()
            return
        if not (host and username and password):
            self.status = "not_configured"
            self.last_error = "Укажите адрес устройства, логин и пароль в настройках."
            self.last_poll_ts = now
            c.bump()
            return

        try:
            sessions, _raw = self.conn.fetch_sessions((host, port, username, password))
        except Exception as exc:
            was_ok = self.status == "ok"
            text = str(exc)
            self.status, self.last_error, self.last_poll_ts = "error", text, now
            # Log a repeated identical error only once, so a dead router doesn't flood the journal.
            if was_ok or text != self._last_logged_error:
                self._last_logged_error = text
                c.event("ERROR", f"Ошибка опроса {self.label} ({host}:{port}) — {text}", router=self.id)
            if was_ok:
                c.telegram.send(settings, f"⚠ VPN-монитор: нет связи с {self.label} ({host})\n{text}")
            c.bump()
            return

        recovered = self.status == "error"
        self._last_logged_error = ""
        for s in sessions:
            s.router = self.id
        c.enrich_geo(sessions)
        diff = c.store.record_snapshot(sessions, now_ts=now, router=self.id)
        counts = c.store.get_user_counts_map(days=90, now_ts=now)
        details = c.store.get_active_details(self.id)
        for s in sessions:
            s.connects_90d = counts.get(s.login, 1)
            _apply_details(s, details.get(s.key()))

        self.sessions = sessions
        self.status, self.last_error = "ok", ""
        self.last_poll_ts = self.last_success_ts = now
        if recovered:
            c.event("INFO", f"Связь с {self.label} ({host}) восстановлена", router=self.id)
            c.telegram.send(settings, f"✅ VPN-монитор: связь с {self.label} ({host}) восстановлена")

        c.handle_diff(self, settings, diff, first_poll=not self._first_poll_done)
        self._first_poll_done = True
        if now - self._last_version_check >= VERSION_CHECK_SECONDS:
            self._last_version_check = now
            self.check_version(settings)
        c.bump()

    def check_version(self, settings: dict):
        """Router uptime from `show version`: catches reboots even without syslog."""
        try:
            info = parse_show_version(self.conn.run(self.creds(), send_cisco_command, "show version", timeout=30))
        except Exception as exc:
            log.warning("show version на %s: %s", self.label, exc)
            return
        if "uptime_seconds" not in info:
            return
        now = int(time.time())
        boot_ts = now - info["uptime_seconds"]
        info["boot_ts"] = boot_ts
        self.version_info = info
        store = self.collector.store
        key = f"router_boot_ts:{self.id}"
        known = int(store.get_meta(key, "0") or 0)
        # Uptime is reported in whole minutes, so allow some slack before calling it a reboot.
        if known and boot_ts - known > 600:
            reason = f", причина: {info['reload_reason']}" if info.get("reload_reason") else ""
            text = (f"Роутер {self.label} перезагружался: снова работает с "
                    f"{datetime.fromtimestamp(boot_ts):%d.%m %H:%M}{reason}")
            if settings.get("alert_router_reboot", True):
                self.collector.alert(settings, text, router=self.id)
            else:
                self.collector.event("INFO", text, router=self.id)
        if not known or boot_ts - known > 600:
            store.set_meta(key, str(boot_ts))

    def collect_details(self, settings: dict):
        """Fetch AnyConnect version/OS/traffic for new sessions and refresh traffic periodically."""
        refresh_min = _safe_int(settings.get("client_details_refresh_minutes"), 30)
        now = int(time.time())
        # 0 = only when the session starts (details_ts == 0 means never looked up).
        refresh_before = now - refresh_min * 60 if refresh_min > 0 else 1
        pending = self.collector.store.sessions_needing_details(self.id, refresh_before, DETAILS_PER_POLL)
        updated = False
        for p in pending:
            if self._stop.is_set():
                return
            command = DETAIL_COMMAND.format(login=p["login"], context=p["context"])
            try:
                output = self.conn.run(self.creds(), send_cisco_command, command, timeout=25)
            except Exception as exc:
                log.warning("Подробности сессии %s на %s: %s", p["login"], self.label, exc)
                return
            blocks = [b for b in parse_session_details(output) if b["public_ip"] in ("", p["ip"])]
            if not blocks:
                self.collector.store.mark_details_checked(self.id, p["context"], p["login"], p["ip"])
                continue
            self._measure_clock_skew(p, blocks)
            for b in blocks:
                self.collector.store.update_client_details(
                    self.id, p["context"], p["login"], p["ip"], b, created_ts=b["created_ts"]
                )
            updated = True
        if updated:
            details = self.collector.store.get_active_details(self.id)
            for s in self.sessions:
                _apply_details(s, details.get(s.key()))
            self.collector.bump()

    def _measure_clock_skew(self, p: dict, blocks: list[dict]):
        """Router clock minus ours: its absolute Created time vs. our estimate from the session age.

        A difference of whole hours after a move to a server means a wrong time zone there.
        """
        estimates = []
        for s in self.sessions:
            if s.key() != (p["context"], p["login"], p["ip"]):
                continue
            age = parse_cisco_age(s.created)
            if age:
                estimates.append(self.last_success_ts - age[0])
        diffs = [b["created_ts"] - e for b in blocks if b["created_ts"] for e in estimates]
        if diffs:
            skew = min(diffs, key=abs)  # with parallel sessions, the closest pair is the same session
            self._skews = (self._skews + [skew])[-5:]
            self.clock_skew = sorted(self._skews)[len(self._skews) // 2]

    def snapshot(self) -> dict:
        return {
            "id": self.id,
            "name": self.label,
            "host": self.router["host"],
            "status": self.status,
            "last_error": self.last_error,
            "last_poll_ts": self.last_poll_ts,
            "last_success_ts": self.last_success_ts,
            "sessions": len(self.sessions),
            "clock_skew_seconds": self.clock_skew,
            "version": self.version_info,
        }


class Collector:
    """Runs one poller per configured router plus shared work: geo, alerts, backups, reports."""

    def __init__(self, store: ConnectionStatsStore):
        self.store = store
        self.telegram = TelegramNotifier()
        self.pollers: dict[str, RouterPoller] = {}
        self._pollers_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._stop = threading.Event()
        self.started_ts = int(time.time())
        self.version = 0  # bumps on every change the web panel should pick up

        self.ip_cache: dict[str, dict] = self._load_ip_cache()
        self._geo_queue: queue.Queue[str] = queue.Queue()
        self._geo_inflight: set[str] = set()
        self._pending_geo_alerts: dict[str, list[VpnSession]] = {}
        self._multi_ip_alerted: set[tuple[str, frozenset[str]]] = set()
        self._last_purge = 0
        self._last_backup_day = ""
        self._backup_error_day = ""
        self.syslog: SyslogReceiver | None = None
        self._auth_failures = FailureCounter(window=600)
        self._config_cmds: dict[str, deque] = {}
        self._router_ips: dict[str, str] = {}

        self._maintenance = threading.Thread(target=self._maintenance_loop, name="maintenance", daemon=True)
        threading.Thread(target=self._geo_worker, name="geo", daemon=True).start()

    # ------------------------------------------------------------------ lifecycle
    def start(self):
        self.check_downtime()
        self.sync_pollers()
        self._maintenance.start()
        settings = load_settings()
        if settings.get("syslog_enabled", True):
            self.syslog = SyslogReceiver(self.handle_syslog, port=_safe_int(settings.get("syslog_port"), 514))
            if not self.syslog.start():
                self.event("ERROR", f"Приём журнала роутера (syslog) не запущен: {self.syslog.error}")

    def stop(self):
        self._stop.set()
        if self.syslog:
            self.syslog.stop()
        self.heartbeat()
        with self._pollers_lock:
            for p in self.pollers.values():
                p.stop()

    def heartbeat(self):
        self.store.set_meta("heartbeat_ts", str(int(time.time())))

    def check_downtime(self, now: int | None = None) -> tuple[int, int] | None:
        """Record the time the monitor was not running, judged by the last heartbeat."""
        now = now if now is not None else int(time.time())
        last = int(self.store.get_meta("heartbeat_ts", "0") or 0)
        self.heartbeat()
        if not last or now - last < DOWNTIME_MIN_SECONDS:
            return None
        self.store.add_downtime(last, now)
        span = _duration(now - last)
        text = (f"Сбор данных не шёл с {datetime.fromtimestamp(last):%d.%m %H:%M} "
                f"до {datetime.fromtimestamp(now):%d.%m %H:%M} ({span}): сервер монитора был выключен. "
                f"Сессии, начавшиеся и закончившиеся за это время, не учтены.")
        self.event("GAP", text)
        self.telegram.send(load_settings(), f"⏸ VPN-монитор не работал {span}: "
                                            f"с {datetime.fromtimestamp(last):%d.%m %H:%M} "
                                            f"до {datetime.fromtimestamp(now):%d.%m %H:%M}")
        return last, now

    def sync_pollers(self):
        """Start, stop or reconfigure pollers to match the routers in settings."""
        routers = {r["id"]: r for r in get_routers()}
        with self._pollers_lock:
            for rid in list(self.pollers):
                if rid not in routers:
                    self.pollers.pop(rid).stop()
            for rid, cfg in routers.items():
                p = self.pollers.get(rid)
                if p is None:
                    p = RouterPoller(self, cfg)
                    self.pollers[rid] = p
                    p.start()
                elif p.router != cfg:
                    p.router = cfg
                    p.conn.close()  # reconnect with the new address/credentials
                    p.refresh_now()
        self.bump()

    def poller(self, router_id: str) -> RouterPoller:
        with self._pollers_lock:
            p = self.pollers.get(router_id)
        if p is None:
            raise RuntimeError(f"Устройство «{router_id}» не настроено")
        return p

    def all_pollers(self) -> list[RouterPoller]:
        with self._pollers_lock:
            return list(self.pollers.values())

    def all_sessions(self) -> list[VpnSession]:
        return [s for p in self.all_pollers() for s in p.sessions]

    def refresh_now(self, router_id: str | None = None):
        for p in self.all_pollers():
            if router_id in (None, p.id):
                p.refresh_now()

    def snapshot(self) -> dict:
        pollers = self.all_pollers()
        routers = [p.snapshot() for p in pollers]
        active = [r for r in routers if r["status"] != "disabled"]
        statuses = {r["status"] for r in active}
        if not active:
            status = "not_configured"
        elif "error" in statuses:
            status = "error"
        elif statuses == {"ok"}:
            status = "ok"
        elif "not_configured" in statuses:
            status = "not_configured"
        else:
            status = "starting"
        errors = [f"{r['name']}: {r['last_error']}" for r in active if r["status"] in ("error", "not_configured")]
        ok_ts = [r["last_success_ts"] for r in active if r["last_success_ts"]]
        return {
            "status": status,
            "last_error": "; ".join(errors) if len(active) > 1 else (active[0]["last_error"] if active else ""),
            "last_poll_ts": max((r["last_poll_ts"] for r in active), default=0),
            "last_success_ts": min(ok_ts) if ok_ts else 0,
            "started_ts": self.started_ts,
            "version": self.version,
            "routers": routers,
            "sessions": [asdict(s) for p in pollers for s in p.sessions],
        }

    def bump(self):
        with self._state_lock:
            self.version += 1

    # ------------------------------------------------------------------ events & alerts
    def router_prefix(self, router_id: str) -> str:
        """Name the router in messages only when there is more than one."""
        pollers = self.all_pollers()
        if len(pollers) < 2:
            return ""
        p = next((x for x in pollers if x.id == router_id), None)
        return f"[{p.label if p else router_id}] "

    def handle_diff(self, poller: RouterPoller, settings: dict, diff, first_poll: bool):
        notify_conn = bool(settings.get("telegram_notify_sessions", False))
        prefix = self.router_prefix(poller.id)
        for s in diff.connected:
            geo = f" ({s.country}, {s.org})" if s.country and s.country != "Загрузка..." else ""
            self.event(
                "CONNECTED",
                f"Подключился '{s.login}' с IP {s.ip}{geo} [context={s.context}, created={s.created}]",
                login=s.login, ip=s.ip, router=poller.id,
            )
            if notify_conn:
                self.telegram.send(settings, f"🟢 {prefix}{s.login} подключился с {s.ip}{geo}")
            self._check_night_login(settings, s)
            if s.country == "Загрузка...":
                self._pending_geo_alerts.setdefault(s.ip, []).append(s)
            else:
                self._check_new_country(settings, s)
        for r in diff.disconnected:
            self.event(
                "DISCONNECTED",
                f"Отключился '{r['login']}' ({r['ip']}) [context={r['context']}]",
                login=r["login"], ip=r["ip"], router=poller.id,
            )
            if notify_conn:
                self.telegram.send(settings, f"⚪ {prefix}{r['login']} отключился ({r['ip']})")
        self._check_multi_ip(settings, seed_only=first_poll)

    def event(self, event_type: str, message: str, login: str = "", ip: str = "", router: str = ""):
        self.store.add_event(event_type, message, login=login, ip=ip, router=router)
        prefix = self.router_prefix(router) if router else ""
        line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [{event_type}] {prefix}{message}\n"
        try:
            with open(HISTORY_LOG_FILE, "a", encoding="utf-8") as handle:
                handle.write(line)
        except OSError:
            pass
        log.info("%s %s%s", event_type, prefix, message)

    def alert(self, settings: dict, message: str, login: str = "", ip: str = "", router: str = ""):
        self.event("ALERT", message, login=login, ip=ip, router=router)
        if settings.get("telegram_notify_alerts", True):
            self.telegram.send(settings, f"🚨 {self.router_prefix(router)}{message}")

    def _check_multi_ip(self, settings: dict, seed_only: bool):
        if not settings.get("alert_multi_ip", True):
            return
        by_login: dict[str, set[str]] = {}
        for s in self.all_sessions():
            by_login.setdefault(s.login.lower(), set()).add(s.ip)
        current = set()
        for login, ips in by_login.items():
            if len(ips) > 1:
                key = (login, frozenset(ips))
                current.add(key)
                # After a restart, existing cases are remembered instead of re-alerted.
                if key not in self._multi_ip_alerted and not seed_only:
                    self.alert(
                        settings,
                        f"Логин '{login}' одновременно подключён с {len(ips)} IP: {', '.join(sorted(ips))}",
                        login=login,
                    )
        self._multi_ip_alerted = current

    def _check_new_country(self, settings: dict, s: VpnSession):
        if not settings.get("alert_new_country", True) or not s.country or s.country in ("—", "LAN / Локальная"):
            return
        country = s.country.split(" / ")[0]
        known = self.store.get_user_countries(s.login, exclude_ip=s.ip)
        if known and country not in known:
            self.alert(
                settings,
                f"'{s.login}' вошёл из новой страны: {s.country} ({s.ip}, {s.org}). "
                f"Раньше: {', '.join(sorted(known))}",
                login=s.login, ip=s.ip, router=s.router,
            )

    def _check_night_login(self, settings: dict, s: VpnSession):
        if not settings.get("alert_night_logins", False):
            return
        start = _safe_int(settings.get("night_start_hour"), 0)
        end = _safe_int(settings.get("night_end_hour"), 6)
        hour = datetime.now().hour
        in_night = start <= hour < end if start < end else (hour >= start or hour < end)
        if in_night:
            self.alert(settings, f"Ночной вход: '{s.login}' с {s.ip} в {datetime.now():%H:%M}",
                       login=s.login, ip=s.ip, router=s.router)

    # ------------------------------------------------------------------ router syslog
    def router_for_ip(self, ip: str) -> str:
        for p in self.all_pollers():
            host = p.router["host"]
            if host not in self._router_ips:
                try:
                    self._router_ips[host] = socket.gethostbyname(host)
                except OSError:
                    self._router_ips[host] = host
            if ip in (host, self._router_ips[host]):
                return p.id
        return ""

    def handle_syslog(self, msg: SyslogMessage):
        settings = load_settings()
        if is_ignored(msg, list(settings.get("syslog_ignore", DEFAULT_SYSLOG_IGNORE))):
            return
        router = self.router_for_ip(msg.source_ip)
        c = classify(msg)
        self.store.add_syslog(msg.received_ts, router, msg.source_ip, msg.severity, msg.code, msg.text, c.kind)
        prefix = self.router_prefix(router) if router else f"[{msg.source_ip}] "
        now = msg.received_ts
        if c.kind == "restart":
            if settings.get("syslog_alert_restart", True):
                self.alert(settings, c.summary, router=router)
        elif c.kind == "config_cmd":
            q = self._config_cmds.setdefault(router or msg.source_ip, deque(maxlen=30))
            q.append((now, c.login, c.summary))
            self.event("CONFIG", f"Команда конфигурации — {c.summary}", login=c.login, router=router)
        elif c.kind == "config":
            self.event("CONFIG", c.summary, login=c.login, ip=c.ip, router=router)
            if settings.get("syslog_alert_config", True):
                recent = [cmd for ts, who, cmd in self._config_cmds.get(router or msg.source_ip, [])
                          if now - ts < 900 and (not c.login or who == c.login)]
                lines = "\n".join(f"• {x.split(': ', 1)[-1]}" for x in recent[-10:])
                self.telegram.send(settings, f"🛠 {prefix}{c.summary}" + (f"\n{lines}" if lines else ""))
        elif c.kind == "iface_down":
            if settings.get("syslog_alert_interfaces", True):
                self.alert(settings, c.summary, router=router)
        elif c.kind == "iface_up":
            self.event("INFO", c.summary, router=router)
        elif c.kind in ("auth_fail", "login_fail"):
            self.event("AUTH", c.summary, login=c.login, ip=c.ip, router=router)
            threshold = max(1, _safe_int(settings.get("syslog_auth_fail_threshold"), 5))
            key = f"{c.kind}:{c.login or c.ip or msg.source_ip}"
            n = self._auth_failures.add(key, now, threshold)
            if n:
                target = "роутер" if c.kind == "login_fail" else "VPN"
                who = c.login or c.ip or "?"
                self.alert(settings, f"{n} неудачных попыток входа в {target} за 10 минут: {who}"
                                     + (f" с {c.ip}" if c.ip and c.ip != who else ""),
                           login=c.login, ip=c.ip, router=router)
        self.bump()

    def syslog_state(self) -> dict:
        s = self.syslog
        return {
            "enabled": s is not None,
            "port": s.port if s else _safe_int(load_settings().get("syslog_port"), 514),
            "error": s.error if s else "",
            "received": s.received if s else 0,
            "last_ts": s.last_ts if s else 0,
        }

    # ------------------------------------------------------------------ maintenance
    def _maintenance_loop(self):
        while not self._stop.wait(5 if not self._last_backup_day else MAINTENANCE_EVERY_SECONDS):
            settings = load_settings()
            try:
                self.heartbeat()
                self._maybe_backup(settings)
                now = int(time.time())
                if now - self._last_purge > PURGE_EVERY_SECONDS:
                    self._last_purge = now
                    days = _safe_int(settings.get("retention_days"), 180)
                    if days > 0:
                        self.store.purge_older_than(days=days, now_ts=now)
                    syslog_days = _safe_int(settings.get("syslog_retention_days"), 90)
                    if syslog_days > 0:
                        self.store.purge_syslog(syslog_days, now_ts=now)
                from .report import maybe_send_weekly_report

                maybe_send_weekly_report(self, settings)
            except Exception:
                log.exception("Служебные задачи")

    def _maybe_backup(self, settings: dict, force: bool = False) -> str:
        today = datetime.now().strftime("%Y-%m-%d")
        if today == self._last_backup_day and not force:
            return ""
        keep = _safe_int(settings.get("backup_keep_days"), 7)
        try:
            if force:
                path = self.store.backup_to(BACKUP_DIR / f"{self.store.BACKUP_PREFIX}{today}.db")
                self.store.daily_backup(BACKUP_DIR, max(keep, 1), today=today)
            else:
                path = self.store.daily_backup(BACKUP_DIR, keep, today=today)
            self._last_backup_day = today
            if path:
                log.info("Резервная копия базы: %s (%s КБ)", path, path.stat().st_size // 1024)
            return path.name if path else ""
        except Exception as exc:
            # Retry on the next run; journal it once a day so a full disk is noticed.
            if self._backup_error_day != today:
                self._backup_error_day = today
                self.event("ERROR", f"Не удалось сделать резервную копию базы: {exc}")
            if force:
                raise
            return ""

    def backup_now(self) -> str:
        return self._maybe_backup(load_settings(), force=True)

    # ------------------------------------------------------------------ geo
    def _load_ip_cache(self) -> dict[str, dict]:
        try:
            raw = json.loads(IP_CACHE_FILE.read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {}
        except Exception:
            return {}

    def _save_ip_cache(self):
        try:
            IP_CACHE_FILE.write_text(json.dumps(self.ip_cache, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError:
            log.warning("Не удалось сохранить %s", IP_CACHE_FILE)

    def enrich_geo(self, sessions: list[VpnSession]):
        for s in sessions:
            cached = self.ip_cache.get(s.ip)
            if cached:
                s.country, s.org = format_ip_summary(cached)
            elif is_private_or_local_ip(s.ip):
                s.country, s.org = "LAN / Локальная", "Локальная сеть"
            else:
                s.country = s.org = "Загрузка..."
                if s.ip not in self._geo_inflight:
                    self._geo_inflight.add(s.ip)
                    self._geo_queue.put(s.ip)

    def _geo_worker(self):
        while True:
            ip = self._geo_queue.get()
            try:
                data = fetch_ipinfo(ip, timeout=10)
            except Exception as exc:
                log.warning("Геолокация %s: %s", ip, exc)
                data = None
            self._geo_inflight.discard(ip)
            if data:
                self.ip_cache[ip] = data
                self._save_ip_cache()
            loc, org = format_ip_summary(data) if data else ("—", "—")
            if data:
                self.store.update_geo_for_ip(ip, loc, org)
            for s in self.all_sessions():
                if s.ip == ip:
                    s.country, s.org = loc, org
            settings = load_settings()
            for s in self._pending_geo_alerts.pop(ip, []):
                s.country, s.org = loc, org
                self._check_new_country(settings, s)
            self.bump()

    # ------------------------------------------------------------------ admin actions
    def find_session(self, router: str, context: str, login: str, ip: str) -> VpnSession | None:
        for s in self.all_sessions():
            if (s.router, s.context, s.login, s.ip) == (router, context, login, ip):
                return s
        return None

    def disconnect(self, session: VpnSession, actor: str = "") -> tuple[str, str]:
        p = self.poller(session.router)
        template = (p.router.get("disconnect_command") or load_settings().get("disconnect_command")
                    or DEFAULT_DISCONNECT_COMMAND)
        command, output = p.conn.run(p.creds(), disconnect_on_shell, session, template, timeout=25)
        self.event(
            "ADMIN",
            f"Сессия '{session.login}' ({session.ip}) отключена из веб-панели{f' ({actor})' if actor else ''}: {command}",
            login=session.login, ip=session.ip, router=session.router,
        )
        p.refresh_now()
        return command, output

    def session_details(self, session: VpnSession) -> tuple[str, str]:
        p = self.poller(session.router)
        return p.conn.run(p.creds(), session_details_on_shell, session, timeout=25)

    def router_user_entries(self, router_id: str) -> list[tuple[str, int]]:
        p = self.poller(router_id)

        def _fetch(shell):
            for cmd in ROUTER_USERS_COMMANDS:
                entries = parse_router_user_entries(send_cisco_command(shell, cmd, timeout=25))
                if entries:
                    return entries
            return []

        return p.conn.run(p.creds(), _fetch)


def _apply_details(s: VpnSession, d: dict | None):
    if not d:
        return
    s.client_agent = d.get("client_agent", "")
    s.client_os = d.get("client_os", "")
    s.client_version = d.get("client_version", "")
    s.tunnel_ip = d.get("tunnel_ip", "")
    s.rx_packets = int(d.get("rx_packets") or 0)
    s.tx_packets = int(d.get("tx_packets") or 0)


def _duration(seconds: int) -> str:
    hours, rem = divmod(max(0, seconds), 3600)
    days, hours = divmod(hours, 24)
    minutes = rem // 60
    if days:
        return f"{days} д {hours} ч"
    return f"{hours} ч {minutes:02d} мин" if hours else f"{minutes} мин"


def _safe_int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
