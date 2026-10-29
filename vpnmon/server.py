from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import logging.handlers
import mimetypes
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from . import __version__
from .cisco import CiscoConnection, VpnSession, clean_text, is_outdated
from .cleanup import build_cleanup
from .collector import Collector, TelegramNotifier
from .config import (
    BACKUP_DIR,
    DATA_DIR,
    SERVER_LOG_FILE,
    STATS_DB_FILE,
    WEB_STATIC_DIR,
    encode_password,
    get_routers,
    load_settings,
    router_creds,
    save_routers,
    update_settings,
)
from .instance import (
    ExclusiveHTTPServer,
    acquire_single_instance,
    release_single_instance,
    show_error_box,
    tell_user,
)
from .report import WEEKDAYS, build_weekly_report
from .storage import ConnectionStatsStore
from .tls import local_addresses

log = logging.getLogger("vpnmon.server")

SESSION_COOKIE = "vpnmon_session"
SESSION_TTL = 12 * 3600
PBKDF2_ITERATIONS = 310_000
CSRF_HEADER = "X-Requested-With"
BIND_CHOICES = ("127.0.0.1", "0.0.0.0")

# Settings the web panel may read and write as-is. Router credentials and tokens are handled separately.
PUBLIC_SETTINGS = {
    "refresh_seconds": int,
    "retention_days": int,
    "telegram_enabled": bool,
    "telegram_chat_id": str,
    "telegram_notify_sessions": bool,
    "telegram_notify_alerts": bool,
    "alert_multi_ip": bool,
    "alert_new_country": bool,
    "alert_night_logins": bool,
    "night_start_hour": int,
    "night_end_hour": int,
    "backup_keep_days": int,
    "unstable_reconnects_per_day": int,
    "weekly_report_enabled": bool,
    "weekly_report_weekday": int,
    "weekly_report_hour": int,
    "min_client_version": str,
    "client_details_refresh_minutes": int,
    "cleanup_idle_days": int,
    "cleanup_exclude": list,
    "web_bind": str,
    "web_port": int,
    "web_https": bool,
}
SETTING_DEFAULTS = {
    "refresh_seconds": 30,
    "retention_days": 180,
    "telegram_enabled": False,
    "telegram_notify_sessions": False,
    "telegram_notify_alerts": True,
    "alert_multi_ip": True,
    "alert_new_country": True,
    "alert_night_logins": False,
    "night_start_hour": 0,
    "night_end_hour": 6,
    "backup_keep_days": 7,
    "unstable_reconnects_per_day": 3,
    "weekly_report_enabled": True,
    "weekly_report_weekday": 0,
    "weekly_report_hour": 9,
    "min_client_version": "4.10",
    "client_details_refresh_minutes": 30,
    "cleanup_idle_days": 60,
    "cleanup_exclude": [],
    "web_bind": "127.0.0.1",
    "web_port": 8765,
    "web_https": False,
}
# Changing these only takes effect after a restart of the server.
RESTART_SETTINGS = ("web_bind", "web_port", "web_https", "syslog_enabled", "syslog_port")

PUBLIC_SETTINGS |= {
    "alert_router_reboot": bool,
    "syslog_enabled": bool,
    "syslog_port": int,
    "syslog_retention_days": int,
    "syslog_ignore": list,
    "syslog_alert_restart": bool,
    "syslog_alert_config": bool,
    "syslog_alert_interfaces": bool,
    "syslog_auth_fail_threshold": int,
}
SETTING_DEFAULTS |= {
    "alert_router_reboot": True,
    "syslog_enabled": True,
    "syslog_port": 514,
    "syslog_retention_days": 90,
    "syslog_ignore": ["IPPHONE-6-"],
    "syslog_alert_restart": True,
    "syslog_alert_config": True,
    "syslog_alert_interfaces": True,
    "syslog_auth_fail_threshold": 5,
}

# ------------------------------------------------------------------ panel users and roles
BUILTIN_ADMIN = "admin"
ROLES = {"admin": "администратор", "viewer": "только просмотр"}
LOGIN_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,32}$")
# A viewer sees everything but changes nothing: these routes are refused for that role.
ADMIN_ONLY = {
    ("POST", "/api/sessions/disconnect"),
    ("GET", "/api/settings"), ("POST", "/api/settings"),
    ("GET", "/api/routers"), ("POST", "/api/routers/save"), ("POST", "/api/routers/delete"),
    ("POST", "/api/routers/test"),
    ("GET", "/api/report/preview"), ("POST", "/api/report/send"), ("POST", "/api/telegram/test"),
    ("POST", "/api/backup"),
    ("POST", "/api/users/sync"), ("POST", "/api/users/import"), ("POST", "/api/users/remove"),
    ("POST", "/api/server/restart"), ("POST", "/api/server/shutdown"),
    ("GET", "/api/web-users"), ("POST", "/api/web-users/save"), ("POST", "/api/web-users/delete"),
}


def web_users_list(settings: dict) -> list[dict]:
    users = settings.get("web_users")
    if not isinstance(users, list):
        return []
    return [dict(u) for u in users
            if isinstance(u, dict) and u.get("login") and u.get("hash") and u.get("role") in ROLES]


def find_account(settings: dict, login: str) -> dict | None:
    """The built-in admin (password from first setup) or one of the extra panel users."""
    if login.lower() == BUILTIN_ADMIN:
        stored = str(settings.get("web_admin_password_hash", ""))
        return {"login": BUILTIN_ADMIN, "hash": stored, "role": "admin"} if stored else None
    return next((u for u in web_users_list(settings) if u["login"].lower() == login.lower()), None)


def setting(settings: dict, key: str):
    value = settings.get(key, SETTING_DEFAULTS.get(key))
    kind = PUBLIC_SETTINGS.get(key)
    try:
        if kind is int:
            return int(value)
        if kind is bool:
            return bool(value)
        if kind is list:
            return list(value or [])
        return value if value is not None else ""
    except (TypeError, ValueError):
        return SETTING_DEFAULTS.get(key)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt_hex, digest_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class App:
    def __init__(self, bind: str = "127.0.0.1", port: int = 8765, https: bool = False):
        self.store = ConnectionStatsStore(STATS_DB_FILE)
        self.collector = Collector(self.store)
        self.sessions: dict[str, dict] = {}  # token -> {"exp", "login", "role"}
        self.sessions_lock = threading.Lock()
        self.failed_logins: dict[str, list[float]] = {}
        self.httpd: ExclusiveHTTPServer | None = None
        self.running = {"web_bind": bind, "web_port": port, "web_https": https}
        self.restart_requested = False

    # ------------------------------------------------------------------ auth
    def create_session(self, login: str, role: str) -> str:
        token = secrets.token_urlsafe(32)
        with self.sessions_lock:
            now = time.time()
            self.sessions = {t: s for t, s in self.sessions.items() if s["exp"] > now}
            self.sessions[token] = {"exp": now + SESSION_TTL, "login": login, "role": role}
        return token

    def check_session(self, token: str | None) -> dict | None:
        if not token:
            return None
        with self.sessions_lock:
            s = self.sessions.get(token)
            if s and s["exp"] > time.time():
                s["exp"] = time.time() + SESSION_TTL
                return s
            self.sessions.pop(token, None)
        return None

    def drop_session(self, token: str | None):
        with self.sessions_lock:
            self.sessions.pop(token or "", None)

    def drop_user_sessions(self, login: str):
        with self.sessions_lock:
            self.sessions = {t: s for t, s in self.sessions.items() if s["login"].lower() != login.lower()}

    def login_allowed(self, client_ip: str) -> bool:
        now = time.time()
        attempts = [t for t in self.failed_logins.get(client_ip, []) if now - t < 300]
        self.failed_logins[client_ip] = attempts
        return len(attempts) < 5

    def register_failed_login(self, client_ip: str):
        self.failed_logins.setdefault(client_ip, []).append(time.time())


def is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def public_settings(settings: dict) -> dict:
    out = {k: setting(settings, k) for k in PUBLIC_SETTINGS}
    out["telegram_token_set"] = bool(settings.get("telegram_token_encoded"))
    return out


def coerce_settings(payload: dict) -> dict:
    changes: dict = {}
    for key, kind in PUBLIC_SETTINGS.items():
        if key not in payload:
            continue
        value = payload[key]
        try:
            if kind is bool:
                changes[key] = bool(value)
            elif kind is int:
                changes[key] = int(value)
            elif kind is list:
                items = value if isinstance(value, list) else str(value).replace(",", " ").split()
                changes[key] = sorted({str(x).strip() for x in items if str(x).strip()}, key=str.lower)
            else:
                changes[key] = str(value).strip()
        except (TypeError, ValueError):
            raise ApiError(400, f"Некорректное значение поля {key}")
    if "refresh_seconds" in changes and changes["refresh_seconds"] < 10:
        raise ApiError(400, "Интервал опроса — не меньше 10 секунд")
    for key in ("night_start_hour", "night_end_hour", "weekly_report_hour"):
        if key in changes and not 0 <= changes[key] <= 23:
            raise ApiError(400, "Часы должны быть от 0 до 23")
    if "weekly_report_weekday" in changes and not 0 <= changes["weekly_report_weekday"] <= 6:
        raise ApiError(400, "Некорректный день недели")
    if "backup_keep_days" in changes and not 0 <= changes["backup_keep_days"] <= 365:
        raise ApiError(400, "Хранить копии — от 0 до 365 дней (0 — не делать)")
    if "unstable_reconnects_per_day" in changes and changes["unstable_reconnects_per_day"] < 1:
        raise ApiError(400, "Порог переподключений — не меньше 1")
    if "client_details_refresh_minutes" in changes and changes["client_details_refresh_minutes"] < 0:
        raise ApiError(400, "Интервал обновления данных клиента — 0 или больше")
    if "cleanup_idle_days" in changes and not 7 <= changes["cleanup_idle_days"] <= 3650:
        raise ApiError(400, "Срок неактивности — от 7 дней")
    if "web_bind" in changes and changes["web_bind"] not in BIND_CHOICES:
        raise ApiError(400, "Доступ: только этот компьютер или вся сеть")
    if "web_port" in changes and not 1024 <= changes["web_port"] <= 65535:
        raise ApiError(400, "Порт панели — от 1024 до 65535")
    if "min_client_version" in changes and changes["min_client_version"] and \
            not all(p.isdigit() for p in changes["min_client_version"].split(".")):
        raise ApiError(400, "Минимальная версия — в виде 4.10 или 4.10.08025")
    if payload.get("telegram_token"):
        changes["telegram_token_encoded"] = encode_password(str(payload["telegram_token"]).strip())
    if payload.get("telegram_token_clear"):
        changes["telegram_token_encoded"] = ""
    return changes


def router_public(r: dict) -> dict:
    return {k: r[k] for k in ("id", "name", "host", "port", "username", "disconnect_command", "enabled")} | {
        "password_set": bool(r.get("password_encoded")),
    }


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"VpnMonitor/{__version__}"
        protocol_version = "HTTP/1.1"
        timeout = 60  # a stuck client must not keep a thread forever

        def log_message(self, fmt, *args):
            log.debug("%s %s", self.address_string(), fmt % args)

        # -------------------------------------------------------------- plumbing
        @property
        def client_ip(self) -> str:
            return self.client_address[0]

        def cookie_token(self) -> str | None:
            for part in (self.headers.get("Cookie") or "").split(";"):
                name, _, value = part.strip().partition("=")
                if name == SESSION_COOKIE:
                    return value
            return None

        def _cookie(self, token: str, max_age: int) -> str:
            secure = "; Secure" if app.running["web_https"] else ""
            return f"{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}"

        def send_json(self, data, status: int = 200, extra_headers: dict | None = None):
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self._security_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def send_bytes(self, body: bytes, content_type: str, status: int = 200, extra: dict | None = None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self._security_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _security_headers(self):
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                "connect-src 'self'; frame-ancestors 'none'; form-action 'self'",
            )

        def _read_body(self):
            # Read the body before any early rejection, or keep-alive breaks on the unread bytes.
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length > 1_000_000:
                self.close_connection = True
                self._body = b""
                raise ApiError(413, "Слишком большой запрос")
            self._body = self.rfile.read(length) if length > 0 else b""

        def read_json(self) -> dict:
            if not self._body:
                return {}
            try:
                data = json.loads(self._body.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise ApiError(400, "Некорректный JSON")
            if not isinstance(data, dict):
                raise ApiError(400, "Ожидался JSON-объект")
            return data

        # -------------------------------------------------------------- dispatch
        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def _dispatch(self, method: str):
            url = urlparse(self.path)
            path = url.path
            query = {k: v[-1] for k, v in parse_qs(url.query).items()}
            self._body = b""
            try:
                self._read_body()
                if not path.startswith("/api/"):
                    if method != "GET":
                        raise ApiError(405, "Method not allowed")
                    return self.serve_static(path)
                if method == "POST" and self.headers.get(CSRF_HEADER) != "vpnmon":
                    raise ApiError(403, "Отсутствует CSRF-заголовок")
                route = (method, path)
                public = {
                    ("GET", "/api/health"): self.health,
                    ("GET", "/api/auth/status"): self.auth_status,
                    ("POST", "/api/auth/login"): self.auth_login,
                    ("POST", "/api/auth/setup"): self.auth_setup,
                }
                if route in public:
                    return public[route](query)
                self.user = app.check_session(self.cookie_token())
                if not self.user:
                    raise ApiError(401, "Требуется вход")
                if self.user["role"] != "admin" and route in ADMIN_ONLY:
                    raise ApiError(403, "Недостаточно прав: это действие доступно только администратору панели")
                handler = self.routes().get(route)
                if handler is None and method == "GET" and path.startswith("/api/users/"):
                    return self.user_details(unquote(path[len("/api/users/"):]), query)
                if handler is None:
                    raise ApiError(404, "Не найдено")
                return handler(query)
            except ApiError as exc:
                self.send_json({"error": str(exc)}, exc.status)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError, TimeoutError):
                pass
            except Exception as exc:
                log.exception("Ошибка обработки %s %s", method, path)
                self.send_json({"error": f"Внутренняя ошибка: {exc}"}, 500)

        def routes(self):
            return {
                ("POST", "/api/auth/logout"): self.auth_logout,
                ("POST", "/api/auth/password"): self.auth_change_password,
                ("GET", "/api/state"): self.state,
                ("POST", "/api/refresh"): self.refresh,
                ("POST", "/api/sessions/disconnect"): self.disconnect,
                ("POST", "/api/sessions/details"): self.session_details,
                ("GET", "/api/audit"): self.audit,
                ("GET", "/api/export/audit.csv"): self.export_audit,
                ("GET", "/api/clients"): self.clients,
                ("GET", "/api/stats/concurrency"): self.concurrency,
                ("GET", "/api/downtime"): self.downtime,
                ("GET", "/api/events"): self.events,
                ("GET", "/api/settings"): self.get_settings,
                ("POST", "/api/settings"): self.save_settings,
                ("GET", "/api/routers"): self.get_routers,
                ("POST", "/api/routers/save"): self.save_router,
                ("POST", "/api/routers/delete"): self.delete_router,
                ("POST", "/api/routers/test"): self.test_router,
                ("GET", "/api/cleanup"): self.cleanup,
                ("GET", "/api/report/preview"): self.report_preview,
                ("POST", "/api/report/send"): self.report_send,
                ("POST", "/api/telegram/test"): self.telegram_test,
                ("POST", "/api/backup"): self.backup_now,
                ("POST", "/api/users/sync"): self.users_sync,
                ("POST", "/api/users/import"): self.users_import,
                ("POST", "/api/users/remove"): self.users_remove,
                ("GET", "/api/server/info"): self.server_info,
                ("POST", "/api/server/restart"): self.restart,
                ("POST", "/api/server/shutdown"): self.shutdown,
                ("GET", "/api/syslog"): self.syslog_messages,
                ("GET", "/api/syslog/summary"): self.syslog_summary,
                ("GET", "/api/web-users"): self.web_users,
                ("POST", "/api/web-users/save"): self.save_web_user,
                ("POST", "/api/web-users/delete"): self.delete_web_user,
            }

        @property
        def actor(self) -> str:
            user = getattr(self, "user", None)
            return f"{user['login']}, {self.client_ip}" if user else self.client_ip

        # -------------------------------------------------------------- static
        def serve_static(self, path: str):
            rel = "index.html" if path in ("/", "/index.html") else path.lstrip("/")
            target = (WEB_STATIC_DIR / rel).resolve()
            if WEB_STATIC_DIR.resolve() not in target.parents or not target.is_file():
                target = WEB_STATIC_DIR / "index.html"
            ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript",):
                ctype += "; charset=utf-8"
            self.send_bytes(target.read_bytes(), ctype, extra={"Cache-Control": "no-cache"})

        # -------------------------------------------------------------- auth
        def auth_status(self, _q):
            settings = load_settings()
            user = app.check_session(self.cookie_token())
            self.send_json({
                "setup_required": not settings.get("web_admin_password_hash"),
                "setup_allowed": is_loopback(self.client_ip),
                "authenticated": bool(user),
                "login": user["login"] if user else "",
                "role": user["role"] if user else "",
                "multi_user": bool(web_users_list(settings)),
                "version": __version__,
            })

        def _issue_cookie(self, login: str = BUILTIN_ADMIN, role: str = "admin") -> dict:
            return {"Set-Cookie": self._cookie(app.create_session(login, role), SESSION_TTL)}

        def auth_setup(self, _q):
            if load_settings().get("web_admin_password_hash"):
                raise ApiError(409, "Пароль уже задан")
            if not is_loopback(self.client_ip):
                raise ApiError(403, "Первичная настройка доступна только с этого компьютера (localhost)")
            password = str(self.read_json().get("password", ""))
            if len(password) < 8:
                raise ApiError(400, "Пароль — не короче 8 символов")
            update_settings({"web_admin_password_hash": hash_password(password)})
            self.send_json({"ok": True}, extra_headers=self._issue_cookie())

        def auth_login(self, _q):
            if not app.login_allowed(self.client_ip):
                raise ApiError(429, "Слишком много попыток. Подождите 5 минут.")
            data = self.read_json()
            login = str(data.get("login", "")).strip() or BUILTIN_ADMIN
            password = str(data.get("password", ""))
            account = find_account(load_settings(), login)
            if not account or not verify_password(password, account["hash"]):
                app.register_failed_login(self.client_ip)
                app.collector.event("AUTH", f"Неудачный вход в веб-панель ({login}) с {self.client_ip}", ip=self.client_ip)
                raise ApiError(401, "Неверный логин или пароль")
            if not is_loopback(self.client_ip):
                app.collector.event("AUTH", f"Вход в веб-панель: {account['login']} с {self.client_ip}", ip=self.client_ip)
            self.send_json({"ok": True, "role": account["role"]},
                           extra_headers=self._issue_cookie(account["login"], account["role"]))

        def auth_logout(self, _q):
            app.drop_session(self.cookie_token())
            self.send_json({"ok": True}, extra_headers={"Set-Cookie": self._cookie("", 0)})

        def auth_change_password(self, _q):
            data = self.read_json()
            settings = load_settings()
            account = find_account(settings, self.user["login"])
            if not account or not verify_password(str(data.get("current", "")), account["hash"]):
                raise ApiError(400, "Текущий пароль неверен")
            new = str(data.get("new", ""))
            if len(new) < 8:
                raise ApiError(400, "Пароль — не короче 8 символов")
            if account["login"] == BUILTIN_ADMIN:
                update_settings({"web_admin_password_hash": hash_password(new)})
            else:
                users = web_users_list(settings)
                for u in users:
                    if u["login"].lower() == account["login"].lower():
                        u["hash"] = hash_password(new)
                update_settings({"web_users": users})
            app.drop_user_sessions(account["login"])
            self.send_json({"ok": True}, extra_headers=self._issue_cookie(account["login"], account["role"]))

        # -------------------------------------------------------------- panel users
        def web_users(self, _q):
            users = [{"login": BUILTIN_ADMIN, "role": "admin", "builtin": True}]
            users += [{"login": u["login"], "role": u["role"], "builtin": False}
                      for u in web_users_list(load_settings())]
            self.send_json(users)

        def save_web_user(self, _q):
            data = self.read_json()
            login = str(data.get("login", "")).strip()
            role = str(data.get("role", "viewer"))
            password = str(data.get("password", ""))
            if not LOGIN_RE.match(login):
                raise ApiError(400, "Логин: латинские буквы, цифры, точка, дефис, подчёркивание (до 32 символов)")
            if login.lower() == BUILTIN_ADMIN:
                raise ApiError(400, "Логин admin занят встроенным администратором")
            if role not in ROLES:
                raise ApiError(400, "Роль: admin или viewer")
            users = web_users_list(load_settings())
            existing = next((u for u in users if u["login"].lower() == login.lower()), None)
            if existing is None and len(password) < 8:
                raise ApiError(400, "Пароль нового пользователя — не короче 8 символов")
            if password and len(password) < 8:
                raise ApiError(400, "Пароль — не короче 8 символов")
            if existing is None:
                existing = {"login": login}
                users.append(existing)
            existing["role"] = role
            if password:
                existing["hash"] = hash_password(password)
            update_settings({"web_users": users})
            app.drop_user_sessions(login)  # a changed role or password applies at once
            app.collector.event("ADMIN", f"Пользователь панели {login} ({ROLES[role]}) сохранён ({self.actor})")
            self.send_json({"ok": True})

        def delete_web_user(self, _q):
            login = str(self.read_json().get("login", "")).strip()
            users = web_users_list(load_settings())
            left = [u for u in users if u["login"].lower() != login.lower()]
            if len(left) == len(users):
                raise ApiError(404, "Пользователь не найден")
            update_settings({"web_users": left})
            app.drop_user_sessions(login)
            app.collector.event("ADMIN", f"Пользователь панели {login} удалён ({self.actor})")
            self.send_json({"ok": True})

        # -------------------------------------------------------------- router syslog
        def syslog_messages(self, q):
            settings = load_settings()
            try:
                limit = max(1, min(5000, int(q.get("limit", 500))))
                max_sev = max(0, min(7, int(q.get("severity", 7))))
            except ValueError:
                limit, max_sev = 500, 7
            # VPN tunnels (Virtual-Access) go up and down with every session: noise unless asked for.
            hide_text = ["Virtual-Access"] if q.get("noise") != "1" else []
            self.send_json(app.store.get_syslog(
                limit=limit, query=q.get("q", ""), max_severity=max_sev, router=q.get("router", ""),
                code_prefix=q.get("code", ""), kind=q.get("kind", ""), hide_text=hide_text,
            ))

        def syslog_summary(self, _q):
            now = int(time.time())
            self.send_json(app.store.get_syslog_summary(now - 86400) | {
                "receiver": app.collector.syslog_state(),
                "server_ips": [a for a in local_addresses() if not a.startswith("127.")],
            })

        # -------------------------------------------------------------- live data
        def state(self, _q):
            snap = app.collector.snapshot()
            sessions = snap["sessions"]
            minimum = setting(load_settings(), "min_client_version")
            for s in sessions:
                s["client_outdated"] = is_outdated(s["client_version"], minimum)
            snap["kpi"] = {
                "sessions": len(sessions),
                "users": len({s["login"].lower() for s in sessions}),
                "ips": len({s["ip"] for s in sessions}),
                "tunnels": sum(int(s["connections"]) for s in sessions),
            }
            snap["router"] = snap["routers"][0]["host"] if len(snap["routers"]) == 1 else ""
            snap["min_client_version"] = minimum
            snap["user"] = {"login": self.user["login"], "role": self.user["role"]}
            snap["syslog"] = app.collector.syslog_state()
            self.send_json(snap)

        def refresh(self, _q):
            app.collector.refresh_now()
            self.send_json({"ok": True})

        def _session_from_payload(self) -> VpnSession:
            data = self.read_json()
            routers = app.collector.all_pollers()
            router = str(data.get("router") or (routers[0].id if routers else ""))
            s = app.collector.find_session(
                router, str(data.get("context", "")), str(data.get("login", "")), str(data.get("ip", ""))
            )
            if s is None:
                raise ApiError(404, "Сессия уже не активна — обновите список")
            return s

        def disconnect(self, _q):
            s = self._session_from_payload()
            try:
                command, output = app.collector.disconnect(s, actor=self.actor)
            except RuntimeError as exc:
                raise ApiError(502, str(exc))
            self.send_json({"ok": True, "command": command, "output": clean_text(output)})

        def session_details(self, _q):
            s = self._session_from_payload()
            try:
                command, output = app.collector.session_details(s)
            except RuntimeError as exc:
                raise ApiError(502, str(exc))
            self.send_json({"command": command, "output": output.replace("\r", "")})

        # -------------------------------------------------------------- history
        def _days(self, q, default=30) -> int:
            try:
                return max(1, min(3650, int(q.get("days", default))))
            except ValueError:
                return default

        def _summary(self, days: int) -> list[dict]:
            settings = load_settings()
            rows = app.store.get_all_users_summary(
                days=days, unstable_per_day=setting(settings, "unstable_reconnects_per_day")
            )
            minimum = setting(settings, "min_client_version")
            for r in rows:
                r["client_outdated"] = is_outdated(r["client_version"], minimum)
            return rows

        def audit(self, q):
            self.send_json(self._summary(self._days(q)))

        def export_audit(self, q):
            days = self._days(q)
            rows = self._summary(days)
            for r in rows:
                r["routers"] = ",".join(r["routers"])
            buf = io.StringIO()
            fields = ["login", "status_label", "online", "connects_period", "connects_7d", "connects_30d",
                      "connects_90d", "active_days", "work_time", "unique_ips", "last_connected",
                      "days_idle_str", "last_ip", "last_country", "last_org", "source",
                      "reconnects", "reconnects_peak_day", "reconnects_peak_date", "unstable",
                      "client_os", "client_version", "client_outdated", "routers"]
            writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore", delimiter=";")
            writer.writeheader()
            writer.writerows(rows)
            body = ("﻿" + buf.getvalue()).encode("utf-8")  # BOM so Excel opens Cyrillic correctly
            self.send_bytes(body, "text/csv; charset=utf-8", extra={
                "Content-Disposition": f'attachment; filename="vpn-audit-{days}d-{time.strftime("%Y%m%d")}.csv"',
                "Cache-Control": "no-store",
            })

        def clients(self, q):
            """Latest known AnyConnect client per user, grouped by OS and version."""
            rows = [r for r in self._summary(self._days(q, 90)) if r["client_agent"]]
            groups: dict[tuple[str, str], dict] = {}
            for r in rows:
                g = groups.setdefault((r["client_os"], r["client_version"]), {
                    "os": r["client_os"] or "—", "version": r["client_version"] or "—",
                    "outdated": r["client_outdated"], "users": [],
                })
                g["users"].append(r["login"])
            self.send_json({
                "min_version": setting(load_settings(), "min_client_version"),
                "users_with_data": len(rows),
                "groups": sorted(groups.values(), key=lambda g: (-len(g["users"]), g["version"])),
            })

        def user_details(self, login: str, q):
            days = self._days(q, 90)
            self.send_json({
                "login": login,
                "history": app.store.get_user_sessions_history(login, days=days),
                "monthly": app.store.get_user_monthly_breakdown(login, days=days),
                "events": app.store.get_events(limit=100, query=login),
                "min_client_version": setting(load_settings(), "min_client_version"),
            })

        def concurrency(self, q):
            days = self._days(q, 7)
            bucket = 3600 if days <= 14 else 86400
            now = int(time.time())
            self.send_json({
                "bucket": bucket,
                "points": app.store.get_concurrency(days=days, bucket_seconds=bucket, now_ts=now),
                "gaps": app.store.get_downtime(now - days * 86400, now)["intervals"],
            })

        def downtime(self, q):
            now = int(time.time())
            self.send_json(app.store.get_downtime(now - self._days(q, 30) * 86400, now))

        def health(self, _q):
            """For Zabbix / Uptime Kuma: 200 when every enabled router was polled recently, 503 otherwise.

            No login needed, so it reports states only: no hosts, users or addresses.
            """
            snap = app.collector.snapshot()
            now = int(time.time())
            limit = max(120, 3 * setting(load_settings(), "refresh_seconds"))
            routers = [{"id": r["id"], "status": r["status"],
                        "last_success_age": now - r["last_success_ts"] if r["last_success_ts"] else None}
                       for r in snap["routers"] if r["status"] != "disabled"]
            healthy = bool(routers) and all(
                r["status"] == "ok" and r["last_success_age"] is not None and r["last_success_age"] <= limit
                for r in routers)
            self.send_json({
                "status": "ok" if healthy else "degraded",
                "version": __version__,
                "uptime_seconds": now - snap["started_ts"],
                "routers": routers,
            }, 200 if healthy else 503)

        def events(self, q):
            try:
                limit = max(1, min(5000, int(q.get("limit", 500))))
            except ValueError:
                limit = 500
            self.send_json(app.store.get_events(
                limit=limit, event_type=q.get("type", ""), query=q.get("q", "")
            ))

        # -------------------------------------------------------------- settings
        def get_settings(self, _q):
            settings = load_settings()
            self.send_json(public_settings(settings) | {
                "backups": app.store.list_backups(BACKUP_DIR),
                "weekdays": WEEKDAYS,
            })

        def save_settings(self, _q):
            changes = coerce_settings(self.read_json())
            update_settings(changes)
            app.collector.event("ADMIN", f"Настройки изменены из веб-панели ({self.actor})")
            app.collector.refresh_now()
            self.send_json(public_settings(load_settings()))

        # -------------------------------------------------------------- routers
        def get_routers(self, _q):
            status = {r["id"]: r for r in app.collector.snapshot()["routers"]}
            self.send_json([router_public(r) | {"state": status.get(r["id"], {})} for r in get_routers()])

        def _router_from_payload(self, data: dict, existing: dict | None) -> dict:
            r = dict(existing or {"id": "", "password_encoded": "", "enabled": True})
            for key in ("name", "host", "username", "disconnect_command"):
                if key in data:
                    r[key] = str(data[key]).strip()
            try:
                r["port"] = int(data.get("port", r.get("port", 22)))
            except (TypeError, ValueError):
                raise ApiError(400, "Некорректный SSH-порт")
            if "enabled" in data:
                r["enabled"] = bool(data["enabled"])
            if data.get("password"):
                r["password_encoded"] = encode_password(str(data["password"]))
            if not r.get("host"):
                raise ApiError(400, "Укажите адрес устройства")
            if not r.get("username"):
                raise ApiError(400, "Укажите SSH-логин")
            if not 1 <= r["port"] <= 65535:
                raise ApiError(400, "SSH-порт — от 1 до 65535")
            if not r.get("password_encoded"):
                raise ApiError(400, "Укажите пароль")
            r["name"] = r.get("name") or r["host"]
            r.setdefault("disconnect_command", "")
            return r

        def save_router(self, _q):
            data = self.read_json()
            routers = get_routers()
            rid = str(data.get("id") or "")
            idx = next((i for i, r in enumerate(routers) if r["id"] == rid), None)
            if rid and idx is None:
                raise ApiError(404, "Устройство не найдено")
            r = self._router_from_payload(data, routers[idx] if idx is not None else None)
            if idx is None:
                existing = {x["id"] for x in routers}
                r["id"] = "main" if "main" not in existing and not routers else f"r{secrets.token_hex(3)}"
                routers.append(r)
            else:
                routers[idx] = r
            save_routers(routers)
            app.collector.sync_pollers()
            app.collector.event("ADMIN", f"Устройство «{r['name']}» ({r['host']}) сохранено из веб-панели ({self.actor})",
                                router=r["id"])
            self.send_json(router_public(r))

        def delete_router(self, _q):
            rid = str(self.read_json().get("id") or "")
            routers = get_routers()
            target = next((r for r in routers if r["id"] == rid), None)
            if target is None:
                raise ApiError(404, "Устройство не найдено")
            save_routers([r for r in routers if r["id"] != rid])
            app.collector.sync_pollers()
            app.collector.event("ADMIN", f"Устройство «{target['name']}» ({target['host']}) удалено из панели "
                                f"({self.actor}); история его сессий сохранена", router=rid)
            self.send_json({"ok": True})

        def test_router(self, _q):
            """Try a router's settings before saving them; the password may be left empty for a saved router."""
            data = self.read_json()
            existing = next((r for r in get_routers() if r["id"] == data.get("id")), None)
            r = self._router_from_payload(data, existing)
            conn = CiscoConnection(timeout=15)
            try:
                sessions, _ = conn.fetch_sessions(router_creds(r))
            except Exception as exc:
                raise ApiError(502, f"Не удалось подключиться: {exc}")
            finally:
                conn.close()
            self.send_json({"ok": True, "sessions": len(sessions)})

        # -------------------------------------------------------------- accounts
        def cleanup(self, q):
            settings = load_settings()
            try:
                idle = int(q.get("days") or setting(settings, "cleanup_idle_days"))
            except ValueError:
                idle = setting(settings, "cleanup_idle_days")
            self.send_json(build_cleanup(app.store, get_routers(settings), max(1, idle),
                                         set(setting(settings, "cleanup_exclude"))))

        def users_sync(self, q):
            results = []
            for r in get_routers():
                if q.get("router") and q["router"] != r["id"]:
                    continue
                try:
                    entries = app.collector.router_user_entries(r["id"])
                    res = app.store.sync_router_users(r["id"], entries)
                    results.append({"router": r["id"], "name": r["name"], "found": res["total"], **res})
                except Exception as exc:
                    results.append({"router": r["id"], "name": r["name"], "error": str(exc)})
            if results and all("error" in x for x in results):
                raise ApiError(502, "; ".join(f"{x['name']}: {x['error']}" for x in results))
            self.send_json({
                "routers": results,
                "found": sum(x.get("found", 0) for x in results),
                "added": sum(x.get("added", 0) for x in results),
            })

        def users_import(self, _q):
            raw = self.read_json().get("logins", [])
            logins = [str(x).strip() for x in raw if str(x).strip()] if isinstance(raw, list) else []
            self.send_json({"added": app.store.register_known_users(logins, source="imported")})

        def users_remove(self, _q):
            raw = self.read_json().get("logins", [])
            logins = [str(x) for x in raw] if isinstance(raw, list) else []
            self.send_json({"removed": app.store.remove_known_users(logins)})

        # -------------------------------------------------------------- report & telegram
        def report_preview(self, _q):
            settings = load_settings()
            last = int(app.store.get_meta("weekly_report_sent_ts", "0") or 0)
            self.send_json({
                "text": build_weekly_report(app.collector, settings),
                "last_sent_ts": last,
                "telegram_ready": bool(TelegramNotifier.config(settings | {"telegram_enabled": True})),
            })

        def report_send(self, _q):
            settings = load_settings()
            cfg = TelegramNotifier.config(settings | {"telegram_enabled": True})
            if not cfg:
                raise ApiError(400, "Укажите токен бота и chat_id в разделе Telegram и сохраните настройки")
            try:
                TelegramNotifier.send_now(cfg[0], cfg[1], build_weekly_report(app.collector, settings))
            except Exception as exc:
                raise ApiError(502, f"Telegram: {exc}")
            app.collector.event("ADMIN", f"Отчёт отправлен в Telegram вручную ({self.actor})")
            self.send_json({"ok": True})

        def telegram_test(self, _q):
            cfg = TelegramNotifier.config(load_settings() | {"telegram_enabled": True})
            if not cfg:
                raise ApiError(400, "Укажите токен бота и chat_id и сохраните настройки")
            try:
                TelegramNotifier.send_now(cfg[0], cfg[1], "✅ Тестовое сообщение от Cisco AnyConnect Monitor")
            except Exception as exc:
                raise ApiError(502, f"Telegram: {exc}")
            self.send_json({"ok": True})

        def backup_now(self, _q):
            try:
                name = app.collector.backup_now()
            except Exception as exc:
                raise ApiError(500, f"Не удалось сделать копию: {exc}")
            app.collector.event("ADMIN", f"Резервная копия базы создана из веб-панели ({self.actor}): {name}")
            self.send_json({"name": name, "backups": app.store.list_backups(BACKUP_DIR)})

        # -------------------------------------------------------------- server
        def server_info(self, _q):
            from .tls import certificate_info, local_addresses

            settings = load_settings()
            wanted = {k: setting(settings, k) for k in RESTART_SETTINGS}
            run = app.running
            scheme = "https" if run["web_https"] else "http"
            hosts = local_addresses() if run["web_bind"] == "0.0.0.0" else ["127.0.0.1"]
            offset = -(time.altzone if time.localtime().tm_isdst else time.timezone)
            self.send_json({
                "version": __version__,
                "hostname": socket.gethostname(),
                "data_dir": str(DATA_DIR),
                "timezone": f"UTC{'+' if offset >= 0 else '-'}{abs(offset) // 3600:02d}:{abs(offset) % 3600 // 60:02d}",
                "running": run,
                "configured": wanted,
                "restart_required": wanted != run,
                "urls": [f"{scheme}://{h}:{run['web_port']}/" for h in hosts],
                "certificate": certificate_info() if run["web_https"] else {},
                "client_is_local": is_loopback(self.client_ip),
            })

        def restart(self, _q):
            app.collector.event("INFO", f"Перезапуск сервера из веб-панели ({self.actor})")
            app.restart_requested = True
            self.send_json({"ok": True})
            threading.Thread(target=app.httpd.shutdown, daemon=True).start()

        def shutdown(self, _q):
            app.collector.event("INFO", f"Сервер остановлен из веб-панели ({self.actor})")
            self.send_json({"ok": True})
            threading.Thread(target=app.httpd.shutdown, daemon=True).start()

    return Handler


def setup_logging(verbose: bool):
    handler = logging.handlers.RotatingFileHandler(
        SERVER_LOG_FILE, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.addHandler(handler)


def run_bundle_command(args) -> int:
    from .bundle import export_bundle, import_bundle

    title = "Cisco AnyConnect Monitor — перенос"
    try:
        if args.export_bundle:
            m = export_bundle(Path(args.export_bundle))
            text = (f"Архив для переноса сохранён:\n{Path(args.export_bundle).resolve()}\n\n"
                    f"Сессий: {m['sessions']}, устройств: {len(m['routers'])}.\n"
                    f"На сервере нужно будет заново ввести: {', '.join(m['needs_reentry'])}.")
        else:
            m = import_bundle(Path(args.import_bundle), force=args.force, lan=args.lan, port=args.port)
            text = (f"Данные загружены в {m['data_dir']}\n"
                    f"Сессий: {m['sessions_imported']} (из {m['source_host']}, {m['created']}).\n"
                    f"Введите в панели заново: {', '.join(m['needs_reentry'])}.")
        log.info(text)
        if not args.quiet:
            tell_user(title, text)
        return 0
    except Exception as exc:
        log.exception("Перенос данных")
        if not args.quiet:
            tell_user(title, f"Ошибка: {exc}", error=True)
        return 1


def restart_command() -> list[str]:
    args = [a for a in sys.argv[1:] if a != "--open"]
    if getattr(sys, "frozen", False):
        return [sys.executable, *args]
    return [sys.executable, sys.argv[0], *args]


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description="Cisco AnyConnect Monitor — фоновый сборщик и веб-панель")
    parser.add_argument("--bind", help="адрес прослушивания (по умолчанию из настроек или 127.0.0.1)")
    parser.add_argument("--port", type=int, help="порт веб-панели (по умолчанию 8765)")
    parser.add_argument("--open", action="store_true", help="открыть панель в браузере после запуска")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--data-dir", help="папка с базой и настройками (по умолчанию рядом с программой)")
    parser.add_argument("--export-bundle", metavar="ZIP", help="сохранить данные для переноса на другой компьютер и выйти")
    parser.add_argument("--import-bundle", metavar="ZIP", help="загрузить данные из архива переноса и выйти")
    parser.add_argument("--force", action="store_true", help="при импорте заменить существующую базу")
    parser.add_argument("--lan", action="store_true", help="при импорте открыть панель для сети и включить HTTPS")
    parser.add_argument("--quiet", action="store_true", help="не показывать окно с результатом (для скриптов: смотрите server.log и код выхода)")
    args = parser.parse_args(argv)

    setup_logging(args.verbose)
    if args.export_bundle or args.import_bundle:
        return run_bundle_command(args)
    settings = load_settings()
    bind = args.bind or setting(settings, "web_bind")
    port = args.port or setting(settings, "web_port")
    https = setting(settings, "web_https")
    url = f"{'https' if https else 'http'}://{'127.0.0.1' if bind in ('0.0.0.0', '::') else bind}:{port}/"

    if not acquire_single_instance():
        # Start-Server.bat after autostart: don't start a second collector, just show the panel.
        log.info("Сервер уже запущен, второй экземпляр не стартует")
        if args.open:
            webbrowser.open(url)
        return 0

    app = App(bind=bind, port=port, https=https)
    try:
        app.httpd = ExclusiveHTTPServer((bind, port), make_handler(app))
        if https:
            from .tls import ensure_certificate, server_context

            app.httpd.enable_tls(server_context(*ensure_certificate()))
    except OSError as exc:
        log.error("Не удалось занять %s:%s — %s", bind, port, exc)
        show_error_box(
            "Cisco AnyConnect Monitor",
            f"Порт {port} занят другой программой ({exc}).\n\n"
            f"Укажите другой порт в settings.json (\"web_port\") или запустите с --port.",
        )
        return 1
    app.collector.start()
    app.collector.event("INFO", f"Сервер v{__version__} запущен на {url.rstrip('/')}"
                        + (" (доступ из сети)" if bind == "0.0.0.0" else ""))
    print(f"Cisco AnyConnect Monitor: {url}", flush=True)
    if args.open:
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    try:
        app.httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.collector.stop()
        app.httpd.server_close()

    if app.restart_requested:
        # Free the mutex and the port first, then start a fresh, detached copy with the new settings.
        release_single_instance()
        flags = 0
        if sys.platform == "win32":
            flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        subprocess.Popen(restart_command(), creationflags=flags, close_fds=True,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log.info("Сервер перезапускается: %s", restart_command())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
