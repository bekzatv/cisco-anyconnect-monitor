"""Receive the router's own log (syslog over UDP) and turn the important lines into events.

On the router: `logging host <monitor IP>` (it can send to several hosts at once).
"""

from __future__ import annotations

import logging
import re
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass

log = logging.getLogger("vpnmon.syslog")

SEVERITY = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")
_PRI_RE = re.compile(r"^<(\d{1,3})>")
# "%LINEPROTO-5-UPDOWN: Line protocol on Interface ..." (facility may carry a sub-part: %SYS-5-CONFIG_I)
_MSG_RE = re.compile(r"%([A-Z][A-Z0-9_]*)-(\d)-([A-Z0-9_]+)\s*:\s*(.*)$", re.S)
# Anything after these words in a logged command is a secret: "username x secret 9 $9$..."
_SECRET_RE = re.compile(r"\b(secret|password|key-string|key|pre-shared-key|community)\s+(\d\s+)?\S+", re.I)
_PHYSICAL_IF_RE = re.compile(
    r"Interface\s+((?:(?:Gigabit|TenGigabit|Fast)?Ethernet|Serial|Dialer|Cellular|Port-channel)[\w/.:]*)", re.I)


@dataclass
class SyslogMessage:
    received_ts: int
    source_ip: str
    severity: int
    facility: str
    mnemonic: str
    text: str
    raw: str

    @property
    def code(self) -> str:
        return f"{self.facility}-{self.severity}-{self.mnemonic}"


def mask_secrets(text: str) -> str:
    return _SECRET_RE.sub(lambda m: f"{m.group(1)} ***", text)


def parse_syslog(data: bytes, source_ip: str, now: int | None = None) -> SyslogMessage | None:
    raw = data.decode("utf-8", errors="replace").strip()
    if not raw:
        return None
    now = now if now is not None else int(time.time())
    body = raw
    severity = 6
    m = _PRI_RE.match(raw)
    if m:
        severity = int(m.group(1)) & 7
        body = raw[m.end():]
    mm = _MSG_RE.search(body)
    if mm:
        facility, sev, mnemonic, text = mm.groups()
        severity = int(sev)
    else:
        facility, mnemonic, text = "", "", body
    return SyslogMessage(now, source_ip, severity, facility, mnemonic, mask_secrets(text.strip()), mask_secrets(raw))


def is_ignored(msg: SyslogMessage, prefixes: list[str]) -> bool:
    code = msg.code
    return any(p and code.startswith(p) for p in prefixes)


@dataclass
class Classified:
    kind: str = ""          # "", restart, config, iface_down, iface_up, auth_fail, login_fail
    summary: str = ""
    login: str = ""
    ip: str = ""


_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_USER_RE = re.compile(r"\b(?:user(?:name)?|User)\s*[:=]?\s*\[?([A-Za-z0-9_.\-@]+)\]?", re.I)


def classify(msg: SyslogMessage) -> Classified:
    code, text = msg.code, msg.text
    if code.startswith("SYS-5-RESTART") or code.startswith("SYS-5-RELOAD"):
        return Classified("restart", f"Роутер перезагрузился: {text}")
    if code.startswith("SYS-5-CONFIG_I"):
        m = re.search(r"Configured from (\S+) by (\S+)(?: on (\S+))?(?: \((\S+)\))?", text)
        who = m.group(2) if m else ""
        where = (m.group(4) or m.group(3) or m.group(1)) if m else ""
        return Classified("config", f"Конфигурация изменена: {who or '?'}{f' ({where})' if where else ''}", login=who,
                          ip=(m.group(4) or "") if m else "")
    if code.startswith("PARSER-5-CFGLOG_LOGGEDCMD"):
        m = re.search(r"User:\s*(\S+)\s+logged command:\s*(.*)$", text)
        if m:
            return Classified("config_cmd", f"{m.group(1)}: {m.group(2).strip()}", login=m.group(1))
    if code.startswith(("LINK-3-UPDOWN", "LINEPROTO-5-UPDOWN", "LINK-5-CHANGED")):
        iface = _PHYSICAL_IF_RE.search(text)
        if iface:  # Virtual-Access/Tunnel interfaces are VPN users coming and going, not outages
            if re.search(r"to (down|administratively down)", text):
                return Classified("iface_down", f"Интерфейс {iface.group(1)} упал: {text}")
            if "to up" in text:
                return Classified("iface_up", f"Интерфейс {iface.group(1)} поднялся")
    if code.startswith("SEC_LOGIN-4-LOGIN_FAILED"):
        user = _USER_RE.search(text)
        ip = re.search(r"Source:\s*\[?(\d{1,3}(?:\.\d{1,3}){3})", text)
        return Classified("login_fail", f"Неудачный вход на роутер: {text}",
                          login=user.group(1) if user else "", ip=ip.group(1) if ip else "")
    upper = code.upper()
    if ("SSLVPN" in upper or "WEBVPN" in upper or "AAA" in upper or "AUTH" in upper) and \
            re.search(r"FAIL|REJECT|DENIED|DENY|INVALID", upper + " " + text.upper()):
        user = _USER_RE.search(text)
        ip = _IP_RE.search(text)
        return Classified("auth_fail", f"Неудачная попытка входа в VPN: {text}",
                          login=user.group(1) if user else "", ip=ip.group(1) if ip else "")
    return Classified()


class FailureCounter:
    """Sliding-window counter: N failures for one key within `window` seconds trips once."""

    def __init__(self, window: int = 600):
        self.window = window
        self._events: dict[str, deque[int]] = {}
        self._tripped: dict[str, int] = {}

    def add(self, key: str, now: int, threshold: int) -> int | None:
        q = self._events.setdefault(key, deque())
        q.append(now)
        while q and q[0] < now - self.window:
            q.popleft()
        if len(q) >= threshold and now - self._tripped.get(key, 0) > self.window:
            self._tripped[key] = now
            return len(q)
        return None


class SyslogReceiver:
    def __init__(self, handler, bind: str = "0.0.0.0", port: int = 514):
        self.handler = handler
        self.bind, self.port = bind, port
        self.error = ""
        self.received = 0
        self.last_ts = 0
        self._sock: socket.socket | None = None
        self._stop = threading.Event()

    def start(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind((self.bind, self.port))
            sock.settimeout(1.0)
        except OSError as exc:
            self.error = f"Не удалось занять UDP {self.port}: {exc}"
            log.error(self.error)
            return False
        self._sock = sock
        threading.Thread(target=self._run, name="syslog", daemon=True).start()
        log.info("Приём syslog на UDP %s:%s", self.bind, self.port)
        return True

    def stop(self):
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def _run(self):
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                time.sleep(1)
                continue
            msg = parse_syslog(data, addr[0])
            if msg is None:
                continue
            self.received += 1
            self.last_ts = msg.received_ts
            try:
                self.handler(msg)
            except Exception:
                log.exception("Обработка syslog от %s", addr[0])
