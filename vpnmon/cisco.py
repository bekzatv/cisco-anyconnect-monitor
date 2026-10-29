from __future__ import annotations

import re
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .config import KNOWN_HOSTS_FILE

VPN_COMMAND = "show webvpn session context all"

DEFAULT_DISCONNECT_COMMAND = "webvpn session disconnect context {context} name {login}"
OLD_DEFAULT_DISCONNECT_COMMAND = "webvpn session disconnect name {login} context {context}"

FALLBACK_DISCONNECT_COMMANDS = (
    "webvpn session disconnect context {context} name {login}",
    "webvpn session disconnect context {context} user {login}",
    "webvpn session disconnect context {context} username {login}",
    "webvpn session disconnect context {context} login {login}",
    "webvpn session disconnect context {context} ip-address {ip}",
    "webvpn session disconnect context {context} ip {ip}",
    "webvpn session disconnect name {login} context {context}",
    "webvpn session disconnect user {login} context {context}",
    "webvpn session disconnect username {login} context {context}",
    "webvpn session disconnect login {login} context {context}",
    "webvpn session disconnect ip-address {ip} context {context}",
    "webvpn session disconnect ip {ip} context {context}",
    "clear webvpn session context {context} name {login}",
    "clear webvpn session context {context} user {login}",
    "clear webvpn session context {context} username {login}",
    "clear webvpn session context {context} ip-address {ip}",
    "clear webvpn session user {login} context {context}",
    "clear webvpn session username {login} context {context}",
    "clear webvpn session user {login}",
)

DETAIL_SESSION_COMMANDS = (
    "show webvpn session user {login} context {context}",
    "show webvpn session username {login} context {context}",
    "show webvpn session name {login} context {context}",
    "show webvpn session user {login}",
    "show webvpn session context {context}",
)

ROUTER_USERS_COMMANDS = (
    "show running-config | include ^username ",
    "show running-config | section username",
    "show aaa local user",
)

_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.\-@]+$")


@dataclass
class VpnSession:
    context: str
    login: str
    ip: str
    connections: int
    created: str
    last_used: str
    country: str = ""
    org: str = ""
    connects_90d: int = 0
    router: str = "main"
    client_agent: str = ""
    client_os: str = ""
    client_version: str = ""
    tunnel_ip: str = ""
    rx_packets: int = 0
    tx_packets: int = 0

    def key(self) -> tuple[str, str, str]:
        return (self.context, self.login, self.ip)

    def instance_key(self) -> tuple[str, str, str, str]:
        return (self.context, self.login, self.ip, self.created)


def clean_text(text: str) -> str:
    cleaned = re.sub(r"[^\x09\x0a\x0d\x20-\x7e]", "", text)
    return re.sub(r"\s+", " ", cleaned).strip()


_AGE_UNITS = {"y": 365 * 86400, "w": 7 * 86400, "d": 86400, "h": 3600, "m": 60, "s": 1}


def parse_cisco_age(text: str) -> tuple[int, int] | None:
    """Parse a Cisco uptime-style age ("03:21:20", "1d02h", "2w3d") into (seconds, resolution_seconds).

    The Created / Last_Used columns of `show webvpn session` are ages, not timestamps:
    they grow on every poll, so they can't be used as a stable session identifier.
    """
    value = (text or "").strip().lower()
    m = re.fullmatch(r"(\d+):(\d{1,2}):(\d{1,2})", value)
    if m:
        h, mi, s = (int(x) for x in m.groups())
        return h * 3600 + mi * 60 + s, 1
    parts = re.findall(r"(\d+)([ywdhms])", value)
    if parts and "".join(n + u for n, u in parts) == value:
        total = sum(int(n) * _AGE_UNITS[u] for n, u in parts)
        return total, _AGE_UNITS[parts[-1][1]]
    return None


def parse_router_usernames(output: str) -> list[str]:
    usernames: list[str] = []
    seen: set[str] = set()
    for raw_line in output.splitlines():
        line = clean_text(raw_line)
        if not line:
            continue
        m = re.match(
            r"^username\s+([A-Za-z0-9_.\-@]+)\s+(?:privilege|secret|password|algorithm-type|nopassword|autocommand|access-class|one-time|view|common-criteria-policy)\b",
            line,
            flags=re.IGNORECASE,
        )
        if m:
            u = m.group(1).strip()
            if u.lower() not in seen:
                seen.add(u.lower())
                usernames.append(u)
    return usernames


def parse_router_user_entries(output: str) -> list[tuple[str, int]]:
    """Local usernames with their privilege level (IOS default is 1). Secrets are never kept."""
    entries: dict[str, tuple[str, int]] = {}
    for raw_line in output.splitlines():
        line = clean_text(raw_line)
        m = re.match(
            r"^username\s+([A-Za-z0-9_.\-@]+)\s+(?:privilege|secret|password|algorithm-type|nopassword|autocommand|access-class|one-time|view|common-criteria-policy)\b(.*)$",
            line,
            flags=re.IGNORECASE,
        )
        if not m:
            continue
        priv = re.search(r"\bprivilege\s+(\d+)", line, flags=re.IGNORECASE)
        entries.setdefault(m.group(1).lower(), (m.group(1), int(priv.group(1)) if priv else 1))
    return list(entries.values())


# "Client User-Agent : AnyConnect Windows 4.4.01054"; two "key : value" pairs per line are common.
_DETAIL_PAIR_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9 /\-]*?)\s*:\s(.*?)(?=\s{2,}[A-Za-z][A-Za-z0-9 /\-]*?\s*:\s|\s*$)"
)
_CREATED_ABS_RE = re.compile(
    r"(\d{1,2}):(\d{2}):(\d{2})(?:\.\d+)?\s+\S+\s+\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{4})"
)
_MONTHS = {m: i for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}


def parse_session_details(output: str) -> list[dict]:
    """Parse `show webvpn session user X context Y` into one dict per session block."""
    blocks: list[dict] = []
    current: dict = {}
    for raw_line in output.replace("\r", "").splitlines():
        for key, value in _DETAIL_PAIR_RE.findall(raw_line.rstrip()):
            key = re.sub(r"\s+", " ", key.strip()).lower()
            if key in ("session type", "username") and key in current:
                blocks.append(current)
                current = {}
            current[key] = value.strip()
    if current:
        blocks.append(current)
    out = []
    for b in blocks:
        if "username" not in b and "client user-agent" not in b:
            continue
        agent = b.get("client user-agent", "")
        os_name, version = parse_user_agent(agent)
        out.append({
            "username": b.get("username", ""),
            "public_ip": b.get("public ip", ""),
            "agent": agent,
            "os": os_name,
            "version": version,
            "tunnel_ip": b.get("tunnel ip", ""),
            "rx_packets": _to_int(b.get("rx ip packets")),
            "tx_packets": _to_int(b.get("tx ip packets")),
            "created_ts": parse_created_absolute(b.get("created", "")),
        })
    return out


def parse_created_absolute(text: str) -> int | None:
    """"08:17:10.322 ALM Fri Oct 23 2026" -> local timestamp (the zone name is ignored)."""
    m = _CREATED_ABS_RE.search(text or "")
    if not m:
        return None
    hh, mm, ss, mon, day, year = m.groups()
    month = _MONTHS.get(mon.lower())
    if not month:
        return None
    try:
        return int(time.mktime((int(year), month, int(day), int(hh), int(mm), int(ss), 0, 0, -1)))
    except (OverflowError, ValueError):
        return None


def parse_user_agent(agent: str) -> tuple[str, str]:
    """"AnyConnect Windows 4.4.01054" -> ("Windows", "4.4.01054")."""
    text = (agent or "").strip()
    if not text:
        return "", ""
    versions = re.findall(r"\d+(?:\.\d+){1,3}", text)
    version = versions[-1] if versions else ""
    low = text.lower()
    if "android" in low:
        os_name = "Android"
    elif any(x in low for x in ("iphone", "ipad", "ios")):
        os_name = "iOS"
    elif "darwin" in low or "mac" in low:
        os_name = "macOS"
    elif "linux" in low:
        os_name = "Linux"
    elif "win" in low:
        os_name = "Windows"
    else:
        os_name = ""
    return os_name, version


_UPTIME_UNITS = {"year": 365 * 86400, "week": 7 * 86400, "day": 86400, "hour": 3600, "minute": 60, "second": 1}


def parse_show_version(output: str) -> dict:
    """Uptime, IOS version, model and last reload reason from `show version`."""
    text = output.replace("\r", "")
    info: dict = {}
    m = re.search(r"^(\S+) uptime is (.+)$", text, re.M)
    if m:
        info["hostname"] = m.group(1)
        info["uptime_text"] = m.group(2).strip()
        info["uptime_seconds"] = sum(
            int(n) * _UPTIME_UNITS[u] for n, u in re.findall(r"(\d+)\s+(year|week|day|hour|minute|second)s?", m.group(2))
        )
    m = re.search(r"Cisco IOS.*?Version ([\w.()]+)", text)
    if m:
        info["ios_version"] = m.group(1)
    m = re.search(r"^[Cc]isco (\S+) \(revision", text, re.M)
    if m:
        info["model"] = m.group(1)
    m = re.search(r"Last reload reason:\s*(.+)$", text, re.M) or re.search(r"System returned to ROM by (.+)$", text, re.M)
    if m:
        info["reload_reason"] = m.group(1).strip()
    return info


def version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", version or "")[:4])


def is_outdated(version: str, minimum: str) -> bool:
    if not version or not minimum:
        return False
    v, m = version_tuple(version), version_tuple(minimum)
    return bool(v and m) and v[: len(m)] < m


def _to_int(value) -> int:
    try:
        return int(str(value).split()[0])
    except (TypeError, ValueError, IndexError):
        return 0


def parse_webvpn_sessions(output: str) -> list[VpnSession]:
    sessions: list[VpnSession] = []
    context = ""
    for raw_line in output.splitlines():
        line = clean_text(raw_line)
        if not line:
            continue
        context_match = re.match(r"^WebVPN context name:\s*(.+)$", line, flags=re.IGNORECASE)
        if context_match:
            context = context_match.group(1).strip()
            continue
        if line.lower().startswith("client_login_name"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        login, ip, connections, created, last_used = parts[:5]
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            continue
        try:
            connection_count = int(connections)
        except ValueError:
            continue
        sessions.append(
            VpnSession(
                context=context,
                login=login,
                ip=ip,
                connections=connection_count,
                created=created,
                last_used=last_used,
            )
        )
    return sessions


def check_paramiko_compatibility():
    try:
        import paramiko
        from paramiko.transport import Transport
    except ImportError as exc:
        raise RuntimeError(
            "Paramiko is not installed. Run: python -m pip install -r requirements.txt"
        ) from exc

    legacy_kex = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"}
    if not legacy_kex.intersection(Transport._kex_info):
        raise RuntimeError(
            'This Cisco IOS SSH server needs legacy key-exchange algorithms. '
            'Install Paramiko 3.x: python -m pip install "paramiko>=3.5,<4" --upgrade'
        )
    return paramiko


def _trust_on_first_use_policy(paramiko, known_hosts: Path):
    class TrustOnFirstUse(paramiko.MissingHostKeyPolicy):
        """Remember the router key on first connect; paramiko rejects a changed key afterwards."""

        def missing_host_key(self, client, hostname, key):
            client.get_host_keys().add(hostname, key.get_name(), key)
            known_hosts.parent.mkdir(parents=True, exist_ok=True)
            client.save_host_keys(str(known_hosts))

    return TrustOnFirstUse()


def open_cisco_shell(
    host: str,
    username: str,
    password: str,
    port: int = 22,
    timeout: int = 12,
    known_hosts: Path = KNOWN_HOSTS_FILE,
):
    paramiko = check_paramiko_compatibility()
    client = paramiko.SSHClient()
    if known_hosts.exists():
        client.load_host_keys(str(known_hosts))
    client.set_missing_host_key_policy(_trust_on_first_use_policy(paramiko, known_hosts))
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
        )
    except paramiko.BadHostKeyException as exc:
        client.close()
        raise RuntimeError(
            f"SSH-ключ устройства {host} изменился с прошлого подключения. "
            f"Возможна подмена устройства. Если ключ сменили намеренно, удалите строку {host} "
            f"из файла {known_hosts}."
        ) from exc
    shell = client.invoke_shell()
    shell.settimeout(1)
    return client, shell


def send_cisco_command(shell, command: str, timeout: int = 12) -> str:
    output_parts: list[str] = []
    prompt_re = re.compile(r"[\r\n][\w.@()/-]+[#>]\s*$")
    confirm_sent = False
    yes_sent = False

    shell.send(command + "\n")
    time.sleep(0.4)
    deadline = time.time() + timeout

    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode("utf-8", errors="ignore")
            output_parts.append(chunk)
            output = "".join(output_parts)
            if not confirm_sent and re.search(r"\[(confirm|ok)\]", output, flags=re.IGNORECASE):
                shell.send("\n")
                confirm_sent = True
                continue
            if not yes_sent and re.search(r"\[(yes/no|y/n)\]", output, flags=re.IGNORECASE):
                shell.send("yes\n")
                yes_sent = True
                continue
            if prompt_re.search(output):
                break
        else:
            time.sleep(0.2)

    return "".join(output_parts)


def fetch_webvpn_sessions(
    host: str,
    username: str,
    password: str,
    port: int = 22,
    timeout: int = 12,
) -> tuple[list[VpnSession], str]:
    client, shell = open_cisco_shell(host, username, password, port=port, timeout=timeout)
    try:
        send_cisco_command(shell, "terminal length 0", timeout=timeout)
        raw_output = send_cisco_command(shell, VPN_COMMAND, timeout=timeout)
        return parse_webvpn_sessions(raw_output), raw_output
    finally:
        client.close()


def fetch_router_usernames_ssh(
    host: str,
    username: str,
    password: str,
    port: int = 22,
    timeout: int = 15,
) -> tuple[list[str], str]:
    client, shell = open_cisco_shell(host, username, password, port=port, timeout=timeout)
    try:
        send_cisco_command(shell, "terminal length 0", timeout=timeout)
        combined_out: list[str] = []
        for cmd in ROUTER_USERS_COMMANDS:
            out = send_cisco_command(shell, cmd, timeout=timeout)
            combined_out.append(out)
            users = parse_router_usernames(out)
            if users:
                return users, out
        return [], "\n".join(combined_out)
    finally:
        client.close()


def fetch_session_details_ssh(
    host: str,
    username: str,
    password: str,
    session: VpnSession,
    port: int = 22,
    timeout: int = 12,
) -> tuple[str, str]:
    client, shell = open_cisco_shell(host, username, password, port=port, timeout=timeout)
    try:
        send_cisco_command(shell, "terminal length 0", timeout=timeout)
        return session_details_on_shell(shell, session, timeout=timeout)
    finally:
        client.close()


def session_details_on_shell(shell, session: VpnSession, timeout: int = 12) -> tuple[str, str]:
    attempted: list[str] = []
    output = ""
    for template in DETAIL_SESSION_COMMANDS:
        command = template.format(**asdict(session)).strip()
        if not command or command in attempted:
            continue
        attempted.append(command)
        output = send_cisco_command(shell, command, timeout=timeout)
        if not is_invalid_cisco_command(output):
            return command, output
    return attempted[0] if attempted else "", output


def disconnect_webvpn_session(
    host: str,
    username: str,
    password: str,
    session: VpnSession,
    command_template: str,
    port: int = 22,
    timeout: int = 12,
) -> tuple[str, str]:
    client, shell = open_cisco_shell(host, username, password, port=port, timeout=timeout)
    try:
        send_cisco_command(shell, "terminal length 0", timeout=timeout)
        return disconnect_on_shell(shell, session, command_template, timeout=timeout)
    finally:
        client.close()


def disconnect_on_shell(
    shell, session: VpnSession, command_template: str, timeout: int = 12
) -> tuple[str, str]:
    for field in (session.login, session.context, session.ip):
        if not _SAFE_TOKEN_RE.match(field or ""):
            raise RuntimeError(f"Недопустимое значение для команды Cisco: {field!r}")
    templates = disconnect_command_templates(command_template)
    attempted: list[str] = []
    for template in templates:
        try:
            command = template.format(**asdict(session)).strip()
        except (KeyError, ValueError) as exc:
            raise RuntimeError(f"Некорректный шаблон команды отключения: {exc}") from exc
        if not command:
            continue
        output = send_cisco_command(shell, command, timeout=timeout)
        attempted.append(f"{command}\n{clean_text(output)}")
        if not is_invalid_cisco_command(output):
            return command, output

    help_output = collect_disconnect_help(shell, session, timeout=timeout)
    raise RuntimeError(
        "Все команды отключения завершились ошибкой:\n\n"
        + "\n\n".join(attempted)
        + "\n\nСправка Cisco (?):\n\n"
        + help_output
    )


def disconnect_command_templates(value: str) -> list[str]:
    parts = [part.strip() for part in re.split(r"[;\r\n]+", value or "") if part.strip()]
    templates = parts or [DEFAULT_DISCONNECT_COMMAND]
    if len(templates) == 1 and templates[0] == DEFAULT_DISCONNECT_COMMAND:
        for fallback in FALLBACK_DISCONNECT_COMMANDS:
            if fallback not in templates:
                templates.append(fallback)
    return templates


def is_invalid_cisco_command(output: str) -> bool:
    lowered = output.lower()
    return (
        "% invalid input" in lowered
        or "% incomplete command" in lowered
        or "% ambiguous command" in lowered
    )


def collect_disconnect_help(shell, session: VpnSession, timeout: int = 12) -> str:
    help_commands = [
        "webvpn session disconnect ?",
        "webvpn session disconnect context ?",
        f"webvpn session disconnect context {session.context} ?",
        f"webvpn session disconnect context {session.context} user ?",
        "clear webvpn session ?",
        "clear webvpn session context ?",
        f"clear webvpn session context {session.context} ?",
        "clear webvpn session user ?",
    ]
    outputs: list[str] = []
    for command in help_commands:
        output = send_cisco_command(shell, command, timeout=min(timeout, 8))
        outputs.append(f"{command}\n{clean_text(output)}")
    return "\n\n".join(outputs)


def ipv4_sort_key(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)


class CiscoConnection:
    """One long-lived SSH shell shared by polling and admin actions, reopened on failure."""

    def __init__(self, timeout: int = 25):
        self.timeout = timeout
        self._lock = threading.Lock()
        self._client = None
        self._shell = None
        self._target: tuple[str, int, str, str] | None = None

    def _ensure(self, host: str, port: int, username: str, password: str):
        target = (host, port, username, password)
        transport = self._client.get_transport() if self._client else None
        if self._shell is not None and target == self._target and transport and transport.is_active():
            return self._shell
        self._close_unlocked()
        self._client, self._shell = open_cisco_shell(
            host, username, password, port=port, timeout=self.timeout
        )
        self._target = target
        send_cisco_command(self._shell, "terminal length 0", timeout=self.timeout)
        return self._shell

    def run(self, creds: tuple[str, int, str, str], func, *args, **kwargs):
        """Run func(shell, ...) under the connection lock; retry once on a fresh connection."""
        with self._lock:
            reused = self._shell is not None
            try:
                return func(self._ensure(*creds), *args, **kwargs)
            except Exception:
                transport = self._client.get_transport() if self._client else None
                if transport and transport.is_active():
                    raise
                # The connection died (router exec-timeout, reboot): reconnect once if it was a stale one.
                self._close_unlocked()
                if not reused:
                    raise
            return func(self._ensure(*creds), *args, **kwargs)

    def fetch_sessions(self, creds: tuple[str, int, str, str]) -> tuple[list[VpnSession], str]:
        def _fetch(shell):
            raw = send_cisco_command(shell, VPN_COMMAND, timeout=self.timeout)
            return parse_webvpn_sessions(raw), raw

        return self.run(creds, _fetch)

    def close(self):
        with self._lock:
            self._close_unlocked()

    def _close_unlocked(self):
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
        self._client = None
        self._shell = None
        self._target = None
