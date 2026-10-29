"""Minimal fake Cisco IOS SSH server for manual and integration testing.

python tests/fake_router.py --port 2222   (login: admin / admin)
Serves `show webvpn session context all` with Created/Last_Used ages that grow over time,
and supports `webvpn session disconnect context <ctx> name <login>`.
"""

from __future__ import annotations

import argparse
import socket
import threading
import time

import paramiko

START = time.time()
# login, ip, connections, age at start (s)
PROFILES = {
    "main": [
        ["ivanov", "203.0.113.10", 1, 3 * 3600 + 1200],
        ["petrov", "203.0.113.20", 2, 8 * 3600],
        ["petrov", "203.0.113.20", 1, 600],
        ["sidorov", "198.51.100.30", 1, 95 * 3600],
        ["kuznetsova", "198.51.100.40", 1, 40],
        ["shared", "192.0.2.50", 1, 7200],
        ["shared", "192.0.2.60", 1, 300],
    ],
    "branch": [
        ["branch01", "203.0.113.110", 1, 2 * 3600],
        ["branch02", "203.0.113.111", 1, 900],
        ["ivanov", "203.0.113.112", 1, 120],
    ],
}
AGENTS = {
    "ivanov": "AnyConnect Windows 4.4.01054",
    "petrov": "AnyConnect Windows 4.10.07073",
    "sidorov": "AnyConnect Darwin_i386 4.10.08025",
    "kuznetsova": "AnyConnect Windows 4.4.01054",
    "shared": "AnyConnect Android 4.10.05085",
    "branch01": "Cisco Secure Client Windows 5.1.2.42",
}
USERS = {
    "main": [("ivanov", 0), ("petrov", 0), ("sidorov", 0), ("kuznetsova", 0), ("shared", 0),
             ("olduser1", 0), ("olduser2", 0), ("root", 15), ("admin", 15)],
    "branch": [("branch01", 0), ("branch02", 0), ("ivanov", 0), ("admin", 15)],
}
PROFILE = "main"
SESSIONS: list = []
LOCK = threading.Lock()
PROMPT = "\r\nrouter#"


def age_str(seconds: int) -> str:
    if seconds >= 86400:
        return f"{seconds // 86400}d{(seconds % 86400) // 3600:02d}h"
    h, rem = divmod(seconds, 3600)
    return f"{h:02d}:{rem // 60:02d}:{rem % 60:02d}"


def sessions_output() -> str:
    elapsed = int(time.time() - START)
    lines = ["WebVPN context name: SSL_Context",
             "Client_Login_Name  Client_IP_Address  No_of_Connections  Created  Last_Used"]
    with LOCK:
        for login, ip, conns, age in SESSIONS:
            lines.append(f"{login:<18} {ip:<18} {conns:<18} {age_str(age + elapsed)} {age_str((elapsed * 7) % 90)}")
    return "\r\n".join(lines)


class Server(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == ("admin", "admin") else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, *args):
        return True


def session_detail(login: str) -> str:
    """Same layout as IOS 15.7 `show webvpn session user X context Y`."""
    elapsed = int(time.time() - START)
    blocks = []
    with LOCK:
        rows = [r for r in SESSIONS if r[0] == login]
    for i, (user, ip, conns, age) in enumerate(rows):
        created = time.strftime("%H:%M:%S.000 ALM %a %b %d %Y", time.localtime(START - age))
        blocks.append("\r\n".join([
            "Session Type      : Full Tunnel",
            f"Client User-Agent : {AGENTS.get(user, 'AnyConnect Windows 4.10.07073')}",
            "",
            f"Username          : {user:<20} Num Connection : {conns}",
            f"Public IP         : {ip:<20} VRF Name       : None",
            "Context           : SSL_Context          Policy Group   : SSL_Policy",
            f"Last-Used         : 00:00:00             Created        : {created}",
            f"Tunnel IP         : 10.0.251.{100 + i:<14} Netmask        : 255.255.255.0",
            f"Rx IP Packets     : {elapsed * 37 + age:<20} Tx IP Packets  : {elapsed * 29 + age // 2}",
        ]))
    return "\r\n".join(blocks) if blocks else "% No session found"


def handle_command(cmd: str) -> str:
    parts = cmd.split()
    if cmd == "terminal length 0":
        return ""
    if cmd == "show webvpn session context all":
        return sessions_output()
    if parts[:5] == ["webvpn", "session", "disconnect", "context", "SSL_Context"] and len(parts) == 7 and parts[5] == "name":
        with LOCK:
            for i, row in enumerate(SESSIONS):
                if row[0] == parts[6]:
                    del SESSIONS[i]
                    return ""
        return "% No session found"
    if cmd == "show version":
        up = int(time.time() - START) + 9 * 86400
        return ("Cisco IOS Software, C2951 Software (C2951-UNIVERSALK9-M), Version 15.7(3)M4b, RELEASE SOFTWARE (fc1)\r\n"
                f"router uptime is {up // 86400} days, {up % 86400 // 3600} hours, {up % 3600 // 60} minutes\r\n"
                "Last reload reason: power-on\r\n"
                "Cisco CISCO2951/K9 (revision 1.1) with 1001472K/47104K bytes of memory.")
    if cmd.startswith("show running-config"):
        return "\r\n".join(f"username {u} privilege {p} secret 9 $9$fakehash" for u, p in USERS[PROFILE])
    if cmd.startswith("show webvpn session user") and len(parts) >= 5:
        return session_detail(parts[4])
    return "              ^\r\n% Invalid input detected at '^' marker."


def serve_client(sock, host_key):
    transport = paramiko.Transport(sock)
    transport.add_server_key(host_key)
    transport.start_server(server=Server())
    chan = transport.accept(20)
    if chan is None:
        return
    chan.send("router#")
    buf = ""
    try:
        while transport.is_active():
            data = chan.recv(1024)
            if not data:
                break
            buf += data.decode(errors="ignore")
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                out = handle_command(line.strip())
                chan.send(line.strip() + ("\r\n" + out if out else "") + PROMPT)
    except Exception:
        pass
    finally:
        transport.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--profile", choices=sorted(PROFILES), default="main")
    ap.add_argument("--key", help="host key file, kept between runs so known_hosts stays valid")
    args = ap.parse_args()
    global PROFILE
    PROFILE = args.profile
    SESSIONS.extend([list(r) for r in PROFILES[PROFILE]])
    if args.key:
        try:
            host_key = paramiko.RSAKey.from_private_key_file(args.key)
        except (FileNotFoundError, paramiko.SSHException):
            host_key = paramiko.RSAKey.generate(2048)
            host_key.write_private_key_file(args.key)
    else:
        host_key = paramiko.RSAKey.generate(2048)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(5)
    print(f"fake router on 127.0.0.1:{args.port}", flush=True)
    while True:
        client, _ = srv.accept()
        threading.Thread(target=serve_client, args=(client, host_key), daemon=True).start()


if __name__ == "__main__":
    main()
