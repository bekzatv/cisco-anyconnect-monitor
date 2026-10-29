"""Create a demo data folder with three weeks of made-up history.

Try the panel without a Cisco router:

    python tools/make_demo.py --data-dir demo
    python tests/fake_router.py --port 2222
    python server.py --data-dir demo --open        # login: admin / demo-password

All names are invented and all addresses come from the documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so nothing here belongs to a real network.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

DAY = 86400
USERS = [
    # login, typical start hour, hours per day, days per week, client, profile
    ("ivanov", 9, 8, 5, "AnyConnect Windows 4.4.01054", "office"),
    ("petrov", 8, 9, 5, "AnyConnect Windows 4.10.07073", "office"),
    ("sidorov", 10, 7, 4, "AnyConnect Darwin_i386 4.10.08025", "office"),
    ("kuznetsova", 9, 8, 5, "AnyConnect Windows 4.4.01054", "office"),
    ("shared", 8, 10, 6, "AnyConnect Android 4.10.05085", "shared"),
    ("smirnova", 9, 6, 3, "AnyConnect Windows 4.10.07073", "office"),
    ("popov", 13, 5, 5, "Cisco Secure Client Windows 5.1.2.42", "office"),
    ("vasilieva", 9, 8, 5, "AnyConnect Windows 4.4.01054", "flaky"),
    ("sokolov", 7, 10, 5, "AnyConnect Windows 4.10.07073", "office"),
    ("mikhailova", 9, 4, 2, "AnyConnect Windows 4.10.07073", "office"),
    ("novikov", 10, 8, 5, "AnyConnect Windows 4.4.01054", "flaky"),
    ("fedorova", 9, 8, 5, "AnyConnect Darwin_i386 4.10.08025", "office"),
    ("morozov", 9, 8, 1, "AnyConnect Windows 4.4.01054", "rare"),
    ("volkova", 8, 9, 5, "AnyConnect Windows 4.10.07073", "office"),
    ("alekseev", 20, 3, 3, "AnyConnect Windows 4.10.07073", "evening"),
    ("lebedeva", 9, 8, 5, "AnyConnect Windows 4.4.01054", "office"),
    ("branch01", 8, 10, 6, "Cisco Secure Client Windows 5.1.2.42", "office"),
    ("warehouse02", 7, 11, 6, "AnyConnect Windows 4.4.01054", "office"),
]
NEVER = ["olduser1", "olduser2", "contractor7", "temp_audit", "trainee3"]
ISPS = [
    ("KZ / Almaty", "AS64500 Example Telecom"), ("KZ / Astana", "AS64501 Demo Networks"),
    ("KZ / Karaganda", "AS64502 Sample Mobile"), ("KZ / Shymkent", "AS64500 Example Telecom"),
]


def doc_ip(rng: random.Random) -> str:
    return f"{rng.choice(['192.0.2', '198.51.100', '203.0.113'])}.{rng.randint(2, 250)}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default="demo")
    ap.add_argument("--days", type=int, default=21)
    ap.add_argument("--fake-router-port", type=int, default=2222)
    ap.add_argument("--web-port", type=int, default=8765)
    args = ap.parse_args()

    data = Path(args.data_dir).resolve()
    if (data / "connection_stats.db").exists():
        sys.exit(f"{data} already has a database; pick another --data-dir")
    data.mkdir(parents=True, exist_ok=True)
    os.environ["VPNMON_DATA_DIR"] = str(data)
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from vpnmon.config import encode_password
    from vpnmon.server import hash_password
    from vpnmon.storage import ConnectionStatsStore, _iso

    rng = random.Random(42)
    store = ConnectionStatsStore(data / "connection_stats.db")
    now = int(time.time())
    start_day = datetime.fromtimestamp(now - args.days * DAY).replace(hour=0, minute=0, second=0, microsecond=0)
    home_ip = {u[0]: doc_ip(rng) for u in USERS}
    geo = {}
    rows = []
    for login, hour, length, per_week, agent, profile in USERS:
        os_name = "macOS" if "Darwin" in agent else "Android" if "Android" in agent else "Windows"
        version = agent.split()[-1]
        for d in range(args.days):
            day = start_day + timedelta(days=d)
            workday = day.weekday() < 5 or (per_week == 6 and day.weekday() == 5)
            if not workday or rng.random() > per_week / 5.5:
                continue
            ip = home_ip[login] if rng.random() < 0.85 else doc_ip(rng)
            geo.setdefault(ip, rng.choice(ISPS))
            begin = int((day + timedelta(hours=hour, minutes=rng.randint(-40, 40))).timestamp())
            end = begin + int(length * 3600 * rng.uniform(0.7, 1.15))
            if begin > now:
                continue
            end = min(end, now)
            pieces = [(begin, end)]
            if profile == "flaky" and rng.random() < 0.6:  # short sessions with quick reconnects
                pieces, t = [], begin
                while t < end:
                    t2 = min(end, t + rng.randint(5, 50) * 60)
                    pieces.append((t, t2))
                    t = t2 + rng.randint(20, 240)
            for a, b in pieces:
                rows.append((login, ip, a, b, os_name, version, agent))

    with store._connect() as conn:
        for login, ip, a, b, os_name, version, agent in rows:
            country, org = geo[ip]
            active = 1 if b >= now - 60 else 0
            conn.execute(
                """INSERT INTO session_events (router, login, context, ip, created_raw, country, org,
                       peak_connections, first_seen_ts, last_seen_ts, first_seen_iso, last_seen_iso, is_active,
                       client_agent, client_os, client_version, tunnel_ip, rx_packets, tx_packets, details_ts)
                   VALUES ('main', ?, 'SSL_Context', ?, '00:00:00', ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (login, ip, country, org, a, b, _iso(a), _iso(b), active, agent, os_name, version,
                 f"10.99.0.{rng.randint(2, 250)}", (b - a) * 9, (b - a) * 7, b),
            )
        conn.execute("INSERT INTO downtime (start_ts, end_ts) VALUES (?, ?)", (now - 5 * DAY + 3 * 3600, now - 5 * DAY + 7 * 3600))
        conn.commit()

    store.register_known_users([u[0] for u in USERS] + NEVER, source="router", now_ts=now - args.days * DAY)
    store.sync_router_users("main", [(u[0], 0) for u in USERS] + [(n, 0) for n in NEVER]
                            + [("admin", 15), ("netadmin", 15)], now_ts=now - args.days * DAY)
    events = [
        (now - 2 * DAY + 3600, "ALERT", "'sidorov' вошёл из новой страны: TR / Istanbul (198.51.100.77, AS64510 Example Hosting). Раньше: KZ", "sidorov"),
        (now - 3 * DAY + 7200, "ALERT", "Логин 'shared' одновременно подключён с 2 IP: 192.0.2.50, 192.0.2.60", "shared"),
        (now - 5 * DAY + 7 * 3600, "GAP", "Сбор данных не шёл 4 ч 00 мин: сервер монитора был выключен.", ""),
        (now - 1 * DAY, "CONFIG", "Конфигурация изменена: netadmin (192.168.10.5)", "netadmin"),
    ]
    for ts, kind, msg, login in events:
        store.add_event(kind, msg, login=login, now_ts=ts, router="main")
    for ts, sev, code, text, kind in [
        (now - DAY - 120, 5, "PARSER-5-CFGLOG_LOGGEDCMD", "User:netadmin  logged command:ip access-list standard 25", "config_cmd"),
        (now - DAY - 60, 5, "PARSER-5-CFGLOG_LOGGEDCMD", "User:netadmin  logged command: permit 192.168.10.0 0.0.0.255", "config_cmd"),
        (now - DAY, 5, "SYS-5-CONFIG_I", "Configured from console by netadmin on vty0 (192.168.10.5)", "config"),
        (now - 3 * 3600, 3, "LINK-3-UPDOWN", "Interface GigabitEthernet0/1, changed state to down", "iface_down"),
        (now - 3 * 3600 + 300, 3, "LINK-3-UPDOWN", "Interface GigabitEthernet0/1, changed state to up", "iface_up"),
        (now - 2 * 3600, 4, "CRYPTO-4-IKMP_BAD_MESSAGE", "IKE message from 203.0.113.200 failed its sanity check", ""),
    ]:
        store.add_syslog(ts, "main", "127.0.0.1", sev, code, text, kind)

    cache = {ip: {"ip": ip, "country": c.split(" / ")[0], "city": c.split(" / ")[1], "org": o} for ip, (c, o) in geo.items()}
    for ip, c, o in [("203.0.113.10", "KZ / Astana", "AS64501 Demo Networks"), ("203.0.113.20", "KZ / Almaty", "AS64500 Example Telecom"),
                     ("198.51.100.30", "KZ / Karaganda", "AS64502 Sample Mobile"), ("198.51.100.40", "KZ / Almaty", "AS64500 Example Telecom"),
                     ("192.0.2.50", "KZ / Pavlodar", "AS64502 Sample Mobile"), ("192.0.2.60", "KZ / Semey", "AS64502 Sample Mobile")]:
        cache[ip] = {"ip": ip, "country": c.split(" / ")[0], "city": c.split(" / ")[1], "org": o}
    (data / "ip_cache.json").write_text(json.dumps(cache, indent=2, ensure_ascii=False), encoding="utf-8")
    (data / "settings.json").write_text(json.dumps({
        "routers": [{"id": "main", "name": "Demo core", "host": "127.0.0.1", "port": args.fake_router_port,
                     "username": "admin", "password_encoded": encode_password("admin"),
                     "disconnect_command": "", "enabled": True}],
        "refresh_seconds": 15, "web_port": args.web_port, "syslog_port": 5514,
        "web_admin_password_hash": hash_password("demo-password"),
    }, indent=2), encoding="utf-8")
    print(f"Demo data: {data}  ({len(rows)} sessions, {len(USERS)} users)")
    print(f"Run: python tests/fake_router.py --port {args.fake_router_port}")
    print(f"     python server.py --data-dir \"{data}\" --open     (admin / demo-password)")


if __name__ == "__main__":
    main()
