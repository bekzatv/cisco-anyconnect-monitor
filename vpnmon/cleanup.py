"""Accounts to remove: local router users without VPN activity for N days.

The panel only prepares the list and the commands; nothing is ever sent to the router.
"""

from __future__ import annotations

import time
from datetime import datetime

from .storage import ConnectionStatsStore

ADMIN_PRIVILEGE = 15


def plural(n: int, one: str, few: str, many: str) -> str:
    """Russian plural: 1 сессия, 2 сессии, 5 сессий."""
    n10, n100 = n % 10, n % 100
    if n10 == 1 and n100 != 11:
        return one
    if 2 <= n10 <= 4 and not 12 <= n100 <= 14:
        return few
    return many


def _date(ts: int | None) -> str:
    return datetime.fromtimestamp(ts).strftime("%d.%m.%Y") if ts else ""


def build_cleanup(store: ConnectionStatsStore, routers: list[dict], idle_days: int,
                  exclude: set[str], now_ts: int | None = None) -> dict:
    now_ts = now_ts if now_ts is not None else int(time.time())
    exclude = {x.strip().lower() for x in exclude if x.strip()}
    result = {"idle_days": idle_days, "generated": _date(now_ts), "routers": []}
    for router in routers:
        users, observed_since = store.get_router_user_activity(router["id"])
        synced = store.get_meta(f"router_users_synced:{router['id']}")
        entry = {
            "id": router["id"],
            "name": router["name"],
            "host": router["host"],
            "synced_ts": int(synced) if synced else 0,
            "observed_since": observed_since or 0,
            "observed_days": (now_ts - observed_since) // 86400 if observed_since else 0,
            # Never-seen users can't be idle for longer than monitoring has been running.
            "ready_from": _date(observed_since + idle_days * 86400) if observed_since else "",
            "users_total": len(users),
            "candidates": [],
            "excluded": [],
            "active": 0,
            "commands": "",
        }
        monitor_user = router.get("username", "").lower()
        for u in users:
            login = u["login"]
            if int(u["privilege"] or 0) >= ADMIN_PRIVILEGE:
                entry["excluded"].append({"login": login, "reason": f"администратор (privilege {u['privilege']})"})
                continue
            if login.lower() == monitor_user:
                entry["excluded"].append({"login": login, "reason": "учётка мониторинга"})
                continue
            if login.lower() in exclude:
                entry["excluded"].append({"login": login, "reason": "в списке исключений"})
                continue
            if u["online"]:
                entry["active"] += 1
                continue
            if not observed_since:
                continue
            last_ts = int(u["last_ts"]) if u["last_ts"] else None
            idle_since = last_ts or max(observed_since, int(u["first_synced_ts"] or 0))
            days = (now_ts - idle_since) // 86400
            if days >= idle_days:
                entry["candidates"].append({
                    "login": login,
                    "privilege": u["privilege"],
                    "last_activity": _date(last_ts) if last_ts else "",
                    "idle_days": days,
                    "never": last_ts is None,
                })
            else:
                entry["active"] += 1
        entry["candidates"].sort(key=lambda c: (-c["idle_days"], c["login"].lower()))
        entry["commands"] = cleanup_commands(entry, idle_days, now_ts)
        result["routers"].append(entry)
    return result


def cleanup_commands(entry: dict, idle_days: int, now_ts: int) -> str:
    if not entry["candidates"]:
        return ""
    n = len(entry["candidates"])
    lines = [
        f"! {entry['name']} ({entry['host']}): {n} {plural(n, 'учётка', 'учётки', 'учёток')} без входа "
        f"{idle_days}+ дней, список от {_date(now_ts)}",
        "! Проверьте список перед применением. Пустая строка после каждой команды",
        "! подтверждает вопрос IOS [confirm].",
        "configure terminal",
    ]
    for c in entry["candidates"]:
        lines.append(f" no username {c['login']}")
        lines.append("")
    lines += ["end", "write memory"]
    return "\n".join(lines) + "\n"
