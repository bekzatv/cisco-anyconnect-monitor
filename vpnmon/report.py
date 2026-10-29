"""Weekly summary sent to Telegram: who worked, who never logged in, alerts, peak load."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from .cisco import is_outdated
from .cleanup import build_cleanup, plural
from .config import get_routers
from .storage import DEFAULT_UNSTABLE_PER_DAY, format_duration_hm

if TYPE_CHECKING:
    from .collector import Collector

log = logging.getLogger("vpnmon.report")

WEEKDAYS = ("понедельник", "вторник", "среда", "четверг", "пятница", "суббота", "воскресенье")
MAX_NAMES = 40


def _int(settings: dict, key: str, default: int) -> int:
    try:
        return int(settings.get(key, default))
    except (TypeError, ValueError):
        return default


def _names(items: list[str], limit: int = MAX_NAMES) -> str:
    shown = ", ".join(items[:limit])
    return shown + (f" и ещё {len(items) - limit}" if len(items) > limit else "")


def build_weekly_report(collector: "Collector", settings: dict, now_ts: int | None = None) -> str:
    store = collector.store
    now_ts = now_ts if now_ts is not None else int(time.time())
    since = now_ts - 7 * 86400
    d0, d1 = datetime.fromtimestamp(since), datetime.fromtimestamp(now_ts)
    lines = [f"📊 VPN: отчёт за неделю {d0:%d.%m} – {d1:%d.%m.%Y}"]

    snap = collector.snapshot()
    routers = [r for r in snap["routers"] if r["status"] != "disabled"]
    if len(routers) > 1:
        lines.append("Устройства: " + ", ".join(f"{r['name']} ({r['sessions']} сейчас)" for r in routers))

    stats = store.get_period_stats(since, now_ts)
    worked = [u for u in stats["users"] if u["seconds"] > 0]
    worked_keys = {u["login"].lower() for u in worked}
    total_seconds = sum(u["seconds"] for u in worked)
    admins = store.get_admin_logins()
    vpn_accounts = [k for k in stats["known"] if k.lower() not in admins or k.lower() in worked_keys]
    lines.append("")
    lines.append(f"👥 Работали: {len(worked)} из {len(vpn_accounts)} учёток, "
                 f"новых сессий: {stats['sessions_started']}, всего в сети: {format_duration_hm(total_seconds)}")
    if worked:
        top = [f"{i}. {u['login']} — {format_duration_hm(u['seconds'])}" for i, u in enumerate(worked[:10], 1)]
        lines.append("Больше всех в сети:\n" + "\n".join(top))

    never = [k for k in vpn_accounts if k.lower() not in worked_keys]
    if never:
        lines.append("")
        lines.append(f"💤 Ни разу не входили за неделю ({len(never)}): {_names(never)}")

    points = store.get_concurrency(days=7, bucket_seconds=3600, now_ts=now_ts)
    peak = max(points, key=lambda p: p["peak"], default=None)
    if peak and peak["peak"]:
        at = datetime.fromtimestamp(peak["ts"])
        lines.append("")
        lines.append(f"📈 Пик нагрузки: {peak['peak']} {plural(peak['peak'], 'сессия', 'сессии', 'сессий')} одновременно "
                     f"({peak['users']} польз.) — {WEEKDAYS[at.weekday()]}, {at:%d.%m %H:00}")

    alerts = store.get_events(limit=200, event_type="ALERT", since_ts=since, until_ts=now_ts)
    lines.append("")
    if alerts:
        lines.append(f"🚨 Тревоги ({len(alerts)}):")
        for e in alerts[:8]:
            lines.append(f"• {datetime.fromtimestamp(e['ts']):%d.%m %H:%M} {e['message']}")
        if len(alerts) > 8:
            lines.append(f"• … и ещё {len(alerts) - 8}")
    else:
        lines.append("🚨 Тревог не было")

    down = store.get_downtime(since, now_ts)
    if down["count"]:
        lines.append(f"⏸ Монитор не работал: {format_duration_hm(down['total_seconds'])} "
                     f"({down['count']} {plural(down['count'], 'раз', 'раза', 'раз')}) — "
                     f"статистика за эти часы неполная")
    errors = [e for e in store.get_events(limit=500, event_type="ERROR", since_ts=since, until_ts=now_ts)
              if "Ошибка опроса" in e["message"]]
    if errors:
        lines.append(f"⚠ Связь с роутером терялась: {len(errors)} {plural(len(errors), 'раз', 'раза', 'раз')}")

    summary = store.get_all_users_summary(
        days=7, now_ts=now_ts,
        unstable_per_day=_int(settings, "unstable_reconnects_per_day", DEFAULT_UNSTABLE_PER_DAY),
    )
    unstable = [u for u in summary if u["unstable"]]
    if unstable:
        lines.append("")
        lines.append("📶 Нестабильные подключения: " + ", ".join(
            f"{u['login']} ({u['reconnects_peak_day']}/день)" for u in unstable[:15]))

    minimum = str(settings.get("min_client_version", "4.10") or "")
    if minimum:
        old = [u for u in summary if u["client_version"] and is_outdated(u["client_version"], minimum)]
        if old:
            versions: dict[str, int] = {}
            for u in old:
                versions[u["client_version"]] = versions.get(u["client_version"], 0) + 1
            breakdown = ", ".join(f"{v} — {n}" for v, n in sorted(versions.items(), key=lambda x: -x[1]))
            lines.append(f"💻 Устаревший AnyConnect (< {minimum}): {len(old)} польз. ({breakdown})")

    idle_days = _int(settings, "cleanup_idle_days", 60)
    cleanup = build_cleanup(store, get_routers(settings), idle_days,
                            set(settings.get("cleanup_exclude") or []), now_ts=now_ts)
    candidates = sum(len(r["candidates"]) for r in cleanup["routers"])
    if candidates:
        lines.append(f"🗑 Кандидаты на удаление (без входа {idle_days}+ дн.): {candidates} — "
                     f"список и команды в панели, раздел «Учётки»")
    return "\n".join(lines)


def scheduled_time(settings: dict, now: datetime) -> datetime:
    """This week's send time (e.g. Monday 09:00)."""
    weekday = min(6, max(0, _int(settings, "weekly_report_weekday", 0)))
    hour = min(23, max(0, _int(settings, "weekly_report_hour", 9)))
    monday = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    return monday + timedelta(days=weekday, hours=hour)


def maybe_send_weekly_report(collector: "Collector", settings: dict, now: datetime | None = None) -> bool:
    """Send once per week after the scheduled time, also if the server was off at that moment."""
    if not settings.get("weekly_report_enabled", True):
        return False
    from .collector import TelegramNotifier

    if not TelegramNotifier.config(settings):
        return False
    now = now or datetime.now()
    due = scheduled_time(settings, now)
    if now < due:
        return False
    last = int(collector.store.get_meta("weekly_report_sent_ts", "0") or 0)
    if last >= int(due.timestamp()):
        return False
    collector.store.set_meta("weekly_report_sent_ts", str(int(now.timestamp())))
    text = build_weekly_report(collector, settings, now_ts=int(now.timestamp()))
    collector.telegram.send(settings, text)
    collector.event("INFO", "Еженедельный отчёт отправлен в Telegram")
    return True
