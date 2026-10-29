import json
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpnmon import config  # noqa: E402
from vpnmon.cisco import VpnSession  # noqa: E402
from vpnmon.cleanup import build_cleanup  # noqa: E402
from vpnmon.report import build_weekly_report, maybe_send_weekly_report  # noqa: E402
from vpnmon.storage import ConnectionStatsStore  # noqa: E402

T0 = 1_760_000_000
DAY = 86400


def sess(login, age="00:10:00", ip="1.2.3.4", ctx="C"):
    return VpnSession(ctx, login, ip, 1, age, "00:00:01")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.store = ConnectionStatsStore(self.dir / "s.db")

    def tearDown(self):
        self.tmp.cleanup()


class MultiRouterTest(Base):
    def test_routers_do_not_close_each_others_sessions(self):
        self.store.record_snapshot([sess("bob")], now_ts=T0, router="a")
        self.store.record_snapshot([sess("eve", ip="5.5.5.5")], now_ts=T0, router="b")
        diff = self.store.record_snapshot([], now_ts=T0 + 30, router="b")
        self.assertEqual([r["login"] for r in diff.disconnected], ["eve"])
        with self.store._connect() as c:
            active = {(r["router"], r["login"]) for r in c.execute(
                "SELECT router, login FROM session_events WHERE is_active = 1")}
        self.assertEqual(active, {("a", "bob")})

    def test_same_login_on_two_routers_is_two_sessions(self):
        self.store.record_snapshot([sess("bob")], now_ts=T0, router="a")
        diff = self.store.record_snapshot([sess("bob")], now_ts=T0, router="b")
        self.assertEqual(len(diff.connected), 1)
        summary = {u["login"]: u for u in self.store.get_all_users_summary(days=30, now_ts=T0 + 60)}
        self.assertEqual(summary["bob"]["routers"], ["a", "b"])


class ClientDetailsTest(Base):
    def test_details_are_stored_and_refreshed(self):
        self.store.record_snapshot([sess("bob")], now_ts=T0, router="a")
        pending = self.store.sessions_needing_details("a", refresh_before_ts=1)
        self.assertEqual([p["login"] for p in pending], ["bob"])
        info = {"agent": "AnyConnect Windows 4.4.01054", "os": "Windows", "version": "4.4.01054",
                "tunnel_ip": "10.0.0.5", "rx_packets": 100, "tx_packets": 50}
        self.assertEqual(self.store.update_client_details("a", "C", "bob", "1.2.3.4", info, now_ts=T0 + 5), 1)
        self.assertEqual(self.store.sessions_needing_details("a", refresh_before_ts=1), [])
        self.assertEqual(len(self.store.sessions_needing_details("a", refresh_before_ts=T0 + 600)), 1)
        d = self.store.get_active_details("a")[("C", "bob", "1.2.3.4")]
        self.assertEqual((d["client_version"], d["rx_packets"]), ("4.4.01054", 100))
        summary = {u["login"]: u for u in self.store.get_all_users_summary(days=30, now_ts=T0 + 60)}
        self.assertEqual(summary["bob"]["client_version"], "4.4.01054")

    def test_parallel_sessions_matched_by_created_time(self):
        self.store.record_snapshot([sess("bob", "02:00:00"), sess("bob", "00:01:00")], now_ts=T0, router="a")
        info = {"agent": "AnyConnect Windows 5.1.0.1", "os": "Windows", "version": "5.1.0.1"}
        self.store.update_client_details("a", "C", "bob", "1.2.3.4", info, created_ts=T0 - 60)
        with self.store._connect() as c:
            rows = {r["first_seen_ts"]: r["client_version"] for r in c.execute(
                "SELECT first_seen_ts, client_version FROM session_events")}
        self.assertEqual(rows, {T0 - 7200: "", T0 - 60: "5.1.0.1"})


class CleanupTest(Base):
    router = {"id": "a", "name": "Core", "host": "192.168.1.1", "username": "netadmin"}

    def setup_router(self, observed_since):
        # Monitoring started at `observed_since`; "used" logged in then, "gone" never.
        self.store.record_snapshot([sess("used")], now_ts=observed_since, router="a")
        self.store.record_snapshot([], now_ts=observed_since + 600, router="a")
        self.store.sync_router_users("a", [("used", 0), ("gone", 0), ("root", 15), ("netadmin", 15),
                                           ("svc", 0), ("fresh", 0)], now_ts=observed_since)

    def test_never_seen_users_wait_for_the_observation_window(self):
        self.setup_router(T0)
        res = build_cleanup(self.store, [self.router], idle_days=60, exclude=set(), now_ts=T0 + 10 * DAY)
        r = res["routers"][0]
        self.assertEqual(r["candidates"], [])
        self.assertEqual(r["observed_days"], 10)
        reasons = {x["login"]: x["reason"] for x in r["excluded"]}
        self.assertIn("администратор", reasons["root"])
        self.assertIn("администратор", reasons["netadmin"])

    def test_candidates_after_window_with_exclusions_and_commands(self):
        self.setup_router(T0)
        # A user added to the router recently must not be proposed.
        self.store.sync_router_users("a", [("used", 0), ("gone", 0), ("root", 15), ("netadmin", 15),
                                           ("svc", 0), ("fresh", 0), ("newbie", 0)], now_ts=T0 + 55 * DAY)
        res = build_cleanup(self.store, [self.router], idle_days=60, exclude={"SVC"}, now_ts=T0 + 70 * DAY)
        r = res["routers"][0]
        logins = [c["login"] for c in r["candidates"]]
        self.assertEqual(sorted(logins), ["fresh", "gone", "used"])
        self.assertNotIn("newbie", logins)
        self.assertIn("svc", {x["login"] for x in r["excluded"]})
        used = next(c for c in r["candidates"] if c["login"] == "used")
        self.assertFalse(used["never"])
        cmds = r["commands"].splitlines()
        self.assertEqual(cmds[3], "configure terminal")
        self.assertIn(" no username gone", cmds)
        self.assertEqual(cmds[cmds.index(" no username gone") + 1], "")  # answers [confirm]
        self.assertEqual(cmds[-2:], ["end", "write memory"])
        self.assertNotIn("root", r["commands"])

    def test_resync_removes_deleted_users(self):
        self.setup_router(T0)
        res = self.store.sync_router_users("a", [("used", 0)], now_ts=T0 + DAY)
        self.assertEqual(res["removed"], 5)
        users, _ = self.store.get_router_user_activity("a")
        self.assertEqual([u["login"] for u in users], ["used"])


class FakeCollector:
    def __init__(self, store):
        self.store = store
        self.sent = []
        self.events = []
        self.telegram = mock.Mock()
        self.telegram.send.side_effect = lambda settings, text: self.sent.append(text)

    def snapshot(self):
        return {"routers": [{"name": "Core", "status": "ok", "sessions": 1}]}

    def event(self, *args, **kwargs):
        self.events.append(args)


class ReportTest(Base):
    def test_report_sections(self):
        now = T0 + 7 * DAY
        self.store.register_known_users(["bob", "idle1"], now_ts=T0)
        self.store.sync_router_users("main", [("bob", 0), ("idle1", 0), ("root", 15)], now_ts=T0)
        self.store.record_snapshot([sess("bob", "00:00:00")], now_ts=now - 3 * 3600, router="main")
        self.store.record_snapshot([sess("bob", "03:00:00")], now_ts=now, router="main")
        self.store.add_event("ALERT", "Логин 'x' одновременно подключён с 2 IP", now_ts=now - 100)
        self.store.update_client_details("main", "C", "bob", "1.2.3.4",
                                         {"agent": "AnyConnect Windows 4.4.01054", "os": "Windows", "version": "4.4.01054"})
        text = build_weekly_report(FakeCollector(self.store), {"min_client_version": "4.10"}, now_ts=now)
        self.assertIn("Работали: 1 из 2", text)
        self.assertIn("bob — 3ч 00м", text)
        self.assertIn("Ни разу не входили за неделю (1): idle1", text)  # root (privilege 15) is left out
        self.assertIn("Тревоги (1)", text)
        self.assertIn("Пик нагрузки: 1", text)
        self.assertIn("Устаревший AnyConnect (< 4.10): 1", text)

    def test_schedule_sends_once_per_week(self):
        fc = FakeCollector(self.store)
        settings = {"weekly_report_enabled": True, "telegram_enabled": True, "telegram_chat_id": "1",
                    "telegram_token_encoded": config.encode_password("t"),
                    "weekly_report_weekday": 0, "weekly_report_hour": 9}
        monday_8 = datetime(2026, 10, 26, 8, 0)
        self.assertFalse(maybe_send_weekly_report(fc, settings, now=monday_8))
        self.assertTrue(maybe_send_weekly_report(fc, settings, now=monday_8.replace(hour=9, minute=1)))
        self.assertFalse(maybe_send_weekly_report(fc, settings, now=monday_8.replace(hour=15)))
        # The server was off on Monday morning: it catches up on Tuesday.
        self.assertTrue(maybe_send_weekly_report(fc, settings, now=datetime(2026, 11, 3, 11, 0)))
        self.assertEqual(len(fc.sent), 2)
        self.assertFalse(maybe_send_weekly_report(fc, settings | {"telegram_enabled": False},
                                                  now=datetime(2026, 11, 10, 10, 0)))


class RouterSettingsTest(unittest.TestCase):
    def test_legacy_settings_become_router_main_and_mirror_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            path.write_text(json.dumps({"host": "192.168.1.1", "port": 22, "username": "adm",
                                        "password_encoded": config.encode_password("pw"),
                                        "dark_mode": True}), encoding="utf-8")
            with mock.patch.object(config, "SETTINGS_FILE", path):
                routers = config.get_routers()
                self.assertEqual([(r["id"], r["host"]) for r in routers], [("main", "192.168.1.1")])
                self.assertEqual(config.router_creds(routers[0])[3], "pw")
                second = dict(routers[0], id="r2", name="Branch", host="10.0.0.2")
                config.save_routers([dict(routers[0], host="10.0.0.9"), second])
                saved = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(saved["host"], "10.0.0.9")  # desktop app keeps working
                self.assertTrue(saved["dark_mode"])
                self.assertEqual([r["id"] for r in config.get_routers()], ["main", "r2"])


class TlsTest(unittest.TestCase):
    def test_self_signed_certificate(self):
        from vpnmon import tls

        with tempfile.TemporaryDirectory() as tmp:
            cert, key = tls.ensure_certificate(Path(tmp) / "c.pem", Path(tmp) / "k.pem")
            info = tls.certificate_info(cert)
            self.assertEqual(len(info["sha256"].split(":")), 32)
            tls.server_context(cert, key)  # loads without error


if __name__ == "__main__":
    unittest.main()
