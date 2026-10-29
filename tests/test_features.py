import socket
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpnmon.cisco import VpnSession  # noqa: E402
from vpnmon.instance import ExclusiveHTTPServer, acquire_single_instance  # noqa: E402
from vpnmon.storage import ConnectionStatsStore  # noqa: E402

T0 = 1_760_000_000


def hms(seconds: int) -> str:
    h, rem = divmod(seconds, 3600)
    return f"{h:02d}:{rem // 60:02d}:{rem % 60:02d}"


class StoreCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.store = ConnectionStatsStore(self.dir / "s.db")

    def tearDown(self):
        self.tmp.cleanup()

    def session(self, login: str, start: int, end: int, ip: str = "1.2.3.4"):
        """Record a session seen from `start` to `end` with 30 s polls."""
        for now in range(start, end + 1, 30):
            self.store.record_snapshot([VpnSession("C", login, ip, 1, hms(now - start), "00:00:01")], now_ts=now)
        self.store.record_snapshot([], now_ts=end + 30)


class ReconnectTest(StoreCase):
    def test_flaky_user_is_unstable(self):
        t = T0
        for _ in range(4):  # 4 short sessions, 1 minute apart
            self.session("flaky", t, t + 300)
            t += 300 + 90
        self.session("steady", T0, T0 + 8 * 3600, ip="5.5.5.5")
        rows = {u["login"]: u for u in self.store.get_all_users_summary(days=30, now_ts=T0 + 9 * 3600)}
        self.assertEqual(rows["flaky"]["reconnects"], 3)
        self.assertTrue(rows["flaky"]["unstable"])
        self.assertEqual(rows["steady"]["reconnects"], 0)
        self.assertFalse(rows["steady"]["unstable"])
        history = self.store.get_user_sessions_history("flaky", days=30, now_ts=T0 + 9 * 3600)
        self.assertEqual([h["reconnect"] for h in history], [True, True, True, False])

    def test_long_break_and_parallel_device_are_not_reconnects(self):
        self.session("bob", T0, T0 + 600)
        self.session("bob", T0 + 600 + 3600, T0 + 600 + 7200)  # back after an hour
        self.session("bob", T0 + 4200 + 1800, T0 + 4200 + 2400, ip="9.9.9.9")  # second device, overlaps
        rows = {u["login"]: u for u in self.store.get_all_users_summary(days=30, now_ts=T0 + 9000)}
        self.assertEqual(rows["bob"]["reconnects"], 0)

    def test_threshold(self):
        t = T0
        for _ in range(3):
            self.session("flaky", t, t + 300)
            t += 360
        rows = {u["login"]: u for u in self.store.get_all_users_summary(days=30, now_ts=t, unstable_per_day=3)}
        self.assertEqual(rows["flaky"]["reconnects"], 2)
        self.assertFalse(rows["flaky"]["unstable"])


class BackupTest(StoreCase):
    def test_daily_backup_and_rotation(self):
        self.session("bob", T0, T0 + 120)
        backups = self.dir / "backups"
        for day in range(1, 10):
            self.store.daily_backup(backups, keep=7, today=f"2026-10-{day:02d}")
        names = [b["name"] for b in self.store.list_backups(backups)]
        self.assertEqual(len(names), 7)
        self.assertEqual(names[0], "connection_stats-2026-10-09.db")
        self.assertNotIn("connection_stats-2026-10-02.db", names)
        # Second call on the same day doesn't rewrite.
        self.assertIsNone(self.store.daily_backup(backups, keep=7, today="2026-10-09"))
        copy = ConnectionStatsStore(backups / names[0])
        self.assertEqual(len(copy.get_user_sessions_history("bob", days=0)), 1)

    def test_keep_zero_disables(self):
        self.assertIsNone(self.store.daily_backup(self.dir / "b", keep=0))
        self.assertFalse((self.dir / "b").exists())


class SingleInstanceTest(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "named mutex is Windows-only")
    def test_mutex_and_exclusive_port(self):
        self.assertTrue(acquire_single_instance("VpnMonTest"))
        self.assertFalse(acquire_single_instance("VpnMonTest"))
        first = ExclusiveHTTPServer(("127.0.0.1", 0), None)
        try:
            port = first.server_address[1]
            with self.assertRaises(OSError):
                ExclusiveHTTPServer(("127.0.0.1", port), None)
        finally:
            first.server_close()


if __name__ == "__main__":
    unittest.main()
