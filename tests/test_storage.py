import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpnmon.cisco import VpnSession, parse_cisco_age  # noqa: E402
from vpnmon.storage import ConnectionStatsStore, merge_duplicate_sessions  # noqa: E402

T0 = 1_760_000_000


def hms(seconds: int) -> str:
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def sess(login: str, age: str, ip: str = "1.2.3.4") -> VpnSession:
    return VpnSession("SSL_Context", login, ip, 1, age, "00:00:01")


class ParseAgeTest(unittest.TestCase):
    def test_formats(self):
        self.assertEqual(parse_cisco_age("03:21:20"), (12080, 1))
        self.assertEqual(parse_cisco_age("1d02h"), (93600, 3600))
        self.assertEqual(parse_cisco_age("2w3d"), (17 * 86400, 86400))
        self.assertIsNone(parse_cisco_age("garbage"))


class SnapshotTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = ConnectionStatsStore(Path(self.tmp.name) / "s.db")

    def tearDown(self):
        self.tmp.cleanup()

    def rows(self):
        with self.store._connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM session_events ORDER BY id")]

    def test_growing_created_is_one_session(self):
        # Session started 1h before T0; poll every 31 s for an hour.
        for i in range(120):
            now = T0 + i * 31
            diff = self.store.record_snapshot([sess("bob", hms(3600 + i * 31))], now_ts=now)
            self.assertEqual(len(diff.connected), 1 if i == 0 else 0)
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["first_seen_ts"], T0 - 3600)
        self.assertEqual(rows[0]["last_seen_ts"], T0 + 119 * 31)
        summary = {u["login"]: u for u in self.store.get_all_users_summary(days=30, now_ts=T0 + 4000)}
        self.assertEqual(summary["bob"]["connects_period"], 1)

    def test_reconnect_same_ip_is_new_session(self):
        self.store.record_snapshot([sess("bob", "00:10:00")], now_ts=T0)
        diff = self.store.record_snapshot([], now_ts=T0 + 30)
        self.assertEqual(len(diff.disconnected), 1)
        diff = self.store.record_snapshot([sess("bob", "00:00:05")], now_ts=T0 + 60)
        self.assertEqual(len(diff.connected), 1)
        self.assertEqual(len(self.rows()), 2)

    def test_reconnect_without_a_gap_poll_is_new_session(self):
        self.store.record_snapshot([sess("bob", "02:00:00")], now_ts=T0)
        diff = self.store.record_snapshot([sess("bob", "00:00:20")], now_ts=T0 + 30)
        self.assertEqual(len(diff.connected), 1)
        self.assertEqual(len(diff.disconnected), 1)

    def test_missed_poll_resumes_session(self):
        self.store.record_snapshot([sess("bob", "00:10:00")], now_ts=T0)
        self.store.record_snapshot([], now_ts=T0 + 30)  # router hiccup
        diff = self.store.record_snapshot([sess("bob", "00:11:00")], now_ts=T0 + 60)
        self.assertEqual(diff.connected, [])
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.rows()[0]["is_active"], 1)

    def test_two_parallel_sessions_same_ip(self):
        snap = lambda now, a, b: [sess("bob", hms(a)), sess("bob", hms(b))]
        self.store.record_snapshot(snap(T0, 600, 60), now_ts=T0)
        self.store.record_snapshot(snap(T0 + 30, 630, 90), now_ts=T0 + 30)
        self.assertEqual(len(self.rows()), 2)

    def test_coarse_age(self):
        self.store.record_snapshot([sess("bob", "1d02h")], now_ts=T0)
        self.store.record_snapshot([sess("bob", "1d02h")], now_ts=T0 + 1800)
        self.store.record_snapshot([sess("bob", "1d03h")], now_ts=T0 + 3000)
        self.assertEqual(len(self.rows()), 1)

    def test_concurrency(self):
        self.store.record_snapshot([sess("a", "00:00:00"), sess("b", "00:00:00", "5.5.5.5")], now_ts=T0)
        self.store.record_snapshot([sess("a", "00:30:00")], now_ts=T0 + 1800)
        buckets = self.store.get_concurrency(days=1, now_ts=T0 + 1800)
        self.assertEqual(max(b["peak"] for b in buckets), 2)


class MigrationTest(unittest.TestCase):
    def test_old_rows_are_merged(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "old.db"
            conn = sqlite3.connect(db)
            conn.execute(
                "CREATE TABLE session_events (id INTEGER PRIMARY KEY AUTOINCREMENT, login TEXT, "
                "context TEXT, ip TEXT, created_raw TEXT, country TEXT DEFAULT '', org TEXT DEFAULT '', "
                "peak_connections INTEGER DEFAULT 1, first_seen_ts INTEGER, last_seen_ts INTEGER, "
                "first_seen_iso TEXT, last_seen_iso TEXT, is_active INTEGER DEFAULT 1)"
            )
            # Old behaviour: a new row per poll, Created growing, only the last row active.
            for i in range(10):
                now = T0 + i * 31
                conn.execute(
                    "INSERT INTO session_events (login, context, ip, created_raw, country, "
                    "first_seen_ts, last_seen_ts, first_seen_iso, last_seen_iso, is_active) "
                    "VALUES ('bob','C','1.2.3.4',?,?,?,?,'x','x',?)",
                    (hms(1000 + i * 31), "KZ" if i == 3 else "", now, now, 1 if i == 9 else 0),
                )
            conn.commit()
            conn.close()

            store = ConnectionStatsStore(db)
            with store._connect() as c:
                rows = [dict(r) for r in c.execute("SELECT * FROM session_events")]
                from vpnmon.storage import SCHEMA_VERSION
                self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
                routers = [r[0] for r in c.execute("SELECT DISTINCT router FROM session_events")]
                self.assertEqual(routers, ["main"])
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["first_seen_ts"], T0 - 1000)
            self.assertEqual(rows[0]["last_seen_ts"], T0 + 9 * 31)
            self.assertEqual(rows[0]["is_active"], 1)
            self.assertEqual(rows[0]["country"], "KZ")
            self.assertTrue(list(Path(tmp).glob("old.db.before-v2-*.bak")))

    def test_interleaved_parallel_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "old.db"
            ConnectionStatsStore(db)  # create schema
            conn = sqlite3.connect(db)
            conn.execute("PRAGMA user_version = 0")
            for i in range(10):
                now = T0 + i * 31
                for age in (5000, 300):  # two sessions of one login from one IP
                    conn.execute(
                        "INSERT INTO session_events (login, context, ip, created_raw, first_seen_ts, "
                        "last_seen_ts, first_seen_iso, last_seen_iso, is_active) "
                        "VALUES ('bob','C','1.2.3.4',?,?,?,'x','x',0)",
                        (hms(age + i * 31), now, now),
                    )
            conn.commit()
            self.assertEqual(merge_duplicate_sessions(conn), (2, 18))
            conn.close()


if __name__ == "__main__":
    unittest.main()
