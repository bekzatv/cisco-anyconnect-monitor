import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpnmon import config  # noqa: E402
from vpnmon.bundle import export_bundle, import_bundle  # noqa: E402
from vpnmon.cisco import VpnSession  # noqa: E402
from vpnmon.collector import Collector  # noqa: E402
from vpnmon.storage import ConnectionStatsStore  # noqa: E402

T0 = 1_760_000_000


class BundleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pc = Path(self.tmp.name) / "pc"
        self.server = Path(self.tmp.name) / "server"
        self.pc.mkdir()
        store = ConnectionStatsStore(self.pc / "connection_stats.db")
        store.record_snapshot([VpnSession("C", "bob", "1.2.3.4", 1, "00:10:00", "00:00:01")], now_ts=T0)
        (self.pc / "known_hosts").write_text("192.168.1.1 ssh-rsa AAAA\n", encoding="utf-8")
        (self.pc / "settings.json").write_text(json.dumps({
            "host": "192.168.1.1", "port": 22, "username": "adm",
            "password_encoded": config.encode_password("secret"),
            "telegram_token_encoded": config.encode_password("tok"), "telegram_chat_id": "42",
            "web_admin_password_hash": "pbkdf2_sha256$1$aa$bb", "refresh_seconds": 15,
        }), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_roundtrip_without_secrets(self):
        zip_path = Path(self.tmp.name) / "move.zip"
        manifest = export_bundle(zip_path, data_dir=self.pc)
        self.assertEqual(manifest["sessions"], 1)
        self.assertIn("токен Telegram", manifest["needs_reentry"])
        with zipfile.ZipFile(zip_path) as z:
            blob = b"".join(z.read(n) for n in z.namelist() if n != "connection_stats.db")
        self.assertNotIn(b"dpapi:", blob)
        self.assertNotIn(b"b64:", blob)

        result = import_bundle(zip_path, data_dir=self.server, lan=True, port=8443)
        self.assertEqual(result["sessions_imported"], 1)
        s = json.loads((self.server / "settings.json").read_text(encoding="utf-8"))
        self.assertEqual(s["routers"][0]["host"], "192.168.1.1")
        self.assertNotIn("password_encoded", s["routers"][0])
        self.assertNotIn("password_encoded", s)
        self.assertEqual(s["web_admin_password_hash"], "pbkdf2_sha256$1$aa$bb")
        self.assertEqual((s["web_bind"], s["web_https"], s["web_port"], s["refresh_seconds"]), ("0.0.0.0", True, 8443, 15))
        self.assertTrue((self.server / "known_hosts").read_text(encoding="utf-8").startswith("192.168.1.1"))
        # A router without a password waits for it instead of polling with nothing.
        with mock.patch.object(config, "SETTINGS_FILE", self.server / "settings.json"):
            router = config.get_routers()[0]
        self.assertEqual(config.router_creds(router)[3], "")

    def test_import_refuses_to_overwrite_without_force(self):
        zip_path = Path(self.tmp.name) / "move.zip"
        export_bundle(zip_path, data_dir=self.pc)
        import_bundle(zip_path, data_dir=self.server)
        with self.assertRaises(RuntimeError):
            import_bundle(zip_path, data_dir=self.server)
        import_bundle(zip_path, data_dir=self.server, force=True)
        self.assertTrue(list(self.server.glob("connection_stats.db.before-import-*")))

    def test_rejects_foreign_zip(self):
        bad = Path(self.tmp.name) / "bad.zip"
        with zipfile.ZipFile(bad, "w") as z:
            z.writestr("../evil.txt", "x")
        with self.assertRaises(RuntimeError):
            import_bundle(bad, data_dir=self.server)
        self.assertFalse((Path(self.tmp.name) / "evil.txt").exists())


class DowntimeTest(unittest.TestCase):
    def test_gap_is_recorded_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ConnectionStatsStore(Path(tmp) / "s.db")
            c = Collector(store)
            with mock.patch("vpnmon.collector.load_settings", return_value={}), \
                    mock.patch("vpnmon.collector.HISTORY_LOG_FILE", Path(tmp) / "h.log"):
                self.assertIsNone(c.check_downtime(now=T0))  # first ever start: nothing to compare
                store.set_meta("heartbeat_ts", str(T0))
                self.assertIsNone(c.check_downtime(now=T0 + 120))  # quick restart is not downtime
                store.set_meta("heartbeat_ts", str(T0))
                self.assertEqual(c.check_downtime(now=T0 + 4 * 3600), (T0, T0 + 4 * 3600))
            down = store.get_downtime(T0 - 3600, T0 + 5 * 3600)
            self.assertEqual((down["count"], down["total_seconds"]), (1, 4 * 3600))
            self.assertEqual(store.get_downtime(T0 + 3600, T0 + 2 * 3600)["total_seconds"], 3600)  # clipped
            self.assertEqual([e["type"] for e in store.get_events(event_type="GAP")], ["GAP"])


if __name__ == "__main__":
    unittest.main()
