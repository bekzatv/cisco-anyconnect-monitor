import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpnmon.cisco import parse_show_version  # noqa: E402
from vpnmon.collector import Collector, RouterPoller  # noqa: E402
from vpnmon.server import find_account, hash_password, web_users_list  # noqa: E402
from vpnmon.storage import ConnectionStatsStore  # noqa: E402
from vpnmon.syslog import FailureCounter, classify, is_ignored, mask_secrets, parse_syslog  # noqa: E402

T0 = 1_760_000_000

SHOW_VERSION = """Cisco IOS Software, C2951 Software (C2951-UNIVERSALK9-M), Version 15.7(3)M4b, RELEASE SOFTWARE (fc1)
ROM: System Bootstrap, Version 15.0(1r)M6, RELEASE SOFTWARE (fc1)
CORE-RTR uptime is 1 week, 2 days, 4 hours, 32 minutes
System returned to ROM by power-on
Last reload reason: power-on
Cisco CISCO2951/K9 (revision 1.1) with 1001472K/47104K bytes of memory.
"""


def pkt(text: str, pri: int = 190) -> bytes:
    return f"<{pri}>{text}".encode()


class SyslogParseTest(unittest.TestCase):
    def test_cisco_message(self):
        m = parse_syslog(pkt("2008: Oct 28 08:23:22.157: %LINEPROTO-5-UPDOWN: Line protocol on Interface "
                             "GigabitEthernet0/1, changed state to down"), "192.168.1.1", now=T0)
        self.assertEqual((m.code, m.severity, m.source_ip), ("LINEPROTO-5-UPDOWN", 5, "192.168.1.1"))
        c = classify(m)
        self.assertEqual(c.kind, "iface_down")
        self.assertTrue(c.summary.startswith("Интерфейс GigabitEthernet0/1 упал"), c.summary)

    def test_vpn_tunnel_flaps_are_not_outages(self):
        m = parse_syslog(pkt("%LINEPROTO-5-UPDOWN: Line protocol on Interface Virtual-Access6, changed state to down"),
                         "192.168.1.1")
        self.assertEqual(classify(m).kind, "")

    def test_config_change_and_logged_command(self):
        m = parse_syslog(pkt("%SYS-5-CONFIG_I: Configured from console by netadmin on vty0 (192.168.10.5)"), "192.168.1.1")
        c = classify(m)
        self.assertEqual((c.kind, c.login, c.ip), ("config", "netadmin", "192.168.10.5"))
        m = parse_syslog(pkt("%PARSER-5-CFGLOG_LOGGEDCMD: User:netadmin  logged command:username bob secret 9 $9$abcdef"),
                         "192.168.1.1")
        c = classify(m)
        self.assertEqual((c.kind, c.login), ("config_cmd", "netadmin"))
        self.assertNotIn("$9$abcdef", m.text)
        self.assertNotIn("$9$abcdef", m.raw)
        self.assertIn("secret ***", c.summary)

    def test_restart_and_auth_failures(self):
        self.assertEqual(classify(parse_syslog(pkt("%SYS-5-RESTART: System restarted --"), "x")).kind, "restart")
        m = parse_syslog(pkt("%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 1.2.3.4] [localport: 22]"), "x")
        c = classify(m)
        self.assertEqual((c.kind, c.login, c.ip), ("login_fail", "admin", "1.2.3.4"))
        m = parse_syslog(pkt("%SSLVPN-5-LOGIN_AUTH_REJECTED: Failed to authenticate user ivanov from 5.6.7.8"), "x")
        c = classify(m)
        self.assertEqual((c.kind, c.login, c.ip), ("auth_fail", "ivanov", "5.6.7.8"))

    def test_mask_and_ignore(self):
        self.assertEqual(mask_secrets("snmp-server community S3cr3t RO"), "snmp-server community *** RO")
        m = parse_syslog(pkt("%IPPHONE-6-REGISTER: ephone-12 IP:10.1.1.5 has registered."), "x")
        self.assertTrue(is_ignored(m, ["IPPHONE-6-"]))
        self.assertFalse(is_ignored(m, []))

    def test_failure_counter_trips_once_per_window(self):
        fc = FailureCounter(window=600)
        hits = [fc.add("bob", T0 + i, 5) for i in range(8)]
        self.assertEqual([h is not None for h in hits], [False] * 4 + [True] + [False] * 3)
        self.assertIsNotNone(fc.add("bob", T0 + 700, 1))


class CollectorSyslogTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = ConnectionStatsStore(Path(self.tmp.name) / "s.db")
        self.c = Collector(self.store)
        self.sent = []
        self.c.telegram.send = lambda settings, text: self.sent.append(text)
        self.patches = [
            mock.patch("vpnmon.collector.load_settings", return_value={"syslog_auth_fail_threshold": 3}),
            mock.patch("vpnmon.collector.HISTORY_LOG_FILE", Path(self.tmp.name) / "h.log"),
        ]
        for p in self.patches:
            p.start()
        poller = RouterPoller(self.c, {"id": "main", "name": "Core", "host": "192.168.1.1", "port": 22,
                                       "username": "a", "password_encoded": "", "enabled": True})
        self.c.pollers["main"] = poller

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def feed(self, text, ip="192.168.1.1"):
        self.c.handle_syslog(parse_syslog(pkt(text), ip, now=int(time.time())))

    def test_pipeline(self):
        self.feed("%IPPHONE-6-REGISTER: ephone-1 has registered.")
        self.feed("%PARSER-5-CFGLOG_LOGGEDCMD: User:netadmin  logged command:interface Gi0/1")
        self.feed("%PARSER-5-CFGLOG_LOGGEDCMD: User:netadmin  logged command:shutdown")
        self.feed("%SYS-5-CONFIG_I: Configured from console by netadmin on vty0 (192.168.10.5)")
        self.feed("%SYS-5-RESTART: System restarted --")
        for _ in range(3):
            self.feed("%SSLVPN-5-LOGIN_AUTH_REJECTED: Failed to authenticate user ivanov from 5.6.7.8")
        self.feed("%LINK-3-UPDOWN: Interface Dialer1, changed state to down", ip="10.9.9.9")

        rows = self.store.get_syslog(limit=50)
        self.assertNotIn("IPPHONE-6-REGISTER", [r["code"] for r in rows])  # dropped as noise
        self.assertEqual(rows[-1]["router"], "main")
        self.assertEqual(rows[0]["router"], "")  # unknown source keeps its IP
        alerts = [e["message"] for e in self.store.get_events(event_type="ALERT")]
        self.assertTrue(any("перезагрузился" in a for a in alerts))
        self.assertTrue(any("3 неудачных попыток входа в VPN" in a and "ivanov" in a for a in alerts))
        self.assertTrue(any("Dialer1" in a for a in alerts))
        config_msg = next(t for t in self.sent if "Конфигурация изменена" in t)
        self.assertIn("netadmin", config_msg)
        self.assertIn("• interface Gi0/1", config_msg)
        self.assertIn("• shutdown", config_msg)
        self.assertEqual(len([e for e in self.store.get_events(event_type="CONFIG")]), 3)


class VersionTest(unittest.TestCase):
    def test_parse_show_version(self):
        v = parse_show_version(SHOW_VERSION)
        self.assertEqual(v["uptime_seconds"], 9 * 86400 + 4 * 3600 + 32 * 60)
        self.assertEqual((v["ios_version"], v["model"], v["reload_reason"]), ("15.7(3)M4b", "CISCO2951/K9", "power-on"))

    def test_reboot_detected_from_uptime(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ConnectionStatsStore(Path(tmp) / "s.db")
            c = Collector(store)
            c.telegram.send = lambda *a: None
            p = RouterPoller(c, {"id": "main", "name": "Core", "host": "192.168.1.1", "port": 22,
                                 "username": "a", "password_encoded": "", "enabled": True})
            with mock.patch("vpnmon.collector.HISTORY_LOG_FILE", Path(tmp) / "h.log"):
                p.conn.run = lambda *a, **k: SHOW_VERSION
                p.check_version({})
                p.check_version({})  # same boot: nothing
                self.assertEqual(store.get_events(event_type="ALERT"), [])
                p.conn.run = lambda *a, **k: SHOW_VERSION.replace("1 week, 2 days, 4 hours, 32 minutes", "3 minutes")
                p.check_version({})
            alerts = store.get_events(event_type="ALERT")
            self.assertEqual(len(alerts), 1)
            self.assertIn("перезагружался", alerts[0]["message"])
            self.assertIn("power-on", alerts[0]["message"])


class AccountsTest(unittest.TestCase):
    def test_builtin_admin_and_extra_users(self):
        settings = {
            "web_admin_password_hash": hash_password("adminpass"),
            "web_users": [{"login": "ivan", "hash": hash_password("viewpass1"), "role": "viewer"},
                          {"login": "bad", "role": "viewer"}],  # no hash: ignored
        }
        self.assertEqual(find_account(settings, "admin")["role"], "admin")
        self.assertEqual(find_account(settings, "IVAN")["role"], "viewer")
        self.assertIsNone(find_account(settings, "bad"))
        self.assertEqual([u["login"] for u in web_users_list(settings)], ["ivan"])
        self.assertIsNone(find_account({}, "admin"))


if __name__ == "__main__":
    unittest.main()
