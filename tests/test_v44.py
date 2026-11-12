"""4.4: router configuration history, employee directory with access end dates, pool and license usage."""

import sys
import tempfile
import time
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpnmon.cisco import VpnSession  # noqa: E402
from vpnmon.cleanup import build_cleanup  # noqa: E402
from vpnmon.collector import Collector, RouterPoller, parse_date  # noqa: E402
from vpnmon.routercfg import (  # noqa: E402
    ConfigUnavailable,
    config_diff,
    config_hash,
    diff_counts,
    extract_config,
    mask_line,
    parse_ip_local_pools,
    parse_sslvpn_license,
    vpn_pool_names,
)
from vpnmon.server import parse_directory_csv  # noqa: E402
from vpnmon.storage import ConnectionStatsStore  # noqa: E402
from vpnmon.syslog import parse_syslog  # noqa: E402

T0 = 1_760_000_000
DAY = 86400

CONFIG = """show running-config\r
Building configuration...\r
\r
Current configuration : 2048 bytes\r
!\r
! Last configuration change at 10:15:02 ALM Tue Nov 11 2026 by netadmin\r
!\r
version 15.7\r
hostname CORE-RTR\r
!\r
enable secret 9 $9$enablehash\r
username ivanov privilege 0 secret 9 $9$ivanovhash\r
username netadmin privilege 15 secret 9 $9$adminhash\r
!\r
ip local pool SSLVPN_POOL 10.0.251.1 10.0.251.50\r
ip local pool LAN 192.168.50.1 192.168.50.20\r
snmp-server community s3cret RO\r
ntp clock-period 17179869\r
webvpn context SSL_Context\r
 policy group SSL_Policy\r
  svc address-pool "SSLVPN_POOL" netmask 255.255.255.0\r
!\r
end\r
\r
CORE-RTR#"""

POOLS = """ Pool                     Begin           End             Free  In use   Blocked
 SSLVPN_POOL              10.0.251.1      10.0.251.50       10      40         0
                          10.0.252.1      10.0.252.50       45       5         0
 LAN                      192.168.50.1    192.168.50.20     12       8         0
CORE-RTR#"""

LICENSE = """Index 1 Feature: ipbasek9
        Period left: Life time
Index 5 Feature: SSL_VPN
        Period left: Life time
        License Type: Permanent
        License State: Active, In Use
        License Count: 25/7/0  (Active/In-use/Violation)
        License Priority: Medium
Index 6 Feature: ios-ips-update
"""


def router(rid="main", **extra):
    return {"id": rid, "name": "Core", "host": "192.168.1.1", "port": 22, "username": "monitor",
            "password_encoded": "x", "enabled": True} | extra


class ParseTest(unittest.TestCase):
    def test_extract_config_drops_noise_and_volatile_lines(self):
        text = extract_config(CONFIG)
        self.assertTrue(text.startswith("!\n!\nversion 15.7"), text[:40])
        self.assertTrue(text.endswith("end\n"))
        self.assertNotIn("Last configuration change", text)
        self.assertNotIn("clock-period", text)
        self.assertNotIn("CORE-RTR#", text)
        # The same configuration read at another time gives the same hash.
        later = CONFIG.replace("10:15:02", "23:59:59")
        self.assertEqual(config_hash(extract_config(later)), config_hash(text))

    def test_refused_or_cut_output_is_not_stored(self):
        with self.assertRaises(ConfigUnavailable):
            extract_config("show running-config\r\n              ^\r\n% Invalid input detected at '^' marker.\r\nR#")
        with self.assertRaises(ConfigUnavailable):
            extract_config(CONFIG.split("webvpn")[0])  # no "end": the reply was cut short

    def test_secrets_are_masked(self):
        cases = {
            "username ivanov privilege 0 secret 9 $9$abc": "username ivanov privilege 0 secret 9 <скрыто>",
            "enable secret 5 $1$xyz": "enable secret 5 <скрыто>",
            "snmp-server community public RO": "snmp-server community <скрыто> RO",
            "crypto isakmp key 6 Sup3r address 1.2.3.4": "crypto isakmp key 6 <скрыто> address 1.2.3.4",
            "ntp authentication-key 1 md5 0822455D0A16 7": "ntp authentication-key 1 md5 <скрыто> 7",
            " key-string 7 0822455D0A16": " key-string 7 <скрыто>",
        }
        for line, want in cases.items():
            self.assertEqual(mask_line(line), want)
        for line in ("service password-encryption", "key chain EIGRP", "password encryption aes",
                     "crypto pki trustpoint TP-self", " rsakeypair TP-key"):
            self.assertEqual(mask_line(line), line)

    def test_diff_shows_changed_password_without_the_value(self):
        old = extract_config(CONFIG)
        new = old.replace("$9$ivanovhash", "$9$newhash").replace("username netadmin", "username petrov privilege 0 "
                                                                   "secret 9 $9$p\nusername netadmin")
        diff = config_diff(old, new)
        self.assertIn("-username ivanov privilege 0 secret 9 <скрыто>", diff)
        self.assertIn("+username ivanov privilege 0 secret 9 <скрыто>", diff)
        self.assertIn("+username petrov privilege 0 secret 9 <скрыто>", diff)
        self.assertFalse(any("hash" in line or "$9$" in line for line in diff))
        self.assertEqual(diff_counts(old, new), (2, 1))

    def test_vpn_pools_and_pool_usage(self):
        self.assertEqual(vpn_pool_names(extract_config(CONFIG)), {"SSLVPN_POOL"})
        pools = {p["name"]: p for p in parse_ip_local_pools(POOLS)}
        self.assertEqual((pools["SSLVPN_POOL"]["total"], pools["SSLVPN_POOL"]["in_use"]), (100, 45))
        self.assertEqual(pools["SSLVPN_POOL"]["percent"], 45)
        self.assertEqual(len(pools["SSLVPN_POOL"]["ranges"]), 2)
        self.assertEqual(pools["LAN"]["percent"], 40)

    def test_license(self):
        self.assertEqual(parse_sslvpn_license(LICENSE), {"limit": 25, "in_use": 7, "state": "Active, In Use"})
        self.assertIsNone(parse_sslvpn_license("Index 1 Feature: ipbasek9\n  License Count: Non-Counted"))

    def test_directory_csv(self):
        rows = parse_directory_csv("﻿Логин;ФИО;Отдел;Доступ до\nivanov;Иванов И.;Бухгалтерия;31.12.2026\n;x;y;\n")
        self.assertEqual(rows, [{"login": "ivanov", "full_name": "Иванов И.", "department": "Бухгалтерия",
                                 "expires": "31.12.2026"}])
        rows = parse_directory_csv("petrov\tПетров\tИТ\t+7 701\tподрядчик\t2026-11-30")
        self.assertEqual(rows[0]["comment"], "подрядчик")
        self.assertEqual(parse_date(rows[0]["expires"]), parse_date("30.11.2026"))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = ConnectionStatsStore(Path(self.tmp.name) / "s.db")
        self.c = Collector(self.store)
        self.sent = []
        self.c.telegram.send = lambda settings, text: self.sent.append(text)
        self.log_patch = mock.patch("vpnmon.collector.HISTORY_LOG_FILE", Path(self.tmp.name) / "h.log")
        self.log_patch.start()

    def tearDown(self):
        self.log_patch.stop()
        self.tmp.cleanup()

    def poller(self, outputs: dict, **extra) -> RouterPoller:
        p = RouterPoller(self.c, router(**extra))
        p.conn.run = lambda creds, func, cmd, **kw: outputs.get(cmd, "")
        self.c.pollers[p.id] = p
        return p


class ConfigBackupTest(Base):
    def test_versions_are_kept_only_on_change(self):
        outputs = {"show running-config": CONFIG}
        p = self.poller(outputs)
        p.periodic_checks({}, now=T0)  # first copy
        p.periodic_checks({}, now=T0 + 3600)  # not due yet
        p.periodic_checks({}, now=T0 + DAY)  # daily check, nothing changed
        self.assertEqual(len(self.store.list_router_configs("main")), 1)

        outputs["show running-config"] = CONFIG.replace("hostname CORE-RTR", "hostname CORE-RTR\r\nip domain name corp.local")
        p.request_config_backup("netadmin")
        p._config_due_ts = T0 + DAY + 10
        p.periodic_checks({}, now=T0 + DAY + 20)
        versions = self.store.list_router_configs("main")
        self.assertEqual(len(versions), 2)
        self.assertEqual((versions[0]["reason"], versions[0]["changed_by"]), ("изменение конфигурации", "netadmin"))
        self.assertEqual((versions[0]["added"], versions[0]["removed"]), (1, 0))
        self.assertTrue(any("+ip domain name corp.local" in t for t in self.sent))
        events = [e["message"] for e in self.store.get_events(event_type="CONFIG")]
        self.assertTrue(any("первая копия" in m for m in events))
        self.assertTrue(any("изменилась (изменил netadmin): +1 −0" in m for m in events))
        prev = self.store.previous_router_config(versions[0]["id"])
        self.assertEqual(prev["id"], versions[1]["id"])

    def test_failure_is_logged_once_and_retried_later(self):
        p = self.poller({"show running-config": "show running-config\r\n% Invalid input detected\r\nR#"})
        p.periodic_checks({}, now=T0)
        p.periodic_checks({}, now=T0 + 60)  # waits for the retry time
        self.assertIn("privilege 15", p.config_error)
        self.assertEqual(len(self.store.get_events(event_type="ERROR")), 1)
        self.assertEqual(self.store.list_router_configs(), [])

    def test_keep_limit(self):
        for i in range(5):
            self.store.add_router_config("main", f"v{i}\n", f"sha{i}", now_ts=T0 + i, keep=3)
        self.assertEqual([v["sha"] for v in self.store.list_router_configs("main")], ["sha4", "sha3", "sha2"])

    def test_syslog_config_message_schedules_a_copy(self):
        p = self.poller({})
        with mock.patch("vpnmon.collector.load_settings", return_value={}):
            self.c.handle_syslog(parse_syslog(
                b"<189>%SYS-5-CONFIG_I: Configured from console by netadmin on vty0 (192.168.10.5)",
                "192.168.1.1", now=int(time.time())))
        self.assertGreater(p._config_due_ts, 0)
        self.assertEqual(p._config_by, ["netadmin"])


class CapacityTest(Base):
    def test_pool_and_license_alerts_once_with_hysteresis(self):
        outputs = {"show running-config": CONFIG, "show ip local pool": POOLS, "show license": LICENSE}
        p = self.poller(outputs)
        settings = {"pool_alert_percent": 40}
        p.periodic_checks(settings, now=T0)
        cap = p.capacity()
        self.assertEqual([x["name"] for x in cap["pools"]], ["SSLVPN_POOL"])  # LAN pool is not for VPN
        self.assertEqual(cap["license"], {"limit": 25, "used": 0, "percent": 0, "source": "router",
                                          "state": "Active, In Use"})
        alerts = [e["message"] for e in self.store.get_events(event_type="ALERT")]
        self.assertEqual(len(alerts), 1)
        self.assertIn("«SSLVPN_POOL» на Core заполнен на 45%: занято 45 из 100", alerts[0])
        p.periodic_checks(settings, now=T0 + 400)
        self.assertEqual(len(self.store.get_events(event_type="ALERT")), 1)  # still full: no repeat
        outputs["show ip local pool"] = POOLS.replace("40         0", " 2         0").replace("10      40", "48       2")
        p.periodic_checks(settings, now=T0 + 800)
        outputs["show ip local pool"] = POOLS
        p.periodic_checks(settings, now=T0 + 1200)
        self.assertEqual(len(self.store.get_events(event_type="ALERT")), 2)  # dropped below, then full again

    def test_manual_license_limit_wins(self):
        p = self.poller({"show ip local pool": POOLS, "show license": LICENSE}, license_limit=4)
        p.sessions = [VpnSession("C", f"u{i}", "1.2.3.4", 1, "00:01:00", "00:00:01") for i in range(3)]
        p.periodic_checks({"config_backup_enabled": False, "pool_alert_percent": 70}, now=T0)
        self.assertEqual(p.capacity()["license"]["percent"], 75)
        alerts = [e["message"] for e in self.store.get_events(event_type="ALERT")]
        self.assertTrue(any("Лицензии AnyConnect на Core заполнен на 75%: занято 3 из 4" in a for a in alerts), alerts)


class DirectoryTest(Base):
    def test_save_replace_and_clear(self):
        self.store.save_directory_entries([{"login": "Ivanov", "full_name": "Иванов И.", "department": "Бух"}])
        self.store.save_directory_entries([{"login": "ivanov", "full_name": "Иванов Иван", "expires": "2026-12-31"}])
        d = self.store.get_directory()
        self.assertEqual((d["ivanov"]["full_name"], d["ivanov"]["department"]), ("Иванов Иван", ""))
        self.store.save_directory_entries([{"login": "IVANOV"}])  # every field empty: removed
        self.assertEqual(self.store.get_directory(), {})

    def test_alert_names_the_person(self):
        self.store.save_directory_entries([{"login": "ivanov", "full_name": "Иванов И.", "department": "Бухгалтерия"}])
        self.c.alert({}, "Ночной вход: 'ivanov'", login="IVANOV")
        self.assertEqual(self.sent, ["🚨 Ночной вход: 'ivanov' — Иванов И., Бухгалтерия"])

    def test_expiry_reminder_once_a_day(self):
        now = datetime(2026, 11, 12, 10, 0).timestamp()
        self.store.save_directory_entries([
            {"login": "contractor", "full_name": "ТОО Подрядчик", "expires": "2026-11-14"},
            {"login": "old", "expires": "2026-11-01"},
            {"login": "gone", "expires": "2026-11-01"},
            {"login": "later", "expires": "2027-01-01"},
        ])
        self.store.sync_router_users("main", [("contractor", 0), ("old", 0), ("later", 0)], now_ts=int(now))
        text = self.c.check_expiry({}, now=now)
        self.assertIn("⛔ old — доступ до 01.11.2026, срок истёк 11 дн. назад", text)
        self.assertIn("⚠ contractor (ТОО Подрядчик) — доступ до 14.11.2026, осталось 2 дн.", text)
        self.assertNotIn("gone", text)  # already deleted on the router
        self.assertNotIn("later", text)
        self.assertEqual(self.c.check_expiry({}, now=now + 3600), "")  # same day
        self.assertEqual(self.c.check_expiry({}, now=datetime(2026, 11, 13, 7, 0).timestamp()), "")  # before 9:00
        self.assertEqual(len(self.sent), 1)

    def test_audit_marks_accounts_deleted_on_the_router(self):
        from vpnmon.cleanup import mark_deleted_accounts

        now = int(time.time())
        for login in ("ivanov", "olduser", "online"):
            self.store.record_snapshot([VpnSession("C", login, "1.2.3.4", 1, "00:10:00", "00:00:01")],
                                       now_ts=now - DAY, router="main")
        self.store.record_snapshot([VpnSession("C", "online", "1.2.3.4", 1, "00:10:00", "00:00:01")],
                                   now_ts=now - DAY + 60, router="main")
        rows = self.store.get_all_users_summary(days=30, now_ts=now)
        # Accounts not loaded from the router yet: nothing can be called deleted.
        self.assertFalse(mark_deleted_accounts(self.store, [router()], rows))
        self.assertFalse(any(r["deleted"] for r in rows))

        self.store.sync_router_users("main", [("ivanov", 0), ("olduser", 0)], now_ts=now)
        self.store.sync_router_users("main", [("ivanov", 0)], now_ts=now)  # olduser deleted on the router
        rows = self.store.get_all_users_summary(days=30, now_ts=now)
        self.assertTrue(mark_deleted_accounts(self.store, [router()], rows))
        deleted = {r["login"]: r["deleted"] for r in rows}
        # History stays, the row is only flagged; a user online right now is never flagged.
        self.assertEqual(deleted, {"ivanov": False, "olduser": True, "online": False})
        # A second router whose accounts were never loaded disables the check.
        self.assertFalse(mark_deleted_accounts(self.store, [router(), router("branch")], rows))

    def test_expired_account_is_a_cleanup_candidate_even_if_used(self):
        now = int(datetime(2026, 11, 12, 10, 0).timestamp())
        self.store.sync_router_users("main", [("contractor", 0), ("ivanov", 0)], now_ts=now - 100 * DAY)
        for login in ("contractor", "ivanov"):
            s = VpnSession("C", login, "1.2.3.4", 1, "00:10:00", "00:00:01")
            self.store.record_snapshot([s], now_ts=now - DAY, router="main")
            self.store.record_snapshot([], now_ts=now - DAY + 60, router="main")
        self.store.save_directory_entries([{"login": "contractor", "full_name": "ТОО Подрядчик",
                                            "expires": "2026-11-10"}])
        r = build_cleanup(self.store, [router()], 60, set(), now_ts=now)["routers"][0]
        self.assertEqual([c["login"] for c in r["candidates"]], ["contractor"])
        self.assertEqual((r["candidates"][0]["expired"], r["candidates"][0]["person"]), ("10.11.2026", "ТОО Подрядчик"))
        self.assertIn(" no username contractor", r["commands"])
        self.assertIn("с истёкшим сроком доступа (1)", r["commands"])


if __name__ == "__main__":
    unittest.main()
