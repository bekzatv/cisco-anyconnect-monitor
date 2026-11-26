"""Local DB-IP database, two sources checked against each other, mobile operators and the admin's labels."""

import gzip
import io
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpnmon import geodb  # noqa: E402
from vpnmon.collector import Collector  # noqa: E402
from vpnmon.geodb import IpLabels, LocalGeoDB, merge_geo, normalize_cidr  # noqa: E402
from vpnmon.storage import SCHEMA_VERSION, ConnectionStatsStore  # noqa: E402

ALMATY = {"country": "KZ", "region": "Almaty", "city": "Almaty", "loc": "43.2525,76.9115", "org": "AS9198 JSC Kazakhtelecom"}
LOCAL_ALMATY = {"country": "KZ", "region": "Almaty", "city": "Almaty (Medeū)", "lat": 43.2601, "lon": 76.9627,
                "asn": 9198, "org": "JSC Kazakhtelecom"}
LOCAL_ASTANA = {"country": "KZ", "region": "Astana", "city": "Astana", "lat": 51.15, "lon": 71.46,
                "asn": 206026, "org": "Kar-Tel LLC"}
T_NOV = 1_795_000_000  # 2026-11-18


class MergeTest(unittest.TestCase):
    def test_sources_agree(self):
        a = merge_geo(LOCAL_ALMATY, ALMATY)
        self.assertEqual(a.loc, "KZ / Almaty")
        self.assertEqual(a.org, "AS9198 JSC Kazakhtelecom")
        self.assertEqual(a.note, "")
        self.assertIn("DB-IP: KZ, Almaty", a.detail)

    def test_sources_disagree(self):
        a = merge_geo(LOCAL_ASTANA, ALMATY | {"org": "AS9198 JSC Kazakhtelecom"})
        self.assertEqual(a.loc, "KZ / Almaty или Astana")
        self.assertIn("conflict", a.note)

    def test_mobile_operator(self):
        a = merge_geo(LOCAL_ASTANA, None)
        self.assertEqual(a.loc, "KZ / Astana")
        self.assertEqual(a.org, "AS206026 Kar-Tel LLC")
        self.assertEqual(a.note, "mobile")
        self.assertIn("Beeline", a.detail)
        by_name = merge_geo(None, {"country": "KZ", "city": "Almaty", "org": "AS1 Some Mobile LLP"})
        self.assertEqual(by_name.note, "mobile")
        extra = merge_geo(None, {"country": "KZ", "city": "Almaty", "org": "AS4242 Radio LLP"}, extra_mobile={4242})
        self.assertEqual(extra.note, "mobile")

    def test_label_wins(self):
        label = {"cidr": "89.218.158.0/24", "label": "Офис Астана", "country": "", "comment": "главный"}
        a = merge_geo(LOCAL_ASTANA, ALMATY, label)
        self.assertEqual(a.loc, "KZ / Офис Астана")
        self.assertEqual(a.note, "label")
        self.assertTrue(a.detail.startswith("Своя подпись сети 89.218.158.0/24: главный"))

    def test_nothing_known(self):
        self.assertIsNone(merge_geo(None, None))
        self.assertIsNone(merge_geo(None, {"bogon": True}))


class LabelsTest(unittest.TestCase):
    def test_most_specific_network_wins(self):
        labels = IpLabels([
            {"cidr": "10.0.0.0/8", "label": "Сеть"},
            {"cidr": "10.1.2.0/24", "label": "Офис"},
            {"cidr": "10.1.2.7/32", "label": "Принтер"},
            {"cidr": "garbage", "label": "x"},
        ])
        self.assertEqual(labels.match("10.1.2.7")["label"], "Принтер")
        self.assertEqual(labels.match("10.1.2.8")["label"], "Офис")
        self.assertEqual(labels.match("10.9.9.9")["label"], "Сеть")
        self.assertIsNone(labels.match("8.8.8.8"))
        self.assertIsNone(labels.match("not-an-ip"))

    def test_normalize(self):
        self.assertEqual(normalize_cidr(" 10.1.2.7 "), "10.1.2.7/32")
        self.assertEqual(normalize_cidr("10.1.2.7/24"), "10.1.2.0/24")
        with self.assertRaises(ValueError):
            normalize_cidr("10.1.2")


class StoreLabelsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = ConnectionStatsStore(Path(self.tmp.name) / "s.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_crud(self):
        self.assertEqual(SCHEMA_VERSION, 7)
        self.store.save_ip_label("10.1.2.0/24", "Офис", "KZ", "")
        self.store.save_ip_label("10.1.3.0/24", "Офис 2", "", "", old_cidr="10.1.2.0/24")
        rows = self.store.list_ip_labels()
        self.assertEqual([(r["cidr"], r["label"]) for r in rows], [("10.1.3.0/24", "Офис 2")])
        self.assertEqual(self.store.delete_ip_label("10.1.3.0/24"), 1)
        self.assertEqual(self.store.list_ip_labels(), [])


class CollectorGeoTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = ConnectionStatsStore(Path(self.tmp.name) / "s.db")
        self.c = Collector(self.store)
        self.c._queue_geo = mock.Mock()
        self.local = {}
        self.c.geodb.lookup = lambda ip: self.local.get(ip)

    def tearDown(self):
        self.tmp.cleanup()

    def test_local_answer_while_ipinfo_is_asked(self):
        self.local["5.6.7.8"] = LOCAL_ASTANA
        a = self.c.geo_answer("5.6.7.8", {})
        self.assertEqual(a.loc, "KZ / Astana")
        self.c._queue_geo.assert_called_once_with("5.6.7.8")

    def test_settings_switch_sources_off(self):
        self.local["5.6.7.8"] = LOCAL_ASTANA
        self.c.ip_cache["5.6.7.8"] = ALMATY | {"_fetched": time.time()}
        self.assertEqual(self.c.geo_answer("5.6.7.8", {"geo_local_db_enabled": False}).loc, "KZ / Almaty")
        self.assertEqual(self.c.geo_answer("5.6.7.8", {"geo_ipinfo_enabled": False}).loc, "KZ / Astana")
        self.assertEqual(self.c.geo_answer("5.6.7.8", {"geo_ipinfo_enabled": False,
                                                       "geo_local_db_enabled": False}).loc, "—")

    def test_unknown_address_is_loading_then_dash_after_a_failure(self):
        self.c._geo_inflight.add("5.6.7.9")
        self.assertIsNone(self.c.geo_answer("5.6.7.9", {}))
        self.c._geo_inflight.discard("5.6.7.9")
        self.c._store_remote("5.6.7.9", None, int(time.time()))
        self.c._queue_geo.reset_mock()
        self.assertEqual(self.c.geo_answer("5.6.7.9", {}).loc, "—")
        self.c._queue_geo.assert_not_called()  # not asked again on every poll

    def test_label_applies_to_private_addresses_too(self):
        self.assertEqual(self.c.geo_answer("10.1.2.3", {}).loc, "LAN / Локальная")
        self.store.save_ip_label("10.1.2.0/24", "Офис Астана", "KZ")
        self.c.reload_ip_labels()
        a = self.c.geo_answer("10.1.2.3", {})
        self.assertEqual((a.loc, a.note), ("KZ / Офис Астана", "label"))


class LocalDbUpdateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.urls = []
        self.published = set()

        def opener(url):
            self.urls.append(url)
            if not any(m in url for m in self.published):
                raise geodb.NotPublished(url)
            return io.BytesIO(gzip.compress(b"mmdb-bytes"))

        self.db = LocalGeoDB(Path(self.tmp.name) / "geoip", opener=opener)
        p = mock.patch.object(LocalGeoDB, "_validate", staticmethod(lambda path, kind: None))
        p.start()
        self.addCleanup(p.stop)
        q = mock.patch.object(geodb, "maxminddb", object())
        q.start()
        self.addCleanup(q.stop)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_months(self):
        self.assertEqual(geodb.previous_month("2026-01"), "2025-12")
        self.assertEqual(geodb.previous_month("2026-11"), "2026-10")

    def test_falls_back_to_last_month_then_takes_the_new_one(self):
        self.published = {"2026-10"}
        self.assertTrue(self.db.update_due(T_NOV))
        installed = self.db.update(now=T_NOV)
        self.assertEqual(installed, [("city", "2026-10"), ("asn", "2026-10")])
        self.assertEqual(self.db.path("city").read_bytes(), b"mmdb-bytes")
        self.assertEqual(self.db.month("city"), "2026-10")
        self.assertFalse(self.db.update_due(T_NOV + 60))  # waits before asking again
        self.assertTrue(self.db.update_due(T_NOV + geodb.DB_RETRY_SECONDS))

        self.published = {"2026-10", "2026-11"}
        self.assertEqual(self.db.update(now=T_NOV + geodb.DB_RETRY_SECONDS),
                         [("city", "2026-11"), ("asn", "2026-11")])
        self.assertFalse(self.db.update_due(T_NOV + 2 * geodb.DB_RETRY_SECONDS))
        self.assertEqual(self.db.update(now=T_NOV + 2 * geodb.DB_RETRY_SECONDS), [])
        self.assertEqual(sorted(p.name for p in self.db.folder.iterdir()),
                         ["dbip-asn-lite.mmdb", "dbip-city-lite.mmdb", "dbip-versions.json"])

    def test_failed_download_keeps_old_files(self):
        self.published = {"2026-11"}
        self.db.update(now=T_NOV)
        self.db._open_url = mock.Mock(side_effect=OSError("нет сети"))
        self.db.path("city").write_bytes(b"old")
        (self.db.folder / geodb.VERSIONS_FILE).write_text('{"city": "2026-10", "asn": "2026-11"}', encoding="utf-8")
        with self.assertRaises(OSError):
            self.db.update(now=T_NOV + geodb.DB_RETRY_SECONDS)
        self.assertEqual(self.db.path("city").read_bytes(), b"old")
        self.assertIn("нет сети", self.db.status()["error"])


@unittest.skipIf(geodb.maxminddb is None, "maxminddb is not installed")
class RealReaderTest(unittest.TestCase):
    def test_missing_files_give_no_answer(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = LocalGeoDB(Path(tmp))
            self.assertIsNone(db.lookup("8.8.8.8"))
            self.assertFalse(db.status()["available"])
            self.assertTrue(db.update_due(T_NOV))


if __name__ == "__main__":
    unittest.main()
