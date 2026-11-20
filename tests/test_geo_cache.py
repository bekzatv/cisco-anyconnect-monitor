"""Geolocation answers expire, so a reassigned address does not keep an old town forever."""

import queue
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpnmon.collector import Collector  # noqa: E402
from vpnmon.geo import GEO_CACHE_SECONDS, geo_is_stale  # noqa: E402
from vpnmon.cisco import VpnSession  # noqa: E402
from vpnmon.storage import ConnectionStatsStore  # noqa: E402

T0 = 1_760_000_000


class GeoCacheTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.c = Collector(ConnectionStatsStore(Path(self.tmp.name) / "s.db"))
        self.c._geo_queue = queue.Queue()  # the real worker keeps waiting on the old queue

    def tearDown(self):
        self.tmp.cleanup()

    def session(self, ip):
        return VpnSession(context="ctx", login="ivanov", ip=ip, connections=1, created="", last_used="", router="r1")

    def test_staleness(self):
        self.assertTrue(geo_is_stale({"city": "Astana"}, T0))  # written before timestamps existed
        self.assertFalse(geo_is_stale({"_fetched": T0}, T0 + GEO_CACHE_SECONDS - 1))
        self.assertTrue(geo_is_stale({"_fetched": T0}, T0 + GEO_CACHE_SECONDS))
        self.assertFalse(geo_is_stale({"_private": True}, T0))

    def test_stale_entry_is_shown_and_refreshed(self):
        self.c.ip_cache["5.6.7.8"] = {"country": "KZ", "city": "Astana", "org": "AS1 X", "_fetched": T0}
        s = self.session("5.6.7.8")
        self.c.enrich_geo([s], now=T0 + 60)
        self.assertEqual(s.country, "KZ / Astana")
        self.assertTrue(self.c._geo_queue.empty())
        self.c.enrich_geo([s], now=T0 + GEO_CACHE_SECONDS)
        self.assertEqual(s.country, "KZ / Astana")  # the old answer stays until the new one arrives
        self.assertEqual(self.c._geo_queue.get_nowait(), "5.6.7.8")
        self.c.enrich_geo([s], now=T0 + GEO_CACHE_SECONDS + 5)
        self.assertTrue(self.c._geo_queue.empty())  # already queued once


if __name__ == "__main__":
    unittest.main()
