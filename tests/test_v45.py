"""4.5: update check against GitHub releases."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpnmon import updates  # noqa: E402
from vpnmon.collector import Collector  # noqa: E402
from vpnmon.storage import ConnectionStatsStore  # noqa: E402

T0 = 1_760_000_000


def release(version):
    return lambda: {"version": version, "url": f"https://example.invalid/v{version}", "published": "2026-11-16",
                    "notes": ""}


class UpdateCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = ConnectionStatsStore(Path(self.tmp.name) / "s.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_version_compare(self):
        self.assertTrue(updates.is_newer("4.10", "4.9"))
        self.assertTrue(updates.is_newer("4.5.1", "4.5"))
        self.assertFalse(updates.is_newer("4.5", "4.5.0"))
        self.assertFalse(updates.is_newer("4.4", "4.5"))
        self.assertFalse(updates.is_newer("", "4.5"))

    def test_new_release_is_announced_once(self):
        with mock.patch.object(updates, "__version__", "4.5"):
            state = updates.check_for_update(self.store, now=T0, fetch=release("4.6"))
            self.assertTrue(state["available"] and state["is_new"])
            self.assertFalse(updates.check_due(self.store, T0 + 3600))
            self.assertTrue(updates.check_due(self.store, T0 + updates.CHECK_EVERY_SECONDS))
            again = updates.check_for_update(self.store, now=T0 + 90000, fetch=release("4.6"))
            self.assertTrue(again["available"])
            self.assertFalse(again["is_new"])
            self.assertTrue(updates.check_for_update(self.store, now=T0 + 180000, fetch=release("4.7"))["is_new"])

    def test_same_version_or_no_releases(self):
        with mock.patch.object(updates, "__version__", "4.5"):
            self.assertFalse(updates.check_for_update(self.store, now=T0, fetch=release("4.5"))["available"])
            state = updates.check_for_update(self.store, now=T0, fetch=lambda: None)
            self.assertEqual((state["available"], state["latest"], state["error"]), (False, None, ""))

    def test_failure_keeps_last_answer_and_waits(self):
        def offline():
            raise OSError("no route to host")

        with mock.patch.object(updates, "__version__", "4.5"):
            updates.check_for_update(self.store, now=T0, fetch=release("4.6"))
            later = T0 + updates.CHECK_EVERY_SECONDS
            state = updates.check_for_update(self.store, now=later, fetch=offline)
            self.assertIn("no route", state["error"])
            self.assertTrue(state["available"])  # the earlier answer still stands
            self.assertFalse(updates.check_due(self.store, later + 60))
            self.assertTrue(updates.check_due(self.store, later + updates.RETRY_SECONDS))

    def test_collector_journals_and_notifies(self):
        c = Collector(self.store)
        sent = []
        c.telegram.send = lambda settings, text: sent.append(text)
        with mock.patch("vpnmon.collector.HISTORY_LOG_FILE", Path(self.tmp.name) / "h.log"), \
                mock.patch.object(updates, "__version__", "4.5"), \
                mock.patch.object(updates, "fetch_latest_release", release("4.6")):
            c.check_update({})
            c.check_update({})  # not due again
            c.check_update({"update_check_enabled": False}, force=True)  # the button always checks
        self.assertEqual(len(sent), 1)
        self.assertIn("4.6", sent[0])
        self.assertEqual(len([e for e in self.store.get_events(event_type="INFO") if "новая версия" in e["message"]]), 1)


if __name__ == "__main__":
    unittest.main()
