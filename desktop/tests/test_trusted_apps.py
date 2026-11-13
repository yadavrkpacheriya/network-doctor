# -*- coding: utf-8 -*-
"""Trusted services (e.g. Acronis backup): a device's daily-usage spike should not be raised as a
problem (nd_usage.insights()'s "device_spike" kind) once its top app is marked trusted - the user runs
it on purpose and does not want it flagged in alerts every time."""

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import nd_usage as NU  # noqa: E402


class TrustedAppsTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = NU.UsageStore(os.path.join(self.dir, "usage.db"),
                                    os.path.join(self.dir, "usage-settings.json"))

    def _seed_spike(self, app="Acronis Asia Pte Ltd administrator"):
        import datetime as dt
        today = dt.date(2026, 11, 13)
        with self.store._db() as db:
            # 5 normal days (~10MB) then a spike day (4x+) on the same device, mostly the given app
            for i in range(5, 0, -1):
                day = (today - dt.timedelta(days=i)).isoformat()
                db.execute("INSERT INTO usage VALUES (?,?,?,?,?,?,?,?,?)",
                           (day, 10, "AA:BB:CC:DD:EE:01", "Windows Update", "", "neutral", 5_000_000, 5_000_000, 1))
            db.execute("INSERT INTO usage VALUES (?,?,?,?,?,?,?,?,?)",
                       (today.isoformat(), 10, "AA:BB:CC:DD:EE:01", app, "", "work", 3_000_000_000, 3_000_000_000, 1))
        return today

    def test_spike_is_flagged_by_default(self):
        today = self._seed_spike()
        kinds = [i for i in self.store.insights(today=today) if i.get("kind") == "device_spike"]
        self.assertEqual(len(kinds), 1)

    def test_trusted_app_suppresses_the_spike_alert(self):
        today = self._seed_spike()
        self.store.set_trusted("acronis")
        kinds = [i for i in self.store.insights(today=today) if i.get("kind") == "device_spike"]
        self.assertEqual(kinds, [])

    def test_trusted_matches_by_substring_either_way(self):
        today = self._seed_spike(app="acronis.com")
        self.store.set_trusted("Acronis")
        kinds = [i for i in self.store.insights(today=today) if i.get("kind") == "device_spike"]
        self.assertEqual(kinds, [])

    def test_untrust_restores_the_alert(self):
        today = self._seed_spike()
        self.store.set_trusted("acronis", True)
        self.store.set_trusted("acronis", False)
        kinds = [i for i in self.store.insights(today=today) if i.get("kind") == "device_spike"]
        self.assertEqual(len(kinds), 1)

    def test_trust_persists_across_reloads(self):
        self.store.set_trusted("acronis")
        store2 = NU.UsageStore(os.path.join(self.dir, "usage.db"), os.path.join(self.dir, "usage-settings.json"))
        self.assertTrue(store2.is_trusted("Acronis Asia Pte Ltd administrator"))
        self.assertEqual(store2.trusted_apps(), ["acronis"])


if __name__ == "__main__":
    unittest.main()
