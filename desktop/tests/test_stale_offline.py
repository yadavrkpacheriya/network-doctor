# -*- coding: utf-8 -*-
"""A camera / PC that has been OFFLINE for 2+ days is flagged (dead / unplugged / removed), while one gone
only a few hours (asleep, roaming) is not."""
import datetime as dt
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_core as core  # noqa: E402

try:
    from test_warning_fixes import fresh_db, raw_with
except Exception:  # pragma: no cover
    fresh_db = raw_with = None


@unittest.skipIf(fresh_db is None, "shared test helpers unavailable")
class StaleOffline(unittest.TestCase):
    def _db(self, hours_ago, category):
        db = fresh_db()
        db["scans"] = 5
        seen = (dt.datetime.now() - dt.timedelta(hours=hours_ago)).strftime("%Y-%m-%d %H:%M")
        db["devices"] = {"AA:BB:CC:00:00:11": {"first_seen": "2026-10-01 09:00", "last_seen": seen,
                                               "category": category, "names": ["Gate Cam"], "ip": "192.168.0.60"}}
        db["last_online_macs"] = []
        return db

    def test_camera_offline_three_days_is_flagged(self):
        devs = core.build_devices(raw_with({}), [], self._db(72, core.CAT_CAM))
        stale = [d for d in devs if d.get("stale_gone")]
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0]["prev_cat"], core.CAT_CAM)

    def test_offline_three_days_raises_an_issue(self):
        db = self._db(72, core.CAT_CAM)
        devs = core.build_devices(raw_with({}), [], db)
        issues, _ = core.analyse(raw_with({}), devs, db)
        self.assertTrue([i for i in issues if "offline for 2+ days" in i["title"]])

    def test_phone_offline_three_days_is_not_flagged(self):
        devs = core.build_devices(raw_with({}), [], self._db(72, core.CAT_PHONE))
        self.assertFalse([d for d in devs if d.get("stale_gone")])   # phones roam - not flagged

    def test_camera_asleep_a_few_hours_is_not_stale(self):
        devs = core.build_devices(raw_with({}), [], self._db(5, core.CAT_CAM))
        self.assertFalse([d for d in devs if d.get("stale_gone")])


if __name__ == "__main__":
    unittest.main()
