"""'New / changed this week' mark in All devices (nd_core.recent_mark, build_devices, update_history)."""
import unittest

import nd_core as core
import nd_tools as T

BASE = "2026-11-01 09:00"


class Mark(unittest.TestCase):
    def test_new_this_week_is_marked_with_the_date(self):
        self.assertEqual(core.recent_mark("2026-11-13 22:49", None, BASE, "2026-11-14 14:45"),
                         "new since 13-Nov 22:49")

    def test_mark_goes_away_after_a_week(self):
        self.assertEqual(core.recent_mark("2026-11-05 10:00", None, BASE, "2026-11-14 14:45"), "")

    def test_devices_of_the_very_first_scans_are_not_new(self):
        self.assertEqual(core.recent_mark(BASE, None, BASE, "2026-11-01 09:30"), "")
        self.assertEqual(core.recent_mark("2026-11-01 09:40", None, BASE, "2026-11-01 10:00"), "")

    def test_a_device_that_moved_to_another_group_says_where_it_was(self):
        ch = {"from": core.CAT_UNK, "time": "2026-11-13 23:10"}
        self.assertEqual(core.recent_mark(BASE, ch, BASE, "2026-11-14 14:45"),
                         f"was under '{core.CAT_UNK}' until 13-Nov 23:10")
        self.assertEqual(core.recent_mark(BASE, dict(ch, time="2026-11-02 10:00"), BASE, "2026-11-14 14:45"), "")

    def test_bad_dates_never_raise(self):
        self.assertEqual(core.recent_mark("", {}, "", "2026-11-14 14:45"), "")
        self.assertEqual(core.recent_mark("x", "y", None, None), "")


class HistoryAndFilter(unittest.TestCase):
    def test_type_change_is_remembered_in_the_history(self):
        db = {"devices": {"AA:BB:CC:00:00:01": {"first_seen": BASE, "names": [], "ips": [],
                                                 "category": core.CAT_UNK}}, "ip_owner": {}}
        devs = [{"mac": "AA:BB:CC:00:00:01", "ip": "192.168.0.90", "online": True, "category": core.CAT_CAM,
                 "vendor": "", "names": {}, "name": "cam", "upnp": {}}]
        raw = {"meta": {"started": "2026-11-13 23:10", "finished": "2026-11-13 23:12"}}
        core._update_db(db, raw, devs)
        h = db["devices"]["AA:BB:CC:00:00:01"]
        self.assertEqual(h["cat_changed"], {"from": core.CAT_UNK, "time": "2026-11-13 23:10"})
        self.assertEqual(h["category"], core.CAT_CAM)

    def test_show_filter(self):
        devs = [{"name": "a", "recent": "new since 13-Nov 22:49", "online": True},
                {"name": "b", "recent": "", "online": True}]
        self.assertEqual([d["name"] for d in T.filter_devices(devs, show=T.SHOW[6])], ["a"])
        self.assertEqual(len(T.filter_devices(devs)), 2)


if __name__ == "__main__":
    unittest.main()
