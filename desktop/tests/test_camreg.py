# -*- coding: utf-8 -*-
"""Camera firmware registry: remembers details across sessions and tracks firmware version changes."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_camreg as R  # noqa: E402


class Record(unittest.TestCase):
    def test_new_camera_is_stored_with_history(self):
        reg = {}
        R.record(reg, {"name": "Gate", "ip": "192.168.1.64", "mac": "AA:BB:CC:00:00:64",
                       "brand": "Local", "model": "HB-X8", "firmware": "V5.00"}, now=_t("2026-11-17"))
        e = reg["AA:BB:CC:00:00:64"]
        self.assertEqual(e["model"], "HB-X8")
        self.assertEqual(e["firmware"], "V5.00")
        self.assertEqual(e["history"], [{"ver": "V5.00", "date": "2026-11-17"}])

    def test_firmware_change_appends_history(self):
        reg = {}
        R.record(reg, {"mac": "M", "firmware": "V5.00"}, now=_t("2026-11-17"))
        R.record(reg, {"mac": "M", "firmware": "V5.00"}, now=_t("2026-11-18"))   # same -> no new history
        R.record(reg, {"mac": "M", "firmware": "V5.10"}, now=_t("2026-11-19"))   # changed -> appended
        self.assertEqual([h["ver"] for h in reg["M"]["history"]], ["V5.00", "V5.10"])
        self.assertEqual(reg["M"]["firmware"], "V5.10")
        self.assertEqual(reg["M"]["last_seen"], "2026-11-19")

    def test_ip_key_when_no_mac(self):
        reg = {}
        R.record(reg, {"ip": "192.168.1.70", "model": "X"})
        self.assertIn("192.168.1.70", reg)


class Outdated(unittest.TestCase):
    def test_only_flags_models_with_a_target(self):
        reg = {}
        R.record(reg, {"mac": "A", "name": "c1", "ip": "1.1.1.1", "model": "HB-X8", "firmware": "V5.00"})
        R.record(reg, {"mac": "B", "name": "c2", "ip": "1.1.1.2", "model": "HB-X8", "firmware": "V5.10"})
        R.record(reg, {"mac": "C", "name": "c3", "ip": "1.1.1.3", "model": "OTHER", "firmware": "V1"})
        out = R.outdated(reg, {"HB-X8": "V5.10"})       # OTHER has no target -> never judged
        self.assertEqual([o["name"] for o in out], ["c1"])

    def test_summary_groups_firmware_by_model(self):
        reg = {}
        R.record(reg, {"mac": "A", "model": "HB-X8", "firmware": "V5.00"})
        R.record(reg, {"mac": "B", "model": "HB-X8", "firmware": "V5.10"})
        s = R.summary(reg)
        self.assertEqual(s["cameras"], 2)
        self.assertEqual(s["models"]["HB-X8"], ["V5.00", "V5.10"])


import time  # noqa: E402


def _t(day):
    return time.mktime(time.strptime(day, "%Y-%m-%d"))


if __name__ == "__main__":
    unittest.main()
