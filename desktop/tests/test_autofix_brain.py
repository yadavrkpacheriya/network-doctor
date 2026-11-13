# -*- coding: utf-8 -*-
"""The "learning brain": every auto-fix is recorded with an undo, a post-fix regression check decides
success/failure, and a fix-kind's own track record lowers or raises how readily it is tried again."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import nd_autofix as AF  # noqa: E402


class AutoFixBrainTests(unittest.TestCase):
    def setUp(self):
        self.history = []
        self.stats = {}

    def test_new_fix_is_recorded_and_undoable(self):
        e = AF.new_fix(self.history, "ip_conflict", "Two devices use 192.168.0.3",
                       mac="AA:BB:CC:DD:EE:01", ip="192.168.0.3", cmd="/ip ...", undo_cmd="/ip ... remove")
        self.assertEqual(e["status"], AF.STATUS_APPLIED)
        self.assertEqual(len(self.history), 1)
        self.assertTrue(e["undo_cmd"])

    def test_undo_marks_status_and_feeds_stats(self):
        e = AF.new_fix(self.history, "ip_conflict", "t", mac="M1", ip="1.2.3.4")
        AF.record_try(self.stats, "ip_conflict")
        AF.mark_undone(self.history, self.stats, e["id"])
        self.assertEqual(e["status"], AF.STATUS_UNDONE)
        self.assertEqual(self.stats["ip_conflict"]["undone"], 1)

    def test_double_undo_is_a_no_op(self):
        e = AF.new_fix(self.history, "loop", "t")
        AF.record_try(self.stats, "loop")
        AF.mark_undone(self.history, self.stats, e["id"])
        AF.mark_undone(self.history, self.stats, e["id"])
        self.assertEqual(self.stats["loop"]["undone"], 1)

    def test_regression_check_flags_a_new_alert_on_the_same_device(self):
        e = AF.new_fix(self.history, "ip_conflict", "t", mac="AA:BB", ip="192.168.0.3", now=1000)
        before = {e["id"]: {"old-alert-1"}}
        active = [{"id": "old-alert-1", "mac": "AA:BB", "ip": "192.168.0.3"},   # pre-existing, not new
                  {"id": "new-alert-2", "mac": "AA:BB", "ip": "192.168.0.3"}]   # appeared after the fix
        ok, bad = AF.check_regressions(self.history, active, before, now=1000 + AF.REGRESSION_WINDOW + 1)
        self.assertEqual(ok, [])
        self.assertEqual(bad, [e["id"]])

    def test_regression_check_marks_ok_when_nothing_new_shows_up(self):
        e = AF.new_fix(self.history, "multicast", "t", mac="AA:BB", now=1000)
        before = {e["id"]: set()}
        ok, bad = AF.check_regressions(self.history, [], before, now=1000 + AF.REGRESSION_WINDOW + 1)
        self.assertEqual(ok, [e["id"]])
        self.assertEqual(bad, [])

    def test_regression_check_ignores_fixes_still_inside_their_window(self):
        e = AF.new_fix(self.history, "loop", "t", now=1000)
        ok, bad = AF.check_regressions(self.history, [], {e["id"]: set()}, now=1000 + 60)
        self.assertEqual((ok, bad), ([], []))

    def test_mark_ok_increments_tries_and_ok(self):
        e = AF.new_fix(self.history, "dhcp_conflict", "t")
        AF.mark_ok(self.history, self.stats, e["id"])
        self.assertEqual(e["status"], AF.STATUS_OK)
        self.assertEqual(self.stats["dhcp_conflict"], {"tries": 1, "ok": 1, "undone": 0})

    def test_confidence_is_full_for_an_untried_kind(self):
        self.assertEqual(AF.confidence(self.stats, "new_kind"), 1.0)

    def test_confidence_drops_as_undos_accumulate(self):
        self.stats["ip_conflict"] = {"tries": 4, "ok": 2, "undone": 2}
        self.assertAlmostEqual(AF.confidence(self.stats, "ip_conflict"), 0.5)

    def test_threshold_eases_down_with_a_clean_record(self):
        self.stats["loop"] = {"tries": 9, "ok": 9, "undone": 0}
        self.assertLess(AF.repeat_threshold(self.stats, "loop", base=5), 5)

    def test_threshold_rises_after_an_undo(self):
        self.stats["ip_conflict"] = {"tries": 2, "ok": 1, "undone": 1}
        self.assertGreater(AF.repeat_threshold(self.stats, "ip_conflict", base=5), 5)

    def test_threshold_never_drops_below_one(self):
        self.stats["loop"] = {"tries": 300, "ok": 300, "undone": 0}
        self.assertGreaterEqual(AF.repeat_threshold(self.stats, "loop", base=5), 1)

    def test_stats_summary_reports_confidence_percent(self):
        self.stats["loop"] = {"tries": 4, "ok": 3, "undone": 1}
        rows = AF.stats_summary(self.stats)
        self.assertEqual(rows, [{"kind": "loop", "tries": 4, "ok": 3, "undone": 1, "confidence": 75}])


if __name__ == "__main__":
    unittest.main()
