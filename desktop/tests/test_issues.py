# -*- coding: utf-8 -*-
"""Recurring-issue tracker: grouping, top-10, needs-Claude, and the Claude hand-off."""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_issues as ISS  # noqa: E402

NOW = 1_700_000_000


def item(kind, ip, count, status, t_ago_h, text="x", title="T"):
    t = NOW - t_ago_h * 3600
    return {"kind": kind, "ip": ip, "count": count, "status": status, "t": t, "last": t,
            "text": text, "title": title, "fix": "reserve it"}


class Issues(unittest.TestCase):
    def setUp(self):
        self.items = [
            item("dhcp_conflict", "192.168.0.74", 2, "open", 1),
            item("dhcp_conflict", "192.168.0.74", 3, "open", 5),      # same problem again
            item("ip_conflict", "192.168.0.39", 1, "fixed", 2),
            item("mtu", "", 1, "fixed", 30 * 24),                     # old, outside the 1-day window
        ]

    def test_group_merges_same_device_and_kind(self):
        rows = ISS.group(self.items, now=NOW, days=1)
        conflict = next(r for r in rows if r["kind"] == "dhcp_conflict")
        self.assertEqual(conflict["count"], 5)          # 2 + 3
        self.assertEqual(conflict["hits"], 2)
        self.assertTrue(conflict["open"])

    def test_recurring_needs_3_plus(self):
        rec = ISS.recurring(self.items, now=NOW, days=1, min_count=3)
        self.assertTrue(any(r["kind"] == "dhcp_conflict" for r in rec))
        self.assertFalse(any(r["kind"] == "ip_conflict" for r in rec))   # only seen once

    def test_old_items_excluded_from_today(self):
        rows = ISS.group(self.items, now=NOW, days=1)
        self.assertFalse(any(r["kind"] == "mtu" for r in rows))

    def test_needs_claude_only_for_open_recurring(self):
        rows = ISS.group(self.items, now=NOW, days=1)
        conflict = next(r for r in rows if r["kind"] == "dhcp_conflict")
        self.assertTrue(ISS.needs_claude(conflict))
        ipc = next(r for r in rows if r["kind"] == "ip_conflict")
        self.assertFalse(ISS.needs_claude(ipc))         # fixed, and not recurring

    def test_claude_report_has_history_and_code(self):
        rows = ISS.group(self.items, now=NOW, days=1)
        conflict = next(r for r in rows if r["kind"] == "dhcp_conflict")
        md = ISS.claude_report(conflict, self.items, code="def fix(): pass", brain_note="keeps coming back", now=NOW)
        self.assertIn("recurring issue for Claude", md)
        self.assertIn("192.168.0.74", md)
        self.assertIn("def fix()", md)
        self.assertIn("ROOT CAUSE", md)


if __name__ == "__main__":
    unittest.main()
