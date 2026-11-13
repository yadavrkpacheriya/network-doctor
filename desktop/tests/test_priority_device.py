# -*- coding: utf-8 -*-
"""IP-conflict priority device: tagging a device as the 'default' for an IP (nd_tools.priority_mac_for)
is what the ip_conflict auto-fix uses to decide which of the quarrelling MACs gets the IP-MAC binding."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_tools as T  # noqa: E402


class PriorityDeviceTests(unittest.TestCase):
    def test_priority_value_normalizes_like_watch(self):
        self.assertEqual(T.priority_value("yes"), "1")
        self.assertEqual(T.priority_value("no"), "")
        self.assertIsNone(T.priority_value(None))

    def test_set_tag_stores_priority_field(self):
        db = {}
        T.set_tag(db, "AA:BB", priority="Yes")
        self.assertEqual(T.tags_of(db)["AA:BB"]["priority"], "Yes")

    def test_picks_the_single_tagged_mac(self):
        tags = {"AA:BB": {"priority": "1"}, "CC:DD": {}}
        self.assertEqual(T.priority_mac_for(tags, ["AA:BB", "CC:DD"]), "AA:BB")

    def test_no_pick_when_nobody_is_tagged(self):
        tags = {"AA:BB": {}, "CC:DD": {}}
        self.assertIsNone(T.priority_mac_for(tags, ["AA:BB", "CC:DD"]))

    def test_no_pick_when_both_are_tagged(self):
        """Ambiguous - the auto-fix must not guess which one the user meant."""
        tags = {"AA:BB": {"priority": "1"}, "CC:DD": {"priority": "1"}}
        self.assertIsNone(T.priority_mac_for(tags, ["AA:BB", "CC:DD"]))

    def test_untagged_mac_not_in_the_list_is_ignored(self):
        tags = {"AA:BB": {"priority": "1"}, "EE:FF": {"priority": "1"}}
        self.assertEqual(T.priority_mac_for(tags, ["AA:BB", "CC:DD"]), "AA:BB")


if __name__ == "__main__":
    unittest.main()
