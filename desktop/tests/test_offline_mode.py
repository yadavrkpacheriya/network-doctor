# -*- coding: utf-8 -*-
"""Offline mode hides only internet pages. Guards that local features (cameras, PCs, scan, usage, fixes...)
are never in the online-only set, and that known internet pages are."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    import nd_tabs as T
except ImportError:                      # tkinter not present (headless CI box) - skip; the Windows build has it
    T = None


@unittest.skipIf(T is None, "tkinter not available")
class OnlinePages(unittest.TestCase):
    def test_internet_pages_are_marked(self):
        for p in ("t_speed", "t_web", "t_dns", "t_remote", "expose"):
            self.assertIn(p, T.ONLINE_PAGES)

    def test_local_features_stay_visible_offline(self):
        # these must NEVER be hidden offline - they are the whole point of offline use
        for p in ("cameras", "computers", "devices", "inventory", "usage", "pccare", "commands",
                  "t_ports", "t_wol", "t_switch", "t_mac", "t_backup", "setup", "binding", "map", "sweep"):
            self.assertNotIn(p, T.ONLINE_PAGES, p + " must work offline")

    def test_every_section_keeps_at_least_one_page_offline(self):
        # no menu section should vanish entirely in offline mode
        for key, _title, _c, _l, subs in T.SECTIONS:
            visible = [p for p, _t in subs if p not in T.ONLINE_PAGES]
            self.assertTrue(visible, "section %s has no offline pages" % key)

    def test_offline_section_set_is_short_and_core(self):
        # offline keeps the menu to a few sections: cameras, computers, scan, fixes, setup
        self.assertLessEqual(len(T.OFFLINE_SECTIONS), 5)
        for key in ("cameras_s", "computers_s", "devices_s", "fix_s"):
            self.assertIn(key, T.OFFLINE_SECTIONS)

    def test_offline_sections_all_exist(self):
        real = {s[0] for s in T.SECTIONS}
        for key in T.OFFLINE_SECTIONS:
            self.assertIn(key, real, key + " is not a real section")


if __name__ == "__main__":
    unittest.main()
