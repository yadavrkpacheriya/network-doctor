"""Tests for the "Router configuration changed" alert kind (nd_alerts.py) - wired so a hand-made change
on the router (outside the app) surfaces in the normal Alerts feed instead of going unnoticed."""
import unittest

import nd_alerts as AL


class ConfigChangedAlert(unittest.TestCase):
    def test_recognized_and_not_auto_fixed(self):
        r = AL.explain("Router configuration changed", "warning", "192.168.0.70", "192.168.0.1")
        self.assertEqual(r["kind"], "config_changed")
        self.assertNotIn("config_changed", AL.AUTO_SAFE)  # informational only - nothing to auto-apply
        self.assertEqual(r["auto"], [])

    def test_links_to_the_backup_page(self):
        r = AL.explain("Router configuration changed")
        self.assertEqual(r["app"], ("Open Config backup", "t_backup"))

    def test_is_informational_priority_not_critical(self):
        r = AL.explain("Router configuration changed")
        self.assertEqual(r["prio"], 3)


if __name__ == "__main__":
    unittest.main()
