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


class RouterCpuHasReadOnlyDiagnostic(unittest.TestCase):
    """NetworkDoctor._auto_fix()'s new "find" path (auto-diagnose, no change made) looks for a
    where == 'router_read' entry on any repeating alert - this protects that contract staying in place
    for router_cpu, the one kind that currently has one."""

    def test_router_cpu_has_a_router_read_entry(self):
        r = AL.explain("The router's CPU is very busy", "warning")
        diag = next((a for a in r["auto"] if a["where"] == "router_read"), None)
        self.assertIsNotNone(diag)
        self.assertTrue(diag["cmd"])

    def test_router_read_entries_never_write_anything(self):
        """A 'router_read' command must be a query, never something that could change router state -
        auto-diagnose runs these unconditionally, with no AUTO_SAFE gate, so this must hold for every
        kind that ever gets one, not just router_cpu."""
        for kind in ("router_cpu",):
            r = AL.explain({"router_cpu": "The router's CPU is very busy"}[kind], "warning")
            for a in r["auto"]:
                if a["where"] == "router_read":
                    self.assertNotIn("add ", a["cmd"])
                    self.assertNotIn("set ", a["cmd"])
                    self.assertNotIn("remove ", a["cmd"])
                    self.assertIn("print", a["cmd"])


if __name__ == "__main__":
    unittest.main()
