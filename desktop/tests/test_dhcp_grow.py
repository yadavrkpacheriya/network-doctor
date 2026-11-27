# -*- coding: utf-8 -*-
"""Permanent DHCP-full cure (Rakesh, 27 Nov): the pool must GROW itself by 20 when it runs low on free IPs, so
'DHCP pool full' never repeats. The router script is self-guarding (only grows when <20 free, caps at .254)."""
import unittest
import nd_alerts as AL
import nd_bandwidth as B


class GrowScript(unittest.TestCase):
    def test_grow_script_present_and_guarded(self):
        s = AL.DHCP_GROW
        self.assertIn("/ip pool set", s)        # it widens the pool
        self.assertIn("free < 20", s)           # only when low on free addresses
        self.assertIn("254", s)                 # capped below broadcast
        self.assertIn("grew DHCP pool", s)      # logs when it acts

    def test_bandwidth_builder_matches_and_guards_subnet(self):
        self.assertTrue(B.grow_pool_script("192.168.0.0/24"))
        self.assertEqual(B.grow_pool_script("192.168.0.0/25"), "")   # not a /24 -> no script
        self.assertIn("/ip pool set", B.grow_pool_script_generic())

    def test_dhcp_full_autofix_includes_all_three_cures_plus_grow(self):
        r = AL.explain("The DHCP pool is almost full - new devices may get no address",
                       "warning", "192.168.0.70", "192.168.0.1")
        self.assertEqual(r["kind"], "dhcp_full")
        self.assertIn("dhcp_full", AL.AUTO_SAFE)
        fix = next(a for a in r["auto"] if a["where"] == "router")
        cmd = fix["cmd"]
        self.assertIn("make-static", cmd)       # 1) reserve fixed gear
        self.assertIn("lease-time=30m", cmd)     # 2) short lease so ghosts clear
        self.assertIn("/ip pool set", cmd)       # 3) grow the pool when low
        self.assertIn("grew DHCP pool", cmd)


if __name__ == "__main__":
    unittest.main()


class ReclaimFirst(unittest.TestCase):
    """Rakesh (27 Nov): free the OLD IP a rotated-MAC phone left behind BEFORE adding new ones - reclaim then grow."""
    def test_reclaim_runs_before_grow(self):
        s = AL.DHCP_GROW
        reclaim = s.index("lease remove [find where dynamic=yes and status!=bound]")
        grow = s.index("free < 20")
        self.assertLess(reclaim, grow)
        self.assertIn("lease remove [find where dynamic=yes and status!=bound]", B.grow_pool_script("192.168.0.0/24"))
