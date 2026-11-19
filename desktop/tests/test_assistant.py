import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_assistant as A
import nd_alerts as AL


class Plan(unittest.TestCase):
    def test_block_named_site(self):
        p = A.plan("please block youtube on the wifi")
        self.assertEqual(p["kind"], "sites")
        self.assertTrue(p["understood"])
        self.assertIn("youtube.com", p["sites"])
        self.assertIn("ND site-block", p["router_script"])
        self.assertIn("cache flush", p["undo_script"])

    def test_block_category(self):
        p = A.plan("block social media for everyone")
        self.assertEqual(p["kind"], "sites")
        self.assertTrue(any("instagram" in s or "facebook" in s for s in p["sites"]))

    def test_unblock_runs_removal(self):
        p = A.plan("unblock instagram")
        self.assertEqual(p["kind"], "sites")
        self.assertIn("Unblock", p["title"])
        # unblocking applies the removal; its router_script must NOT add a block line
        self.assertNotIn("match-subdomain=yes", p["router_script"])
        self.assertIn("remove", p["router_script"])
        self.assertIn("match-subdomain=yes", p["undo_script"])

    def test_slow(self):
        for s in ("internet is slow", "google sheets keeps loading", "pages hang, mtu issue"):
            self.assertEqual(A.plan(s)["kind"], "slow", s)

    def test_scan(self):
        self.assertEqual(A.plan("check my network for problems")["kind"], "scan")

    def test_exposure_without_ip_scans(self):
        p = A.plan("a camera is open to the internet")
        self.assertEqual(p["kind"], "scan")
        self.assertTrue(p["understood"])

    def test_exposure_with_ip_handed_to_recipe(self):
        p = A.plan("192.168.0.203 can be opened from the internet")
        self.assertEqual(p["kind"], "recipe")
        self.assertIn("192.168.0.203", p["recipe_text"])

    def test_dhcp_offer_loop_router_text(self):
        p = A.plan("dhcp1 offering lease 192.168.0.38 for FE:EA:4C:27:3C:36 without success")
        self.assertEqual(p["kind"], "recipe")
        self.assertTrue(p["understood"])

    def test_dhcp_plain_phrasings(self):
        for txt in ("dhcp offering lease failed", "dhcp lease failed"):
            p = A.plan(txt)
            self.assertTrue(p["understood"], txt)
            self.assertEqual(p["kind"], "recipe", txt)

    def test_dhcp_recipe_offers_reserve(self):
        r = AL.recipe("dhcp1 offering lease 192.168.0.38 for FE:EA:4C:27:3C:36 without success")
        self.assertEqual(r["kind"], "dhcp_fail")
        self.assertTrue(r["auto"])                     # a one-click reserve is offered
        self.assertIn("192.168.0.38", r["auto"][0]["cmd"])
        self.assertIn("FE:EA:4C:27:3C:36", r["auto"][0]["cmd"])

    def test_dhcp_pool_full_not_misread_as_new_device(self):
        # the pool text contains "new devices may get no address" - must classify as dhcp_full, not new_device
        r = AL.recipe("The DHCP pool is almost full - new devices may get no address. Widen the range.")
        self.assertEqual(r["kind"], "dhcp_full")
        self.assertTrue(r["auto"])                      # offers the lease-time fix
        self.assertIn("lease", r["auto"][0]["cmd"])

    def test_real_new_device_still_classifies(self):
        r = AL.recipe("6 new device(s) on the network (3 Phones): iPhone-16 192.168.0.17")
        self.assertEqual(r["kind"], "new_device")

    def test_unknown(self):
        p = A.plan("make me a sandwich")
        self.assertEqual(p["kind"], "none")
        self.assertFalse(p["understood"])

    def test_empty(self):
        self.assertEqual(A.plan("")["kind"], "none")


if __name__ == "__main__":
    unittest.main()
