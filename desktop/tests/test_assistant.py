import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_assistant as A


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

    def test_unknown(self):
        p = A.plan("make me a sandwich")
        self.assertEqual(p["kind"], "none")
        self.assertFalse(p["understood"])

    def test_empty(self):
        self.assertEqual(A.plan("")["kind"], "none")


if __name__ == "__main__":
    unittest.main()
