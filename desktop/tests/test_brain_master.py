# -*- coding: utf-8 -*-
"""Master-brain upgrade: fix recipes per kind, window-aware recurrence, and the recurring-issue pattern finder."""
import unittest

import nd_brain as BR


class Recipes(unittest.TestCase):
    def test_regular_issues_have_recipes_and_safe_flags(self):
        self.assertTrue(BR.recipe("ip_conflict")["auto"])          # safe -> self-heals
        self.assertTrue(BR.recipe("dhcp_conflict")["auto"])
        self.assertFalse(BR.recipe("bogus_mac")["auto"])           # blocks/binding -> reviewed
        self.assertFalse(BR.recipe("random_mac")["auto"])
        self.assertIsNone(BR.recipe("not_a_kind"))

    def test_decide_attaches_the_recipe(self):
        kb = BR.blank()
        BR.seed(kb)
        d = BR.decide(kb, "two devices use the same ip 192.168.0.64", recipe_kind="ip_conflict",
                      cat="network")
        self.assertEqual(d["kind"], "ip_conflict")
        self.assertIn("recipe", d)
        self.assertTrue(d["recipe"]["permanent"])

    def test_seeded_curriculum_names_the_regular_issues(self):
        kb = BR.blank()
        BR.seed(kb)
        # no keyword rule given: the learned text model alone should lean to the right kind
        for text, kind in [("phone with a private randomized mac shows as a new device", "random_mac"),
                           ("cameras with a fake or cloned mac address", "bogus_mac"),
                           ("static ip clashes with the dhcp pool", "dhcp_conflict")]:
            d = BR.decide(kb, text)
            self.assertEqual(d["kind"], kind, text)


class Recurrence(unittest.TestCase):
    def test_recur_count_ignores_old_hits(self):
        kb = BR.blank()
        now = 1_000_000
        kb["recur"]["ip_conflict|network"] = [now - 8 * 86400, now - 100, now - 50]  # one is outside 7d
        self.assertEqual(BR.recur_count(kb, "ip_conflict|network", now=now), 2)

    def test_decide_recurring_uses_the_window(self):
        kb = BR.blank(); BR.seed(kb)
        now = 2_000_000
        kb["recur"]["ip_conflict|network"] = [now - 30, now - 20, now - 10]          # 3 recent
        d = BR.decide(kb, "ip conflict on the network", recipe_kind="ip_conflict", cat="network", now=now)
        self.assertTrue(d["recurring"])
        # all old -> not recurring any more
        kb["recur"]["ip_conflict|network"] = [now - 40 * 86400] * 5
        d2 = BR.decide(kb, "ip conflict on the network", recipe_kind="ip_conflict", cat="network", now=now)
        self.assertFalse(d2["recurring"])


class PatternFinder(unittest.TestCase):
    def test_recurring_report_ranks_and_attaches_recipes(self):
        kb = BR.blank()
        now = 3_000_000
        kb["recur"] = {
            "ip_conflict|network": [now - 10, now - 20, now - 30, now - 40],   # 4x
            "camera_down|cctv": [now - 5, now - 6, now - 7],                    # 3x
            "mtu|network": [now - 1],                                           # 1x -> below min
        }
        rep = BR.recurring_report(kb, now=now)
        self.assertEqual([r["kind"] for r in rep], ["ip_conflict", "camera_down"])
        self.assertEqual(rep[0]["count"], 4)
        self.assertTrue(rep[0]["recipe"]["auto"])          # ip_conflict self-heals
        self.assertFalse(rep[1]["recipe"]["auto"])         # camera reboot is reviewed


if __name__ == "__main__":
    unittest.main()
