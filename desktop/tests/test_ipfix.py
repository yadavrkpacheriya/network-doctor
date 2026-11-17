# -*- coding: utf-8 -*-
"""Permanent fixed-IP conflict fix: choose the keeper, reserve on the router, switch the losing camera to DHCP."""
import unittest

import nd_ipfix as F
import nd_routeros as RO
from sim import FakeRouter, router_socket, RouterOS_against

A = "AA:BB:CC:00:00:64"   # a camera
B = "AA:BB:CC:00:00:65"   # the other device
IP = "192.168.0.64"


class ChooseKeeper(unittest.TestCase):
    def test_priority_tag_wins(self):
        who, why = F.choose_keeper(IP, [A, B], [], tags={A: {"priority": True, "name": "gate-cam"}})
        self.assertEqual(who, A)
        self.assertIn("tagged", why)

    def test_lease_holder_wins_when_untagged(self):
        who, why = F.choose_keeper(IP, [A, B], [{"address": IP, "mac-address": B}], tags={})
        self.assertEqual(who, B)                      # the device the router already knows keeps it
        self.assertIn("leases", why)

    def test_ambiguous_returns_none(self):
        who, why = F.choose_keeper(IP, [A, B], [], tags={})
        self.assertIsNone(who)                         # never guess
        self.assertIn("manual", why)

    def test_two_tagged_is_ambiguous(self):
        who, _ = F.choose_keeper(IP, [A, B], [], tags={A: {"priority": True}, B: {"priority": True}})
        self.assertIsNone(who)


class PermanentPlan(unittest.TestCase):
    def test_reserve_plus_switch_when_loser_is_a_known_camera(self):
        plan = F.permanent_plan(
            IP, [A, B],
            leases=[{"address": IP, "mac-address": A}],         # A holds the lease -> A keeps IP
            cameras=[{"mac": B, "ip": "192.168.0.99", "method": "hik", "name": "hall-cam"}],
            saved={B: ("admin", "pw")})
        self.assertEqual(plan["keeper"], A)
        self.assertTrue(plan["auto_router_ok"])
        self.assertIsNotNone(plan["reserve"])
        self.assertEqual(plan["switch"], {"ip": "192.168.0.99", "method": "hik",
                                          "cred": ("admin", "pw"), "mac": B})

    def test_no_switch_without_saved_login(self):
        plan = F.permanent_plan(IP, [A, B], leases=[{"address": IP, "mac-address": A}],
                                cameras=[{"mac": B, "ip": IP, "method": "hik"}], saved={})
        self.assertIsNone(plan["switch"])              # won't touch a camera with no saved login
        self.assertIsNotNone(plan["reserve"])

    def test_no_keeper_means_no_router_change(self):
        plan = F.permanent_plan(IP, [A, B], leases=[], cameras=[], saved={})
        self.assertFalse(plan["auto_router_ok"])
        self.assertIsNone(plan["reserve"])


class ReserveAgainstFakeRouter(unittest.TestCase):
    def test_reserve_makes_the_lease_static_on_the_router(self):
        fr = FakeRouter()
        fr.model.add_lease(IP, A, host="gate-cam", dynamic="true", status="bound")
        cmd, undo = F.reserve_recipe(IP, A, "gate-cam")
        # the app runs reserve recipes as a script; the fake maps make-static/set onto its lease table
        with router_socket(fr.model):
            r = RouterOS_against(fr.model)
            # emulate the make-static + address set the recipe performs
            lease = fr.model.tables["/ip/dhcp-server/lease"][0]
            with r:
                r.talk(["/ip/dhcp-server/lease/set", "=.id=" + lease[".id"],
                        "=dynamic=false", "=address=" + IP, "=comment=ND: fixed IP - gate-cam"])
            rows = None
            with r:
                rows = r.cmd("/ip/dhcp-server/lease/print", q_address=IP)
        self.assertEqual(rows[0]["dynamic"], "false")
        self.assertEqual(rows[0]["mac-address"], A)
        self.assertTrue(rows[0]["comment"].startswith("ND: fixed IP"))

    def test_reserve_recipe_uses_full_paths_and_is_undoable(self):
        cmd, undo = F.reserve_recipe(IP, A, "gate-cam")
        self.assertIn("/ip dhcp-server lease make-static", cmd)   # full path, not bare verb
        self.assertIn("/ip dhcp-server lease add", cmd)
        self.assertIn("make-static", cmd)
        self.assertIn("remove", undo)
        self.assertIn("ND: fixed IP", undo)


if __name__ == "__main__":
    unittest.main()
