# -*- coding: utf-8 -*-
"""ARP sweep across common subnets - finds a camera on a different subnet (the '4th camera won't show' case),
because ARP is a Layer-2 broadcast that crosses subnets on one switch."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_poecheck as P  # noqa: E402


class ArpSweep(unittest.TestCase):
    def test_finds_devices_across_subnets(self):
        replies = {
            "192.168.0.0/24": {"192.168.0.70": {"F8:75:A4:00:00:70"}},
            "192.168.1.0/24": {"192.168.1.108": {"3C:EF:8C:11:22:33"}},   # the off-subnet 4th camera
        }
        res = P.arp_sweep(["192.168.0.0/24", "192.168.1.0/24", "10.0.0.0/24"],
                          lambda net: replies.get(net, {}))
        ips = {r["ip"] for r in res}
        self.assertIn("192.168.1.108", ips)                 # found despite being on another subnet
        cam = next(r for r in res if r["ip"] == "192.168.1.108")
        self.assertEqual(cam["mac"], "3C:EF:8C:11:22:33")
        self.assertEqual(cam["how"], "ARP")

    def test_a_failing_subnet_is_skipped_not_fatal(self):
        def arp(net):
            if net == "bad":
                raise OSError("no iface")
            return {"192.168.1.5": {"AA:BB:CC:DD:EE:FF"}}
        res = P.arp_sweep(["bad", "192.168.1.0/24"], arp)
        self.assertEqual([r["ip"] for r in res], ["192.168.1.5"])

    def test_no_duplicate_ips(self):
        res = P.arp_sweep(["a", "b"], lambda net: {"192.168.1.9": {"AA:AA:AA:AA:AA:AA"}})
        self.assertEqual(len(res), 1)


if __name__ == "__main__":
    unittest.main()
