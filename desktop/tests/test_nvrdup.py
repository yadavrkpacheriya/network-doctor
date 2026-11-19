# -*- coding: utf-8 -*-
"""Duplicate-camera detection across and within NVRs."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_nvrdup as ND  # noqa: E402


def ch(n, ip, mac=""):
    return {"chan": n, "ip": ip, "mac": mac, "name": "CAM%d" % n}


class NvrDup(unittest.TestCase):
    def test_same_camera_twice_in_one_nvr(self):
        nvrs = [{"nvr": "192.168.0.22", "name": "Upper NVR",
                 "channels": [ch(1, "192.168.0.31"), ch(2, "192.168.0.32"), ch(3, "192.168.0.31")]}]
        d = ND.find_duplicates(nvrs)
        self.assertEqual(len(d["within"]), 1)
        self.assertEqual(d["within"][0]["camera"], "192.168.0.31")
        self.assertEqual(d["within"][0]["channels"], [1, 3])
        self.assertEqual(d["cross"], [])

    def test_same_camera_on_two_nvrs(self):
        nvrs = [{"nvr": "192.168.0.22", "name": "Upper", "channels": [ch(1, "192.168.0.31")]},
                {"nvr": "192.168.0.74", "name": "Office", "channels": [ch(5, "192.168.0.31")]}]
        d = ND.find_duplicates(nvrs)
        self.assertEqual(d["within"], [])
        self.assertEqual(len(d["cross"]), 1)
        self.assertEqual({o["nvr"] for o in d["cross"][0]["on"]}, {"192.168.0.22", "192.168.0.74"})

    def test_mac_matches_even_if_ip_differs(self):
        nvrs = [{"nvr": "a", "name": "A", "channels": [ch(1, "192.168.0.31", "AA:BB:CC:00:00:01")]},
                {"nvr": "b", "name": "B", "channels": [ch(2, "192.168.1.31", "AA:BB:CC:00:00:01")]}]
        d = ND.find_duplicates(nvrs)
        self.assertEqual(len(d["cross"]), 1)        # same MAC = same camera, despite different IP

    def test_no_duplicates(self):
        nvrs = [{"nvr": "a", "name": "A", "channels": [ch(1, "192.168.0.31"), ch(2, "192.168.0.32")]}]
        d = ND.find_duplicates(nvrs)
        self.assertEqual(d["within"], [])
        self.assertEqual(d["cross"], [])

    def test_find_orphans(self):
        # a camera live on the network but on no recorder (and not a recorder itself) is an orphan
        nvrs = [{"nvr": "192.168.0.22", "name": "A", "channels": [ch(1, "192.168.0.31")]}]
        live = [{"ip": "192.168.0.31", "name": "in nvr"},   # already on NVR-A -> not orphan
                {"ip": "192.168.0.22", "name": "the NVR"},   # the recorder itself -> not orphan
                {"ip": "192.168.0.99", "name": "Gate"}]      # live, in no recorder -> ORPHAN
        o = ND.find_orphans(nvrs, live)
        self.assertEqual(len(o), 1)
        self.assertEqual(o[0]["ip"], "192.168.0.99")
        self.assertEqual(o[0]["name"], "Gate")

    def test_orphans_deduped_and_empty_safe(self):
        self.assertEqual(ND.find_orphans([], [{"ip": "1.1.1.1"}, {"ip": "1.1.1.1"}]), [{"ip": "1.1.1.1", "name": ""}])
        self.assertEqual(ND.find_orphans([], []), [])


if __name__ == "__main__":
    unittest.main()
