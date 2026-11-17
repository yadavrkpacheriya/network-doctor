# -*- coding: utf-8 -*-
"""Direct-link discovery: an ARP reply on a different subnet (the off-subnet 4th camera) still becomes a
device in the scan - build_devices lists every raw['arp'] entry regardless of its IP range."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_core as core  # noqa: E402

try:
    from test_warning_fixes import fresh_db
except Exception:  # pragma: no cover
    fresh_db = None


@unittest.skipIf(fresh_db is None, "shared test helpers unavailable")
class L2Discover(unittest.TestCase):
    def test_off_subnet_arp_entry_becomes_a_device(self):
        # the PC is 192.168.0.70; the camera kept 192.168.1.108 - found only by the L2 ARP sweep
        raw = {"meta": {"gateway": "192.168.0.1", "local_ip": "192.168.0.70", "started": "2026-11-17"},
               "arp": {"192.168.1.108": {"3C:EF:8C:11:22:33"}, "192.168.0.70": {"F8:75:A4:00:00:70"}},
               "ping": {}, "ports": {}, "http": {}, "nbns": {}, "dns": {}, "upnp": {}, "self_mac": "F8:75:A4:00:00:70"}
        devs = core.build_devices(raw, {}, fresh_db())
        ips = {ip for d in devs for ip in d.get("ips", [])}
        self.assertIn("192.168.1.108", ips)                 # the off-subnet camera is listed
        cam = next(d for d in devs if "192.168.1.108" in d.get("ips", set()))
        self.assertEqual(cam["mac"], "3C:EF:8C:11:22:33")

    def test_common_subnets_cover_the_usual_camera_ranges(self):
        for n in ("192.168.0.0/24", "192.168.1.0/24", "10.0.0.0/24"):
            self.assertIn(n, core.L2_SUBNETS)


if __name__ == "__main__":
    unittest.main()
