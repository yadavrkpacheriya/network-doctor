# -*- coding: utf-8 -*-
"""3.21.2: nd_tools.mentioned_devices() - turn a MAC/IP buried in an alert's text into rows with a name, type
and IP the person can actually read, search on and copy."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_core as core  # noqa: E402
import nd_tools as T  # noqa: E402


def dev(ip, mac, name="", cat=core.CAT_PC):
    return {"ip": ip, "mac": mac, "name": name, "category": cat}


class MentionedDevices(unittest.TestCase):
    def test_empty_text_or_no_devices_gives_nothing(self):
        self.assertEqual(T.mentioned_devices("", [dev("192.168.0.5", "AA:BB:CC:00:00:01")]), [])
        self.assertEqual(T.mentioned_devices("AA:BB:CC:00:00:01 did something", []), [])

    def test_a_known_mac_comes_back_with_its_full_device_details(self):
        devices = [dev("192.168.0.31", "5A:5A:02:8C:D5:F2", "Camera .31", core.CAT_CAM)]
        text = "Broadcast storm: 675/s - top senders 5a:5a:02:8c:d5:f2 (259)"
        out = T.mentioned_devices(text, devices)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["name"], "Camera .31")
        self.assertEqual(out[0]["category"], core.CAT_CAM)
        self.assertEqual(out[0]["ip"], "192.168.0.31")
        self.assertEqual(out[0]["mac"], "5A:5A:02:8C:D5:F2")
        self.assertEqual(out[0]["note"], "259 pkt/s")

    def test_several_macs_keep_their_first_seen_order_and_each_gets_a_row(self):
        devices = [dev("192.168.0.31", "5A:5A:02:8C:D5:F2", "Camera .31"), dev("192.168.0.69", "00:12:43:43:1B:13", "Camera .69")]
        text = "top senders 5A:5A:02:8C:D5:F2 (259), 00:12:43:43:1B:13 (50)"
        out = T.mentioned_devices(text, devices)
        self.assertEqual([r["mac"] for r in out], ["5A:5A:02:8C:D5:F2", "00:12:43:43:1B:13"])
        self.assertEqual(out[1]["note"], "50 pkt/s")

    def test_a_mac_not_in_the_current_device_list_still_gets_a_copyable_row(self):
        out = T.mentioned_devices("ARP spoofing: D4:D6:DF:0F:EB:87 claims to be the router",
                                  [dev("192.168.0.1", "AA:BB:CC:00:00:01", "Router")])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["mac"], "D4:D6:DF:0F:EB:87")
        self.assertEqual(out[0]["name"], "")
        self.assertEqual(out[0]["category"], "not in current device list")

    def test_the_same_mac_mentioned_twice_is_only_listed_once(self):
        devices = [dev("192.168.0.1", "AA:BB:CC:00:00:01", "Router")]
        text = "Router MAC AA:BB:CC:00:00:01 changed - was AA:BB:CC:00:00:01 before"
        self.assertEqual(len(T.mentioned_devices(text, devices)), 1)

    def test_an_ip_with_no_mac_in_the_text_is_matched_by_ip_too(self):
        devices = [dev("192.168.0.106", "D4:D6:DF:0F:EB:87", "DVR", core.CAT_CAM)]
        out = T.mentioned_devices("192.168.0.106: Dahua DVR/NVR is reachable from the internet", devices)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["name"], "DVR")
        self.assertEqual(out[0]["mac"], "D4:D6:DF:0F:EB:87")

    def test_an_ip_that_matches_no_device_is_skipped_not_shown_as_an_empty_row(self):
        out = T.mentioned_devices("255.255.255.255 port 51413", [dev("192.168.0.1", "AA:BB:CC:00:00:01")])
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()
