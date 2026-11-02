# -*- coding: utf-8 -*-
"""Tests for nd_linux with sample /proc and /sys files (they run on every OS)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_linux as L  # noqa: E402

ROUTE = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
"""

ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.168.0.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0
192.168.0.20     0x1         0x2         00:11:22:33:44:55     *        eth0
192.168.0.99     0x1         0x0         00:00:00:00:00:00     *        eth0
"""


def write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


class Proc(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        write(self.tmp.name, "net/route", ROUTE)
        write(self.tmp.name, "net/arp", ARP)

    def tearDown(self):
        self.tmp.cleanup()

    def test_gateway_lowest_metric(self):
        self.assertEqual(L.default_gateway(self.tmp.name), ("192.168.0.1", "eth0"))

    def test_no_route(self):
        write(self.tmp.name, "net/route", ROUTE.splitlines()[0] + "\n")
        self.assertEqual(L.default_gateway(self.tmp.name), (None, None))

    def test_arp_skips_incomplete(self):
        self.assertEqual(L.arp_table(self.tmp.name), {"192.168.0.1": "AA:BB:CC:DD:EE:01",
                                                      "192.168.0.20": "00:11:22:33:44:55"})

    def test_missing_files(self):
        self.assertEqual(L.arp_table("/nonexistent"), {})
        self.assertEqual(L.default_gateway("/nonexistent"), (None, None))


class Sys(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        r = self.tmp.name
        for rel, text in {"eth0/address": "00:11:22:33:44:55", "eth0/operstate": "up", "eth0/speed": "100",
                          "eth0/duplex": "half", "eth0/mtu": "1500", "eth0/statistics/rx_errors": "120",
                          "eth0/statistics/tx_errors": "3", "eth0/statistics/rx_dropped": "0",
                          "eth0/statistics/tx_dropped": "0", "eth0/device/vendor": "0x8086",
                          "wlan0/address": "a0:b1:c2:d3:e4:f5", "wlan0/operstate": "up", "wlan0/speed": "-1",
                          "wlan0/mtu": "1500", "wlan0/device/vendor": "0x14e4", "wlan0/wireless/x": "",
                          "docker0/address": "02:42:00:00:00:01", "docker0/operstate": "down",
                          "lo/address": "00:00:00:00:00:00"}.items():
            write(r, rel, text)

    def tearDown(self):
        self.tmp.cleanup()

    def test_adapters(self):
        addrs = {"eth0": ("192.168.0.50", 24), "wlan0": ("192.168.1.7", 24)}
        ads = {a["name"]: a for a in L.adapters(self.tmp.name, lambda n: addrs.get(n, (None, None)))}
        self.assertEqual(sorted(ads), ["docker0", "eth0", "wlan0"])  # lo left out
        e = ads["eth0"]
        self.assertEqual((e["status"], e["bps"], e["speed"], e["duplex"], e["mac"], e["rxerr"], e["ip"], e["prefix"]),
                         ("Up", 100_000_000, "100 Mbps", False, "00:11:22:33:44:55", 120, "192.168.0.50", 24))
        self.assertFalse(e["wifi"] or e["virtual"])
        w = ads["wlan0"]
        self.assertTrue(w["wifi"])
        self.assertEqual((w["bps"], w["duplex"]), (0, None))
        self.assertTrue(ads["docker0"]["virtual"])
        self.assertEqual(ads["docker0"]["status"], "Disconnected")

    def test_findings_use_linux_adapters(self):
        import nd_net
        addrs = {"eth0": ("192.168.0.50", 24)}
        ads = L.adapters(self.tmp.name, lambda n: addrs.get(n, (None, None)))
        text = " ".join(t for _, t in nd_net.adapter_findings(ads))
        self.assertIn("100 Mbps", text)
        self.assertIn("HALF duplex", text)
        self.assertIn("123 packet errors", text)


if __name__ == "__main__":
    unittest.main()
