# -*- coding: utf-8 -*-
"""3.21: scan finds devices on EVERY IP range (this PC's adapters + the router's tables) and lists MACs that have no IP."""
import ipaddress
import os
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_core as core  # noqa: E402
import nd_ranges as NR  # noqa: E402

N = ipaddress.ip_network

IPCONFIG = """
Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.0.70
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.0.1

Ethernet adapter vEthernet (WSL):

   IPv4 Address. . . . . . . . . . . : 172.20.32.1
   Subnet Mask . . . . . . . . . . . : 255.255.240.0

Wireless LAN adapter Wi-Fi:

   Autoconfiguration IPv4 Address. . : 169.254.12.5
   Subnet Mask . . . . . . . . . . . : 255.255.0.0

Ethernet adapter Ethernet 2:

   IPv4 Address. . . . . . . . . . . : 192.168.1.50(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 
"""

IP_ADDR = """1: lo    inet 127.0.0.1/8 scope host lo
2: eth0    inet 10.10.0.5/24 brd 10.10.0.255 scope global eth0
3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
"""

IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.0.9 netmask 0xffffff00 broadcast 192.168.0.255
"""


class Adapters(unittest.TestCase):
    def test_windows_all_adapters_skip_virtual_and_linklocal(self):
        nets = NR.nets_of(NR.parse_ipconfig(IPCONFIG))
        self.assertEqual(sorted(map(str, nets)), ["192.168.0.0/24", "192.168.1.0/24"])

    def test_linux_and_mac(self):
        self.assertEqual(list(map(str, NR.nets_of(NR.parse_ip_addr(IP_ADDR)))), ["10.10.0.0/24"])
        self.assertEqual(list(map(str, NR.nets_of(NR.parse_ifconfig(IFCONFIG)))), ["192.168.0.0/24"])

    def test_big_or_public_networks_are_not_adapters(self):
        self.assertEqual(NR.nets_of([("10.0.0.5", 8, "Ethernet"), ("8.8.8.8", 24, "Ethernet"), ("100.64.0.5", 24, "Ethernet")]), [])

    def test_local_networks_never_raises(self):
        def boom(*a, **k):
            raise OSError("x")
        self.assertEqual(NR.local_networks(boom, True, False), [])


class Plan(unittest.TestCase):
    def test_router_interfaces_and_seen_devices_are_added(self):
        cands = NR.router_candidates(
            [{"address": "192.168.0.1/24", "interface": "bridge"}, {"address": "192.168.1.1/24", "interface": "ether5"},
             {"address": "203.0.113.5/30", "interface": "ether1"}, {"address": "10.0.0.1/24", "interface": "x", "disabled": "true"}],
            [{"address": "192.168.0.0/24"}, {"address": "192.168.2.0/24"}])
        plan = NR.plan_extra_nets([N("192.168.0.0/24")], cands, ["10.9.9.4", "10.9.9.7", "172.16.5.9", "8.8.8.8"])
        got = {str(n) for n, _ in plan["added"]}
        self.assertEqual(got, {"192.168.1.0/24", "192.168.2.0/24", "10.9.9.0/24", "172.16.5.0/24"})

    def test_public_cgnat_linklocal_and_host_routes_never_added(self):
        cands = [(N("203.0.113.0/24"), "x"), (N("100.64.0.0/24"), "x"), (N("169.254.0.0/24"), "x"), (N("192.168.5.7/32"), "x")]
        self.assertEqual(NR.plan_extra_nets([N("192.168.0.0/24")], cands, ["100.64.1.1", "169.254.2.2"])["added"], [])

    def test_huge_router_range_only_adds_the_24s_with_devices(self):
        cands = [(N("10.0.0.0/8"), "router interface")]
        plan = NR.plan_extra_nets([N("192.168.0.0/24")], cands, ["10.4.4.4", "10.4.4.9", "10.7.0.2"])
        self.assertEqual([str(n) for n, _ in plan["added"]], ["10.4.4.0/24", "10.7.0.0/24"])

    def test_limit_is_respected_and_reported(self):
        seen = [f"10.{i}.0.5" for i in range(1, 40)]
        plan = NR.plan_extra_nets([N("192.168.0.0/24")], [], seen, limit=1024)
        total = 254 + sum(254 for _ in plan["added"])
        self.assertLessEqual(total, 1024)
        self.assertTrue(plan["skipped"])

    def test_already_covered_not_added_twice(self):
        plan = NR.plan_extra_nets([N("192.168.0.0/23")], [(N("192.168.1.0/24"), "x")], ["192.168.0.9"])
        self.assertEqual(plan["added"], [])


class MacOnly(unittest.TestCase):
    def test_only_unknown_external_macs(self):
        hosts = [{"mac-address": "aa:bb:cc:00:00:01", "on-interface": "ether3", "vid": "1"},
                 {"mac-address": "AA:BB:CC:00:00:02", "on-interface": "ether4", "local": "true"},
                 {"mac-address": "01:00:5E:00:00:05", "on-interface": "ether4"},
                 {"mac-address": "AA:BB:CC:00:00:03", "on-interface": "ether2"},
                 {"mac-address": "AA:BB:CC:00:00:01", "on-interface": "ether3"}]
        out = NR.mac_only_hosts(hosts, ["AA:BB:CC:00:00:03"])
        self.assertEqual([x["mac"] for x in out], ["AA:BB:CC:00:00:01"])
        self.assertEqual(out[0]["port"], "ether3")

    def test_neighbor_ips(self):
        self.assertEqual(NR.neighbor_ips([{"address": "192.168.1.9", "mac-address": "aa:bb:cc:dd:ee:ff"},
                                          {"address": "8.8.8.8", "mac-address": "aa:bb:cc:dd:ee:00"}, {}]),
                         {"192.168.1.9": "AA:BB:CC:DD:EE:FF"})


class Integration(unittest.TestCase):
    """core.scan() end to end with the network faked: the second range is swept and its devices appear."""

    def run_scan(self, opts):
        swept = []
        patches = [
            mock.patch.object(core, "detect_network", lambda: ("192.168.0.1", "192.168.0.70")),
            mock.patch.object(core, "ping", lambda ip, wait_ms=800: swept.append(ip) or (64 if ip in ("192.168.0.1", "192.168.1.20") else None)),
            mock.patch.object(core, "tcp_open", lambda ip, port, timeout=0.6: False),
            mock.patch.object(core, "netbios_query", lambda ip, timeout=1.2: None),
            mock.patch.object(core, "ssdp_discover", lambda lip, wait=4: {}),
            mock.patch.object(core, "http_info", lambda ip, port: None),
            mock.patch.object(core, "reverse_dns", lambda ip: ""),
            mock.patch.object(core, "os_arp_table", lambda: {"192.168.0.1": "AA:00:00:00:00:01"}),
            mock.patch.object(core, "local_mac", lambda lip: "AA:00:00:00:00:70"),
            mock.patch.object(core, "local_dhcp_enabled", lambda lip: True),
            mock.patch.object(core, "local_lease_seconds", lambda lip: None),
            mock.patch.object(core, "gateway_monitor", lambda gw, count, result: None),
            mock.patch.object(core, "dhcp_probe_udp", lambda mac, wait=5: []),
            mock.patch.object(core, "is_admin", lambda: False),
            mock.patch.object(core, "scapy_ok", lambda: False),
            mock.patch.object(core.NR, "local_networks", lambda run, w, m: [N("192.168.0.0/24")]),
            mock.patch("time.sleep", lambda s: None),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        raw = core.scan("192.168.0.0/24", opts, lambda p, t: None, threading.Event())
        return raw, swept

    def fetch(self):
        return {"arp": {"192.168.0.1": "AA:00:00:00:00:01", "192.168.1.20": "AA:00:00:00:01:20", "10.9.9.4": "AA:00:00:00:09:04"},
                "leases": {"AA:00:00:00:01:20": {"host": "Cam-Store", "ip": "192.168.1.20", "static": False, "status": "bound"}},
                "addresses": [{"address": "192.168.0.1/24", "interface": "bridge"},
                              {"address": "192.168.1.1/24", "interface": "ether5"}],
                "dhcp_networks": [], "neighbors": [],
                "hosts": [{"mac-address": "AA:00:00:00:01:20", "on-interface": "ether5"},
                          {"mac-address": "AA:00:00:00:77:77", "on-interface": "ether7", "vid": "1"}]}

    def test_other_ranges_are_swept_and_devices_found(self):
        raw, swept = self.run_scan({"router_fetch": self.fetch})
        self.assertIn("192.168.1.20", swept)
        self.assertIn("10.9.9.4", swept)
        self.assertEqual({a["net"] for a in raw["auto_ranges"]}, {"192.168.1.0/24", "10.9.9.0/24"})
        self.assertIn("192.168.1.20", raw["arp"])  # known by the router, not by this PC
        self.assertIn("192.168.1.0/24", raw["meta"]["subnet"])

    def test_switch_only_mac_becomes_an_issue(self):
        raw, _ = self.run_scan({"router_fetch": self.fetch})
        db = {"labels": {}, "devices": {}, "tags": {}, "ip_owner": {}, "scans": 0}
        devs = core.build_devices(raw, {}, db)
        self.assertEqual([x["mac"] for x in raw["mac_only"]], ["AA:00:00:00:77:77"])
        issues, checks = core.analyse(raw, devs, db)
        hit = [i for i in issues if "no IP in any scanned range" in i["title"]]
        self.assertEqual(len(hit), 1)
        self.assertIn("ether7", hit[0]["items"][0])

    def test_option_off_scans_only_the_given_range(self):
        raw, swept = self.run_scan({"router_fetch": self.fetch, "auto_ranges": False})
        self.assertNotIn("192.168.1.20", swept)
        self.assertEqual(raw["auto_ranges"], [])

    def test_router_failure_does_not_stop_the_scan(self):
        def bad():
            raise RuntimeError("router down")
        raw, swept = self.run_scan({"router_fetch": bad})
        self.assertIn("192.168.0.1", swept)
        self.assertEqual(raw["auto_ranges"], [])

    def test_no_router_login_still_scans(self):
        raw, swept = self.run_scan({})
        self.assertIn("192.168.0.1", swept)


if __name__ == "__main__":
    unittest.main()
