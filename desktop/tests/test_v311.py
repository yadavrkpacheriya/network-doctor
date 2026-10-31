# -*- coding: utf-8 -*-
"""Network Doctor 3.11: multi-network scan, router device list (SNMP), network guard, inventory, .rsc files,
usage history / productivity / learning, DNS answers for the usage history."""

import os
import socket
import struct
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import nd_core as core  # noqa: E402
import nd_dnsfilter as DF  # noqa: E402
import nd_snmp as S  # noqa: E402
import nd_tools as T  # noqa: E402
import nd_usage as U  # noqa: E402
from test_snmp import FakeAgent  # noqa: E402


class Networks(unittest.TestCase):
    def test_parse_several(self):
        n = core.parse_nets("192.168.0.0/24, 192.168.1.0/24;10.0.0.5/30")
        self.assertEqual([str(x) for x in n], ["192.168.0.0/24", "192.168.1.0/24", "10.0.0.4/30"])

    def test_limits(self):
        with self.assertRaises(ValueError):
            core.parse_nets("10.0.0.0/16")
        with self.assertRaises(ValueError):
            core.parse_nets("")
        self.assertEqual(len(core.parse_nets("192.168.0.0/22")), 1)

    def test_router_arp_over_snmp(self):
        mib = {f"{core.ARP_OID}.2.192.168.0.20": bytes.fromhex("C056E3AABB01"),
               f"{core.ARP_OID}.2.192.168.1.64": bytes.fromhex("C056E3AABB02"),
               f"{core.ARP_OID}.2.192.168.0.99": bytes.fromhex("FFFFFFFFFFFF"),  # broadcast entry ignored
               "1.3.6.1.2.1.4.23.0": 1}
        agent = FakeAgent(mib, community="netdoctor")
        arp, comm = core.router_arp_table("127.0.0.1", None, timeout=0.5, port=agent.port)
        self.assertEqual(comm, "netdoctor")
        self.assertEqual(arp, {"192.168.0.20": "C0:56:E3:AA:BB:01", "192.168.1.64": "C0:56:E3:AA:BB:02"})


class Guard(unittest.TestCase):
    def test_commands_and_undo(self):
        a, u = T.guard_commands({"dhcp": True, "dns": True, "dns_target": "router", "random": True},
                                ["AA:BB:CC:DD:EE:01"], "192.168.0.10", "bridge")
        self.assertIn("src-port=67 dst-port=68 action=drop", a)
        self.assertIn("src-mac-address=AA:BB:CC:DD:EE:01/FF:FF:FF:FF:FF:FF", a)
        self.assertIn("action=redirect to-ports=53", a)
        self.assertIn("02:00:00:00:00:00/02:00:00:00:00:00", a)
        for line in u.splitlines()[1:]:
            self.assertIn("remove", line)
        a2, _ = T.guard_commands({"dns": True, "dns_target": "pc"}, [], "192.168.0.10")
        self.assertIn("to-addresses=192.168.0.10 to-ports=53", a2)
        self.assertIn("src-address=!192.168.0.10", a2)  # this PC's own look-ups are not looped back to itself
        self.assertEqual(a.count("{"), a.count("}"))

    def test_rogue_candidates(self):
        devs = [{"ip": "192.168.0.1", "mac": "M0", "online": True, "ports": [53]},
                {"ip": "192.168.0.50", "mac": "M1", "online": True, "ports": [80, 53]},
                {"ip": "192.168.0.51", "mac": "M2", "online": True, "ports": [80]}]
        raw = {"meta": {"tests": {"dhcp": {"192.168.0.1": {}, "192.168.0.51": {}}}}}
        c = {x["dev"]["ip"]: x["why"] for x in T.rogue_candidates(devs, raw, "192.168.0.1")}
        self.assertEqual(set(c), {"192.168.0.50", "192.168.0.51"})
        self.assertIn("DHCP", c["192.168.0.51"])


class Rsc(unittest.TestCase):
    def test_import_friendly(self):
        d = tempfile.mkdtemp()
        name = T.write_rsc(os.path.join(d, "IP MAC binding (1).rsc"), "/ip dhcp-server lease\nadd comment=\"Café\"\n",
                           "remove\n")
        self.assertEqual(name, "IP-MAC-binding--1-.rsc")
        raw = open(os.path.join(d, name), "rb").read()
        self.assertNotIn(b"\r", raw)
        raw.decode("ascii")
        self.assertTrue(raw.startswith(b':put "Network Doctor: apply - start"'))
        self.assertTrue(os.path.exists(os.path.join(d, "IP-MAC-binding--1--undo.rsc")))


class Inventory(unittest.TestCase):
    def test_merge(self):
        db = {"devices": {"AA:00:00:00:00:02": {"first_seen": "2026-10-01", "last_seen": "2026-10-20 10:00",
                                                "ip": "192.168.0.9", "names": ["OLD-PC"]}},
              "tags": {"AA:00:00:00:00:01": {"name": "Accounts PC", "dept": "Accounts"}},
              "pc_reports": {"ACC-PC": {"macs": ["AA:00:00:00:00:01"], "os": "Windows 11 Pro", "time": "t",
                                        "hw": T.clean_hw({"model": "OptiPlex 7090", "serial": "ABC123", "ram_gb": 16,
                                                          "last_boot": "20261030083000.500000+330"})}}}
        devs = [{"mac": "AA:00:00:00:00:01", "ip": "192.168.0.40", "online": True, "name": "ACC-PC",
                 "vendor": "Dell", "category": "Computers", "first_seen": "2026-09-01", "names": {}}]
        leases = [{"mac-address": "AA:00:00:00:00:03", "address": "192.168.0.77", "host-name": "Galaxy-S23"}]
        rows = {r["mac"]: r for r in T.inventory_rows(devs, db, leases)}
        self.assertEqual(rows["AA:00:00:00:00:01"]["name"], "Accounts PC")
        self.assertEqual(rows["AA:00:00:00:00:01"]["model"], "OptiPlex 7090")
        self.assertEqual(rows["AA:00:00:00:00:01"]["serial"], "ABC123")
        self.assertEqual(rows["AA:00:00:00:00:02"]["status"], "last seen 2026-10-20 10:00")
        self.assertEqual(rows["AA:00:00:00:00:03"]["host"], "Galaxy-S23")
        self.assertEqual(T.clean_hw({"last_boot": "20261030083000.500000+330"})["last_boot"], "2026-10-30 08:30")
        p = os.path.join(tempfile.mkdtemp(), "inv.csv")
        T.export_inventory_csv(p, list(rows.values()))
        self.assertIn("OptiPlex 7090", open(p, encoding="utf-8-sig").read())


class Usage(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "usage.db")
        self.s = U.UsageStore(self.path)
        self.s.set_devices([{"mac": "AA:00:00:00:00:01", "ip": "192.168.0.40", "name": "ACC-PC", "online": True}],
                           {"AA:00:00:00:00:01": {"dept": "Accounts"}})
        self.s.learn_names([("142.250.1.1", "rr3---sn-a.googlevideo.com"), ("52.96.1.1", "outlook.office365.com"),
                            ("13.107.1.1", "teams.microsoft.com"), ("10.0.0.1", "private.lan")])

    def test_site_and_classify(self):
        self.assertEqual(U.site_of("rr3---sn-a.googlevideo.com"), "googlevideo.com")
        self.assertEqual(U.site_of("services.gst.gov.in"), "gst.gov.in")
        self.assertEqual(U.site_of("mail.google.com"), "mail.google.com")
        self.assertEqual(U.classify("teams.microsoft.com")[1], U.WORK)
        self.assertEqual(U.classify("googlevideo.com"), ("YouTube", U.PERSONAL))
        self.assertEqual(U.classify("", "", 6881)[1], U.PERSONAL)
        self.assertEqual(U.classify("unknown.example")[0], "unknown.example")
        self.assertEqual(U.productivity(30, 10), 75)
        self.assertIsNone(U.productivity(0, 0))

    def test_flows_to_summary(self):
        t0 = time.mktime(time.localtime()[:3] + (10, 0, 0, 0, 0, -1))
        for i in range(12):  # one hour, every 5 minutes: video and Teams
            self.s.add_flow("192.168.0.40", "142.250.1.1", 443, 6, 2_000_000, False, now=t0 + i * 300)
            self.s.add_flow("192.168.0.40", "13.107.1.1", 443, 6, 400_000, False, now=t0 + i * 300 + 10)
        self.s.add_flow("192.168.0.40", "8.8.8.8", 53, 17, 500, True, now=t0 + 3700)
        sm = self.s.summary(1)
        apps = {a["app"]: a for a in sm["apps"]}
        self.assertEqual(apps["YouTube"]["bytes"], 24_000_000)
        self.assertEqual(apps["YouTube"]["cat"], U.PERSONAL)
        self.assertEqual(apps["Microsoft 365"]["cat"], U.WORK)
        dev = sm["devices"][0]
        self.assertEqual(dev["name"], "ACC-PC")
        self.assertEqual(dev["dept"], "Accounts")
        self.assertEqual(dev["personal"], 60)   # 12 active 5-minute slots
        self.assertEqual(dev["work"], 60)
        self.assertEqual(dev["score"], 50)
        self.assertEqual(dev["top"], "YouTube")
        self.assertIn("googlevideo.com", [x["site"] for x in sm["sites"]])

    def test_user_category_wins_and_rewrites_history(self):
        t0 = time.time()
        self.s.add_flow("192.168.0.40", "142.250.1.1", 443, 6, 1000, False, now=t0)
        self.s.set_category("app", "YouTube", U.WORK)
        self.assertEqual({a["app"]: a["cat"] for a in self.s.summary(1)["apps"]}["YouTube"], U.WORK)
        s2 = U.UsageStore(self.path)  # remembered
        self.assertEqual(U.classify("googlevideo.com", overrides=s2.overrides)[1], U.WORK)
        self.s.set_category("app", "YouTube", None)
        self.assertEqual({a["app"]: a["cat"] for a in self.s.summary(1)["apps"]}["YouTube"], U.PERSONAL)

    def test_dns_visits(self):
        self.s.dns_seen("192.168.0.40", "www.flipkart.com", ["104.1.1.1"])
        sm = self.s.summary(1)
        site = next(x for x in sm["sites"] if x["site"] == "flipkart.com")
        self.assertEqual(site["visits"], 1)
        self.assertEqual(site["cat"], U.PERSONAL)
        self.assertEqual(self.s.ip_name["104.1.1.1"], "www.flipkart.com")

    def test_learning_finds_peak_habit_and_heavy_device(self):
        import datetime as dt
        for back in range(6, -1, -1):
            day = dt.date.today() - dt.timedelta(days=back)
            for hour in (9, 11, 15):
                t = time.mktime((day.year, day.month, day.day, hour, 0, 0, 0, 0, -1))
                big = 40_000_000 if hour == 15 else 5_000_000
                self.s.add_flow("192.168.0.40", "142.250.1.1", 443, 6, big, False, now=t)
                self.s.add_flow("192.168.0.40", "52.96.1.1", 443, 6, 3_000_000, False, now=t + 1)
        self.s.add_flow("192.168.0.40", "142.250.1.1", 443, 6, 3_000_000_000, False, now=time.time())
        ins = self.s.insights()
        titles = " | ".join(i["title"] for i in ins)
        self.assertIn("Busiest hours", titles)
        busy = next(i for i in ins if i["title"].startswith("Busiest"))
        self.assertIn("YouTube", busy["text"])
        self.assertIn("Website firewall", busy["action"])
        self.assertIn("not work", titles)

    def test_dashboard_html(self):
        self.s.add_flow("192.168.0.40", "142.250.1.1", 443, 6, 1000, False)
        html = U.dashboard_html(self.s, 30)
        self.assertIn('"YouTube"', html)
        self.assertNotIn("/*DATA*/null", html)
        self.assertNotIn("</script><", html.split("const D=")[1].split(";\nconst CATS")[0])


class DnsAnswers(unittest.TestCase):
    def test_answer_ips(self):
        q = b"\x12\x34\x81\x80" + struct.pack("!HHHH", 1, 2, 0, 0) + b"\x03www\x07example\x03com\x00" + b"\x00\x01\x00\x01"
        cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, 2) + b"\xc0\x10"
        a = b"\xc0\x10" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.216.34")
        self.assertEqual(DF.answer_ips(q + cname + a), ["93.184.216.34"])
        self.assertEqual(DF.answer_ips(b"\x00"), [])


if __name__ == "__main__":
    unittest.main()
