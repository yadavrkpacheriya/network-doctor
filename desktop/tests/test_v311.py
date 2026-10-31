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
        self.assertEqual(U.classify("dropbox.com")[0], "Dropbox")  # 'x.com' must not match inside it
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
        self.assertEqual(apps["Microsoft Teams"]["cat"], U.WORK)
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
        self.assertEqual(self.s.name_for("192.168.0.40", "104.1.1.1"), ("www.flipkart.com", False))

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


class AppCatalogue(unittest.TestCase):
    def setUp(self):
        self.s = U.UsageStore(os.path.join(tempfile.mkdtemp(), "usage.db"))
        self.s.set_devices([{"mac": "AA:00:00:00:00:01", "ip": "192.168.0.40", "name": "SALES-1", "online": True},
                            {"mac": "AA:00:00:00:00:02", "ip": "192.168.0.41", "name": "ACC-1", "online": True}],
                           {"AA:00:00:00:00:01": {"dept": "Sales"}, "AA:00:00:00:00:02": {"dept": "Accounts"}})

    def test_meta_apps_are_told_apart(self):
        for name, app in (("mmg.whatsapp.net", "WhatsApp"), ("web.whatsapp.com", "WhatsApp"),
                          ("scontent-del1-1.cdninstagram.com", "Instagram"),
                          ("instagram.fdel1-1.fna.fbcdn.net", "Instagram"),
                          ("star-mini.c10r.facebook.com", "Facebook"), ("www.messenger.com", "Messenger"),
                          ("rr2---sn-ci5gup-qxa6.googlevideo.com", "YouTube"), ("music.youtube.com", "YouTube Music"),
                          ("doc-0k-6g-docs.googleusercontent.com", "Google Drive / Docs"),
                          ("drive.google.com", "Google Drive / Docs"), ("mail.google.com", "Gmail"),
                          ("meet.google.com", "Google Meet"), ("teams.microsoft.com", "Microsoft Teams"),
                          ("services.gst.gov.in", "GST portal"), ("www.flipkart.com", "Flipkart"),
                          ("api.dream11.com", "Fantasy / real-money games"), ("chatgpt.com", "ChatGPT")):
            self.assertEqual(U.classify(name)[0], app, name)
        self.assertEqual(U.classify("", "Meta Platforms Ireland Ltd")[0],
                         "Meta (Facebook / Instagram / WhatsApp - name not known)")
        self.assertEqual(len({d for _, _, _, ds in U.CATALOG for d in ds}),
                         sum(len(ds) for _, _, _, ds in U.CATALOG), "a domain is listed under two apps")

    def test_shared_front_end_is_not_guessed(self):
        self.s.learn_names([("142.250.1.1", "mail.google.com"), ("142.250.1.1", "www.youtube.com")])
        self.s.add_flow("192.168.0.41", "142.250.1.1", 443, 6, 1000, False)
        self.assertEqual([a["app"] for a in self.s.summary(1)["apps"]], ["Google (shared address)"])

    def test_device_own_lookup_wins(self):
        self.s.learn_names([("142.250.1.1", "mail.google.com"), ("142.250.1.1", "www.youtube.com")])
        self.s.dns_seen("192.168.0.41", "mail.google.com", ["142.250.1.1"])
        self.s.add_flow("192.168.0.41", "142.250.1.1", 443, 6, 1000, False)
        self.assertEqual([a["app"] for a in self.s.summary(1)["apps"]], ["Gmail"])

    def test_whatsapp_is_work_for_sales_only(self):
        self.s.learn_names([("157.240.1.60", "mmg.whatsapp.net")])
        self.s.add_flow("192.168.0.40", "157.240.1.60", 443, 6, 1000, False)
        self.s.add_flow("192.168.0.41", "157.240.1.60", 443, 6, 1000, False)
        self.s.set_category("app", "WhatsApp", U.WORK, dept="Sales")
        cats = {(a["app"], a["cat"]) for a in self.s.summary(1)["apps"]}
        self.assertEqual(cats, {("WhatsApp", U.WORK), ("WhatsApp", U.NEUTRAL)})
        self.s.add_flow("192.168.0.40", "157.240.1.60", 443, 6, 1000, False)  # new traffic follows it too
        sales = self.s.summary(1, dev="AA:00:00:00:00:01")["apps"]
        self.assertEqual([(a["cat"], a["bytes"]) for a in sales], [(U.WORK, 2000)])
        self.s.set_category("app", "WhatsApp", U.PERSONAL)  # everyone else; Sales keeps its own choice
        cats = {(a["app"], a["cat"]) for a in self.s.summary(1)["apps"]}
        self.assertEqual(cats, {("WhatsApp", U.WORK), ("WhatsApp", U.PERSONAL)})
        self.assertEqual(self.s.category_of("WhatsApp", "Sales"), U.WORK)
        lst = {x["app"]: x for x in self.s.app_list()}
        self.assertEqual(lst["WhatsApp"]["depts"], {"Sales": U.WORK})


class PhoneNames(unittest.TestCase):
    def test_dhcp_names_name_and_sort_phones(self):
        raw = {"meta": {"gateway": "192.168.0.1", "local_ip": "192.168.0.10", "started": "2026-10-31 10:00"},
               "arp": {"192.168.0.77": ["DA:A1:19:00:00:01"], "192.168.0.78": ["3C:52:82:01:02:03"],
                       "192.168.0.1": ["48:8F:5A:11:22:33"]},
               "ping": {"192.168.0.78": 128}, "ports": {"192.168.0.78": [445]}, "http": {}, "upnp": {}, "nbns": {},
               "dns": {}, "self_mac": "00:1A:2B:3C:4D:5E",
               "leases": {"DA:A1:19:00:00:01": {"host": "Galaxy-S23", "ip": "192.168.0.77"},
                          "3C:52:82:01:02:03": {"host": "ACCOUNTS-PC", "ip": "192.168.0.78"}}}
        db = {"labels": {}, "devices": {}, "ip_owner": {}, "scans": 0}
        devs = {d["ip"]: d for d in core.build_devices(raw, {}, db)}
        self.assertEqual(devs["192.168.0.77"]["name"], "Galaxy-S23")
        self.assertEqual(devs["192.168.0.77"]["category"], core.CAT_PHONE)
        self.assertEqual(devs["192.168.0.78"]["name"], "ACCOUNTS-PC")
        for n in ("Redmi-Note-12", "iPhone", "OPPO-A78", "vivo-Y21", "realme-narzo", "Pixel-7", "SM-A546E",
                  "android-5f3a1b2c"):
            self.assertRegex(n.lower(), core.PHONE_NAMES)

    def test_router_api_list_in_health_checks(self):
        r = {"meta": {"started": core.now_s(), "gateway": "192.168.0.1", "local_ip": "192.168.0.10",
                      "subnet": "192.168.0.0/24", "admin": True, "scapy": False, "local_subnet": True,
                      "self_dhcp": True, "self_lease": 86400,
                      "tests": {"router_arp": {"community": "router login (API)", "entries": 80}}},
             "arp": {}, "ping": {}, "ports": {}, "http": {}, "nbns": {}, "dns": {}, "upnp": {}, "self_mac": ""}
        r["leases"] = {"A": {"host": "Galaxy"}, "B": {"host": ""}}
        _, checks = core.analyse(r, [], {"devices": {}, "labels": {}, "scans": [], "ip_owner": {}, "bindings": {}})
        c = {x[0]: x for x in checks}
        self.assertEqual(c["Router device list"][1], "pass")
        self.assertIn("router login (API)", c["Router device list"][2])
        self.assertIn("1 of 2", c["Device names from the router"][2])
