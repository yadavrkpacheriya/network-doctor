# -*- coding: utf-8 -*-
"""Tests for the "what changed since the last scan" features: the request was "32 cameras yesterday, 40
today, but I can't find the difference" - these make the diff explicit instead of a bare count:

- nd_core.short_category / category_counts / breakdown_text: "6 CCTV cameras, 2 Phones" instead of "8"
- nd_core._update_db records db["last_online_macs"], the snapshot the next scan diffs against
- nd_core.analyse() raises a "stopped answering since last scan" issue (the new half; "new device(s)
  since the last scan" already existed) with a category breakdown in its title
- nd_tools.filter_devices' two new SHOW choices that isolate exactly the new/missing devices
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_core as core  # noqa: E402
import nd_tools as T  # noqa: E402


def dev(mac, category, online=True, ip="192.168.0.10", name="", vendor="", random=False, notes=None):
    return {"mac": mac, "ip": ip, "ips": [ip], "category": category, "online": online, "name": name,
            "vendor": vendor, "random": random, "notes": notes if notes is not None else [], "http": {},
            "upnp": {}, "ports": [], "names": {}, "reason": "", "tag": {}}


def fresh_db(scans=1, last_online_macs=()):
    return {"devices": {}, "labels": {}, "tags": {}, "ip_owner": {}, "scans": scans,
            "last_online_macs": list(last_online_macs)}


def raw_with(tests=None):
    t = {"gw_ping": {"loss": 0, "avg": 2, "max": 5, "count": 30}}
    t.update(tests or {})
    return {"meta": {"started": core.now_s(), "gateway": "192.168.0.1", "local_ip": "192.168.0.10",
                     "subnet": "192.168.0.0/24", "admin": True, "scapy": False, "local_subnet": True,
                     "self_dhcp": True, "self_lease": 86400, "tests": t},
            "arp": {}, "ping": {}, "ports": {}, "http": {}, "nbns": {}, "dns": {}, "upnp": {}, "self_mac": ""}


def titles(issues):
    return [i["title"] for i in issues]


class CategoryBreakdown(unittest.TestCase):
    def test_short_category_strips_the_long_description(self):
        self.assertEqual(core.short_category(core.CAT_CAM), "CCTV cameras")
        self.assertEqual(core.short_category(core.CAT_NET), "Network equipment")
        self.assertEqual(core.short_category(""), "")
        self.assertEqual(core.short_category(None), "")

    def test_category_counts_sorted_most_common_first(self):
        ds = [dev("m1", core.CAT_CAM), dev("m2", core.CAT_CAM), dev("m3", core.CAT_PHONE)]
        self.assertEqual(list(core.category_counts(ds).items()), [("CCTV cameras", 2), ("Phones", 1)])

    def test_breakdown_text(self):
        ds = [dev("m1", core.CAT_CAM), dev("m2", core.CAT_CAM), dev("m3", core.CAT_PHONE)]
        self.assertEqual(core.breakdown_text(ds), "2 CCTV cameras, 1 Phones")
        self.assertEqual(core.breakdown_text([]), "")


class LastOnlineSnapshot(unittest.TestCase):
    def test_update_db_records_last_online_macs(self):
        db = fresh_db(scans=0, last_online_macs=["old1"])
        raw = raw_with()
        devices = [dev("m1", core.CAT_CAM), dev("m2", core.CAT_PHONE, online=False)]
        core._update_db(db, raw, devices)
        self.assertEqual(db["last_online_macs"], ["m1"])  # offline device excluded
        self.assertEqual(db["scans"], 1)

    def test_macless_devices_never_enter_the_snapshot(self):
        db = fresh_db(scans=0)
        core._update_db(db, raw_with(), [dev("", core.CAT_CAM)])
        self.assertEqual(db["last_online_macs"], [])


class MissingDeviceIssue(unittest.TestCase):
    def test_flags_a_device_that_answered_last_scan_and_now_does_not(self):
        db = fresh_db(scans=3, last_online_macs=["cam1", "cam2", "pc1"])
        db["devices"] = {
            "cam1": {"category": core.CAT_CAM, "names": ["Gate camera"], "ip": "192.168.0.101", "vendor": "Hikvision"},
            "cam2": {"category": core.CAT_CAM, "names": ["Lobby camera"], "ip": "192.168.0.102", "vendor": "Hikvision"},
            "pc1": {"category": core.CAT_PC, "names": ["Accounts PC"], "ip": "192.168.0.21", "vendor": "Dell"},
        }
        online_now = [dev("pc1", core.CAT_PC)]  # both cameras dropped off; pc1 still answers
        # the offline stub build_devices() would add for a recently-missing, still-known device
        stubs = [dev("cam1", core.CAT_OFF, online=False), dev("cam2", core.CAT_OFF, online=False)]
        devices = online_now + stubs
        issues, _ = core.analyse(raw_with(), devices, db)
        missing = [i for i in issues if "stopped answering" in i["title"]]
        self.assertEqual(len(missing), 1)
        self.assertIn("2 device(s) stopped answering since the last scan", missing[0]["title"])
        self.assertIn("CCTV cameras", missing[0]["title"])
        self.assertEqual(len(missing[0]["items"]), 2)

    def test_no_issue_when_nothing_dropped_off(self):
        db = fresh_db(scans=2, last_online_macs=["pc1"])
        db["devices"] = {"pc1": {"category": core.CAT_PC, "names": [], "ip": "192.168.0.21", "vendor": "Dell"}}
        issues, _ = core.analyse(raw_with(), [dev("pc1", core.CAT_PC)], db)
        self.assertEqual([i for i in issues if "stopped answering" in i["title"]], [])

    def test_no_issue_on_the_very_first_scan(self):
        db = fresh_db(scans=0, last_online_macs=[])
        issues, _ = core.analyse(raw_with(), [dev("pc1", core.CAT_PC, online=False)], db)
        self.assertEqual([i for i in issues if "stopped answering" in i["title"]], [])


class DevicesTabFilters(unittest.TestCase):
    def _devs(self):
        return [
            dev("m1", core.CAT_CAM, notes=["NEW on the network"], name="New camera"),
            dev("m2", core.CAT_CAM, online=False, notes=["STOPPED ANSWERING since last scan"], name="Dead camera"),
            dev("m3", core.CAT_PC, name="Ordinary PC"),
        ]

    def test_new_since_last_scan_filter(self):
        out = T.filter_devices(self._devs(), show="New since last scan")
        self.assertEqual([d["name"] for d in out], ["New camera"])

    def test_stopped_answering_filter(self):
        out = T.filter_devices(self._devs(), show="Stopped answering since last scan")
        self.assertEqual([d["name"] for d in out], ["Dead camera"])

    def test_unfiltered_still_returns_everything(self):
        self.assertEqual(len(T.filter_devices(self._devs())), 3)


if __name__ == "__main__":
    unittest.main()
