"""3.14: daily 15:00 updates, inventory details / flags, driver pages, other-brand commands, torrent blocking."""
import os
import re
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_tools as T  # noqa: E402
import nd_update as U  # noqa: E402


def at(y, mo, d, h, mi=0):
    return time.mktime((y, mo, d, h, mi, 0, 0, 0, -1))


class DailyUpdate(unittest.TestCase):
    def test_last_daily(self):
        self.assertEqual(U.last_daily(at(2026, 10, 31, 14, 59)), at(2026, 10, 30, 15))
        self.assertEqual(U.last_daily(at(2026, 10, 31, 15, 1)), at(2026, 10, 31, 15))

    def test_due(self):
        self.assertTrue(U.daily_due(at(2026, 10, 31, 9), at(2026, 10, 31, 15, 2)))   # 15:00 passed, no check yet
        self.assertFalse(U.daily_due(at(2026, 10, 31, 15, 1), at(2026, 10, 31, 20)))  # checked after 15:00
        self.assertFalse(U.daily_due(at(2026, 10, 31, 9), at(2026, 10, 31, 14)))     # before 15:00, checked yesterday-ish
        self.assertTrue(U.daily_due(0, at(2026, 10, 31, 14)))                       # never checked


class Inventory(unittest.TestCase):
    def rows(self, hw):
        db = {"pc_reports": {"PC1": {"macs": ["AA:BB:CC:00:11:22"], "time": "now", "hw": T.clean_hw(hw)}}}
        return T.inventory_rows([], db, [{"mac-address": "AA:BB:CC:00:11:22", "address": "192.168.0.48",
                                          "host-name": "ACCOUNTS-PC"}])

    def test_details_and_flags(self):
        r = self.rows({"maker": "Dell Inc.", "model": "OptiPlex 3020", "serial": "7XK2Q2", "ram_gb": "4",
                       "disks": "HDD 500 GB (WDC)", "antivirus": "Quick Heal (OFF, OUT OF DATE)",
                       "printers": "HP LaserJet M1136", "mice": "HID mouse", "keyboards": "HID Keyboard",
                       "driver_problems": "PCI Simple Communications Controller (code 28)",
                       "last_update": "2026-01-02", "software": "Chrome|Tally|AnyDesk"})[0]
        self.assertEqual(r["ip"], "192.168.0.48")
        self.assertEqual(r["printers"], "HP LaserJet M1136")
        for f in ("driver problem", "low RAM", "HDD (no SSD)", "antivirus off / old"):
            self.assertIn(f, r["flags"])
        self.assertTrue(T.INV_FILTERS["Driver problems"](r))
        self.assertIn("Tally", r["software"])

    def test_good_pc_has_no_flags(self):
        r = self.rows({"model": "ThinkCentre", "ram_gb": "16", "disks": "SSD 512 GB", "disk_gb": "475",
                       "disk_free_gb": "200", "antivirus": "Windows Defender (on, up to date)",
                       "last_update": time.strftime("%Y-%m-%d")})[0]
        self.assertEqual(r["flags"], [])

    def test_csv_has_new_columns(self):
        heads = [c[1] for c in T.INV_COLS]
        for h in ("Disks", "Antivirus", "Printers", "Needs attention"):
            self.assertIn(h, heads)

    def test_driver_pages(self):
        self.assertIn("servicetag/7XK2Q2/drivers", T.driver_page("Dell Inc.", "7XK2Q2"))
        self.assertIn("lenovo.com", T.driver_page("LENOVO", "PF1ABC"))
        self.assertIn("hp.com", T.driver_page("HP", "CND123"))
        self.assertIn("bing.com", T.driver_page("Some Maker", "", "X1"))

    def test_local_inventory_command(self):
        cmd = T.local_inventory_cmd()
        self.assertEqual(cmd[0], "powershell")
        self.assertIn("ConvertTo-Json", cmd[-1])
        self.assertIn("SecurityCenter2", cmd[-1])


class Commands(unittest.TestCase):
    def test_brands_present(self):
        groups = {c[0] for c in T.COMMANDS}
        for g in ("Cisco switch / router (IOS)", "TP-Link switch (JetStream / Omada)", "D-Link switch (DGS / DES)",
                  "FortiGate firewall", "Antivirus", "Windows Firewall", "Drivers & updates", "Printers"):
            self.assertIn(g, groups)

    def test_shape_and_placeholders(self):
        v = T.command_values({"ip": "192.168.0.48", "mac": "AA:BB:CC:DD:EE:FF"}, "192.168.0.1", "", "192.168.0.70")
        self.assertEqual(v["mac_dot"], "aabb.ccdd.eeff")
        for c in T.COMMANDS:
            self.assertEqual(len(c), 5, c)
            text, _ = T.fill(c[3], v)
            self.assertNotIn("{ip}", text)
            self.assertNotIn("{lip}", text)
            # PowerShell script blocks must not look like placeholders
            for k in re.findall(r"\{(\w+)\}", text):
                self.assertFalse(v.get(k), c[2])  # known values are always filled in


class TorrentGuard(unittest.TestCase):
    def test_torrent_rules_and_undo(self):
        fix, undo = T.guard_commands({"torrent": True}, [], "192.168.0.70", "bridge")[:2]
        self.assertIn("BitTorrent protocol", fix)
        self.assertIn("place-before=([/ip firewall filter find]->0)", fix)
        self.assertIn("ND guard: torrent", fix)
        self.assertIn("ND guard", undo)


if __name__ == "__main__":
    unittest.main()
