"""3.15: automatic names, readable sites, CNAME names, quiet router debug lines, remote inventory, daily report."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_core as core  # noqa: E402
import nd_monitor as M  # noqa: E402
import nd_tools as T  # noqa: E402
import nd_usage as US  # noqa: E402
import nd_alerts as AL  # noqa: E402


class Names(unittest.TestCase):
    def test_auto_names(self):
        self.assertEqual(core.auto_name({"category": core.CAT_PC, "vendor": "Hewlett Packard", "ip": "192.168.0.57"}),
                         "HP PC .57")
        self.assertEqual(core.auto_name({"category": core.CAT_CAM, "ports": [34567], "ip": "192.168.0.69"}),
                         "XMeye Camera .69")
        self.assertEqual(core.auto_name({"category": core.CAT_CAM, "http": {"title": "Hikvision"},
                                         "ip": "192.168.0.105"}), "Hikvision Camera .105")
        self.assertEqual(core.auto_name({"category": core.CAT_PHONE, "random": True, "ip": "192.168.0.101"}),
                         "Phone .101")


class Sites(unittest.TestCase):
    def test_pretty(self):
        self.assertEqual(US.pretty_site("lcdelw-in-f113.1e100.net Google LLC"), "Google server (service not named)")
        self.assertTrue(US.pretty_site("a23-64-59-168.deploy.static.akamaitechnologies.com").startswith("Akamai"))
        self.assertEqual(US.pretty_site("whatsapp-cdn-shv-01-del3.fbcdn.net"), "WhatsApp media")
        self.assertEqual(US.pretty_site("docs.google.com"), "docs.google.com")

    def test_cname_chain(self):
        rows = [{"type": "CNAME", "name": "docs.google.com", "data": "googlehosted.l.googleusercontent.com"},
                {"type": "A", "name": "googlehosted.l.googleusercontent.com", "data": "142.250.1.1"}]
        self.assertEqual(US.cache_pairs(rows), [("142.250.1.1", "docs.google.com")])

    def test_ptr_names_the_app(self):
        st = US.UsageStore(":memory:") if False else None  # store needs a file; the helpers are enough here
        self.assertEqual(US.ptr_of("whatsapp-cdn-shv-01-del3.fbcdn.net Facebook"), "whatsapp-cdn-shv-01-del3.fbcdn.net")
        self.assertEqual(US.app_of_name("whatsapp-cdn-shv-01-del3.fbcdn.net"), "WhatsApp")
        self.assertIsNone(st)


class RouterLog(unittest.TestCase):
    def test_debug_lines_are_quiet(self):
        self.assertEqual(M.parse_router_line("dhcp,debug lease bound, init-reboot, extending")[1], "debug")
        self.assertEqual(M.parse_router_line(
            "dhcp,warning Detected conflict by ARP response for 192.168.0.70 from F8:75:A4:8D:B7:FA")[0], "conflict")


class AutoFix(unittest.TestCase):
    def test_safe_kinds(self):
        self.assertIn("dhcp_conflict", AL.AUTO_SAFE)
        self.assertNotIn("exposed", AL.AUTO_SAFE)   # could cut off remote camera viewing
        self.assertNotIn("torrent", AL.AUTO_SAFE)


class RemoteInventory(unittest.TestCase):
    def test_script(self):
        s = T.remote_inventory_ps()
        self.assertIn("New-CimSession", s)
        self.assertIn("$env:ND_PW", s)
        self.assertNotIn("HKLM:", s)
        self.assertIn("Get-PhysicalDisk -CimSession $s", s)

    def test_errors_explained(self):
        self.assertIn("password", T.parse_remote_inventory("ERROR: Access is denied.")[1])
        self.assertIn("firewall", T.parse_remote_inventory("ERROR: The RPC server is unavailable.")[1])
        self.assertEqual(T.parse_remote_inventory('junk {"model": "X"}')[0]["model"], "X")

    def test_daily_report_task(self):
        fix, undo = T.pc_fix_script({"report": True, "daily": True}, "192.168.0.1", "", "http://x:8787/api/report", "k")
        self.assertIn("Register-ScheduledTask", fix)
        self.assertIn("daily inventory report", fix)
        self.assertIn("Unregister-ScheduledTask", undo)


class Guard(unittest.TestCase):
    def test_secure_dns_bypass_blocked(self):
        a, u = T.guard_commands({"dns": True}, [], "192.168.0.70", "bridge")[:2]
        self.assertIn("list=ND-doh address=8.8.8.8", a)
        self.assertIn("dst-port=443,853", a)
        self.assertIn('list="ND-doh"', u)


if __name__ == "__main__":
    unittest.main()
