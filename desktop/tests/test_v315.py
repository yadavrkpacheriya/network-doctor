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
        self.assertIn("ip_conflict", AL.AUTO_SAFE)
        self.assertNotIn("exposed", AL.AUTO_SAFE)   # could cut off remote camera viewing
        self.assertNotIn("torrent", AL.AUTO_SAFE)
        self.assertNotIn("malware", AL.AUTO_SAFE)   # cuts a device off outright - stays a manual, one-click fix

    def test_safe_kinds_carry_an_undo_command(self):
        """Every AUTO_SAFE fix must be revertible - that's what makes auto-applying it on the first
        occurrence (NetworkDoctor.AUTO_FIX_AFTER == 1) safe instead of reckless."""
        r = AL.explain("Detected conflict by ARP response for 192.168.0.70 from F8:75:A4:8D:B7:FA",
                       "warning", "192.168.0.70", "192.168.0.1")
        fix = next(a for a in r["auto"] if a["where"] == "router")
        self.assertTrue(fix["undo"])

    def test_mtu_is_safe_additive_fix_with_undo(self):
        """MSS clamping only adds a passthrough firewall rule (never blocks or exposes anything), so it
        was widened into AUTO_SAFE - but only once it had a real Undo, same bar as the other safe kinds."""
        self.assertIn("mtu", AL.AUTO_SAFE)
        r = AL.explain("Large packets do not pass the line (MTU too small)", "warning", "192.168.0.70",
                       "192.168.0.1")
        fix = next(a for a in r["auto"] if a["where"] == "router")
        self.assertTrue(fix["undo"])
        self.assertIn("mangle remove", fix["undo"])

    def test_dns_and_exposed_stay_manual_despite_having_an_undo(self):
        """Having an undo is necessary but not sufficient: "dns" turns on allow-remote-requests on the
        router's own resolver (a real open-resolver risk if ever reachable from the WAN) and "exposed"
        closes a port a user may have opened on purpose for remote camera viewing - both stay manual."""
        self.assertNotIn("dns", AL.AUTO_SAFE)
        self.assertNotIn("exposed", AL.AUTO_SAFE)

    def test_exposed_fix_has_an_undo_even_though_not_auto_applied(self):
        """Not in AUTO_SAFE (stays a manual, one-click confirm - closing a port forward can break a
        camera's remote-viewing feature someone set up on purpose), but once applied it must still be
        undoable from the Auto-fixes list."""
        r = AL.explain("192.168.0.203: XMeye DVR is reachable from the internet", "critical", "", "", "")
        fix = next(a for a in r["auto"] if a["where"] == "router")
        self.assertTrue(fix["undo"])
        self.assertIn("upnp set enabled=yes", fix["undo"])

    def test_all_real_threat_feed_labels_classify_as_malware(self):
        """Regression for the bug the remote_address test below exists to catch: nd_monitor.FEEDS' actual
        label text ("Hijacked criminal network...", "Known attacker...", "Compromised / attacking
        host...") must each be recognised, not just the ones with the literal word 'malware' in them."""
        for label in ("Hijacked criminal network (Spamhaus DROP)", "Known attacker (FireHOL level 1)",
                      "Compromised / attacking host (Emerging Threats)",
                      "Botnet control server (abuse.ch Feodo Tracker)"):
            r = AL.explain(f"192.168.0.57 connected to 45.135.193.215 - {label}", "critical", "", "", "")
            self.assertEqual(r["kind"], "malware", label)

    def test_malware_steps_name_the_remote_address_to_search_for(self):
        """The alert only ever named the device's own IP - with many devices on the network there was no
        way to tell which program on that PC made the connection. Steps must now point at the actual
        remote (malicious) address so netstat / Resource Monitor can find the culprit process."""
        r = AL.explain("192.168.0.57 connected to 45.135.193.215 - Hijacked criminal network (Spamhaus)",
                       "critical", "", "", "")
        self.assertEqual(r["kind"], "malware")
        self.assertTrue(any("45.135.193.215" in s for s in r["steps"]))


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
