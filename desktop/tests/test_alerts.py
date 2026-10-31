"""Alerts: priority, fixes, troubleshooting steps, history and export."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_alerts as AL  # noqa: E402

REAL = {
    "dhcp,warning Detected conflict by ARP response for 192.168.0.70 from F8:75:A4:8D:B7:FA": ("dhcp_conflict", 2),
    "192.168.0.48: Torrent / peer-to-peer download (255.255.255.255 port 51413)": ("torrent", 2),
    "192.168.0.203: XMeye DVR is reachable from the internet - attackers constantly try its logins "
    "(45.79.125.182 port 34567)": ("exposed", 1),
    "New device(s) on the network: -  192.168.0.65  0A:B3:23:6F:12:70  Private / randomized MAC": ("new_device", 3),
    "IP conflict on 192.168.0.41 - 192.168.0.41 claimed by: 3C:52:82:01:02:04": ("ip_conflict", 1),
    "Broadcast storm on ether3 (12000/second)": ("loop", 1),
}


class Recipes(unittest.TestCase):
    def test_real_alerts(self):
        for text, (kind, prio) in REAL.items():
            r = AL.explain(text, "warning", "192.168.0.70", "192.168.0.1")
            self.assertEqual((r["kind"], r["prio"]), (kind, prio), text)
            self.assertTrue(r["steps"] and r["fix"] and r["why"])

    def test_dhcp_conflict_reserves_ip(self):
        r = AL.explain(next(iter(REAL)), "warning", "192.168.0.70")
        cmd = r["auto"][0]["cmd"]
        self.assertIn("address=192.168.0.70", cmd)
        self.assertIn("F8:75:A4:8D:B7:FA", cmd)
        self.assertIn("Network Doctor PC itself", r["why"])

    def test_exposed_closes_nat(self):
        r = AL.explain(list(REAL)[2])
        self.assertIn("to-addresses=192.168.0.203", r["auto"][0]["cmd"])

    def test_unknown_goes_to_root_cause(self):
        r = AL.explain("Something new", "critical")
        self.assertEqual(r["prio"], 1)
        self.assertEqual(r["app"][1], "rca")


class Log(unittest.TestCase):
    def test_dedupe_resolve_save_export(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "alerts.json")
        log = AL.AlertLog(p)
        t = list(REAL)[1]
        log.add("warning", t, "Live monitor", now=1000)
        log.add("warning", t, "Live monitor", now=1300)   # within an hour: counted
        log.add("warning", t, "Live monitor", now=6000)   # later: new line
        self.assertEqual(len(log.items), 2)
        self.assertEqual(log.items[0]["count"], 2)
        log.add("critical", "IP conflict on 192.168.0.41 - x", "Quick check", now=6100)
        self.assertEqual(log.resolve("IP conflict on 192.168.0.41"), 1)
        log.save()
        self.assertEqual(len(AL.AlertLog(p).items), 3)
        csvp, htmlp = os.path.join(d, "a.csv"), os.path.join(d, "a.html")
        AL.export_csv(csvp, log.recent(), {"192.168.0.48": "ACCOUNTS-PC"})
        AL.export_html(htmlp, log.recent())
        with open(csvp, encoding="utf-8-sig") as f:
            body = f.read()
        self.assertIn("P2 - fix today", body)
        self.assertIn("ACCOUNTS-PC", body)
        with open(htmlp, encoding="utf-8") as f:
            self.assertIn("<ol>", f.read())


if __name__ == "__main__":
    unittest.main()
