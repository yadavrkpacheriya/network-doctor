"""3.19.1: the reset only touches what the app made, and EVERYTHING the app makes can be reset (safety contract)."""
import glob
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_reset as R  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES = [p for p in glob.glob(os.path.join(HERE, "*.py"))]
# objects the app makes that are NOT router rules (phone-app / share users, tokens, report names): not part of a reset
NOT_RULES = ("ND-User", "ND-Token", "ND-Report")


def src(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class Contract(unittest.TestCase):
    def test_every_comment_the_app_writes_is_found_by_the_reset(self):
        """A new rule with a comment the reset does not match would stay on the router for ever: fail the build."""
        bad, seen = [], 0
        for p in SOURCES:
            for m in re.finditer(r'comment=\\?"(ND[^"\\{]*)', src(p)):
                c = m.group(1)
                seen += 1
                if c.startswith(NOT_RULES):
                    continue
                if not (re.search(R.COMMENT_RE, c) or c.startswith((R.OFF, R.REL))):
                    bad.append((os.path.basename(p), c))
        self.assertGreater(seen, 30, "the scan found almost nothing - the pattern is broken")
        self.assertEqual(bad, [])

    def test_every_queue_name_and_list_the_app_writes_is_found_by_the_reset(self):
        bad = []
        for p in SOURCES:
            t = src(p)
            for m in re.finditer(r'name=\\?"(ND[^"\\{]*)', t):
                if not re.search(R.QUEUE_RE, m.group(1)):
                    bad.append((os.path.basename(p), m.group(1)))
            for m in re.finditer(r"\blist=\\?\"?(ND[^\s\"\\{]*)", t):
                if not re.search(R.LIST_RE, m.group(1)):
                    bad.append((os.path.basename(p), m.group(1)))
        self.assertEqual(bad, [])

    def test_no_source_can_wipe_or_lock_out_the_router(self):
        """No code of the app may wipe the router's configuration, delete without a condition, or change router users
        (the 'router tips' text may MENTION '/ip service ...' as advice for the person; that is not run)."""
        bad = []
        for p in SOURCES:
            if os.path.basename(p) == "nd_reset.py":   # its docstring states these rules; its script is tested below
                continue
            t = src(p)
            for pat in (r"reset-configuration", r"remove \[find\]\s*[\"'\n]", r"/user (add|set|remove)\b",
                        r"/system (reset|package)"):
                for m in re.finditer(pat, t):
                    bad.append((os.path.basename(p), t[:m.start()].count("\n") + 1, m.group(0)))
        self.assertEqual(bad, [], "dangerous router command in the source")


class ResetScript(unittest.TestCase):
    def test_script_shape_and_scopes(self):
        s, notes = R.reset_commands()
        self.assertTrue(s.startswith("#"))
        self.assertIn("nd-before-reset", s)                       # a copy of the config first
        for line in (x for x in s.splitlines() if not x.startswith("#")):
            if "remove" in line:
                self.assertIn("where", line)                      # never an unconditional remove
                self.assertNotIn("[find]", line)
            self.assertEqual(line.count("{"), line.count("}"), line)
            self.assertEqual(line.count('"') % 2, 0, line)
        self.assertIn("NOT touched", " ".join(notes))
        only_ips, _ = R.reset_commands(("ips",))
        self.assertIn("/ip dhcp-server lease remove", only_ips)
        self.assertNotIn("/queue", only_ips)
        self.assertNotIn("firewall", only_ips)
        no_ips, _ = R.reset_commands(("limits",))
        self.assertNotIn("dhcp-server", no_ips)
        with self.assertRaises(ValueError):
            R.reset_commands(())

    def test_switched_off_rules_come_back_before_anything_is_removed(self):
        s, _ = R.reset_commands()
        self.assertLess(s.index("^ND-off: "), s.index(" remove ["))   # restore first, so ISP rules are never removed
        self.assertLess(s.index("^ND-off: "), s.index('comment~"^ND[ :]"'))

    def test_never_matches_isp_or_owner_config(self):
        """Names and comments an ISP / owner uses are not matched by the reset patterns."""
        for c in ("defconf: masquerade", "ISP", "NDA server", "ND", "Nd 1", "DVR forward 37777", "ndoc", "fasttrack",
                  "special ND rule", "ND-User-1"):
            self.assertIsNone(re.search(R.COMMENT_RE, c), c)
        for n in ("default", "ISP-limit", "NDA", "ndq", "queue-ND"):
            self.assertIsNone(re.search(R.QUEUE_RE, n), n)
        for lst in ("LAN", "blocklist", "ND", "NDx", "mylist-ND-"):
            self.assertIsNone(re.search(R.LIST_RE, lst), lst)

    def test_matches_what_the_app_makes(self):
        for c in ("ND phone block AA:BB", "ND isolate AA", "ND block AA", "ND guard: torrent", "ND site-block x.com",
                  "ND: camera no internet", "ND: no-inbound 1.2.3.4", "ND binding", "ND: Ravi | HR",
                  "ND slow-web", "ND: MSS clamp", "ND fair queue"):
            self.assertTrue(re.search(R.COMMENT_RE, c), c)
        for n in ("ND-TOTAL", "ND-NVR", "ND-PC", "ND limit 192.168.0.5", "ND fair queue"):
            self.assertTrue(re.search(R.QUEUE_RE, n), n)
        for lst in ("ND-CAM", "ND-CCTV", "ND-doh"):
            self.assertTrue(re.search(R.LIST_RE, lst), lst)

    def test_classify_lists_only_app_items(self):
        t = {"/ip firewall filter": [{"comment": "defconf: accept"}, {"comment": "ND phone block AA"},
                                     {"comment": "ND-off: fasttrack", "chain": "forward"},
                                     {"comment": "ND-rel: ND isolate BB"}, {"comment": "NDA vpn"}],
             "/ip firewall nat": [{"comment": "ND-off: DVR"}, {"comment": "masquerade"}],
             "/queue simple": [{"name": "ND-PC"}, {"name": "ISP-limit"}],
             "/queue type": [{"name": "ND-pc-up"}, {"name": "default"}],
             "/ip firewall address-list": [{"list": "ND-CAM"}, {"list": "ND-CAM"}, {"list": "LAN"}],
             "/ip dhcp-server lease": [{"comment": "ND: Ravi", "address": "192.168.0.50", "mac-address": "AA"},
                                       {"comment": "isp static", "address": "192.168.0.2"}]}
        f = R.classify(t)
        self.assertEqual({w for _p, w in f["restore"]}, {"fasttrack", "DVR"})
        removed = {w for _p, w in f["remove"]}
        self.assertEqual(removed, {"ND phone block AA", "ND isolate BB", "ND-PC", "ND-pc-up", "ND-CAM",
                                   "192.168.0.50 AA"})
        self.assertNotIn("NDA vpn", removed)
        self.assertIn("nothing", R.report_text({"restore": [], "remove": []}).lower())
        self.assertIn("SWITCHED ON", R.report_text(f))

    def test_patterns_inside_the_script_itself_spare_isp_config(self):
        """Apply the regexes that are really written in the script to ISP-style and ND-style names."""
        s, _ = R.reset_commands()
        pats = set(re.findall(r'~"([^"]+)"', s))
        self.assertTrue(pats)
        isp = ["defconf: masquerade", "ISP", "NDA server", "ND", "DVR forward", "fasttrack", "default", "ISP-limit",
               "LAN", "ND-User-1x"]
        for p in pats:
            if p in (r"^ND-off: ",):
                continue
            for name in isp:
                if name == "ND-User-1x" and p == "^ND-":   # a list/queue-type pattern; users are never in those tables
                    continue
                self.assertIsNone(re.search(p, name), f"{p} matches {name}")
        self.assertTrue(any(re.search(p, "ND phone block AA") for p in pats))
        self.assertTrue(any(re.search(p, "ND-CAM") for p in pats))

    def test_global_changes_are_listed_not_touched(self):
        s, _ = R.reset_commands()
        for word in ("/ip dns set", "/ip upnp", "loop-protect", "igmp-snooping", "add-arp"):
            self.assertNotIn(word, s)
        self.assertIn("DNS", R.global_text())


if __name__ == "__main__":
    unittest.main()
