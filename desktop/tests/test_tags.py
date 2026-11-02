# -*- coding: utf-8 -*-
"""Tests for the Devices tab search and filters (nd_tools.filter_devices)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_tools as T  # noqa: E402


def dev(name, ip, mac, vendor="", online=True, **tag):
    return {"name": name, "ip": ip, "ips": [ip], "mac": mac, "vendor": vendor, "reason": "", "notes": [],
            "online": online, "dept": tag.get("dept", ""), "kind": tag.get("kind", ""), "tag": tag}


DEVS = [
    dev("ACC-PC1", "192.168.0.21", "00:11:22:33:44:01", "Dell", dept="Accounts", location="2nd floor",
        router_port="ether3", watch="1"),
    dev("ACC-PC2", "192.168.0.22", "00:11:22:33:44:02", "HP", online=False, dept="Accounts", location="Ground floor"),
    dev("Printer", "192.168.0.50", "00:11:22:33:44:03", "Brother", dept="Admin", location="2nd floor", kind="printer",
        switch_port="7"),
    dev("", "192.168.0.80", "00:11:22:33:44:04", "Hikvision"),
]


def names(ds):
    return [d["name"] or d["ip"] for d in ds]


class Filters(unittest.TestCase):
    def test_no_filter(self):
        self.assertEqual(len(T.filter_devices(DEVS)), 4)

    def test_all_words_must_match(self):
        self.assertEqual(names(T.filter_devices(DEVS, "acc dell")), ["ACC-PC1"])
        self.assertEqual(names(T.filter_devices(DEVS, "acc canon")), [])

    def test_field_words(self):
        self.assertEqual(names(T.filter_devices(DEVS, "dept:admin")), ["Printer"])
        self.assertEqual(names(T.filter_devices(DEVS, 'loc:"2nd floor"')), ["ACC-PC1", "Printer"])
        self.assertEqual(names(T.filter_devices(DEVS, "port:ether3")), ["ACC-PC1"])
        self.assertEqual(names(T.filter_devices(DEVS, "port:7")), ["Printer"])
        self.assertEqual(names(T.filter_devices(DEVS, "type:printer")), ["Printer"])
        self.assertEqual(names(T.filter_devices(DEVS, "vendor:hikvision")), ["192.168.0.80"])
        self.assertEqual(names(T.filter_devices(DEVS, "ip:192.168.0.2")), ["ACC-PC1", "ACC-PC2"])

    def test_unknown_field_is_plain_text(self):
        self.assertEqual(names(T.filter_devices(DEVS, "http:x")), [])

    def test_dropdowns(self):
        self.assertEqual(names(T.filter_devices(DEVS, dept="Accounts")), ["ACC-PC1", "ACC-PC2"])
        self.assertEqual(names(T.filter_devices(DEVS, dept="Accounts", location="2nd floor")), ["ACC-PC1"])

    def test_show(self):
        self.assertEqual(len(T.filter_devices(DEVS, show=T.SHOW[1])), 3)
        self.assertEqual(names(T.filter_devices(DEVS, show=T.SHOW[2])), ["192.168.0.80"])
        self.assertEqual(names(T.filter_devices(DEVS, show=T.SHOW[3])), ["ACC-PC1"])

    def test_tag_values(self):
        self.assertEqual(T.tag_values(DEVS, "dept"), ["Accounts", "Admin"])
        self.assertEqual(T.tag_values(DEVS, "location"), ["2nd floor", "Ground floor"])


if __name__ == "__main__":
    unittest.main()


import unittest as _ut


class SiteBlock(_ut.TestCase):
    """Router-native site blocking for the whole Wi-Fi (DNS static, no PC needed)."""

    def test_builds_match_subdomain_and_regexp_fallback(self):
        import nd_tools as T
        sites = T.sites_for(["social"], ["example.com, mysite.in"])
        apply, undo = T.site_block_commands(sites)
        self.assertIn("match-subdomain=yes", apply)       # RouterOS 7
        self.assertIn("regexp=", apply)                   # RouterOS 6 fallback
        self.assertIn("/ip dns cache flush", apply)
        self.assertIn("instagram.com", apply)             # from the social group
        self.assertIn("example.com", apply)               # custom typed
        self.assertTrue(apply.startswith(':do {/ip dns static remove'))  # replaces old ND set
        self.assertIn('remove [find where comment~"^ND site-block"]', undo)

    def test_normalize(self):
        import nd_tools as T
        self.assertEqual(T.normalize_sites(["WWW.Instagram.com", "*.instagram.com", "instagram.com", "x y"]),
                         ["instagram.com"])

    def test_empty_is_just_cleanup(self):
        import nd_tools as T
        apply, _ = T.site_block_commands([])
        self.assertTrue(apply.splitlines()[0].startswith(':do {/ip dns static remove'))
        self.assertNotIn("dns static add", apply)


class UndoFor(_ut.TestCase):
    def test_comment_rule_reversed(self):
        import nd_slow as S
        undo = T.undo_for(S.fix_script("mss_clamp", mtu=1480))
        self.assertEqual(undo, '/ip firewall mangle remove [find where comment="ND: MSS clamp"]')

    def test_exposure_fix_reversed(self):
        import nd_alerts as AL
        r = AL.explain("192.168.0.203 can be opened from the internet", "critical",
                       "192.168.0.40", "192.168.0.1", "192.168.0.0/24")
        apply = [a["cmd"] for a in r["auto"] if a["where"] == "router"][0]
        undo = T.undo_for(apply)
        self.assertIn('/ip firewall filter remove [find where comment="ND: no-inbound 192.168.0.203"]', undo)
        self.assertIn("/ip upnp set enabled=yes", undo)                     # UPnP turned back on
        self.assertIn("/ip firewall nat enable [find where", undo)          # port-forward re-enabled

    def test_dedup_and_empty(self):
        self.assertEqual(T.undo_for("# nothing to undo here\n/ip dns cache flush"), "")
        # two adds with the same comment collapse to one remove
        s = ('/ip firewall mangle add chain=forward comment="ND: X"\n'
             '/ip firewall mangle add chain=forward comment="ND: X"')
        self.assertEqual(T.undo_for(s).count("remove"), 1)
