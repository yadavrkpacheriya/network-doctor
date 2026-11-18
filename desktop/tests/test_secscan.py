# -*- coding: utf-8 -*-
"""Security check for all device types: exposure flags for everything, but an ACTIVE default-password test
only on devices that can't be locked out (cameras/routers/printers) - never PCs/phones."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_core as core  # noqa: E402
import nd_secscan as SEC  # noqa: E402
import nd_vuln as V  # noqa: E402


class SecScan(unittest.TestCase):
    def test_only_safe_categories_are_tested(self):
        for c in (core.CAT_CAM, core.CAT_ROUTER, core.CAT_NET, core.CAT_PRN, core.CAT_BIO):
            self.assertTrue(SEC.may_test_default(c), c)
        for c in (core.CAT_PC, core.CAT_PHONE, core.CAT_IOT, core.CAT_UNK):
            self.assertFalse(SEC.may_test_default(c), c)   # never brute-force a PC/phone

    def test_exposure_flags_apply_to_any_device(self):
        f = SEC.exposure_findings({23, 80})
        self.assertTrue(any("Telnet" in t for _s, t in f))
        self.assertEqual(SEC.exposure_findings({80, 443}), [])   # https alone is not a finding

    def test_device_findings_puts_default_first(self):
        f = SEC.device_findings(core.CAT_CAM, {21, 23}, default_hit=("admin", "12345"))
        self.assertEqual(f[0][0], "critical")
        self.assertIn("Default", f[0][1])


class VulnActiveLogin(unittest.TestCase):
    def dev(self, cat, vendor, ports):
        return {"ip": "192.168.0.50", "name": "cam", "online": True, "ports": list(ports),
                "vendor": vendor, "category": cat, "http": {}}

    def test_confirmed_default_is_critical(self):
        # cam_login says the factory login works -> a confirmed critical, not a vague "may still"
        f = V.assess([self.dev(core.CAT_CAM, "Hikvision", {80})], db={}, active=True,
                     cam_login=lambda ip, defaults, ports=(), ssl_on=False: ("admin", "12345"))
        hits = [x for x in f if x["title"] == "Default password works"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["sev"], "critical")
        self.assertFalse([x for x in f if x["title"] == "May still use its default password"])

    def test_confirmed_strong_says_nothing(self):
        # cam_login says no default works -> NO default-password finding at all (no false alarm)
        f = V.assess([self.dev(core.CAT_CAM, "Hikvision", {80})], db={}, active=True,
                     cam_login=lambda ip, defaults, ports=(), ssl_on=False: None)
        self.assertFalse([x for x in f if "default password" in x["title"].lower()])

    def test_pc_is_never_brute_forced(self):
        calls = []

        def spy(ip, defaults, ports=(), ssl_on=False):
            calls.append(ip)
            return ("admin", "admin")
        # a PC that looks like a brand is NOT login-tested; it gets the soft reminder instead
        f = V.assess([self.dev(core.CAT_PC, "Hikvision", {80})], db={}, active=True, cam_login=spy)
        self.assertEqual(calls, [])                         # the tester was never called for a PC
        self.assertTrue([x for x in f if x["title"] == "May still use its default password"])


if __name__ == "__main__":
    unittest.main()
