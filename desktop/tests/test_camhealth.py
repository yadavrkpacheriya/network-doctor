# -*- coding: utf-8 -*-
"""Camera health: fault assessment (offline / bad login / default password) and the safe-fix hints, with the
network reads injected so no hardware is needed. Firmware is reported, never auto-flashed."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_camhealth as H  # noqa: E402

CAM = {"name": "Gate", "ip": "192.168.1.64", "mac": "AA:BB:CC:00:00:64"}


class Assess(unittest.TestCase):
    def test_offline_when_no_port_answers(self):
        r = H.assess(CAM, [], None, False)
        self.assertEqual(r["status"], "OFFLINE")
        self.assertIn("PoE", r["fix"])

    def test_ok_when_reachable_and_login_fine(self):
        r = H.assess(CAM, [34567], {"model": "HB-X", "firmware": "V5.00"}, {"user": "admin", "default": False})
        self.assertEqual(r["status"], "OK")
        self.assertEqual(r["firmware"], "V5.00")
        self.assertEqual(r["issues"], [])

    def test_default_password_is_a_fault(self):
        r = H.assess(CAM, [34567], {}, {"user": "admin", "default": True})
        self.assertEqual(r["status"], "CHECK")
        self.assertTrue(any("default password" in i for i in r["issues"]))

    def test_no_working_login_is_flagged(self):
        r = H.assess(CAM, [80], None, None)
        self.assertEqual(r["status"], "CHECK")
        self.assertTrue(any("no saved login" in i for i in r["issues"]))

    def test_login_not_attempted_is_not_a_fault(self):
        r = H.assess(CAM, [554], None, False)          # non-XMeye: reachable, login not checked
        self.assertEqual(r["status"], "OK")


class DefaultDetection(unittest.TestCase):
    def test_known_defaults(self):
        self.assertTrue(H.is_default("admin", ""))
        self.assertTrue(H.is_default("admin", "12345"))
        self.assertFalse(H.is_default("admin", "MyStr0ngPass"))


class Report(unittest.TestCase):
    def test_worst_first_and_summary(self):
        cams = [{"name": "A", "ip": "192.168.1.10"}, {"name": "B", "ip": "192.168.1.11"},
                {"name": "C", "ip": "192.168.1.12"}]

        def ports_of(c):
            return {"192.168.1.10": [34567], "192.168.1.11": [], "192.168.1.12": [80]}[c["ip"]]

        def probe(c):
            if c["ip"] == "192.168.1.10":
                return {"model": "X", "firmware": "V1"}, {"user": "admin", "default": True}  # CHECK
            return None, False
        recs = H.report(cams, ports_of, probe)
        self.assertEqual([r["name"] for r in recs], ["B", "A", "C"])   # OFFLINE(B), CHECK(A), OK(C)
        s = H.summary(recs)
        self.assertEqual((s["offline"], s["check"], s["ok"]), (1, 1, 1))

    def test_a_probe_crash_does_not_sink_the_report(self):
        cams = [{"name": "A", "ip": "192.168.1.10"}]

        def probe(c):
            raise RuntimeError("camera hung")
        recs = H.report(cams, lambda c: [34567], probe)
        self.assertEqual(recs[0]["status"], "OK")       # degrades gracefully, login just not determined


if __name__ == "__main__":
    unittest.main()
