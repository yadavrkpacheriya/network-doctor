# -*- coding: utf-8 -*-
"""3.21: the receiving side of nd_telemetry.py - ShareServer._telemetry() on /api/telemetry (nd_share.py).
No pairing / sign-in needed (an opted-in remote install cannot pair), but still rate-limited and size-capped.
"""
import json
import os
import sys
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_share as SH  # noqa: E402


class TelemetryEndpoint(unittest.TestCase):
    def setUp(self):
        self.store = {}
        self.srv = SH.ShareServer("ND", "9.9", lambda: {"x": 1}, lambda *a: None, self.store, lambda: None)
        try:
            self.srv.start()
        except Exception as e:  # pragma: no cover - port in use on the test machine
            self.skipTest(str(e))
        if not self.srv.httpd:
            self.skipTest("server did not start")
        self.base = "http://127.0.0.1:%d" % SH.HTTP_PORT

    def tearDown(self):
        self.srv.stop()

    def post_raw(self, path, body_bytes, content_type="application/json"):
        req = urllib.request.Request(self.base + path, data=body_bytes, method="POST",
                                     headers={"Content-Type": content_type})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def post(self, body):
        return self.post_raw("/api/telemetry", json.dumps(body).encode())

    def test_accepted_report_is_stored_sanitised(self):
        code, resp = self.post({"install_id": "abc123", "kind": "desktop", "version": "3.21.0",
                                "platform": "Windows-10", "counts": {"scan_manual": 3, "error:wmi": 1},
                                "crashes": [{"context": "unhandled", "type": "ValueError", "message": "bad",
                                            "where": "nd_core.py:9 in scan"}]})
        self.assertEqual(code, 200)
        self.assertEqual(resp["result"], "thanks")
        reports = self.srv.telemetry_reports()
        self.assertEqual(len(reports), 1)
        r = reports[0]
        self.assertEqual(r["install_id"], "abc123")
        self.assertEqual(r["kind"], "desktop")
        self.assertEqual(r["counts"]["scan_manual"], 3)
        self.assertEqual(r["from_ip"], "127.0.0.1")
        self.assertEqual(len(r["crashes"]), 1)
        self.assertEqual(r["crashes"][0]["type"], "ValueError")

    def test_bad_json_is_rejected(self):
        code, resp = self.post_raw("/api/telemetry", b"{not json")
        self.assertEqual(code, 400)
        self.assertEqual(self.srv.telemetry_reports(), [])

    def test_non_dict_body_is_rejected(self):
        code, _ = self.post_raw("/api/telemetry", b"[1, 2, 3]")
        self.assertEqual(code, 400)

    def test_oversized_body_is_rejected(self):
        code, resp = self.post({"counts": {"x": 1}, "pad": "a" * 20000})
        self.assertEqual(code, 413)
        self.assertEqual(self.srv.telemetry_reports(), [])

    def test_second_report_within_a_minute_is_rate_limited(self):
        code1, _ = self.post({"counts": {"a": 1}})
        code2, resp2 = self.post({"counts": {"a": 1}})
        self.assertEqual(code1, 200)
        self.assertEqual(code2, 429)
        self.assertEqual(len(self.srv.telemetry_reports()), 1)

    def test_non_numeric_counts_are_dropped_not_stored_raw(self):
        self.post({"counts": {"ok": 2, "bad": "not-a-number", "worse": True}})
        r = self.srv.telemetry_reports()[0]
        self.assertEqual(r["counts"], {"ok": 2})  # bool is rejected too (isinstance(True, int) is True in Python)

    def test_clear_telemetry_empties_the_store(self):
        self.post({"counts": {"a": 1}})
        self.assertEqual(len(self.srv.telemetry_reports()), 1)
        self.srv.clear_telemetry()
        self.assertEqual(self.srv.telemetry_reports(), [])

    def test_crash_list_is_capped_and_crash_fields_are_truncated(self):
        crashes = [{"context": "c", "type": "E", "message": "m", "where": "w"} for _ in range(30)]
        crashes[0]["message"] = "x" * 500
        self.post({"counts": {}, "crashes": crashes})
        r = self.srv.telemetry_reports()[0]
        self.assertLessEqual(len(r["crashes"]), 20)
        self.assertLessEqual(len(r["crashes"][0]["message"]), 200)


if __name__ == "__main__":
    unittest.main()
