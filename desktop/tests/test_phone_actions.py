"""Phone link /api/action: only a paired phone may act; answers are JSON; the snapshot cache is refreshed."""
import json
import os
import sys
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_share as SH  # noqa: E402


class PhoneActions(unittest.TestCase):
    def setUp(self):
        self.calls = []

        def cmd(name, args=None):
            self.calls.append((name, args))
            return {"ok": True, "message": f"did {name}"} if name != "scan" else "scan started"
        self.store = {}
        self.srv = SH.ShareServer("ND", "9.9", lambda: {"x": 1}, cmd, self.store, lambda: None)
        self.srv.port = 0
        try:
            self.srv.start()
        except Exception as e:  # pragma: no cover - port in use on the test machine
            self.skipTest(str(e))
        if not self.srv.httpd:
            self.skipTest("server did not start")
        self.base = f"http://127.0.0.1:{self.srv.httpd.server_address[1]}"

    def tearDown(self):
        self.srv.stop()

    def post(self, path, body, token=None):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", **({"X-ND-Token": token} if token else {})})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_action_needs_pairing_then_works(self):
        code, _ = self.post("/api/action", {"action": "tag", "args": {"mac": "x"}})
        self.assertEqual(code, 401)
        self.assertEqual(self.calls, [])
        code, r = self.post("/api/pair", {"code": self.srv.code, "phone": "test"})
        self.assertEqual(code, 200)
        code, r = self.post("/api/action", {"action": "tag", "args": {"mac": "AA", "name": "PC"}}, r["token"])
        self.assertEqual((code, r["message"]), (200, "did tag"))
        self.assertEqual(self.calls[-1], ("tag", {"mac": "AA", "name": "PC"}))


if __name__ == "__main__":
    unittest.main()
