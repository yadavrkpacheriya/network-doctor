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

    def get(self, path, token=None):
        req = urllib.request.Request(self.base + path,
                                     headers={**({"X-ND-Token": token} if token else {})})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_lan_phone_can_view_even_with_accounts(self):
        # Turning on Pro accounts must NOT lock a paired LAN phone out of viewing the network
        # (the old blanket gate 401'd here, which the phone app shows as "no longer paired").
        import nd_auth as AU
        acc = AU.Accounts()
        acc.data = {"users": {"owner": {"role": "admin", "salt": "00", "hash": "x", "disabled": False}}}
        acc._save = lambda: None
        self.srv.auth = acc
        self.assertTrue(acc.has_users())
        _, r = self.post("/api/pair", {"code": self.srv.code, "phone": "test"})
        tok = r["token"]
        # loopback counts as LAN -> viewing is allowed without signing in
        code, snap = self.get("/api/state", tok)
        self.assertEqual(code, 200)
        self.assertIn("api", snap)

    def get_raw(self, path, token=None):
        req = urllib.request.Request(self.base + path,
                                     headers={**({"X-ND-Token": token} if token else {})})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read() or b"", dict(e.headers)

    def test_setup_cmd_download(self):
        # The phone (paired, on the LAN) can download the 1-file agent setup as an attachment .cmd.
        def cmd(name, args=None):
            self.calls.append((name, args))
            if name == "setup_cmd":
                return {"ok": True, "filename": "Setup-NetworkDoctor.cmd", "text": "@echo off\r\nREM setup\r\n"}
            return {"ok": True, "message": f"did {name}"}
        self.srv.command_fn = cmd
        _, r = self.post("/api/pair", {"code": self.srv.code, "phone": "test"})
        tok = r["token"]
        code, body, hdrs = self.get_raw("/api/setup-cmd", tok)
        self.assertEqual(code, 200)
        self.assertIn(b"@echo off", body)
        self.assertIn("attachment", hdrs.get("Content-Disposition", ""))
        self.assertIn("Setup-NetworkDoctor.cmd", hdrs.get("Content-Disposition", ""))
        self.assertEqual(self.calls[-1][0], "setup_cmd")

    def test_action_needs_pairing_then_works(self):
        code, _ = self.post("/api/action", {"action": "tag", "args": {"mac": "x"}})
        self.assertEqual(code, 401)
        self.assertEqual(self.calls, [])
        code, r = self.post("/api/pair", {"code": self.srv.code, "phone": "test"})
        self.assertEqual(code, 200)
        code, r = self.post("/api/action", {"action": "tag", "args": {"mac": "AA", "name": "PC"}}, r["token"])
        self.assertEqual((code, r["message"]), (200, "did tag"))
        name, got = self.calls[-1]
        self.assertEqual(name, "tag")
        self.assertEqual(got["mac"], "AA")
        self.assertEqual(got["name"], "PC")  # share server also injects _auth / _ip


if __name__ == "__main__":
    unittest.main()
