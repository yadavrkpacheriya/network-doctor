# -*- coding: utf-8 -*-
"""3.21: the tunnel for reaching this PC from outside - quick (no account) and permanent (Cloudflare API) tiers."""
import io
import json
import os
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_tunnel as T  # noqa: E402


class FakeResp:
    def __init__(self, body, code=200):
        self.body, self.code = body if isinstance(body, bytes) else json.dumps(body).encode(), code
        self._pos = 0

    def read(self, n=None):
        if n is None:
            out, self._pos = self.body[self._pos:], len(self.body)
            return out
        out = self.body[self._pos:self._pos + n]
        self._pos += len(out)
        return out

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Binary(unittest.TestCase):
    def test_locate_prefers_path_then_own_copy(self):
        with mock.patch.object(T.shutil, "which", lambda n: "/usr/bin/cloudflared"):
            self.assertEqual(T.locate("/data"), "/usr/bin/cloudflared")
        with mock.patch.object(T.shutil, "which", lambda n: None), tempfile.TemporaryDirectory() as d:
            own = os.path.join(d, "bin", T._bin_name())
            os.makedirs(os.path.dirname(own))
            open(own, "w").close()
            self.assertEqual(T.locate(d), own)
            self.assertEqual(T.locate(d + "-missing"), "")

    def test_latest_download_url_picks_the_right_asset(self):
        rel = {"tag_name": "v1.2.3", "assets": [{"name": "cloudflared-linux-amd64", "browser_download_url": "https://x/linux"},
                                                {"name": "cloudflared-windows-amd64.exe", "browser_download_url": "https://x/win"}]}
        with mock.patch.object(T, "_get", lambda *a, **k: FakeResp(rel)), \
             mock.patch.object(T, "IS_WIN", True), mock.patch.object(T, "IS_MAC", False):
            url, tag = T.latest_download_url()
        self.assertEqual((url, tag), ("https://x/win", "v1.2.3"))

    def test_latest_download_url_missing_asset_raises(self):
        with mock.patch.object(T, "_get", lambda *a, **k: FakeResp({"tag_name": "v1", "assets": []})):
            with self.assertRaises(T.TunnelError):
                T.latest_download_url()

    def test_ensure_installed_skips_download_when_already_there(self):
        with tempfile.TemporaryDirectory() as d:
            own = os.path.join(d, "bin", T._bin_name())
            os.makedirs(os.path.dirname(own))
            open(own, "w").close()
            with mock.patch.object(T.shutil, "which", lambda n: None):
                got = T.ensure_installed(d)
            self.assertEqual(got, own)

    def test_ensure_installed_downloads_raw_binary(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(T.shutil, "which", lambda n: None), \
             mock.patch.object(T, "IS_WIN", False), mock.patch.object(T, "IS_MAC", False), \
             mock.patch.object(T, "latest_download_url", lambda: ("https://x/linux", "v1")), \
             mock.patch.object(T, "_get", lambda *a, **k: FakeResp(b"FAKE-BINARY")):
            got = T.ensure_installed(d)
            self.assertTrue(os.path.isfile(got))
            self.assertEqual(open(got, "rb").read(), b"FAKE-BINARY")

    def test_ensure_installed_extracts_mac_tgz(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            data = b"FAKE-MAC-BIN"
            info = tarfile.TarInfo(name="cloudflared")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        body = buf.getvalue()
        with tempfile.TemporaryDirectory() as d, mock.patch.object(T.shutil, "which", lambda n: None), \
             mock.patch.object(T, "IS_WIN", False), mock.patch.object(T, "IS_MAC", True), \
             mock.patch.object(T, "latest_download_url", lambda: ("https://x/mac.tgz", "v1")), \
             mock.patch.object(T, "_get", lambda *a, **k: FakeResp(body)):
            got = T.ensure_installed(d)
            self.assertEqual(open(got, "rb").read(), b"FAKE-MAC-BIN")


class FakeProc:
    def __init__(self, lines, rc=None):
        self.stdout = iter(lines)
        self._rc = rc
        self.terminated = self.killed = False

    def poll(self):
        return self._rc

    def terminate(self):
        self.terminated = True
        self._rc = 0

    def wait(self, timeout=None):
        pass

    def kill(self):
        self.killed = True


class Quick(unittest.TestCase):
    def test_parses_the_url_from_cloudflared_output(self):
        lines = ["Starting...\n", "no url here\n", "https://random-words-here.trycloudflare.com\n", "more\n"]
        q = T.QuickTunnel("cloudflared", 8787, popen=lambda *a, **k: FakeProc(lines))
        q.start()
        self.assertEqual(q.wait_url(2), "https://random-words-here.trycloudflare.com")

    def test_no_url_found_times_out_without_hanging(self):
        q = T.QuickTunnel("cloudflared", 8787, popen=lambda *a, **k: FakeProc(["nothing useful\n"]))
        q.start()
        self.assertEqual(q.wait_url(2), "")

    def test_error_line_is_captured(self):
        q = T.QuickTunnel("cloudflared", 8787, popen=lambda *a, **k: FakeProc(["ERROR: failed to connect\n"]))
        q.start()
        q.wait_url(2)
        self.assertIn("ERROR", q.error)

    def test_stop_terminates_the_process(self):
        proc = FakeProc(["https://a.trycloudflare.com\n"])
        q = T.QuickTunnel("cloudflared", 8787, popen=lambda *a, **k: proc)
        q.start()
        q.wait_url(2)
        self.assertTrue(q.running)
        q.stop()
        self.assertTrue(proc.terminated)

    def test_command_line_has_no_port_exposed_beyond_the_one_port(self):
        captured = {}
        def fake_popen(cmd, **kw):
            captured["cmd"] = cmd
            return FakeProc([])
        T.QuickTunnel("cloudflared", 8787, popen=fake_popen).start()
        self.assertEqual(captured["cmd"], ["cloudflared", "tunnel", "--url", "http://localhost:8787", "--no-autoupdate"])


class Api(unittest.TestCase):
    def test_verify_token_ok_and_bad(self):
        with mock.patch.object(T, "_api", lambda *a, **k: {"status": "active"}):
            self.assertEqual(T.verify_token("tok"), (True, "active"))
        with mock.patch.object(T, "_api", side_effect=T.TunnelError("bad token")):
            pass  # side_effect on a function patch needs a MagicMock; direct call below instead

    def test_verify_token_bad(self):
        def boom(*a, **k):
            raise T.TunnelError("invalid")
        with mock.patch.object(T, "_api", boom):
            ok, why = T.verify_token("tok")
        self.assertFalse(ok)
        self.assertIn("invalid", why)

    def test_api_raises_on_cloudflare_error_shape(self):
        resp = {"success": False, "errors": [{"message": "Invalid request headers"}]}
        with mock.patch.object(T.urllib.request, "urlopen", lambda *a, **k: FakeResp(resp)):
            with self.assertRaises(T.TunnelError):
                T._api("/user/tokens/verify", "tok")

    def test_api_handles_http_error_with_json_body(self):
        body = json.dumps({"success": False, "errors": [{"message": "nope"}]}).encode()
        err = urllib.error.HTTPError("url", 400, "Bad", {}, io.BytesIO(body))
        with mock.patch.object(T.urllib.request, "urlopen", side_effect=err):
            with self.assertRaises(T.TunnelError):
                T._api("/zones", "tok")

    def test_zone_id_of_not_found(self):
        with mock.patch.object(T, "_api", lambda *a, **k: []):
            with self.assertRaises(T.TunnelError):
                T.zone_id_of("tok", "example.com")

    def test_zone_id_of_found(self):
        with mock.patch.object(T, "_api", lambda *a, **k: [{"id": "zid1"}]):
            self.assertEqual(T.zone_id_of("tok", "example.com"), "zid1")

    def test_account_id_of_empty_raises(self):
        with mock.patch.object(T, "_api", lambda *a, **k: []):
            with self.assertRaises(T.TunnelError):
                T.account_id_of("tok")

    def test_setup_permanent_happy_path_and_wiring(self):
        calls = []

        def fake_api(path, token, method="GET", body=None, timeout=20):
            calls.append((path, method, body))
            if path == "/user/tokens/verify":
                return {"status": "active"}
            if path.startswith("/zones?name="):
                return [{"id": "zone1"}]
            if path == "/accounts":
                return [{"id": "acct1"}]
            if path == "/accounts/acct1/cfd_tunnel":
                return {"id": "tun1", "token": "runtoken123"}
            if "/configurations" in path:
                return {}
            if path == "/zones/zone1/dns_records":
                return {}
            raise AssertionError("unexpected call " + path)
        with mock.patch.object(T, "_api", fake_api):
            r = T.setup_permanent("tok", "pacheriya.com", "office", 8787)
        self.assertEqual(r, {"hostname": "office.pacheriya.com", "tunnel_id": "tun1", "run_token": "runtoken123"})
        kinds = [c[0] for c in calls]
        self.assertEqual(kinds[0], "/user/tokens/verify")  # token checked before anything is created
        ingress_call = next(c for c in calls if "/configurations" in c[0])
        self.assertEqual(ingress_call[2]["config"]["ingress"][0]["hostname"], "office.pacheriya.com")
        self.assertEqual(ingress_call[2]["config"]["ingress"][0]["service"], "http://localhost:8787")
        self.assertEqual(ingress_call[2]["config"]["ingress"][1], {"service": "http_status:404"})  # no open catch-all
        dns_call = next(c for c in calls if c[0] == "/zones/zone1/dns_records")
        self.assertEqual(dns_call[2]["content"], "tun1.cfargotunnel.com")
        self.assertTrue(dns_call[2]["proxied"])

    def test_setup_permanent_bad_token_stops_before_creating_anything(self):
        def fake_api(path, token, method="GET", body=None, timeout=20):
            if path == "/user/tokens/verify":
                raise T.TunnelError("invalid")
            raise AssertionError("should not reach " + path)
        with mock.patch.object(T, "_api", fake_api):
            with self.assertRaises(T.TunnelError) as c:
                T.setup_permanent("tok", "pacheriya.com", "office", 8787)
        self.assertIn("token", str(c.exception).lower())


class ServiceInstall(unittest.TestCase):
    def test_install_service_windows_ok(self):
        calls = []
        def fake_run(cmd, **kw):
            calls.append(cmd)
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        with mock.patch.object(T, "IS_WIN", True):
            ok = T.install_service("cloudflared.exe", "secrettoken", run=fake_run)
        self.assertTrue(ok)
        self.assertEqual(calls[0], ["cloudflared.exe", "service", "install", "secrettoken"])

    def test_install_service_failure_raises(self):
        def fake_run(cmd, **kw):
            return type("R", (), {"returncode": 1, "stdout": "", "stderr": "permission denied"})()
        with mock.patch.object(T, "IS_WIN", True):
            with self.assertRaises(T.TunnelError):
                T.install_service("cloudflared.exe", "tok", run=fake_run)

    def test_install_service_linux_returns_false_without_running_anything(self):
        called = []
        with mock.patch.object(T, "IS_WIN", False), mock.patch.object(T, "IS_MAC", False):
            ok = T.install_service("cloudflared", "tok", run=lambda *a, **k: called.append(1))
        self.assertFalse(ok)
        self.assertEqual(called, [])

    def test_token_never_appears_in_an_exception_text_from_install_failure(self):
        def fake_run(cmd, **kw):
            return type("R", (), {"returncode": 1, "stdout": "", "stderr": "bad arguments"})()
        with mock.patch.object(T, "IS_WIN", True):
            try:
                T.install_service("cloudflared.exe", "SUPERSECRET", run=fake_run)
            except T.TunnelError as e:
                self.assertNotIn("SUPERSECRET", str(e))


class Instructions(unittest.TestCase):
    def test_phone_instructions_mentions_the_real_address(self):
        txt = T.phone_instructions("office.pacheriya.com")
        self.assertIn("https://office.pacheriya.com", txt)
        self.assertIn("Users & sign-in", txt)

    def test_pair_code_included_when_given(self):
        self.assertIn("1234", T.phone_instructions("x.trycloudflare.com", pair_code="1234"))

    def test_url_with_scheme_is_not_doubled(self):
        txt = T.phone_instructions("https://a.trycloudflare.com")
        self.assertEqual(txt.count("https://"), 1)


if __name__ == "__main__":
    unittest.main()
