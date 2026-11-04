# -*- coding: utf-8 -*-
"""Login sweep: one login is tried ONCE per device, a wrong password stops after the canary devices, results are mapped
to clear statuses, missing data is reported, and phones are checked without any login."""

import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import nd_core as core  # noqa: E402
import nd_sweep as S  # noqa: E402
from fake_routeros import FakeRouter  # noqa: E402


def dev(ip, cat, ports=(), name="", mac=None, **kw):
    d = {"ip": ip, "mac": mac or "AA:BB:CC:00:00:%02X" % int(ip.split(".")[-1]), "category": cat, "ports": list(ports),
         "name": name, "online": True}
    d.update(kw)
    return d


def target(d):
    return {"dev": d, "methods": S.methods_for(d)}


class Fake:
    """Transport that accepts only the right password and counts every attempt per (ip, user, password)."""

    def __init__(self, good, status_for=None):
        self.good, self.calls, self.status_for, self.lock = good, [], status_for or {}, threading.Lock()

    def __call__(self, ip, user, pw, d):
        with self.lock:
            self.calls.append((ip, user, pw))
        if ip in self.status_for:
            raise S.Outcome(self.status_for[ip], "x")
        if (user, pw) == self.good:
            return {"model": "M", "serial": "S1", "firmware": "1.0", "cpu": "i5", "ram_gb": 8, "disk_gb": 100, "os": "Win"}
        raise S.Outcome(S.AUTH, "no")


def sweep(creds, fake, **kw):
    tr = {m: fake for m in S.TRANSPORTS}
    return S.Sweep(creds, transports=tr, gap=0, sleep=lambda s: None, **kw)


class Plan(unittest.TestCase):
    def test_methods_by_type(self):
        self.assertEqual(S.methods_for(dev("192.168.0.2", core.CAT_PHONE, [62078])), [])
        self.assertIn("wmi", S.methods_for(dev("192.168.0.50", core.CAT_PC, [135, 445])))
        self.assertEqual(S.methods_for(dev("192.168.0.1", core.CAT_ROUTER, [80, 8728]))[0], "ros")
        m = S.methods_for(dev("192.168.0.20", core.CAT_CAM, [37777, 80]))
        self.assertEqual(m[0], "dahua")
        self.assertIn("onvif", m)
        self.assertIn("hik", S.methods_for(dev("192.168.0.21", core.CAT_CAM, [8000, 554])))
        self.assertIn("xmeye", S.methods_for(dev("192.168.0.22", core.CAT_CAM, [34567])))

    def test_plan_only_online_lan_not_self_not_phones(self):
        ds = [dev("192.168.0.50", core.CAT_PC, [445]), dev("8.8.8.8", core.CAT_PC, [445]),
              dev("192.168.0.51", core.CAT_PC, [445], online=False), dev("192.168.0.52", core.CAT_PC, [445], self=True),
              dev("192.168.0.53", core.CAT_PHONE, [62078])]
        self.assertEqual([t["dev"]["ip"] for t in S.plan(ds)], ["192.168.0.50"])

    def test_plan_kind_filter(self):
        ds = [dev("192.168.0.50", core.CAT_PC, [445]), dev("192.168.0.20", core.CAT_CAM, [37777])]
        self.assertEqual([t["dev"]["ip"] for t in S.plan(ds, kinds=("cam",))], ["192.168.0.20"])

    def test_private_only(self):
        self.assertTrue(S.is_lan("192.168.1.5"))
        self.assertTrue(S.is_lan("10.0.0.2"))
        for ip in ("8.8.8.8", "127.0.0.1", "169.254.1.1", "", "x"):
            self.assertFalse(S.is_lan(ip))


class Safety(unittest.TestCase):
    def pcs(self, n):
        return [target(dev(f"192.168.0.{50 + i}", core.CAT_PC, [445])) for i in range(n)]

    def test_each_login_tried_once_per_device(self):
        f = Fake(("admin", "good"))
        sw = sweep([("admin", "bad"), ("admin", "good")], f)
        r = sw.run(self.pcs(5))
        self.assertTrue(all(x["status"] == S.OK and x["login"] == 2 for x in r))
        per = {}
        for c in f.calls:
            per[c] = per.get(c, 0) + 1
        self.assertTrue(all(v == 1 for v in per.values()), per)

    def test_wrong_password_stops_after_canary(self):
        f = Fake(("admin", "good"))
        sw = sweep([("admin", "WRONG")], f, breaker=2)
        r = sw.run(self.pcs(20))
        self.assertEqual(len(f.calls), 2)  # only the 2 canary PCs saw the wrong password
        self.assertEqual(sum(x["status"] == S.AUTH for x in r), 2)
        self.assertEqual(sum(x["status"] == S.SKIP for x in r), 18)
        self.assertIn("lock", [x for x in r if x["status"] == S.SKIP][0]["detail"])

    def test_force_overrides_breaker_but_still_once(self):
        f = Fake(("admin", "good"))
        sw = sweep([("admin", "WRONG")], f, breaker=2, force=True)
        r = sw.run(self.pcs(6))
        self.assertEqual(len(f.calls), 6)
        self.assertTrue(all(x["status"] == S.AUTH for x in r))

    def test_working_login_is_not_stopped_by_a_few_refusals(self):
        # a login that works on the canary devices keeps being used even if one later device refuses it
        class Mixed(Fake):
            def __call__(self, ip, user, pw, d):
                if ip.endswith(".55"):
                    raise S.Outcome(S.AUTH, "no")
                return super().__call__(ip, user, pw, d)
        f = Mixed(("admin", "good"))
        r = sweep([("admin", "good")], f).run(self.pcs(8))
        self.assertEqual(sum(x["status"] == S.OK for x in r), 7)
        self.assertEqual(len(S.refused(r)), 1)

    def test_max_three_logins(self):
        sw = sweep([("a", "1"), ("b", "2"), ("c", "3"), ("d", "4")], Fake(("a", "1")))
        self.assertEqual(len(sw.creds), 3)

    def test_empty_user_ignored(self):
        self.assertEqual(sweep([("", "x"), ("admin", "y")], Fake(("admin", "y"))).creds, [("admin", "y")])

    def test_refused_login_not_retried_on_the_same_device_by_another_method(self):
        f = Fake(("admin", "good"))
        t = target(dev("192.168.0.20", core.CAT_CAM, [37777, 80]))  # dahua, onvif, web
        r = sweep([("admin", "bad")], f, force=True).one(t)
        self.assertEqual(r["status"], S.AUTH)
        self.assertEqual(len(f.calls), 1)

    def test_stop(self):
        f = Fake(("admin", "good"))
        sw = sweep([("admin", "good")], f)
        sw.stop.set()
        r = sw.run(self.pcs(3))
        self.assertTrue(all(x["status"] == S.SKIP for x in r))
        self.assertEqual(f.calls, [])

    def test_unreachable_does_not_try_other_logins(self):
        f = Fake(("admin", "good"), {"192.168.0.50": S.UNREACH})
        r = sweep([("admin", "bad"), ("admin", "good")], f).one(self.pcs(1)[0])
        self.assertEqual(r["status"], S.UNREACH)
        self.assertEqual(len(f.calls), 1)

    def test_crash_in_a_transport_is_an_error_not_a_stop(self):
        def boom(ip, user, pw, d):
            raise ValueError("bad")
        r = S.Sweep([("a", "b")], transports={"wmi": boom}, gap=0, sleep=lambda s: None).one(self.pcs(1)[0])
        self.assertEqual(r["status"], S.ERR)

    def test_passwords_never_in_results_or_csv(self):
        f = Fake(("admin", "S3cretPW"))
        r = sweep([("admin", "S3cretPW"), ("x", "OtherPW")], f).run(self.pcs(2))
        blob = repr(r) + S.csv_text(r)
        self.assertNotIn("S3cretPW", blob)
        self.assertNotIn("OtherPW", blob)


class Report(unittest.TestCase):
    def test_missing_fields(self):
        self.assertEqual(S.missing("dahua", {"model": "x", "serial": "", "firmware": "1"}), ["serial"])
        self.assertEqual(S.missing("wmi", {}), list(S.EXPECTED["wmi"]))

    def test_needs_attention_and_summary(self):
        f = Fake(("admin", "good"), {"192.168.0.51": S.BLOCKED})
        ts = [target(dev("192.168.0.50", core.CAT_PC, [445])), target(dev("192.168.0.51", core.CAT_PC, [445]))]
        r = sweep([("admin", "good")], f).run(ts)
        self.assertEqual(S.summary(r), {S.OK: 1, S.BLOCKED: 1})
        self.assertEqual([x["ip"] for x in S.needs_attention(r)], ["192.168.0.51"])

    def test_csv_has_header_and_rows(self):
        r = sweep([("admin", "good")], Fake(("admin", "good"))).run([target(dev("192.168.0.50", core.CAT_PC, [445], name="PC1"))])
        lines = S.csv_text(r).strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("Name,IP"))

    def test_wmi_error_mapping(self):
        self.assertEqual(S.map_wmi_error("wrong user / password, or this user is not an administrator on that PC")[0], S.AUTH)
        self.assertEqual(S.map_wmi_error("the PC's firewall blocks remote WMI")[0], S.BLOCKED)
        self.assertEqual(S.map_wmi_error("something odd")[0], S.ERR)


class Parsers(unittest.TestCase):
    def test_dahua(self):
        kv = S.parse_kv("serialNumber=ABC123\r\ndeviceType=DHI-NVR4216\r\n")
        self.assertEqual(kv["serialNumber"], "ABC123")

    def test_hik(self):
        x = ('<DeviceInfo xmlns="http://www.hikvision.com/ver20/XMLSchema"><deviceName>Cam1</deviceName>'
             '<model>DS-2CD2</model><serialNumber>DS-123</serialNumber><firmwareVersion>V5.5</firmwareVersion></DeviceInfo>')
        h = S.parse_hik(x)
        self.assertEqual((h["model"], h["serial"], h["firmware"]), ("DS-2CD2", "DS-123", "V5.5"))
        self.assertEqual(S.parse_hik("not xml"), {})

    def test_onvif(self):
        ok = ('<s:Envelope xmlns:s="x"><s:Body><tds:GetDeviceInformationResponse xmlns:tds="y"><tds:Manufacturer>H</tds:Manufacturer>'
              '<tds:Model>M1</tds:Model><tds:FirmwareVersion>2</tds:FirmwareVersion><tds:SerialNumber>SN</tds:SerialNumber>'
              '</tds:GetDeviceInformationResponse></s:Body></s:Envelope>')
        d, refused = S.parse_onvif(ok)
        self.assertFalse(refused)
        self.assertEqual(d["serial"], "SN")
        d, refused = S.parse_onvif("<Fault><Reason>Sender not authorized</Reason></Fault>")
        self.assertTrue(refused)

    def test_digest_matches_rfc_example(self):
        # RFC 2617 section 3.5 example
        p = {"realm": "testrealm@host.com", "nonce": "dcd98b7102dd2f0e8b11d0f600bfb0c093", "qop": "auth",
             "opaque": "5ccc069c403ebaf9f0171e9517f40e41"}
        h = S.digest_header("GET", "/dir/index.html", "Mufasa", "Circle Of Life", p, cnonce="0a4f113b")
        self.assertIn('response="6629fae49393a05397450978507c4ef1"', h)

    def test_onvif_token_digest(self):
        t = S.onvif_token("u", "p", nonce=b"0123456789abcdef", created="2026-01-01T00:00:00Z")
        self.assertIn("PasswordDigest", t)
        self.assertNotIn(">p<", t)


class OneShotHttp(unittest.TestCase):
    """The real http_login against a tiny local server: exactly two requests, never more."""

    def server(self, ok_pw):
        import http.server
        import socketserver
        seen = []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                a = self.headers.get("Authorization", "")
                seen.append(a)
                import base64
                if a == "Basic " + base64.b64encode(f"admin:{ok_pw}".encode()).decode():
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"serialNumber=Z9\n")
                else:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="x"')
                    self.end_headers()
        srv = socketserver.TCPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        self.addCleanup(srv.server_close)
        return srv.server_address[1], seen

    def test_wrong_password_is_one_attempt(self):
        port, seen = self.server("good")
        code, _, how = S.http_login("127.0.0.1", port, "/", "admin", "bad")
        self.assertEqual((code, how), (401, "basic"))
        self.assertEqual(len([a for a in seen if a]), 1)
        self.assertEqual(len(seen), 2)

    def test_right_password(self):
        port, _ = self.server("good")
        code, body, _ = S.http_login("127.0.0.1", port, "/", "admin", "good")
        self.assertEqual(code, 200)
        self.assertIn("Z9", body)

    def test_closed_port_is_unreachable(self):
        with self.assertRaises(S.Outcome) as c:
            S.http_login("127.0.0.1", 1, "/", "a", "b")
        self.assertEqual(c.exception.status, S.UNREACH)

    def test_dahua_transport_end_to_end(self):
        port, _ = self.server("good")
        d = {"ports": [80]}
        orig = S._http_port
        S._http_port = lambda dd, prefer=(): (port, False)
        self.addCleanup(setattr, S, "_http_port", orig)
        with self.assertRaises(S.Outcome) as c:
            S.t_dahua("127.0.0.1", "admin", "bad", d)
        self.assertEqual(c.exception.status, S.AUTH)
        self.assertEqual(S.t_dahua("127.0.0.1", "admin", "good", d)["serial"], "Z9")


class Router(unittest.TestCase):
    def test_ros_ok_and_refused(self):
        r = FakeRouter("admin", "pw")
        d = {"api_port": r.port}
        data = S.t_ros("127.0.0.1", "admin", "pw", d)
        self.assertEqual(data["identity"], "Office-Router")
        self.assertIn("7.15", data["version"])
        with self.assertRaises(S.Outcome) as c:
            S.t_ros("127.0.0.1", "admin", "nope", d)
        self.assertEqual(c.exception.status, S.AUTH)

    def test_ros_unreachable(self):
        with self.assertRaises(S.Outcome) as c:
            S.t_ros("127.0.0.1", "a", "b", {"api_port": 1})
        self.assertEqual(c.exception.status, S.UNREACH)


class Phones(unittest.TestCase):
    def test_clean_phone_has_no_findings(self):
        p = dev("192.168.0.210", core.CAT_PHONE, [62078], name="iPhone")
        self.assertEqual(S.phone_health([p]), [])

    def test_ip_shared_with_camera(self):
        p = dev("192.168.0.20", core.CAT_PHONE, [], name="Redmi", mac="AA:00:00:00:00:01")
        c = dev("192.168.0.20", core.CAT_CAM, [37777], mac="AA:00:00:00:00:02")
        f = S.phone_health([p, c])
        self.assertTrue(any(x["level"] == "critical" and "shares" in x["text"] for x in f))

    def test_phone_in_infra_block_and_static(self):
        p = dev("192.168.0.5", core.CAT_PHONE, [], name="Galaxy")
        f = S.phone_health([p], ranges={"infra": ("192.168.0.2", "192.168.0.19")}, ip_type_of=lambda d: "Static")
        txt = " ".join(x["text"] for x in f)
        self.assertIn("infra", txt)
        self.assertIn("by hand", txt)

    def test_reserved_for_another_device(self):
        p = dev("192.168.0.60", core.CAT_PHONE, [], name="Pixel", mac="AA:00:00:00:00:09")
        leases = [{"address": "192.168.0.60", "mac-address": "AA:00:00:00:00:77", "dynamic": "false"}]
        f = S.phone_health([p], lease_rows=leases)
        self.assertTrue(any("reserved" in x["text"] for x in f))

    def test_camera_ports_on_phone(self):
        p = dev("192.168.0.201", core.CAT_PHONE, [37777], name="Android")
        self.assertTrue(any("camera" in x["text"] for x in S.phone_health([p])))

    def test_stale_app_block_is_found_but_released_one_is_not(self):
        p = dev("192.168.0.202", core.CAT_PHONE, [], name="Vivo", mac="AA:00:00:00:00:0A")
        rows = [{"comment": "ND phone block AA:00:00:00:00:0A", "disabled": "false"},
                {"comment": "ND block AA:00:00:00:00:0A", "disabled": "true"},
                {"comment": "ND phone block AA:00:00:00:00:99", "disabled": "false"}]
        f = [x for x in S.phone_health([p], filter_rows=rows) if "blocks it" in x["text"]]
        self.assertEqual(len(f), 1)

    def test_phone_router_knows_but_scan_missed(self):
        leases = [{"address": "192.168.0.230", "mac-address": "DA:11:22:33:44:55", "host-name": "Galaxy-S23", "status": "bound",
                   "dynamic": "true"}]
        f = S.phone_health([], lease_rows=leases)
        self.assertEqual(f[0]["level"], "info")

    def test_phones_never_get_a_login_attempt(self):
        f = Fake(("a", "b"))
        ts = S.plan([dev("192.168.0.230", core.CAT_PHONE, [62078, 80, 445])])
        self.assertEqual(ts, [])
        self.assertEqual(f.calls, [])


if __name__ == "__main__":
    unittest.main()
