"""Tests for nd_camline.py - lining the cameras up on fixed IPs. No camera, router or network is used."""
import unittest

import nd_bandwidth as B
import nd_camline as CL
import nd_core as core
import nd_sweep as S

NET = "192.168.0.0/24"


def dev(ip, mac, cat=core.CAT_CAM, ports=(80, 8000, 554), name=""):
    return {"ip": ip, "mac": mac, "online": True, "category": cat, "ports": list(ports), "name": name,
            "vendor": "", "ips": [ip], "http": None}


def res(mac, method="hik", login=1, status=S.OK):
    return {"mac": mac, "method": method, "status": status, "login": login, "data": {}}


class Plan(unittest.TestCase):
    def setUp(self):
        self.ranges = B.default_ranges(NET)
        self.devs = [dev("192.168.0.1", "AA:00:00:00:00:01", core.CAT_ROUTER, (80,)),
                     dev("192.168.0.64", "AA:00:00:00:00:64"),           # camera outside the block
                     dev("192.168.0.71", "AA:00:00:00:00:71"),           # camera already first in the block
                     dev("192.168.0.180", "AA:00:00:00:01:80"),          # camera outside, no login
                     dev("192.168.0.201", "AA:00:00:00:02:01", ports=(80, 37777))]

    def plan(self, results):
        return CL.line_plan(self.devs, "192.168.0.1", NET, self.ranges, results)

    def test_block_is_71_to_140_and_only_cameras_are_listed(self):
        self.assertEqual(self.ranges["cam"], ("192.168.0.71", "192.168.0.140"))
        rows = self.plan([])
        self.assertEqual({r["ip_now"] for r in rows}, {"192.168.0.64", "192.168.0.71", "192.168.0.180", "192.168.0.201"})

    def test_cameras_get_the_next_free_ips_in_order_and_one_in_the_block_stays(self):
        rows = self.plan([res("AA:00:00:00:00:64"), res("AA:00:00:00:02:01", "dahua")])
        by = {r["ip_now"]: r for r in rows}
        self.assertEqual(by["192.168.0.71"]["action"], "keep")
        self.assertEqual((by["192.168.0.64"]["action"], by["192.168.0.64"]["ip_new"]), ("move", "192.168.0.72"))
        self.assertEqual(by["192.168.0.201"]["ip_new"], "192.168.0.74")
        self.assertEqual(len({r["ip_new"] for r in rows}), len(rows))  # never the same IP twice

    def test_no_login_or_unknown_brand_is_by_hand_never_moved(self):
        rows = self.plan([res("AA:00:00:00:00:64", "onvif"), res("AA:00:00:00:01:80", status=S.AUTH)])
        by = {r["ip_now"]: r for r in rows}
        self.assertEqual(by["192.168.0.64"]["action"], "manual")
        self.assertEqual(by["192.168.0.180"]["action"], "manual")

    def test_csv_has_old_and_new(self):
        rows = self.plan([res("AA:00:00:00:00:64")])
        text = CL.old_new_csv(rows)
        self.assertIn("192.168.0.64,192.168.0.72", text)


class FakeCam:
    """Answers like a camera's web API; records what was sent."""

    def __init__(self, pages):
        self.pages, self.sent = pages, []

    def __call__(self, ip, port, method, path, user, pw, body=None, ssl_on=False, ctype=""):
        self.sent.append((method, path, body))
        return self.pages.get((method, path), (404, "", "digest"))


HIK_STATIC = ('<IPAddress version="2.0"><ipVersion>v4</ipVersion><addressingType>static</addressingType>'
              '<ipAddress>192.168.0.64</ipAddress><subnetMask>255.255.255.0</subnetMask></IPAddress>')


class Switches(unittest.TestCase):
    def test_hikvision_changes_only_the_addressing_type(self):
        cam = FakeCam({("GET", CL.HIK_IP_PATH): (200, HIK_STATIC, "digest"),
                       ("PUT", CL.HIK_IP_PATH): (200, "<statusString>OK</statusString>", "digest")})
        note = CL.hik_set_dhcp("192.168.0.64", 80, False, "admin", "x", send=cam)
        self.assertIn("automatic", note)
        put = next(b for m, p, b in cam.sent if m == "PUT")
        self.assertEqual(put, HIK_STATIC.replace("static", "dynamic"))

    def test_hikvision_already_dhcp_writes_nothing(self):
        cam = FakeCam({("GET", CL.HIK_IP_PATH): (200, HIK_STATIC.replace("static", "dynamic"), "digest")})
        self.assertIn("already", CL.hik_set_dhcp("192.168.0.64", 80, False, "admin", "x", send=cam))
        self.assertFalse([m for m, _, _ in cam.sent if m != "GET"])

    def test_hikvision_reboots_only_when_the_camera_asks(self):
        cam = FakeCam({("GET", CL.HIK_IP_PATH): (200, HIK_STATIC, "digest"),
                       ("PUT", CL.HIK_IP_PATH): (200, "<statusString>Reboot Required</statusString>", "digest")})
        CL.hik_set_dhcp("192.168.0.64", 80, False, "admin", "x", send=cam)
        self.assertIn(("PUT", "/ISAPI/System/reboot", ""), cam.sent)

    def test_refused_login_and_refused_change_raise(self):
        with self.assertRaises(CL.CamError):
            CL.hik_set_dhcp("1.1.1.1", 80, False, "a", "b", send=FakeCam({("GET", CL.HIK_IP_PATH): (401, "", "")}))
        cam = FakeCam({("GET", CL.HIK_IP_PATH): (200, HIK_STATIC, ""), ("PUT", CL.HIK_IP_PATH): (403, "", "")})
        with self.assertRaises(CL.CamError):
            CL.hik_set_dhcp("1.1.1.1", 80, False, "a", "b", send=cam)

    def test_dahua_uses_the_default_interface(self):
        base = "/cgi-bin/configManager.cgi?action="
        cam = FakeCam({("GET", base + "getConfig&name=Network"):
                       (200, "table.Network.DefaultInterface=eth2\ntable.Network.eth2.DhcpEnable=false\n", ""),
                       ("GET", base + "setConfig&Network.eth2.DhcpEnable=true"): (200, "OK", "")})
        self.assertIn("automatic", CL.dahua_set_dhcp("192.168.0.201", 80, False, "admin", "x", send=cam))


class Clock:
    def __init__(self):
        self.t = 0.0

    def sleep(self, s):
        self.t += s

    def now(self):
        return self.t


def row(ip_now, ip_new, login=1):
    return {"dev": dev(ip_now, "AA:00:00:00:00:" + ip_now[-2:]), "ip_now": ip_now, "ip_new": ip_new,
            "action": "move", "method": "hik", "login": login, "why": ""}


class Moving(unittest.TestCase):
    def kw(self, c):
        return dict(sleep=c.sleep, clock=c.now, wait=30, step=3)

    def test_router_refusal_leaves_the_camera_untouched(self):
        touched = []
        ok, text = CL.move_one(row("192.168.0.64", "192.168.0.72"), ("admin", "x"), lambda r: "NOT BOUND",
                               lambda ip: True, set_dhcp=lambda *a: touched.append(a) or "x")
        self.assertFalse(ok)
        self.assertEqual(touched, [])
        self.assertIn("NOT touched", text)

    def test_success_when_it_answers_on_the_new_ip(self):
        c = Clock()
        ok, text = CL.move_one(row("192.168.0.64", "192.168.0.72"), ("admin", "x"), lambda r: "",
                               lambda ip: ip == "192.168.0.72" and c.t >= 9, set_dhcp=lambda *a: "switched",
                               **self.kw(c))
        self.assertTrue(ok)
        self.assertIn("192.168.0.72", text)

    def test_run_stops_at_the_first_failure_and_respects_the_pilot_limit(self):
        c = Clock()
        rows = [row("192.168.0.64", "192.168.0.72"), row("192.168.0.65", "192.168.0.73"),
                row("192.168.0.66", "192.168.0.74")]
        n = CL.run(rows, [("admin", "x")], lambda r: "", lambda ip: True, limit=1,
                   set_dhcp=lambda *a: "switched", **self.kw(c))
        self.assertEqual(n, 1)
        self.assertNotIn("result", rows[1])                      # pilot: only one camera touched
        seen = []
        n = CL.run(rows[1:], [("admin", "x")], lambda r: "", lambda ip: False,
                   set_dhcp=lambda *a: seen.append(a[0]) or "switched", **self.kw(c))
        self.assertEqual(n, 0)
        self.assertEqual(seen, ["192.168.0.65"])                 # the third camera was never touched
        self.assertTrue(rows[1]["result"].startswith("FAILED"))
        self.assertNotIn("result", rows[2])

    def test_missing_login_moves_nothing(self):
        rows = [row("192.168.0.64", "192.168.0.72", login=2)]
        self.assertEqual(CL.run(rows, [("admin", "x")], lambda r: "", lambda ip: True), 0)
        self.assertIn("not moved", rows[0]["result"])


HIK_LIST = ('<InputProxyChannelList><InputProxyChannel version="1.0"><id>1</id><name>Gate</name>'
            '<sourceInputPortDescriptor><proxyProtocol>HIKVISION</proxyProtocol><ipAddress>192.168.0.64</ipAddress>'
            '<managePortNo>8000</managePortNo><userName>admin</userName></sourceInputPortDescriptor>'
            '</InputProxyChannel><InputProxyChannel version="1.0"><id>2</id><name>Store</name>'
            '<sourceInputPortDescriptor><ipAddress>192.168.0.65</ipAddress><userName>viewer</userName>'
            '</sourceInputPortDescriptor></InputProxyChannel></InputProxyChannelList>')
HIK_STATUS = ('<InputProxyChannelStatusList><InputProxyChannelStatus><id>1</id><online>true</online>'
              '</InputProxyChannelStatus><InputProxyChannelStatus><id>2</id><online>false</online>'
              '</InputProxyChannelStatus></InputProxyChannelStatusList>')


def nvr_row(method="hik", login=1):
    return {"dev": dev("192.168.0.141", "AA:00:00:00:01:41", ports=(80, 8000)), "ip_now": "192.168.0.141",
            "group": "nvr", "method": method, "login": login, "action": "keep"}


class Recorder(unittest.TestCase):
    def cam(self, put_code=200):
        return FakeCam({("GET", CL.HIK_CH): (200, HIK_LIST, "digest"),
                        ("PUT", CL.HIK_CH + "/1"): (put_code, "<statusString>OK</statusString>", "digest"),
                        ("PUT", CL.HIK_CH + "/2"): (put_code, "<statusString>OK</statusString>", "digest"),
                        ("GET", CL.HIK_CH + "/status"): (200, HIK_STATUS, "digest")})

    def test_only_the_matching_channel_and_only_its_ip_change(self):
        cam = self.cam()
        cid, note = CL.hik_nvr_update("192.168.0.141", 80, False, "admin", "n", "192.168.0.64", "192.168.0.72",
                                      ("admin", "p&w"), send=cam)
        self.assertEqual(cid, "1")
        puts = [(p, b) for m, p, b in cam.sent if m == "PUT"]
        self.assertEqual(len(puts), 1)
        self.assertTrue(puts[0][0].endswith("/1"))
        self.assertIn("<ipAddress>192.168.0.72</ipAddress>", puts[0][1])
        self.assertNotIn("192.168.0.65", puts[0][1])                 # the other channel is not in what is sent
        self.assertIn("<password>p&amp;w</password>", puts[0][1])    # same user as the camera login: rewritten

    def test_a_channel_with_another_user_keeps_its_own_login(self):
        cam = self.cam()
        CL.hik_nvr_update("192.168.0.141", 80, False, "admin", "n", "192.168.0.65", "192.168.0.73", ("admin", "pw"),
                          send=cam)
        self.assertNotIn("<password>", next(b for m, p, b in cam.sent if m == "PUT"))

    def test_no_channel_for_that_ip_writes_nothing(self):
        cam = self.cam()
        self.assertEqual(CL.hik_nvr_update("192.168.0.141", 80, False, "a", "b", "192.168.0.99", "192.168.0.72",
                                           send=cam)[0], "")
        self.assertFalse([m for m, _, _ in cam.sent if m == "PUT"])

    def test_update_recorders_reports_online_and_never_raises(self):
        c = Clock()
        kw = dict(wait=20, step=5, sleep=c.sleep, clock=c.now)
        text = CL.update_recorders([nvr_row()], [("admin", "n")], "192.168.0.64", "192.168.0.72", ("admin", "pw"),
                                   send=self.cam(), **kw)
        self.assertIn("channel 1 now uses 192.168.0.72 and is online", text)
        text = CL.update_recorders([nvr_row()], [("admin", "n")], "192.168.0.65", "192.168.0.73", None,
                                   send=self.cam(), **kw)
        self.assertIn("OFFLINE", text)
        text = CL.update_recorders([nvr_row()], [("admin", "n")], "192.168.0.64", "192.168.0.72", None,
                                   send=self.cam(put_code=403), **kw)
        self.assertIn("did not accept", text)
        self.assertIn("by hand", CL.update_recorders([], [], "192.168.0.64", "192.168.0.72"))
        self.assertIn("by hand", CL.update_recorders([nvr_row()], [("admin", "n")], "192.168.0.99", "192.168.0.72",
                                                     send=self.cam(), **kw))

    def test_dahua_recorder_entry(self):
        base = "/cgi-bin/configManager.cgi?action="
        key = "RemoteDevice.uuid:System_CONFIG_NETCAMERA_INFO_3.Address"
        cam = FakeCam({("GET", base + "getConfig&name=RemoteDevice"):
                       (200, f"table.{key}=192.168.0.64\ntable.RemoteDevice.uuid:System_CONFIG_NETCAMERA_INFO_4."
                             "Address=192.168.0.65\n", ""),
                       ("GET", base + f"setConfig&{key}=192.168.0.72"): (200, "OK", "")})
        k, note = CL.dahua_nvr_update("192.168.0.142", 80, False, "admin", "x", "192.168.0.64", "192.168.0.72",
                                      send=cam)
        self.assertEqual(k, key)

    def test_run_calls_the_recorder_step_only_for_cameras_that_moved(self):
        c = Clock()
        rows = [row("192.168.0.64", "192.168.0.72"), row("192.168.0.65", "192.168.0.73")]
        told = []
        CL.run(rows, [("admin", "x")], lambda r: "", lambda ip: ip == "192.168.0.72",
               set_dhcp=lambda *a: "switched", after_move=lambda r, cred: told.append(r["ip_new"]) or "recorder ok",
               sleep=c.sleep, clock=c.now, wait=9, step=3)
        self.assertEqual(told, ["192.168.0.72"])
        self.assertIn("recorder ok", rows[0]["result"])
        self.assertTrue(rows[1]["result"].startswith("FAILED"))

    def test_recorders_are_picked_from_the_plan(self):
        rows = [nvr_row(), nvr_row("onvif"), dict(nvr_row(), group="cam")]
        self.assertEqual(len(CL.recorders(rows)), 1)


class HttpRequestKeepsGetBehaviour(unittest.TestCase):
    def test_http_login_is_a_get_through_http_request(self):
        seen = {}
        orig = S.http_request
        S.http_request = lambda ip, port, method, path, user, pw, **kw: seen.update(m=method, kw=kw) or (200, "x", "digest")
        try:
            self.assertEqual(S.http_login("1.2.3.4", 80, "/p", "u", "p"), (200, "x", "digest"))
        finally:
            S.http_request = orig
        self.assertEqual(seen["m"], "GET")


if __name__ == "__main__":
    unittest.main()
