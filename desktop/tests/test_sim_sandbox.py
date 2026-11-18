# -*- coding: utf-8 -*-
"""Sandbox proof: the app's real device code runs against in-memory fakes that speak the real protocols.

This is the "test like a real device/server before release" harness. If one of these breaks, an update that
would have misbehaved on a real router or camera is caught here first.
"""
import unittest

import nd_camline as CL
import nd_camhealth as H
import nd_dvrip as DV
import nd_routeros as RO
from sim import FakeRouter, FakeXmeye, FakeHttpCam, FakeOnvifCam, router_socket, RouterOS_against


# =============================================================== fake router over the real API wire protocol
class Router(unittest.TestCase):
    def test_login_identity_and_leases_read_through_the_real_client(self):
        fr = FakeRouter(identity="OfficeRouter", version="7.14")
        fr.model.add_lease("192.168.0.64", "AA:BB:CC:00:00:64", host="cam-gate")
        fr.model.add_lease("192.168.0.10", "AA:BB:CC:00:00:0A", host="pc-reception")
        with router_socket(fr.model):
            r = RouterOS_against(fr.model)
            name, ver = r.identity()
            leases = r.leases()
        self.assertEqual((name, ver), ("OfficeRouter", "7.14"))
        self.assertEqual({l["address"] for l in leases}, {"192.168.0.64", "192.168.0.10"})
        self.assertEqual(next(l["host-name"] for l in leases if l["address"] == "192.168.0.64"), "cam-gate")

    def test_arp_read_and_query_filter(self):
        fr = FakeRouter()
        fr.model.add_arp("192.168.0.64", "AA:BB:CC:00:00:64")
        fr.model.add_arp("192.168.0.65", "AA:BB:CC:00:00:65")
        with router_socket(fr.model):
            r = RouterOS_against(fr.model)
            one = r.cmd("/ip/arp/print", q_address="192.168.0.65")
        self.assertEqual(len(one), 1)
        self.assertEqual(one[0]["mac-address"], "AA:BB:CC:00:00:65")

    def test_add_set_remove_a_binding_row(self):
        fr = FakeRouter()
        with router_socket(fr.model):
            r = RouterOS_against(fr.model)
            r.talk(["/ip/arp/add", "=address=192.168.0.70", "=mac-address=AA:BB:CC:00:00:70",
                    "=interface=bridge"])
            rows = r.cmd("/ip/arp/print")
            self.assertEqual(len(rows), 1)
            rid = rows[0][".id"]
            r.talk(["/ip/arp/set", "=.id=" + rid, "=comment=bound-by-nd"])
            self.assertEqual(r.cmd("/ip/arp/print")[0]["comment"], "bound-by-nd")
            r.talk(["/ip/arp/remove", "=.id=" + rid])
            self.assertEqual(r.cmd("/ip/arp/print"), [])

    def test_run_cli_as_string_ros7(self):
        fr = FakeRouter(version="7.14")
        fr.model.cli["/ip/firewall/filter/print"] = " 0  chain=forward action=accept"
        with router_socket(fr.model):
            r = RouterOS_against(fr.model)
            out = r.run_cli("/ip/firewall/filter/print")
        self.assertIn("chain=forward", out)
        self.assertEqual(fr.model.ran, ["/ip/firewall/filter/print"])

    def test_run_cli_ros6_file_fallback(self):
        fr = FakeRouter(version="6.49", ros6=True)
        fr.model.cli["/export"] = "# jan/01/1970\n/ip address add address=192.168.0.1/24\n"
        with router_socket(fr.model):
            r = RouterOS_against(fr.model)
            out = r.run_cli("/export")
        self.assertIn("ip address add", out)


# =============================================================== fake XMeye / DVRIP over the real binary protocol
class Xmeye(unittest.TestCase):
    def test_read_info_login_and_name(self):
        dev = FakeXmeye(user="admin", pw="camPass1", model="HB-X8", serial="XM777", name="gate-1")
        info = DV.read_info("192.168.0.64", "admin", "camPass1", connect=dev.connect())
        self.assertEqual((info["model"], info["serial"], info["name"]), ("HB-X8", "XM777", "gate-1"))

    def test_login_refused_with_wrong_password(self):
        dev = FakeXmeye(user="admin", pw="right")
        with self.assertRaises(DV.DvrError) as cm:
            DV.read_info("192.168.0.64", "admin", "wrong", connect=dev.connect())
        self.assertTrue(cm.exception.refused)

    def test_set_dhcp_switches_and_reboots(self):
        dev = FakeXmeye(user="admin", pw="pw")
        note = DV.set_dhcp("192.168.0.64", "admin", "pw", connect=dev.connect())
        self.assertIn("automatic", note)
        self.assertTrue(dev.config["NetWork.NetDHCP"][0]["Enable"])
        self.assertTrue(dev.rebooted)

    def test_set_dhcp_idempotent(self):
        dev = FakeXmeye(user="admin", pw="pw")
        dev.config["NetWork.NetDHCP"][0]["Enable"] = True
        note = DV.set_dhcp("192.168.0.64", "admin", "pw", connect=dev.connect())
        self.assertIn("already", note)

    def test_recorder_update_repoints_one_channel(self):
        dev = FakeXmeye(user="admin", pw="pw")
        dev.config["NetWork.RemoteDeviceV3"] = [{"IPAddress": "192.168.0.64"}, {"IPAddress": "192.168.0.99"}]
        changed, note = DV.recorder_update("192.168.0.2", "admin", "pw", "192.168.0.64", "192.168.0.120",
                                           connect=dev.connect())
        self.assertTrue(changed)
        self.assertEqual(dev.config["NetWork.RemoteDeviceV3"][0]["IPAddress"], "192.168.0.120")

    def test_set_static_ip_writes_address_and_turns_dhcp_off(self):
        dev = FakeXmeye(user="admin", pw="pw")
        dev.config["NetWork.NetDHCP"][0]["Enable"] = True
        dev.config["NetWork.NetCommon"] = {"HostName": "gate", "HostIP": "192.168.1.64",
                                           "Submask": "255.255.255.0", "GateWay": "192.168.1.1"}
        note = DV.set_static_ip("192.168.1.64", "admin", "pw", "192.168.1.70", gw="192.168.1.1",
                                connect=dev.connect())
        self.assertIn("192.168.1.70", note)
        self.assertEqual(dev.config["NetWork.NetCommon"]["HostIP"], "192.168.1.70")
        self.assertFalse(dev.config["NetWork.NetDHCP"][0]["Enable"])        # DHCP turned off so the IP sticks

    def test_set_static_ip_rejects_a_bad_address(self):
        dev = FakeXmeye(user="admin", pw="pw")
        with self.assertRaises(DV.DvrError):
            DV.set_static_ip("192.168.1.64", "admin", "pw", "999.1.1.1", connect=dev.connect())

    def test_set_mac_writes_when_a_mac_field_exists(self):
        dev = FakeXmeye(user="admin", pw="pw")
        dev.config["NetWork.NetCommon"] = {"HostIP": "192.168.0.92", "MAC": "A0:00:00:01:7F:F0"}
        r = DV.set_mac("192.168.0.92", "admin", "pw", "02:11:22:33:44:55", connect=dev.connect())
        self.assertTrue(r["ok"])
        self.assertEqual(dev.config["NetWork.NetCommon"]["MAC"], "02:11:22:33:44:55")

    def test_set_mac_keeps_dash_format(self):
        dev = FakeXmeye(user="admin", pw="pw")
        dev.config["NetWork.NetCommon"] = {"MAC": "A0-00-00-01-7F-F0"}
        DV.set_mac("192.168.0.92", "admin", "pw", "02:11:22:33:44:55", connect=dev.connect())
        self.assertEqual(dev.config["NetWork.NetCommon"]["MAC"], "02-11-22-33-44-55")

    def test_set_mac_honest_when_no_mac_field(self):
        dev = FakeXmeye(user="admin", pw="pw")
        dev.config["NetWork.NetCommon"] = {"HostIP": "192.168.0.92"}      # no MAC setting - fixed in firmware
        r = DV.set_mac("192.168.0.92", "admin", "pw", "02:11:22:33:44:55", connect=dev.connect())
        self.assertFalse(r["ok"])
        self.assertIn("fixed in firmware", r["note"])

    def test_set_mac_rejects_bad_mac(self):
        dev = FakeXmeye(user="admin", pw="pw")
        with self.assertRaises(DV.DvrError):
            DV.set_mac("192.168.0.92", "admin", "pw", "not-a-mac", connect=dev.connect())

    def test_list_channels_on_an_nvr(self):
        nvr = FakeXmeye(user="admin", pw="pw",
                        channel_names=["Gate", "Lobby", "Parking", "CAM4"],
                        digital=[{"Enable": True, "DeviceInfo": {"HostIP": "192.168.0.31"}},
                                 {"Enable": True, "DeviceInfo": {"HostIP": "192.168.0.32"}},
                                 {"Enable": False, "DeviceInfo": {"HostIP": "0.0.0.0"}},
                                 {"Enable": False}])
        chans = DV.list_channels("192.168.0.74", "admin", "pw", connect=nvr.connect())
        self.assertEqual(len(chans), 4)
        self.assertEqual(chans[0]["name"], "Gate")
        self.assertEqual(chans[0]["ip"], "192.168.0.31")
        self.assertEqual(chans[1]["ip"], "192.168.0.32")
        self.assertEqual(chans[2]["ip"], "")            # 0.0.0.0 is not a real camera IP
        self.assertEqual(chans[0]["online"], True)
        self.assertEqual(chans[3]["name"], "CAM4")

    def test_list_channels_dict_wrapped_digital(self):
        # some firmwares wrap the channel list inside a dict instead of returning a bare list
        nvr = FakeXmeye(user="admin", pw="pw", channel_names=["Gate", "Lobby"],
                        digital={"DigitalChannel": [{"Enable": True, "DeviceInfo": {"HostIP": "192.168.0.31"}},
                                                    {"Enable": True, "DeviceInfo": {"HostIP": "192.168.0.32"}}]})
        chans = DV.list_channels("192.168.0.74", "admin", "pw", connect=nvr.connect())
        self.assertEqual(chans[0]["ip"], "192.168.0.31")
        self.assertEqual(chans[1]["ip"], "192.168.0.32")

    def test_list_channels_single_camera_box(self):
        cam = FakeXmeye(user="admin", pw="pw", name="front-gate")
        chans = DV.list_channels("192.168.0.64", "admin", "pw", connect=cam.connect())
        self.assertEqual(len(chans), 1)
        self.assertEqual(chans[0]["name"], "front-gate")


# =============================================================== fake HTTP cameras over nd_camline setters
class HttpCameras(unittest.TestCase):
    def test_hik_static_to_dhcp_then_idempotent(self):
        cam = FakeHttpCam(brand="hik", addressing="static")
        note = CL.hik_set_dhcp("192.168.0.64", 80, False, "admin", "pw", send=cam)
        self.assertIn("automatic", note)
        self.assertEqual(cam.addressing, "dynamic")
        self.assertIn("already", CL.hik_set_dhcp("192.168.0.64", 80, False, "admin", "pw", send=cam))

    def test_hik_wrong_login_raises(self):
        cam = FakeHttpCam(brand="hik", user="admin", pw="right")
        with self.assertRaises(CL.CamError):
            CL.hik_set_dhcp("192.168.0.64", 80, False, "admin", "wrong", send=cam)

    def test_dahua_enables_dhcp(self):
        cam = FakeHttpCam(brand="dahua", dhcp_enable=False)
        note = CL.dahua_set_dhcp("192.168.0.65", 80, False, "admin", "pw", send=cam)
        self.assertIn("automatic", note)
        self.assertTrue(cam.dhcp_enable)

    def test_reboot_camera_hik(self):
        cam = FakeHttpCam(brand="hik")
        note = CL.reboot_camera("192.168.0.64", "admin", "pw", ports=(80,), send=cam)
        self.assertIn("Hikvision", note)
        self.assertTrue(cam.rebooted)

    def test_default_password_detected_on_hik(self):
        # a camera still on a factory login (admin/12345) IS flagged
        cam = FakeHttpCam(brand="hik", user="admin", pw="12345")
        hit = CL.default_login_http("192.168.0.64", list(H.COMMON_DEFAULTS), ports=(80,), send=cam)
        self.assertEqual(hit, ("admin", "12345"))

    def test_strong_password_not_flagged(self):
        # a camera with a real password is NOT flagged (no false "error")
        cam = FakeHttpCam(brand="hik", user="admin", pw="S7rong!pass")
        hit = CL.default_login_http("192.168.0.64", list(H.COMMON_DEFAULTS), ports=(80,), send=cam)
        self.assertIsNone(hit)

    def test_default_password_detected_on_dahua(self):
        cam = FakeHttpCam(brand="dahua", user="admin", pw="admin")
        hit = CL.default_login_http("192.168.0.65", list(H.COMMON_DEFAULTS), ports=(80,), send=cam)
        self.assertEqual(hit, ("admin", "admin"))


# =============================================================== fake ONVIF camera over nd_camline setter
class Onvif(unittest.TestCase):
    def test_onvif_sets_dhcp_and_reboots_when_needed(self):
        cam = FakeOnvifCam(dhcp=False, reboot_needed=True)
        note = CL.onvif_set_dhcp("192.168.0.66", 80, False, "admin", "pw", call=cam)
        self.assertIn("automatic", note)
        self.assertTrue(cam.dhcp)
        self.assertTrue(cam.rebooted)

    def test_onvif_already_on_dhcp(self):
        cam = FakeOnvifCam(dhcp=True)
        self.assertIn("already", CL.onvif_set_dhcp("192.168.0.66", 80, False, "admin", "pw", call=cam))


if __name__ == "__main__":
    unittest.main()
