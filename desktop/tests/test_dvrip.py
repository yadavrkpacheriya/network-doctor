"""XMeye / NetSurveillance (DVRIP, port 34567): nd_dvrip.py against a fake device - no network is used."""
import json
import struct
import unittest

import nd_camline as CL
import nd_dvrip as DV
import nd_sweep as S


class FakeDevice:
    """Speaks the device side of the protocol over an in-memory 'socket'."""

    def __init__(self, password="secret", config=None, restart_on_set=False, lock=False):
        self.password, self.restart_on_set, self.lock = password, restart_on_set, lock
        self.config = config or {}
        self.out, self.seen, self.sets, self.rebooted = b"", [], [], False

    def connect(self, addr, timeout):
        self.addr = addr
        return self

    def settimeout(self, t):
        pass

    def close(self):
        pass

    def sendall(self, data):
        _ff, _v, session, seq, msg, size = struct.unpack("<BB2xII2xHI", data[:20])
        assert data[0] == 0xFF and len(data) == 20 + size and data.endswith(b"\x0a\x00")
        req = json.loads(data[20:-2].decode())
        self.seen.append((msg, req))
        if msg == DV.LOGIN:
            if self.lock:
                ans = {"Ret": 206}
            elif req["PassWord"] == DV.sofia_hash(self.password) and req["UserName"] == "admin":
                ans = {"Ret": 100, "SessionID": "0x0000000B"}
            else:
                ans = {"Ret": 203}
        elif req.get("SessionID") != "0x0000000B":
            ans = {"Ret": 104}
        elif msg in (DV.CONFIG_GET, DV.INFO, DV.TITLES):
            name = req["Name"]
            ans = {"Ret": 100, "Name": name, name: self.config[name]} if name in self.config else {"Ret": 607}
        elif msg == DV.CONFIG_SET:
            name = req["Name"]
            self.config[name] = req[name]
            self.sets.append(name)
            ans = {"Ret": 603 if self.restart_on_set else 100}
        elif msg == DV.MACHINE:
            self.rebooted = True
            ans = {"Ret": 100}
        else:
            ans = {"Ret": 102}
        body = json.dumps(ans).encode() + b"\x0a\x00"
        self.out += struct.pack("<BB2xII2xHI", 0xFF, 1, 11, seq, msg + 1, len(body)) + body

    def recv(self, n):
        part, self.out = self.out[:n], self.out[n:]
        return part


def camera(**kw):
    cfg = {"SystemInfo": {"SerialNo": "abc123", "HardWare": "XM530", "SoftWareVersion": "V5.00"},
           "ChannelTitle": ["Gate cam"],
           "NetWork.NetCommon": {"HostName": "LocalHost", "HostIP": "0x4000A8C0"},
           "NetWork.NetDHCP": [{"Enable": False, "Interface": "eth0"}, {"Enable": False, "Interface": "wlan0"}]}
    return FakeDevice(config=cfg, **kw)


class Basics(unittest.TestCase):
    def test_password_form_and_address_form(self):
        self.assertEqual(DV.sofia_hash(""), "tlJwpbo6")            # the well-known form of an empty password
        self.assertEqual(DV.ip_to_hex("192.168.0.64"), "0x4000A8C0")
        self.assertEqual(DV.hex_to_ip("0x4000A8C0"), "192.168.0.64")

    def test_header_is_20_bytes_and_carries_the_length(self):
        p = DV.pack(11, 3, DV.CONFIG_GET, {"Name": "x"})
        self.assertEqual(DV.unpack_head(p[:20]), (11, 3, DV.CONFIG_GET, len(p) - 20))
        with self.assertRaises(DV.DvrError):
            DV.unpack_head(b"HTTP/1.1 400 Bad Req")


class Info(unittest.TestCase):
    def test_login_and_details(self):
        dev = camera()
        info = DV.read_info("192.168.0.64", "admin", "secret", connect=dev.connect)
        self.assertEqual(info, {"serial": "abc123", "model": "XM530", "firmware": "V5.00", "name": "Gate cam"})
        self.assertEqual(dev.addr, ("192.168.0.64", 34567))

    def test_wrong_password_is_refused_and_nothing_else_is_asked(self):
        dev = camera()
        with self.assertRaises(DV.DvrError) as e:
            DV.read_info("192.168.0.64", "admin", "wrong", connect=dev.connect)
        self.assertTrue(e.exception.refused)
        self.assertEqual(len(dev.seen), 1)

    def test_sweep_reports_refused_as_a_login_failure(self):
        from unittest import mock
        with mock.patch.object(DV, "read_info", side_effect=DV.DvrError("account locked", refused=True)):
            with self.assertRaises(S.Outcome) as e:
                S.t_xmeye("192.168.0.64", "admin", "secret", {})
        self.assertEqual(e.exception.status, S.AUTH)
        with mock.patch.object(DV, "read_info", side_effect=ConnectionRefusedError()):
            with self.assertRaises(S.Outcome) as e:
                S.t_xmeye("192.168.0.64", "admin", "secret", {})
        self.assertEqual(e.exception.status, S.UNREACH)


class Dhcp(unittest.TestCase):
    def test_only_the_wired_interface_is_switched(self):
        dev = camera()
        note = DV.set_dhcp("192.168.0.64", "admin", "secret", connect=dev.connect)
        self.assertIn("automatic", note)
        self.assertEqual(dev.config["NetWork.NetDHCP"],
                         [{"Enable": True, "Interface": "eth0"}, {"Enable": False, "Interface": "wlan0"}])
        self.assertFalse(dev.rebooted)

    def test_already_automatic_writes_nothing(self):
        dev = camera()
        dev.config["NetWork.NetDHCP"][0]["Enable"] = True
        self.assertIn("already", DV.set_dhcp("192.168.0.64", "admin", "secret", connect=dev.connect))
        self.assertEqual(dev.sets, [])

    def test_restarts_only_when_the_camera_asks(self):
        dev = camera(restart_on_set=True)
        self.assertIn("restarting", DV.set_dhcp("192.168.0.64", "admin", "secret", connect=dev.connect))
        self.assertTrue(dev.rebooted)


def recorder(addr_a="192.168.0.64", addr_b="192.168.0.65"):
    return FakeDevice(config={"NetWork.RemoteDeviceV3": [
        {"ConnType": "SINGLE", "Decoder": [{"IPAddress": addr_a, "Port": 34567, "UserName": "admin"}]},
        {"ConnType": "SINGLE", "Decoder": [{"IPAddress": addr_b, "Port": 34567, "UserName": "admin"}]}]})


class Recorder(unittest.TestCase):
    def test_one_matching_channel_gets_the_new_ip(self):
        dev = recorder()
        ok, note = DV.recorder_update("192.168.0.141", "admin", "secret", "192.168.0.64", "192.168.0.72",
                                      connect=dev.connect)
        self.assertTrue(ok)
        ips = [x["Decoder"][0]["IPAddress"] for x in dev.config["NetWork.RemoteDeviceV3"]]
        self.assertEqual(ips, ["192.168.0.72", "192.168.0.65"])

    def test_address_written_in_the_devices_own_form_keeps_that_form(self):
        dev = recorder(DV.ip_to_hex("192.168.0.64"))
        DV.recorder_update("192.168.0.141", "admin", "secret", "192.168.0.64", "192.168.0.72", connect=dev.connect)
        self.assertEqual(dev.config["NetWork.RemoteDeviceV3"][0]["Decoder"][0]["IPAddress"],
                         DV.ip_to_hex("192.168.0.72"))

    def test_no_match_or_two_matches_write_nothing(self):
        dev = recorder()
        self.assertFalse(DV.recorder_update("192.168.0.141", "admin", "secret", "192.168.0.99", "192.168.0.72",
                                            connect=dev.connect)[0])
        self.assertEqual(dev.sets, [])
        dev = recorder("192.168.0.64", "192.168.0.64")
        with self.assertRaises(DV.DvrError):
            DV.recorder_update("192.168.0.141", "admin", "secret", "192.168.0.64", "192.168.0.72",
                               connect=dev.connect)
        self.assertEqual(dev.sets, [])


class LineUp(unittest.TestCase):
    def test_xmeye_cameras_are_now_movable_and_recorders_are_updated(self):
        self.assertIn("xmeye", CL.MOVABLE)
        self.assertIs(CL.SETTERS["xmeye"], CL.xmeye_set_dhcp)
        nvr = {"dev": {"ip": "192.168.0.141", "ports": [34567]}, "ip_now": "192.168.0.141", "group": "nvr",
               "method": "xmeye", "login": 1}
        calls = []
        text = CL.update_recorders([nvr], [("admin", "x")], "192.168.0.64", "192.168.0.72",
                                   xmeye_update=lambda ip, u, p, old, new: calls.append((ip, old, new))
                                   or (True, f"recorder entry now uses {new}"))
        self.assertEqual(calls, [("192.168.0.141", "192.168.0.64", "192.168.0.72")])
        self.assertIn("now uses 192.168.0.72", text)


if __name__ == "__main__":
    unittest.main()
