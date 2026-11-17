# -*- coding: utf-8 -*-
"""Direct PoE camera check: discovery message builders + response parsers + merge, fed real sample replies
so nothing touches the network."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_poecheck as P  # noqa: E402

ONVIF_REPLY = (b'<?xml version="1.0"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope">'
               b'<e:Body><d:ProbeMatches xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
               b'<d:ProbeMatch><d:Scopes>onvif://www.onvif.org/name/Hikvision onvif://www.onvif.org/hardware/DS-2CD'
               b'</d:Scopes><d:XAddrs>http://192.168.1.64/onvif/device_service</d:XAddrs>'
               b'</d:ProbeMatch></d:ProbeMatches></e:Body></e:Envelope>')

SADP_REPLY = (b'<?xml version="1.0" encoding="utf-8"?><ProbeMatch><Uuid>x</Uuid>'
              b'<DeviceType>IPCamera</DeviceType><DeviceDescription>DS-2CD2043</DeviceDescription>'
              b'<DeviceSN>DS-2CD2043G0</DeviceSN><IPv4Address>192.168.1.64</IPv4Address>'
              b'<MAC>44-19-b6-aa-bb-cc</MAC></ProbeMatch>')

DAHUA_REPLY = (b'\x20\x00\x00\x00' + b'\x00' * 16 +
               b'{"method":"client.notifyDevInfo","params":{"deviceInfo":{"IPAddress":"192.168.1.108",'
               b'"mac":"3c-ef-8c-11-22-33","DeviceType":"IPC-HFW","SerialNo":"ABC123"}}}')


class Builders(unittest.TestCase):
    def test_onvif_probe_is_a_ws_discovery_probe(self):
        msg = P.onvif_probe_msg("uuid:abc")
        self.assertIn(b"Probe", msg)
        self.assertIn(b"NetworkVideoTransmitter", msg)

    def test_dahua_probe_has_dhip_header_and_search(self):
        msg = P.dahua_probe_msg()
        self.assertEqual(msg[:4], b"\x20\x00\x00\x00")
        self.assertIn(b"DHDiscover.search", msg)


class Parsers(unittest.TestCase):
    def test_onvif_extracts_ip_and_brand(self):
        r = P.parse_onvif(ONVIF_REPLY, "192.168.1.64")
        self.assertEqual(r["ip"], "192.168.1.64")
        self.assertEqual(r["brand"], "Hikvision")
        self.assertEqual(r["how"], "ONVIF")

    def test_sadp_extracts_ip_mac_model(self):
        r = P.parse_hik(SADP_REPLY)
        self.assertEqual(r["ip"], "192.168.1.64")
        self.assertEqual(r["mac"], "44:19:B6:AA:BB:CC")
        self.assertEqual(r["model"], "DS-2CD2043")
        self.assertEqual(r["brand"], "Hikvision")

    def test_dahua_extracts_ip_mac(self):
        r = P.parse_dahua(DAHUA_REPLY)
        self.assertEqual(r["ip"], "192.168.1.108")
        self.assertEqual(r["mac"], "3C:EF:8C:11:22:33")
        self.assertEqual(r["brand"], "Dahua")

    def test_non_camera_reply_is_ignored(self):
        self.assertIsNone(P.parse_onvif(b"just some udp noise"))
        self.assertIsNone(P.parse_dahua(b"no json here"))


XMEYE_REPLY = (b'\xff\x00\x00\x00' + b'\x00' * 12 + b'\xfb\x05\x00\x00' +
               b'{"NetWork.NetCommon":{"HostIP":"0x6401A8C0","HostName":"IPC-GATE","MAC":"00:12:41:aa:bb:cc",'
               b'"TCPPort":34567}}\n\x00')


class LocalBrands(unittest.TestCase):
    def test_xmeye_search_builds_and_parses(self):
        self.assertEqual(P.xmeye_probe_msg()[:1], b"\xff")       # DVRIP header
        r = P.parse_xmeye(XMEYE_REPLY)
        self.assertEqual(r["ip"], "192.168.1.100")              # HostIP hex decoded
        self.assertEqual(r["mac"], "00:12:41:AA:BB:CC")
        self.assertEqual(r["model"], "IPC-GATE")
        self.assertEqual(r["how"], "XMeye")

    def test_onvif_finds_a_generic_camera_with_no_brand(self):
        reply = (b'<e:Envelope><e:Body><d:ProbeMatches xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
                 b'<d:ProbeMatch><d:XAddrs>http://192.168.1.50/onvif/device_service</d:XAddrs>'
                 b'</d:ProbeMatch></d:ProbeMatches></e:Body></e:Envelope>')
        r = P.parse_onvif(reply, "192.168.1.50")
        self.assertEqual(r["ip"], "192.168.1.50")               # found even with no recognizable brand
        self.assertEqual(r["brand"], "")

    def test_port_sweep_finds_cameras_by_service_brand_agnostic(self):
        # a no-name camera that answers NO discovery, only its RTSP + XMeye ports
        def connect(ip, port, timeout=0.6):
            return (ip, port) in {("192.168.1.90", 554), ("192.168.1.90", 34567), ("192.168.1.5", 80)}
        res = P.sweep_ports(["192.168.1.90", "192.168.1.5", "192.168.1.200"], connect=connect)
        self.assertEqual([r["ip"] for r in res], ["192.168.1.5", "192.168.1.90"])
        self.assertEqual(res[1]["guess"], "XMeye/local DVR camera")   # 34567 open


class MergeAndDiscover(unittest.TestCase):
    def test_same_camera_seen_by_two_protocols_merges(self):
        onvif = P.parse_onvif(ONVIF_REPLY, "192.168.1.64")
        sadp = P.parse_hik(SADP_REPLY)
        merged = P.merge([onvif, sadp])
        self.assertEqual(len(merged), 1)                       # same IP -> one camera
        cam = merged[0]
        self.assertEqual(cam["mac"], "44:19:B6:AA:BB:CC")      # MAC filled from SADP
        self.assertEqual(set(cam["seen_by"]), {"ONVIF", "SADP"})

    def test_discover_end_to_end_with_injected_responses(self):
        def collect(messages, timeout):
            return [("ONVIF", ONVIF_REPLY, "192.168.1.64"),
                    ("SADP", SADP_REPLY, "192.168.1.64"),
                    ("Dahua", DAHUA_REPLY, "192.168.1.108")]
        cams = P.discover(collect=collect, alive=lambda ip: 80)
        self.assertEqual([c["ip"] for c in cams], ["192.168.1.64", "192.168.1.108"])
        self.assertTrue(all(c["port"] == 80 for c in cams))    # confirmed reachable
        self.assertEqual(cams[0]["brand"], "Hikvision")
        self.assertEqual(cams[1]["brand"], "Dahua")


if __name__ == "__main__":
    unittest.main()
