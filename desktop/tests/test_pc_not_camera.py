# -*- coding: utf-8 -*-
"""Regression: a Windows PC that happens to answer on RTSP port 554 must NOT be filed under cameras.
Real case (26 Nov): 'SAURABH' laptop (Windows RPC/NetBIOS/file-sharing) showed up under CCTV cameras because
port 554 was open. A camera never runs SMB file sharing or answers with a Windows computer name, so strong
Windows evidence wins over a lone 554."""
import unittest
import nd_core as core


def dev(ports=(), vendor="", name="", netbios=None, smb=None, ttl=None, upnp=None, http=None, random=False):
    return {"ip": "192.168.0.88", "ports": list(ports), "vendor": vendor, "name": name,
            "upnp": upnp or {}, "http": http or {}, "random": random, "ttl": ttl,
            "names": {k: v for k, v in (("netbios", netbios), ("smb", smb)) if v}}


class PcVsCamera(unittest.TestCase):
    def cat(self, **kw):
        return core.categorize(dev(**kw), "192.168.0.1")

    def test_windows_pc_with_rtsp_554_is_a_pc_not_a_camera(self):
        # the SAURABH case: SMB + RPC + NetBIOS name, and 554 open
        c, why = self.cat(ports=(135, 139, 445, 554), netbios="SAURABH", vendor="Intel Corporate")
        self.assertEqual(c, core.CAT_PC)
        self.assertIn("Windows", why)

    def test_rdp_box_with_554_is_a_pc(self):
        c, why = self.cat(ports=(3389, 554), netbios="DESK-01")
        self.assertEqual(c, core.CAT_PC)

    def test_real_camera_on_554_only_is_still_a_camera(self):
        # no Windows ports, no computer name -> genuine camera
        c, why = self.cat(ports=(554, 80), vendor="Hikvision")
        self.assertEqual(c, core.CAT_CAM)

    def test_nvr_on_34567_is_still_a_camera_even_if_smb_seen(self):
        # a camera-only DVR port (34567/37777) or camera brand outranks a stray SMB guess
        c, why = self.cat(ports=(34567,), vendor="Hikvision", netbios="NVR1")
        self.assertEqual(c, core.CAT_CAM)

    def test_camera_brand_with_smb_false_positive_stays_camera(self):
        c, why = self.cat(ports=(445, 554), vendor="Dahua")
        self.assertEqual(c, core.CAT_CAM)

    def test_plain_windows_pc_unaffected(self):
        c, why = self.cat(ports=(445, 139), netbios="RAKESH")
        self.assertEqual(c, core.CAT_PC)


if __name__ == "__main__":
    unittest.main()
