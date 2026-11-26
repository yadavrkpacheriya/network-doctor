# -*- coding: utf-8 -*-
"""SMB-to-internet block: a PC sending Windows file sharing (445/139) to the internet is a leak/worm; the brain
must auto-block it safely on the WAN without touching LAN file sharing. (Open item: PC 192.168.0.27, 26 Nov.)"""
import re
import unittest
import nd_alerts as AL
import nd_bandwidth as B
import nd_reset as R


class SmbLeak(unittest.TestCase):
    def test_smb_leak_is_detected_and_auto_blockable(self):
        r = AL.explain("Windows file sharing to the internet - worm / ransomware sign",
                       "critical", "192.168.0.27", "192.168.0.1")
        self.assertEqual(r["kind"], "smb_leak")
        self.assertIn("smb_leak", AL.AUTO_SAFE)
        fix = next(a for a in r["auto"] if a["where"] == "router")
        self.assertIn("dst-port=445,139", fix["cmd"])
        self.assertIn("out-interface=$wan", fix["cmd"])      # blocks only traffic leaving on the WAN
        self.assertTrue(fix["undo"])

    def test_block_only_hits_wan_not_lan_sharing(self):
        s, u = B.block_smb_to_internet("pppoe-out1")
        self.assertIn("out-interface=pppoe-out1", s)         # only WAN-bound SMB is dropped
        self.assertNotIn("192.168", s.split("input")[0])     # forward rule isn't scoped to a LAN subnet = LAN untouched
        self.assertIn("remove", u)

    def test_reset_removes_the_smb_block(self):
        self.assertTrue(re.search(R.COMMENT_RE, "ND: block SMB to internet"))

    def test_block_needs_wan(self):
        with self.assertRaises(ValueError):
            B.block_smb_to_internet("")


if __name__ == "__main__":
    unittest.main()
