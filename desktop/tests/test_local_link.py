# -*- coding: utf-8 -*-
"""Direct camera check must stay on the local PoE/LAN wire: is_local_link() keeps private + APIPA addresses
and rejects CGNAT/VPN (Tailscale 100.64/10), public and malformed addresses - so a camera reached over a
tunnel (e.g. 100.86.91.63) is never listed as 'connected on this PoE link'."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_poecheck as PC  # noqa: E402


class LocalLink(unittest.TestCase):
    def test_private_and_apipa_are_local(self):
        for ip in ("192.168.0.104", "192.168.1.134", "10.0.0.5", "172.16.4.9", "172.31.0.1", "169.254.12.7"):
            self.assertTrue(PC.is_local_link(ip), ip)

    def test_cgnat_vpn_is_not_local(self):
        # 100.64.0.0/10 is Tailscale / carrier-grade NAT - reached over a tunnel, not the PoE switch
        for ip in ("100.86.91.63", "100.64.0.1", "100.127.255.254"):
            self.assertFalse(PC.is_local_link(ip), ip)

    def test_public_and_bad_are_not_local(self):
        for ip in ("8.8.8.8", "100.200.1.1", "172.32.0.1", "192.169.0.1", "", "nope", "1.2.3"):
            self.assertFalse(PC.is_local_link(ip), ip)


if __name__ == "__main__":
    unittest.main()
