# -*- coding: utf-8 -*-
"""DNS fix uses the ISP's own DNS FIRST (then public as fallback), so banking/UPI apps that reject a foreign
Wi-Fi DNS ('Unsecured Network', works on mobile not Wi-Fi) keep working - while browsing stays fast (Rakesh, 27 Nov)."""
import unittest
import nd_alerts as AL


class IspFirstDns(unittest.TestCase):
    def test_uses_isp_dns_first_then_public_fallback(self):
        s = AL.DNS_FIX
        self.assertIn("dynamic-servers", s)                 # reads what the PPPoE/DHCP link pushed
        self.assertIn("use-peer-dns=yes", s)                # keeps the link handing us the ISP DNS
        self.assertIn("1.1.1.1,8.8.8.8", s)                 # public DNS only as the tail/fallback
        # when ISP DNS is present it is prepended before the public ones
        self.assertIn('$isp . ",1.1.1.1,8.8.8.8"', s)

    def test_still_blocks_dns_from_wan_and_caches(self):
        s = AL.DNS_FIX
        self.assertIn("ND: block DNS from WAN", s)          # still not an open resolver
        self.assertIn("cache-size", s)                      # still caches for speed
        self.assertIn("allow-remote-requests=yes", s)

    def test_falls_back_to_public_when_no_isp_dns(self):
        s = AL.DNS_FIX
        self.assertIn('else={ /ip dns set servers=1.1.1.1,8.8.8.8', s)


if __name__ == "__main__":
    unittest.main()
