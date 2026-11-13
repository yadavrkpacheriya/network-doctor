"""Tests for nd_net.vpn_tunnel_active() / second_opinion_ip() - the CGNAT check's cross-check helpers
(added after a real false-CGNAT reading caused by Tailscale rerouting one of the two IP sources)."""
import unittest
from unittest import mock

import nd_net as NT


class VpnTunnelActive(unittest.TestCase):
    def test_detects_tailscale_by_name(self):
        with mock.patch.object(NT, "run", return_value="Tailscale Tunnel\n   IPv4 Address. . . : 100.95.1.2"):
            self.assertTrue(NT.vpn_tunnel_active())

    def test_detects_cgnat_range_ip_even_without_name_match(self):
        with mock.patch.object(NT, "run", return_value="Ethernet adapter\n   IPv4 Address. . . : 100.70.5.9"):
            self.assertTrue(NT.vpn_tunnel_active())

    def test_no_tunnel_on_plain_lan_output(self):
        with mock.patch.object(NT, "run", return_value="Ethernet adapter\n   IPv4 Address. . . : 192.168.0.70"):
            self.assertFalse(NT.vpn_tunnel_active())

    def test_never_raises_when_run_fails(self):
        with mock.patch.object(NT, "run", side_effect=Exception("boom")):
            self.assertFalse(NT.vpn_tunnel_active())


class SecondOpinionIp(unittest.TestCase):
    def test_uses_first_working_source(self):
        with mock.patch.object(NT, "_get", return_value='{"ip": "1.2.3.4"}'):
            self.assertEqual(NT.second_opinion_ip(), "1.2.3.4")

    def test_falls_back_to_second_source(self):
        calls = {"n": 0}

        def fake_get(url, timeout=6):
            calls["n"] += 1
            if "ipify" in url:
                raise Exception("down")
            return " 5.6.7.8 \n"

        with mock.patch.object(NT, "_get", side_effect=fake_get):
            self.assertEqual(NT.second_opinion_ip(), "5.6.7.8")

    def test_empty_when_all_sources_fail(self):
        with mock.patch.object(NT, "_get", side_effect=Exception("down")):
            self.assertEqual(NT.second_opinion_ip(), "")


if __name__ == "__main__":
    unittest.main()
