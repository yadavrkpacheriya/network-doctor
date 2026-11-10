# -*- coding: utf-8 -*-
"""Wi-Fi analyzer (Fix & Commands > Wi-Fi analyzer): used to say "Wi-Fi analysis works on Windows and
Mac" and do nothing on Linux. wifi_scan() now also drives nmcli on Linux; these tests cover the nmcli
output parser and the Linux branch of wifi_scan() in isolation (no real nmcli involved)."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_core as core  # noqa: E402
import nd_net as NT  # noqa: E402

NMCLI_OUT = (
    "yes:HomeWiFi:AA\\:BB\\:CC\\:DD\\:EE\\:FF:6:130 Mbit/s:78:WPA2\n"
    "no:Neighbour:11\\:22\\:33\\:44\\:55\\:66:11:54 Mbit/s:40:WPA1 WPA2\n"
    "no:OpenCafe:AB\\:CD\\:EF\\:12\\:34\\:56:1:65 Mbit/s:20:--\n"
)


class ParseNmcliWifi(unittest.TestCase):
    def test_active_network_becomes_connected(self):
        cur, nets = NT.parse_nmcli_wifi(NMCLI_OUT)
        self.assertEqual(cur["ssid"], "HomeWiFi")
        self.assertEqual(cur["bssid"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(cur["channel"], 6)
        self.assertEqual(cur["signal"], 78)
        self.assertEqual(cur["band"], "2.4 GHz")
        self.assertIn("130 Mbit/s", cur["tx"])

    def test_all_networks_are_listed(self):
        _, nets = NT.parse_nmcli_wifi(NMCLI_OUT)
        self.assertEqual(len(nets), 3)
        self.assertEqual({n["ssid"] for n in nets}, {"HomeWiFi", "Neighbour", "OpenCafe"})

    def test_open_network_security_is_reported_as_open(self):
        _, nets = NT.parse_nmcli_wifi(NMCLI_OUT)
        cafe = next(n for n in nets if n["ssid"] == "OpenCafe")
        self.assertEqual(cafe["auth"], "Open")

    def test_blank_input_gives_nothing(self):
        cur, nets = NT.parse_nmcli_wifi("")
        self.assertEqual((cur, nets), ({}, []))


class WifiScanOnLinux(unittest.TestCase):
    def setUp(self):
        self._is_linux, self._is_win, self._is_mac = core.IS_LINUX, core.IS_WIN, core.IS_MAC
        core.IS_LINUX, core.IS_WIN, core.IS_MAC = True, False, False

    def tearDown(self):
        core.IS_LINUX, core.IS_WIN, core.IS_MAC = self._is_linux, self._is_win, self._is_mac

    def test_networks_found_runs_nmcli_and_returns_no_note(self):
        with mock.patch.object(NT, "run", return_value=NMCLI_OUT):
            cur, nets, note = NT.wifi_scan()
        self.assertTrue(nets)
        self.assertEqual(note, "")
        self.assertEqual(cur["ssid"], "HomeWiFi")

    def test_no_output_gives_an_actionable_note_instead_of_the_old_unsupported_message(self):
        with mock.patch.object(NT, "run", return_value=""):
            cur, nets, note = NT.wifi_scan()
        self.assertEqual(nets, [])
        self.assertNotIn("works on Windows and Mac", note)
        self.assertIn("nmcli", note)


if __name__ == "__main__":
    unittest.main()
