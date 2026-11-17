# -*- coding: utf-8 -*-
"""Ping series (loss bursts, spikes), upgraded Wi-Fi advice and the "Why is it slow?" verdict logic."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_net as NT  # noqa: E402

WIN = ("Pinging 8.8.8.8 with 32 bytes of data:\nReply from 8.8.8.8: bytes=32 time=12ms TTL=117\nRequest timed out.\n"
       "Request timed out.\nReply from 8.8.8.8: bytes=32 time<1ms TTL=117\nReply from 8.8.8.8: bytes=32 time=400ms TTL=117\n"
       "Ping statistics for 8.8.8.8:\n    Packets: Sent = 5, Received = 3, Lost = 2 (40% loss),\n")
LIN = ("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=10.1 ms\n64 bytes from 1.1.1.1: icmp_seq=4 ttl=57 time=11.0 ms\n")


def st(series):
    return NT.series_stats(series)


class PingSeries(unittest.TestCase):
    def test_windows_timeouts_keep_their_place(self):
        self.assertEqual(NT.parse_ping_series(WIN, 5), [12.0, None, None, 0.5, 400.0])

    def test_linux_gaps_in_icmp_seq_are_losses(self):
        self.assertEqual(NT.parse_ping_series(LIN, 5), [10.1, None, None, 11.0, None])

    def test_short_output_is_padded_as_lost(self):
        self.assertEqual(NT.parse_ping_series("", 3), [None, None, None])

    def test_spikes_burst_and_percentile(self):
        s = st([10.0] * 90 + [300.0, 250.0, None, None, None, 10.0, 10.0, 10.0, 10.0, 10.0])
        self.assertEqual(s["spikes"], 2)
        self.assertEqual(s["burst"], 3)
        self.assertEqual(s["sent"], 100)
        self.assertAlmostEqual(s["loss"], 3.0)
        self.assertEqual(s["median"], 10.0)

    def test_steady_line_has_no_spikes(self):
        s = st([5.0, 6.0, 5.5] * 30)
        self.assertEqual(s["spikes"], 0)
        self.assertEqual(s["burst"], 0)

    def test_nothing_answered(self):
        s = st([None] * 10)
        self.assertEqual((s["recv"], s["loss"], s["burst"], s["spikes"]), (0, 100.0, 10, 0))

    def test_ping_stats_keeps_old_keys(self):
        with mock.patch.object(NT, "run", return_value=LIN):
            r = NT.ping_stats("1.1.1.1", 5)
        for k in ("sent", "recv", "loss", "min", "avg", "max", "jitter"):
            self.assertIn(k, r)
        self.assertEqual(r["recv"], 2)

    def test_ping_series_stops_on_request(self):
        import threading
        ev = threading.Event()
        ev.set()
        with mock.patch.object(NT, "run", return_value=LIN):
            self.assertEqual(NT.ping_series("1.1.1.1", 100, ev), [])


class WifiExtra(unittest.TestCase):
    CUR = {"ssid": "Office", "bssid": "AA:AA:AA:AA:AA:01", "channel": 6, "signal": 45, "band": "2.4 GHz", "tx": "36"}

    def nets(self, extra=()):
        return [dict(self.CUR)] + list(extra)

    def test_signal_words(self):
        self.assertEqual(NT.signal_label(90)[0], "excellent")
        self.assertEqual(NT.signal_label(20)[0], "weak")
        self.assertEqual(NT.signal_label(50)[1], -75)

    def test_suggests_5ghz_of_same_wifi(self):
        n = self.nets([{"ssid": "Office", "bssid": "AA:AA:AA:AA:AA:02", "channel": 36, "signal": 70, "band": "5 GHz"}])
        self.assertTrue(any("5 GHz" in x and "connect" in x for x in NT.wifi_extra(n, self.CUR)))

    def test_finds_stronger_ap_of_same_wifi(self):
        n = self.nets([{"ssid": "Office", "bssid": "AA:AA:AA:AA:AA:09", "channel": 11, "signal": 80, "band": "2.4 GHz"}])
        self.assertTrue(any("stronger access point" in x for x in NT.wifi_extra(n, self.CUR)))

    def test_crowded_channel_and_low_link_speed(self):
        n = self.nets([{"ssid": f"N{i}", "bssid": f"BB:{i:02d}", "channel": 6 + (i % 2), "signal": 60, "band": "2.4 GHz"}
                       for i in range(3)])
        out = NT.wifi_extra(n, self.CUR)
        self.assertTrue(any("shared air" in x for x in out))
        self.assertTrue(any("Link speed is only 36" in x for x in out))

    def test_not_connected_adds_nothing_and_analyse_still_works(self):
        self.assertEqual(NT.wifi_extra([], {}), [])
        lines, counts = NT.wifi_analyse(self.nets(), self.CUR)
        self.assertTrue(any("Signal is fair" in x for x in lines))
        self.assertEqual(counts, {6: 1})


def good(n=100, rtt=3.0):
    return st([rtt] * n)


class Judge(unittest.TestCase):
    def base(self, **kw):
        rep = {"wifi": {}, "wifi_lines": [], "gw": good(), "inet": good(rtt=20), "dns": 30, "devices": 40, "adapters": []}
        rep.update(kw)
        return NT.slowdown_judge(rep)

    def test_all_healthy(self):
        v, f = self.base()
        self.assertIn("ALL OK", v)
        self.assertEqual([s for s, _ in f if s != "ok"], [])

    def test_internet_only_bad_blames_isp(self):
        v, f = self.base(inet=st([20.0] * 80 + [None] * 20))
        self.assertIn("ISP", v)
        self.assertTrue(any("lost" in t for _, t in f))

    def test_router_loss_blames_lan_not_isp(self):
        v, f = self.base(gw=st([3.0] * 90 + [None] * 10), inet=st([20.0] * 80 + [None] * 20))
        self.assertIn("inside the office", v)
        self.assertTrue(any(s == "critical" for s, _ in f))

    def test_weak_wifi_is_local_cause(self):
        v, f = self.base(wifi={"signal": 25})
        self.assertIn("own Wi-Fi", v)

    def test_spikes_to_router_are_reported(self):
        v, f = self.base(gw=st([3.0] * 94 + [200.0] * 6))
        self.assertTrue(any("spike" in t for _, t in f))

    def test_router_not_answering(self):
        v, f = self.base(gw=st([None] * 20))
        self.assertTrue(any("does not answer" in t for _, t in f))

    def test_slow_and_broken_dns(self):
        _, f = self.base(dns=400)
        self.assertTrue(any("DNS slow" in t for _, t in f))
        v, f = self.base(dns=None)
        self.assertTrue(any("do not resolve" in t for _, t in f))

    def test_adapter_problem_is_local(self):
        v, f = self.base(adapters=[("warning", "Ethernet runs at only 100 Mbps")])
        self.assertIn("own Wi-Fi/cable", v)


class Screen(unittest.TestCase):
    def rep(self, **kw):
        r = {"wifi": {}, "wifi_lines": [], "gw": good(), "gw_ip": "192.168.0.1", "inet": good(rtt=20), "dns": 30,
             "devices": 40, "adapters": []}
        r.update(kw)
        return r

    def test_ok_screen_is_short_and_has_no_fix_section(self):
        txt = [t for t, _ in NT.slowdown_screen(self.rep())]
        self.assertTrue(any(t.startswith("> router") and t.endswith("OK") for t in txt))
        self.assertTrue(any(t.startswith("ALL OK") for t in txt))
        self.assertNotIn("FIX:", txt)
        self.assertLess(len(txt), 10)

    def test_problem_then_fix_at_the_bottom(self):
        scr = NT.slowdown_screen(self.rep(gw=st([3.0] * 90 + [None] * 10), wifi={"ssid": "Office", "signal": 30,
                                                                                    "channel": 6}))
        txt = [t for t, _ in scr]
        self.assertIn("FIX:", txt)
        self.assertTrue(txt[-1].startswith(" "))             # fixes are the last lines
        self.assertTrue(txt.index("FIX:") > max(i for i, t in enumerate(txt) if t.startswith("> router")))
        self.assertTrue(any("Move closer" in t for t in txt))
        self.assertTrue(any("Restart the router" in t for t in txt))

    def test_fixes_are_not_repeated(self):
        scr = NT.slowdown_screen(self.rep(gw=st([3.0] * 90 + [None] * 10), inet=st([3.0] * 90 + [None] * 10)))
        fixes = [t for t, _ in scr if t.startswith(" ") and t[1].isdigit()]
        self.assertEqual(len(fixes), len(set(fixes)))

    def test_isp_fix_says_call_isp(self):
        txt = [t for t, _ in NT.slowdown_screen(self.rep(inet=st([20.0] * 80 + [None] * 20)))]
        self.assertTrue(any("call the ISP" in t for t in txt))

    def test_dns_and_cable_fixes(self):
        txt = [t for t, _ in NT.slowdown_screen(self.rep(dns=400, adapters=[("warning", "Ethernet runs at only 100 Mbps")]))]
        self.assertTrue(any("1.1.1.1" in t for t in txt))
        self.assertTrue(any("patch cable" in t for t in txt))

    def test_wifi_lines_become_plain_fixes(self):
        lines = ["  ! This PC is on 2.4 GHz but 'X' is also on 5 GHz here - connect to the 5 GHz one for faster",
                 "  ! A stronger access point of 'X' is in range"]
        txt = [t for t, _ in NT.slowdown_screen(self.rep(wifi_lines=lines))]
        self.assertTrue(any("5 GHz Wi-Fi name" in t for t in txt))
        self.assertTrue(any("nearer box" in t for t in txt))


class SlowdownCheckRuns(unittest.TestCase):
    def test_full_run_with_fakes(self):
        with mock.patch.object(NT, "wifi_scan", return_value=({}, [], "")), \
                mock.patch.object(NT, "adapters", return_value=[]), \
                mock.patch.object(NT, "ping_series", return_value=[3.0] * 10), \
                mock.patch.object(NT, "dns_ms", return_value=20.0):
            v, f, rep = NT.slowdown_check("192.168.0.1", 12, 10)
        self.assertIn("ALL OK", v)
        self.assertEqual(rep["devices"], 12)
        self.assertEqual(rep["gw"]["recv"], 10)


if __name__ == "__main__":
    unittest.main()
