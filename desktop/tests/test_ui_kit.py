# -*- coding: utf-8 -*-
"""Pure view builders behind the pictures (always run) + a draw smoke test of the shared widgets (skipped when
this machine has no Tk / display)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_net as NT  # noqa: E402


def good(n=100, rtt=3.0):
    return NT.series_stats([rtt] * n)


class Views(unittest.TestCase):
    def rep(self, **kw):
        r = {"wifi": {"ssid": "Office", "signal": 70}, "wifi_lines": [], "gw": good(), "gw_ip": "10.0.0.1",
             "inet": good(rtt=20), "gw_series": [3.0] * 100, "inet_series": [20.0] * 100, "dns": 30, "devices": 5,
             "adapters": []}
        r.update(kw)
        return r

    def test_all_ok_view(self):
        v = NT.slowdown_view(self.rep())
        self.assertEqual((v["level"], v["fixes"]), ("ok", []))
        self.assertEqual([c[0] for c in v["cards"]], ["Wi-Fi", "Router", "Internet", "DNS", "Devices"])
        self.assertEqual(len(v["lines"]), 2)

    def test_router_loss_view_has_fix_and_bad_card(self):
        v = NT.slowdown_view(self.rep(gw=NT.series_stats([3.0] * 85 + [None] * 15)))
        self.assertEqual(v["level"], "bad")
        self.assertTrue(any("Restart the router" in f for f, _ in v["fixes"]))
        self.assertEqual([c for c in v["cards"] if c[0] == "Router"][0][3], "bad")

    def test_router_no_answer_card(self):
        v = NT.slowdown_view(self.rep(gw=NT.series_stats([None] * 10)))
        self.assertEqual([c for c in v["cards"] if c[0] == "Router"][0][1], "NO ANSWER")

    def test_wifi_view_bars_and_fixes(self):
        cur = {"ssid": "O", "channel": 6, "signal": 45, "tx": "36"}
        nets = [cur, {"ssid": "A", "channel": 6, "signal": 60}, {"ssid": "B", "channel": 1, "signal": 50},
                {"ssid": "C", "channel": 36, "signal": 50}]
        lines = ["  ! Weak signal - move closer", "Best 2.4 GHz channel here: 11  (only 1, 6 and 11 do not overlap)",
                 "Least used 5 GHz channel here: 149"]
        v = NT.wifi_view(cur, nets, lines)
        titles = [c[0] for c in v["cards"]]
        self.assertIn("Best 2.4 GHz", titles)
        self.assertIn("Best 5 GHz", titles)
        self.assertEqual([c[2] for c in v["bars24"] if c[0] == "ch 6"], ["bad"])   # your own channel is red
        self.assertEqual([b[0] for b in v["bars5"]], ["ch 36"])
        self.assertEqual(len(v["fixes"]), 1)

    def test_adapter_cards_levels(self):
        ads = [{"name": "Eth", "status": "Up", "bps": 100_000_000, "speed": "100 Mbps", "duplex": True},
               {"name": "Eth2", "status": "Up", "bps": 1_000_000_000, "speed": "1 Gbps", "duplex": False},
               {"name": "Eth3", "status": "Up", "bps": 1_000_000_000, "speed": "1 Gbps", "duplex": True},
               {"name": "Down", "status": "Down"}, {"name": "V", "status": "Up", "virtual": True}]
        self.assertEqual([c[3] for c in NT.adapter_cards(ads)], ["warn", "bad", "ok"])


class Widgets(unittest.TestCase):
    def setUp(self):
        try:
            import tkinter as tk
            self.tk = tk
            self.root = tk.Tk()
        except Exception as e:  # no Tk or no display
            self.skipTest(str(e))

    def tearDown(self):
        self.root.destroy()

    def test_everything_draws_and_tiles_toggle(self):
        import nd_ui as U
        r = self.root
        U.HowTo(r, "#0e7490", "T", "what", "when", ["a", "b"]).pack()
        p = U.Panel(r)
        p.pack()
        p.cards([("A", "1", "n", "ok"), ("B", "2", "", "bad")])
        p.verdict("PROBLEM", "bad", [("do this", "why")])
        U.Gauge(r).set(45, 100, "%", "x", "warn")
        U.Bars(r).set([("ch 1", 2, "ok", "2")], "t")
        ln = U.Lines(r)
        ln.set([("a", [1.0, None, 3.0], "ok")], "t")
        ln.set([("a", [None, None], "ok")], "t")
        v = self.tk.BooleanVar(value=False)
        tl = U.Tiles(r)
        tl.pack()
        tl.set([dict(title="Ads", sub="x", var=v, usage=0.5, usage_text="1 GB")])
        r.update()
        tl.tiles[0][0].event_generate("<Button-1>")
        r.update()
        self.assertTrue(v.get())
        p.clear()
        self.assertEqual(p.winfo_children(), [])


if __name__ == "__main__":
    unittest.main()
