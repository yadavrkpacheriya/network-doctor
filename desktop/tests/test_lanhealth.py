# -*- coding: utf-8 -*-
"""LAN-health diagnosis: broadcast storms, switching loops, slow/half-duplex links, proxy-ARP.
Pure-function tests (the live diagnose() path is exercised with a fake router)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_lanhealth as L  # noqa: E402


class Rates(unittest.TestCase):
    def test_bcast_rate_counts_all_four_counters_per_second(self):
        a = {"rx-broadcast": "100", "tx-broadcast": "100", "rx-multicast": "0", "tx-multicast": "0"}
        b = {"rx-broadcast": "1100", "tx-broadcast": "1100", "rx-multicast": "0", "tx-multicast": "0"}
        self.assertAlmostEqual(L.bcast_rate(a, b, 2.0), 1000.0)   # (1000+1000)/2

    def test_counter_wrap_after_reboot_is_not_a_storm(self):
        a = {"rx-broadcast": "5000000"}
        b = {"rx-broadcast": "10"}            # wrapped/reset
        self.assertEqual(L.bcast_rate(a, b, 1.0), 0.0)

    def test_find_storms_classifies_and_sorts(self):
        a = {"eth1": {"rx-broadcast": "0"}, "eth2": {"rx-broadcast": "0"}, "eth3": {"rx-broadcast": "0"}}
        b = {"eth1": {"rx-broadcast": "600"},    # 600/s -> warn
             "eth2": {"rx-broadcast": "3000"},   # 3000/s -> bad
             "eth3": {"rx-broadcast": "50"}}     # quiet
        s = L.find_storms(a, b, 1.0)
        self.assertEqual([(n, sev) for n, _p, sev in s], [("eth2", "bad"), ("eth1", "warn")])


class Loops(unittest.TestCase):
    def test_same_mac_on_two_ports_is_a_loop(self):
        h1 = [{"mac-address": "AA:BB:CC:00:00:01", "on-interface": "eth1"}]
        h2 = [{"mac-address": "aa:bb:cc:00:00:01", "on-interface": "eth5"}]   # same MAC moved ports
        loops = L.detect_loop(h1, h2)
        self.assertEqual(loops[0][0], "AA:BB:CC:00:00:01")
        self.assertEqual(loops[0][1], ["eth1", "eth5"])

    def test_stable_mac_is_not_a_loop(self):
        h1 = [{"mac-address": "AA:BB:CC:00:00:02", "on-interface": "eth1"}]
        h2 = [{"mac-address": "AA:BB:CC:00:00:02", "on-interface": "eth1"}]
        self.assertEqual(L.detect_loop(h1, h2), [])


class Links(unittest.TestCase):
    def test_speed_and_duplex_parsing(self):
        self.assertEqual(L.link_speed_bps({"rate": "1Gbps"}), 1_000_000_000)
        self.assertEqual(L.link_speed_bps({"rate": "100Mbps"}), 100_000_000)
        self.assertTrue(L.is_full_duplex({"full-duplex": "true"}))
        self.assertFalse(L.is_full_duplex({"full-duplex": "false"}))

    def test_slow_links_flags_100mbps_and_half_duplex(self):
        eths = [{"name": "eth1", "rate": "1Gbps", "full-duplex": "true", "status": "link-ok"},   # fine
                {"name": "eth2", "rate": "100Mbps", "full-duplex": "true", "status": "link-ok"}, # slow
                {"name": "eth3", "rate": "1Gbps", "full-duplex": "false", "status": "link-ok"},  # half duplex
                {"name": "eth4", "rate": "", "status": "no-link"}]                               # down: ignore
        got = {n for n, _s, _f in L.slow_links(eths)}
        self.assertEqual(got, {"eth2", "eth3"})


class Fixes(unittest.TestCase):
    def test_fixes_are_router_commands(self):
        self.assertIn("arp=enabled", L.fix_script("no_proxy_arp", lan="bridge"))
        self.assertIn("igmp-snooping=yes", L.fix_script("igmp_snoop", lan="bridge"))
        self.assertIn("bridge host print", L.fix_script("mac_winbox_find_loop"))
        self.assertEqual(L.fix_script("unknown"), "")


class FakeRouter:
    """Minimal stand-in for nd_routeros.RouterOS: context manager + cmd(path, **kw) returning preset rows."""
    def __init__(self, responses):
        self.responses = responses
        self._i = {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cmd(self, path, **kw):
        seq = self.responses.get(path, [])
        if callable(seq):
            return seq()
        # allow a path to return different rows on successive calls (for 2-sample reads)
        idx = self._i.get(path, 0)
        self._i[path] = idx + 1
        if seq and isinstance(seq[0], list):           # list of samples
            return seq[min(idx, len(seq) - 1)]
        return seq


class LiveDiagnose(unittest.TestCase):
    def test_storm_shows_up_as_critical(self):
        r = FakeRouter({
            "/interface/print": [
                [{"name": "eth1", "rx-broadcast": "0"}],      # sample A
                [{"name": "eth1", "rx-broadcast": "4000"}],   # sample B -> 4000/s with dt~1
            ],
            "/interface/bridge/port/print": [{"interface": "eth1", "bridge": "bridge"}],
            "/interface/bridge/host/print": [],
            "/interface/ethernet/monitor": [],
            "/ip/arp/print": [],
            "/interface/bridge/print": [{"name": "bridge", "arp": "enabled"}],
        })
        out = L.diagnose(r, dt=1.0)
        self.assertTrue(any(f["sev"] == "critical" and "Broadcast flood" in f["title"] for f in out))

    def test_clean_lan_reports_healthy(self):
        r = FakeRouter({
            "/interface/print": [[{"name": "eth1", "rx-broadcast": "0"}],
                                 [{"name": "eth1", "rx-broadcast": "5"}]],
            "/interface/bridge/port/print": [{"interface": "eth1", "bridge": "bridge"}],
            "/interface/bridge/host/print": [{"mac-address": "AA:BB:CC:00:00:01", "on-interface": "eth1"}],
            "/interface/ethernet/monitor": [{"name": "eth1", "rate": "1Gbps", "full-duplex": "true",
                                             "status": "link-ok"}],
            "/ip/arp/print": [{"address": "192.168.0.2"}],
            "/interface/bridge/print": [{"name": "bridge", "arp": "enabled"}],
        })
        out = L.diagnose(r, dt=1.0)
        self.assertEqual(out[0]["sev"], "ok")

    def test_router_error_is_calm_info(self):
        class Boom:
            def __enter__(self): raise RuntimeError("no route to host")
            def __exit__(self, *a): return False
        out = L.diagnose(Boom(), dt=1.0)
        self.assertEqual(out[0]["sev"], "info")


if __name__ == "__main__":
    unittest.main()


class BrainPipeline(unittest.TestCase):
    """The LAN-health finding TITLES must map to the alert 'kind' that carries a safe auto-fix, so the brain
    applies the reversible fixes automatically (the user's ask: solve it regularly, not by hand each time)."""
    def test_broadcast_and_loop_findings_are_auto_fixable(self):
        import nd_alerts as AL
        bc = AL.explain("Broadcast flood on eth5 (3200 packets/sec)")
        self.assertEqual(bc["kind"], "multicast")
        self.assertIn("multicast", AL.AUTO_SAFE)
        self.assertTrue(any(a["where"] == "router" and "igmp" in a["cmd"].lower() for a in bc["auto"]))
        lp = AL.explain("Possible switching loop: AA:BB:CC:00:00:01 seen on 2 ports")
        self.assertEqual(lp["kind"], "loop")
        self.assertIn("loop", AL.AUTO_SAFE)

    def test_slow_cable_is_alert_only_not_auto_changed(self):
        import nd_alerts as AL
        c = AL.explain("eth3 runs at 100 Mbps HALF-duplex")
        self.assertNotIn(c["kind"], AL.AUTO_SAFE)   # software can't fix a bad cable - must stay a human alert


class DnsIntegrity(unittest.TestCase):
    """Genuine banking/UPI apps show 'Unsecured Network' when the network silently redirects their DNS or forces
    a proxy - which is also a data-leak vector. The LAN check must flag these (Rakesh, 27 Nov)."""
    def _router(self, nat=None, proxy=False):
        base = {
            "/interface/print": [{"name": "eth1", "rx-broadcast": "0"}],
            "/interface/bridge/port/print": [{"interface": "eth1", "bridge": "bridge"}],
            "/interface/bridge/host/print": [], "/interface/ethernet/monitor": [],
            "/ip/arp/print": [], "/interface/bridge/print": [{"name": "bridge", "arp": "enabled"}],
            "/ip/firewall/nat/print": nat or [],
            "/ip/proxy/print": [{"enabled": "true" if proxy else "false"}],
        }

        class R:
            def __enter__(s): return s
            def __exit__(s, *a): return False
            def cmd(s, path, **k): return base.get(path, [])
        return R()

    def test_dns_redirect_flagged(self):
        nat = [{"protocol": "udp", "dst-port": "53", "action": "dst-nat", "to-addresses": "10.9.9.9"}]
        out = L.diagnose(self._router(nat=nat), dt=0.05)
        self.assertTrue(any("redirecting DNS" in f["title"] and f["sev"] == "critical" for f in out))

    def test_our_own_dns_rule_not_flagged(self):
        nat = [{"protocol": "udp", "dst-port": "53", "action": "dst-nat", "comment": "ND: something"}]
        out = L.diagnose(self._router(nat=nat), dt=0.05)
        self.assertFalse(any("redirecting DNS" in f["title"] for f in out))

    def test_proxy_on_flagged(self):
        out = L.diagnose(self._router(proxy=True), dt=0.05)
        self.assertTrue(any("web proxy is ON" in f["title"] for f in out))

    def test_clean_router_no_false_alarm(self):
        out = L.diagnose(self._router(), dt=0.05)
        self.assertFalse(any("redirecting DNS" in f["title"] or "web proxy" in f["title"] for f in out))
