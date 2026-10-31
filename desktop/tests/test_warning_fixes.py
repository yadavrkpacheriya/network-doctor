# -*- coding: utf-8 -*-
"""Tests for warnings whose advice used to have no effect:

- broadcast storm raised by multicast (cameras, mDNS, IPv6) that no loop hunt can remove
- "Router log / NetFlow is not arriving" for a router that is set up but quiet, or a PC whose IP changed
- router commands that failed when pasted a second time
- a bound device on another IP: the binding tab now keeps the reserved IP
- phones changing their private MAC reported as "IP now used by a different device"
"""

import io
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_core as core  # noqa: E402
import nd_monitor as M  # noqa: E402
import nd_tools as T  # noqa: E402


def fresh_db():
    return {"devices": {}, "labels": {}, "scans": [], "ip_owner": {}, "bindings": {}}


def raw_with(tests):
    t = {"gw_ping": {"loss": 0, "avg": 2, "max": 5, "count": 30}}
    t.update(tests)
    return {"meta": {"started": core.now_s(), "gateway": "192.168.0.1", "local_ip": "192.168.0.10",
                     "subnet": "192.168.0.0/24", "admin": True, "scapy": False, "local_subnet": True,
                     "self_dhcp": True, "self_lease": 86400, "tests": t},
            "arp": {}, "ping": {}, "ports": {}, "http": {}, "nbns": {}, "dns": {}, "upnp": {}, "self_mac": ""}


def titles(issues):
    return [i["title"] for i in issues]


class BroadcastVsMulticast(unittest.TestCase):
    def test_rates_split(self):
        t = {}
        core.nu_rates(t, ("split", 1000, 5000), ("split", 1200, 20000), 10)
        self.assertEqual(t["bcast_pps"], 20.0)
        self.assertEqual(t["mcast_pps"], 1500.0)
        self.assertNotIn("bcast_mixed", t)

    def test_rates_sum_and_mismatch(self):
        t = {}
        core.nu_rates(t, ("sum", 100, None), ("sum", 4324, None), 10)
        self.assertEqual(t["bcast_pps"], 422.4)
        self.assertTrue(t["bcast_mixed"])
        t = {}
        core.nu_rates(t, ("split", 1, 1), ("sum", 9, None), 10)  # different sources: no number at all
        self.assertEqual(t, {})
        core.nu_rates(t, ("sum", 9, None), ("sum", 1, None), 10)  # counter reset
        self.assertEqual(t, {})

    def test_cameras_multicast_is_not_a_loop(self):
        issues, checks = core.analyse(raw_with({"bcast_pps": 40.0, "mcast_pps": 1800.0}), [], fresh_db())
        tl = titles(issues)
        self.assertFalse(any("broadcast" in x.lower() for x in tl), tl)
        self.assertTrue(any("multicast" in x.lower() for x in tl), tl)
        self.assertIn(("Loop overall", "pass", "based on the tests above"), checks)
        fix = next(i["fix"] for i in issues if "multicast" in i["title"].lower())
        self.assertIn("igmp-snooping=yes", fix)

    def test_real_broadcast_storm_still_found(self):
        issues, checks = core.analyse(raw_with({"bcast_pps": 1500.0, "mcast_pps": 20.0}), [], fresh_db())
        self.assertTrue(any(i["sev"] == "critical" and "broadcast" in i["title"].lower() for i in issues))
        self.assertIn(("Loop overall", "fail", "based on the tests above"), checks)

    def test_mixed_total_is_not_called_a_loop_at_422(self):
        issues, checks = core.analyse(raw_with({"bcast_pps": 422.4, "bcast_mixed": True}), [], fresh_db())
        i = next(i for i in issues if "422.4" in i["title"])
        self.assertIn("multicast", i["title"])
        self.assertEqual(i["sev"], "warning")
        self.assertIn("IGMP", i["fix"])
        self.assertIn(("Loop overall", "pass", "based on the tests above"), checks)

    def test_quick_check_keeps_multicast(self):
        issues, _ = core.analyse_quick(raw_with({"bcast_pps": 10.0, "mcast_pps": 5000.0}), [], fresh_db())
        self.assertTrue(any("multicast" in x.lower() for x in titles(issues)))

    def test_counter_reader_parses_lines(self):
        nu = core.NuCounter()

        class P:
            stdout = io.StringIO("0 0\n123 456\n")
        nu.p = P()
        nu._read()
        self.assertEqual(nu.read(), (123, 456))
        nu.t = time.time() - 60  # stale value is not used
        self.assertIsNone(nu.read())

    @unittest.skipUnless(core.IS_WIN, "Windows only")
    def test_windows_counters_work(self):
        bm = core.bcast_mcast_rx()
        self.assertTrue(bm is None or (isinstance(bm[0], int) and isinstance(bm[1], int)), bm)
        snap = core.nu_snapshot()
        self.assertTrue(snap is None or snap[0] in ("split", "sum"), snap)


class FakeRx:
    def __init__(self, error=None):
        self.error = error


class FakeMon:
    def __init__(self, ran=600, lip="192.168.0.10", last_syslog=None, last_flow=None, err=None):
        self.started = time.time() - ran
        self.lip = lip
        self.last_syslog, self.last_flow = last_syslog, last_flow
        self.syslog_port, self.flow_port = M.SYSLOG_PORT, M.FLOW_PORT
        self.rx_log, self.rx_flow = FakeRx(err), FakeRx()


class FeedNotes(unittest.TestCase):
    def test_never_received(self):
        notes = M.feed_notes(FakeMon(), {})
        self.assertEqual(len(notes), 2)
        self.assertTrue(all("192.168.0.10" in n for n in notes), notes)

    def test_wait_two_minutes_after_start(self):
        self.assertEqual(M.feed_notes(FakeMon(ran=30), {}), [])

    def test_quiet_router_log_is_not_missing(self):
        now = time.time()
        seen = {"syslog": {"ts": now - 86400, "lip": "192.168.0.10"}}
        notes = M.feed_notes(FakeMon(last_flow=now - 10), seen)
        self.assertEqual(notes, [])

    def test_pc_ip_changed(self):
        now = time.time()
        seen = {"syslog": {"ts": now - 3600, "lip": "192.168.0.10"}, "flow": {"ts": now - 3600, "lip": "192.168.0.10"}}
        notes = M.feed_notes(FakeMon(lip="192.168.0.55"), seen)
        self.assertEqual(len(notes), 2)
        self.assertTrue(all("changed from 192.168.0.10 to 192.168.0.55" in n for n in notes), notes)

    def test_netflow_stopped(self):
        now = time.time()
        notes = M.feed_notes(FakeMon(last_syslog=now, last_flow=now - 900), {})
        self.assertEqual(len(notes), 1)
        self.assertIn("stopped arriving", notes[0])

    def test_port_busy(self):
        notes = M.feed_notes(FakeMon(err="UDP 514 busy or blocked: in use"), {})
        self.assertTrue(any("cannot be received" in n for n in notes), notes)


class RouterCommands(unittest.TestCase):
    def test_can_be_pasted_again(self):
        c = M.router_setup_commands("192.168.0.10")
        self.assertIn(":do {/system logging remove [find where action=netdoctor]} on-error={}", c)
        self.assertIn(":do {/system logging action remove [find where name=netdoctor]} on-error={}", c)
        self.assertIn("remote=192.168.0.10 remote-port=", c)
        self.assertIn(f"dst-address=192.168.0.10 port={M.FLOW_PORT}", c)
        self.assertIn(':log warning "Network Doctor router log test"', c)
        # rules are removed before their action, otherwise RouterOS refuses to remove the action
        self.assertLess(c.index("logging remove [find where action"), c.index("logging action remove"))
        self.assertNotIn("{lip}", c)
        self.assertEqual(c.count("{"), c.count("}"))


class Bindings(unittest.TestCase):
    def test_warning_names_device_and_offers_choices(self):
        db = fresh_db()
        db["bindings"]["F8:75:A4:8D:B7:FA"] = {"ip": "192.168.0.87", "time": "x"}
        devs = [{"mac": "F8:75:A4:8D:B7:FA", "ip": "192.168.0.70", "ips": {"192.168.0.70"}, "online": True,
                 "name": "SALES-PC"}]
        out = T.binding_issues(devs, db)
        self.assertEqual(len(out), 1)
        self.assertIn("SALES-PC", out[0]["title"])
        self.assertIn("Moved devices: bind their NEW IP", out[0]["fix"])
        self.assertIn("Forget binding of selected", out[0]["fix"])


class IpFlips(unittest.TestCase):
    def dev(self, ip, mac):
        return {"mac": mac, "ip": ip, "ips": {ip}, "online": True, "name": "", "names": {}, "random":
                core.is_random_mac(mac), "category": core.CAT_UNK, "ports": [], "notes": [], "vendor": "", "reason": ""}

    def test_phone_changing_private_mac_is_not_a_flip(self):
        db = fresh_db()
        db["ip_owner"]["192.168.0.101"] = {"mac": "DA:A1:19:00:00:01", "time": "t", "name": ""}
        issues, _ = core.analyse(raw_with({}), [self.dev("192.168.0.101", "6E:22:33:44:55:66")], db)
        self.assertFalse(any("different device" in x for x in titles(issues)))

    def test_real_device_change_still_reported(self):
        db = fresh_db()
        db["ip_owner"]["192.168.0.40"] = {"mac": "3C:52:82:01:02:03", "time": "t", "name": "OLD"}
        issues, _ = core.analyse(raw_with({}), [self.dev("192.168.0.40", "3C:52:82:01:02:99")], db)
        self.assertTrue(any("different device" in x for x in titles(issues)))


if __name__ == "__main__":
    unittest.main()
