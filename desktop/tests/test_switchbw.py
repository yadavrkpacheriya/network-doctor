# -*- coding: utf-8 -*-
"""nd_switchbw: per-device bandwidth fallback from SNMP switch port counters, used when NetFlow has
nothing for a device (e.g. a camera that only ever talks to a local NVR on the same switch)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_switchbw as SB  # noqa: E402

IFS = [{"index": 1, "name": "Gi1/0/1"}, {"index": 2, "name": "Gi1/0/2"}, {"index": 3, "name": "Gi1/0/3"}]


class SingleMacPorts(unittest.TestCase):
    def test_only_single_mac_ports_are_attributed(self):
        macs = {"AA:AA:AA:AA:AA:AA": "Gi1/0/1",       # alone on its port - confident
                "BB:BB:BB:BB:BB:BB": "Gi1/0/2",       # shares a port with CC - not confident
                "CC:CC:CC:CC:CC:CC": "Gi1/0/2"}
        self.assertEqual(SB.single_mac_ports(macs), {"AA:AA:AA:AA:AA:AA": "Gi1/0/1"})


class MacBandwidth(unittest.TestCase):
    def test_bandwidth_maps_in_to_upload_out_to_download(self):
        macs = {"AA:AA:AA:AA:AA:AA": "Gi1/0/1"}
        port_rates = {1: {"in": 1250.0, "out": 50000.0}}  # bytes/s
        out = SB.mac_bandwidth(IFS, macs, port_rates)
        self.assertEqual(out, {"AA:AA:AA:AA:AA:AA": {"up_bps": 1250.0, "down_bps": 50000.0}})

    def test_shared_port_gives_no_number_rather_than_a_guessed_one(self):
        macs = {"BB:BB:BB:BB:BB:BB": "Gi1/0/2", "CC:CC:CC:CC:CC:CC": "Gi1/0/2"}
        out = SB.mac_bandwidth(IFS, macs, {2: {"in": 1000.0, "out": 2000.0}})
        self.assertEqual(out, {})

    def test_port_with_no_rate_reading_is_skipped(self):
        macs = {"AA:AA:AA:AA:AA:AA": "Gi1/0/3"}  # no entry for index 3 in port_rates
        self.assertEqual(SB.mac_bandwidth(IFS, macs, {1: {"in": 1, "out": 1}}), {})


class MergeCaches(unittest.TestCase):
    def test_merge_combines_several_switches(self):
        a = {"AA:AA:AA:AA:AA:AA": {"up_bps": 1, "down_bps": 2}}
        b = {"BB:BB:BB:BB:BB:BB": {"up_bps": 3, "down_bps": 4}}
        self.assertEqual(SB.merge_caches([a, b, None, {}]), {**a, **b})


class SwitchList(unittest.TestCase):
    def test_add_update_remove(self):
        db = {}
        SB.add_switch(db, "192.168.0.2", "public", "2c", "Core switch")
        self.assertEqual(len(SB.get_switches(db)), 1)
        SB.add_switch(db, "192.168.0.2", "private", "2c", "Core switch (renamed)")  # same IP -> updates, not adds
        xs = SB.get_switches(db)
        self.assertEqual(len(xs), 1)
        self.assertEqual(xs[0]["community"], "private")
        SB.add_switch(db, "192.168.0.3", "public", "2c", "Access switch")
        self.assertEqual(len(SB.get_switches(db)), 2)
        SB.remove_switch(db, "192.168.0.2")
        xs = SB.get_switches(db)
        self.assertEqual([x["ip"] for x in xs], ["192.168.0.3"])


class SampleSwitchNeverRaises(unittest.TestCase):
    def test_unreachable_switch_returns_empty_dict_not_an_exception(self):
        # No real agent on this port/IP combo in the test environment - sample_switch must swallow the
        # SNMP timeout/connection error, exactly like the periodic background sampler needs it to.
        out = SB.sample_switch("127.0.0.1", "public", "2c", timeout=0.2, gap=0.01)
        self.assertEqual(out, {})


if __name__ == "__main__":
    unittest.main()
