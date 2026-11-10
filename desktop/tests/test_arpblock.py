# -*- coding: utf-8 -*-
"""3.22.9: nd_arpblock.plan() - the safety gate for the router-agnostic per-device internet block (ARP
spoofing from this PC instead of a MikroTik firewall rule). Uses the exact same backbone/phone/exclude-list
rules nd_defense.Defense already enforces for a router-side block, so a device that is safe to cut off on a
MikroTik is - and is only - exactly the set of devices this fallback will ever touch too."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_arpblock as AB  # noqa: E402
import nd_defense as DF  # noqa: E402


class Plan(unittest.TestCase):
    def test_an_ordinary_device_is_allowed(self):
        d = DF.Defense({}, gw_ip="192.168.0.1", own_ip="192.168.0.70")
        self.assertEqual(AB.plan("Computers / laptops", "192.168.0.99", "AA:BB:CC:00:00:01", d), "")

    def test_the_network_backbone_is_never_a_target(self):
        d = DF.Defense({})
        why = AB.plan("Network equipment (router / switch / AP)", "192.168.0.5", "AA:BB:CC:00:00:02", d)
        self.assertIn("backbone", why)

    def test_phones_are_never_a_target(self):
        d = DF.Defense({})
        why = AB.plan("Phones / tablets", "192.168.0.50", "AA:BB:CC:00:00:03", d)
        self.assertIn("phones", why.lower())

    def test_the_gateway_itself_is_never_a_target(self):
        d = DF.Defense({}, gw_ip="192.168.0.1")
        why = AB.plan("Computers / laptops", "192.168.0.1", "AA:BB:CC:00:00:04", d)
        self.assertTrue(why)

    def test_this_pc_itself_is_never_a_target(self):
        d = DF.Defense({}, own_ip="192.168.0.70")
        why = AB.plan("Computers / laptops", "192.168.0.70", "AA:BB:CC:00:00:05", d)
        self.assertTrue(why)

    def test_a_person_excluded_device_is_never_a_target(self):
        d = DF.Defense({"defense": {"exclude_macs": ["AA:BB:CC:00:00:06"]}})
        why = AB.plan("Computers / laptops", "192.168.0.80", "AA:BB:CC:00:00:06", d)
        self.assertTrue(why)

    def test_a_device_with_no_known_mac_yet_cannot_be_targeted(self):
        # ARP spoofing needs a MAC to send the fake reply to - unlike a router firewall rule, it has no
        # other way to address the device.
        d = DF.Defense({})
        why = AB.plan("Computers / laptops", "192.168.0.90", "", d)
        self.assertTrue(why)

    def test_an_exposed_camera_is_still_allowed_unlike_defense_guard_for_the_exposed_kind(self):
        # Defense.guard("exposed", cat) restricts that specific ALERT KIND to cameras only - plan() is a
        # plain "block this device" button and must not inherit that unrelated restriction, so an ordinary
        # PC (not a camera) must still be blockable here even though it would be guard()-refused for
        # "exposed" specifically.
        d = DF.Defense({})
        self.assertEqual(d.guard("exposed", "Computers / laptops"), "'exposed' is a router setting: fix the "
                         "port-forward, do not cut the device that has the IP now")
        self.assertEqual(AB.plan("Computers / laptops", "192.168.0.95", "AA:BB:CC:00:00:07", d), "")


class ArpBlockerState(unittest.TestCase):
    """The thread/scapy parts are not exercised here (no live network in CI) - only the plain bookkeeping:
    what's active, when it expires, and that stop()/stop_all() clear it out. _spoof_once()/_resolve() are
    wrapped in try/except in nd_arpblock.py, so calling start()/stop() without scapy installed never raises
    here either - _resolve() just returns '' and start() reports that cleanly."""

    def test_start_without_scapy_fails_cleanly_not_crash(self):
        b = AB.ArpBlocker(self_mac="AA:AA:AA:AA:AA:AA", gw_ip="192.168.0.1")
        ok, msg = b.start("192.168.0.99", "AA:BB:CC:00:00:01", name="Test PC", minutes=5)
        self.assertFalse(ok)
        self.assertTrue(msg)
        self.assertFalse(b.is_blocked("192.168.0.99"))  # never added without a resolved gateway MAC

    def test_expired_uses_the_per_target_deadline(self):
        b = AB.ArpBlocker(self_mac="AA:AA:AA:AA:AA:AA", gw_ip="192.168.0.1")
        with b.lock:
            b.active["192.168.0.10"] = {"mac": "m1", "gw_mac": "g1", "name": "A", "t": 0, "until": 100}
            b.active["192.168.0.20"] = {"mac": "m2", "gw_mac": "g2", "name": "B", "t": 0, "until": 200}
            b.active["192.168.0.30"] = {"mac": "m3", "gw_mac": "g3", "name": "C", "t": 0, "until": 0}  # no limit
        self.assertEqual(sorted(b.expired(now=150)), ["192.168.0.10"])
        self.assertEqual(sorted(b.expired(now=250)), ["192.168.0.10", "192.168.0.20"])

    def test_stop_removes_and_reports_whether_it_was_active(self):
        b = AB.ArpBlocker(self_mac="AA:AA:AA:AA:AA:AA", gw_ip="192.168.0.1")
        with b.lock:
            b.active["192.168.0.10"] = {"mac": "m1", "gw_mac": "g1", "name": "A", "t": 0, "until": 0}
        self.assertTrue(b.stop("192.168.0.10"))
        self.assertFalse(b.is_blocked("192.168.0.10"))
        self.assertFalse(b.stop("192.168.0.10"))  # already gone - no error, just reports nothing to do

    def test_stop_all_clears_everything(self):
        b = AB.ArpBlocker(self_mac="AA:AA:AA:AA:AA:AA", gw_ip="192.168.0.1")
        with b.lock:
            b.active["192.168.0.10"] = {"mac": "m1", "gw_mac": "g1", "name": "A", "t": 0, "until": 0}
            b.active["192.168.0.20"] = {"mac": "m2", "gw_mac": "g2", "name": "B", "t": 0, "until": 0}
        b.stop_all()
        self.assertEqual(b.active, {})


if __name__ == "__main__":
    unittest.main()
