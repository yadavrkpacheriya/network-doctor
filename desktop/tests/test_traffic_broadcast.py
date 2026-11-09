# -*- coding: utf-8 -*-
"""3.21.3: TrafficStore.is_noise() / add() - a LAN broadcast or multicast packet is never a real internet
destination, however its port number reads (255.255.255.255 / x.x.x.255 / 224.0.0.0 happening to carry port
51413 or 6881 was being recorded as the device "downloading a torrent" - it can never actually be one)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_monitor as M  # noqa: E402


class NoThreat:
    def check(self, remote):
        return None


def store(lan="192.168.0.0/24"):
    return M.TrafficStore(lan, NoThreat(), None, lambda *a, **k: None)


def flow(src, dst, sport, dport, proto=17, n=500):
    return {"src": src, "dst": dst, "sport": sport, "dport": dport, "proto": proto, "bytes": n}


class IsNoise(unittest.TestCase):
    def test_limited_broadcast(self):
        self.assertTrue(store().is_noise("255.255.255.255"))

    def test_this_subnets_own_broadcast_address(self):
        self.assertTrue(store().is_noise("192.168.0.255"))

    def test_multicast(self):
        self.assertTrue(store().is_noise("224.0.0.251"))  # mDNS
        self.assertTrue(store().is_noise("239.255.255.250"))  # SSDP

    def test_an_ordinary_internet_address_is_not_noise(self):
        self.assertFalse(store().is_noise("203.0.113.5"))

    def test_a_bad_address_is_not_noise_not_a_crash(self):
        self.assertFalse(store().is_noise("not-an-ip"))


class AddFiltersNoise(unittest.TestCase):
    def test_a_broadcast_on_a_p2p_port_is_not_recorded_as_an_internet_destination_or_flagged_as_torrent(self):
        s = store()
        s.add(flow("192.168.0.44", "255.255.255.255", 51413, 51413))
        rem, threats, risks = s.remotes("192.168.0.44")
        self.assertEqual(rem, [])
        self.assertNotIn("Torrent / peer-to-peer download", risks)

    def test_the_subnets_own_broadcast_is_filtered_the_same_way(self):
        s = store()
        s.add(flow("192.168.0.44", "192.168.0.255", 6881, 6881))
        rem, _, _ = s.remotes("192.168.0.44")
        self.assertEqual(rem, [])

    def test_mdns_multicast_is_filtered(self):
        s = store()
        s.add(flow("192.168.0.44", "224.0.0.251", 5353, 5353))
        rem, _, _ = s.remotes("192.168.0.44")
        self.assertEqual(rem, [])

    def test_a_real_internet_address_on_the_same_p2p_port_is_still_recorded_and_flagged(self):
        """The fix must not blind real torrent detection - only broadcast/multicast noise is excluded."""
        s = store()
        s.add(flow("192.168.0.44", "203.0.113.5", 51413, 40000))
        rem, _, risks = s.remotes("192.168.0.44")
        self.assertEqual(len(rem), 1)
        self.assertIn("203.0.113.5", risks.get("Torrent / peer-to-peer download", set()))

    def test_ordinary_internet_traffic_is_unaffected(self):
        s = store()
        s.add(flow("192.168.0.44", "142.250.1.1", 51000, 443))
        rem, _, _ = s.remotes("192.168.0.44")
        self.assertEqual(len(rem), 1)
        self.assertEqual(rem[0][0], ("142.250.1.1", 443, 17, False))


if __name__ == "__main__":
    unittest.main()
