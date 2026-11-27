# -*- coding: utf-8 -*-
"""Auto-deploy targets PERMANENT PCs only, never 1-3 day guests; phones + NVR grouping fixes (Rakesh, 27 Nov)."""
import datetime as dt
import unittest
import nd_deploy as D
import nd_core as core


class Permanent(unittest.TestCase):
    def _db(self):
        return {"devices": {
            "AA": {"first_seen": "2026-11-01 09:00", "last_seen": "2026-11-27 09:00"},  # 26 days
            "BB": {"first_seen": "2026-11-26 09:00", "last_seen": "2026-11-27 09:00"},  # 1 day (guest)
        }}

    def test_permanent_pc_yes_guest_pc_no(self):
        now = dt.datetime(2026, 11, 27, 10, 0)
        perm = {"category": core.CAT_PC, "mac": "AA", "ip": "192.168.0.57", "name": "RAKESH", "online": True}
        guest = {"category": core.CAT_PC, "mac": "BB", "ip": "192.168.0.90", "name": "Guest", "online": True}
        self.assertTrue(D.is_permanent(perm, self._db(), now=now))
        self.assertFalse(D.is_permanent(guest, self._db(), now=now))

    def test_phone_never_a_deploy_target(self):
        now = dt.datetime(2026, 11, 27, 10, 0)
        phone = {"category": core.CAT_PHONE, "mac": "CC", "ip": "192.168.0.120", "online": True}
        self.assertFalse(D.is_permanent(phone, self._db(), now=now))

    def test_permanent_targets_filters_list(self):
        perm = {"category": core.CAT_PC, "mac": "AA", "ip": "192.168.0.57", "name": "RAKESH", "online": True}
        guest = {"category": core.CAT_PC, "mac": "BB", "ip": "192.168.0.90", "name": "Guest", "online": True}
        phone = {"category": core.CAT_PHONE, "mac": "CC", "ip": "192.168.0.120", "online": True}
        got = [t["name"] for t in D.permanent_targets([perm, guest, phone], self._db())]
        self.assertEqual(got, ["RAKESH"])


class PhoneCategory(unittest.TestCase):
    def test_random_mac_with_mdns_is_phone(self):
        d = {"ip": "192.168.0.120", "ports": [5353], "vendor": "", "name": "", "upnp": {}, "http": {},
             "random": True, "ttl": 64, "names": {}}
        self.assertEqual(core.categorize(d, "192.168.0.1")[0], core.CAT_PHONE)

    def test_random_mac_with_server_port_is_not_forced_phone(self):
        d = {"ip": "192.168.0.121", "ports": [445], "vendor": "", "name": "", "upnp": {}, "http": {},
             "random": True, "ttl": 64, "names": {}}
        self.assertEqual(core.categorize(d, "192.168.0.1")[0], core.CAT_PC)


if __name__ == "__main__":
    unittest.main()
