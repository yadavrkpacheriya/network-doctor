# -*- coding: utf-8 -*-
"""Brain auto-corrects IP changes: a device that MOVED (same machine, new IP, even new MAC) must not stay on the
'offline 2+ days' list; and a long-known PC that visits occasionally (director's laptop) isn't 'dead' at 2 days
(Rakesh, 28 Nov: RAKESH-IT .88->.70 still offline; Ankit/Punjak directors flagged gone)."""
import unittest
import nd_core as core


def _dev(ip, mac, name, online=True, cat=None):
    return {"ip": ip, "mac": mac, "name": name, "online": online, "category": cat or core.CAT_PC,
            "vendor": "", "names": {"netbios": name}, "upnp": {}, "random": False}


def _raw(ts="2026-11-28 11:14"):
    return {"meta": {"started": ts}}


class MovedDevice(unittest.TestCase):
    def test_same_name_new_mac_and_ip_refreshes_old_entry(self):
        # history: RAKESH-IT last on .88 with an old MAC, silent for days
        db = {"devices": {"OLD:MAC:88": {"first_seen": "2026-11-01 09:00", "last_seen": "2026-11-18 09:00",
                                         "ip": "192.168.0.88", "ips": ["192.168.0.88"],
                                         "names": ["RAKESH-IT"], "category": core.CAT_PC}},
              "ip_owner": {}, "scans": 5, "last_online_macs": []}
        # now RAKESH-IT is online on .70 with a (different) MAC
        devices = [_dev("192.168.0.70", "NEW:MAC:70", "RAKESH-IT")]
        core._update_db(db, _raw(), devices)
        # the OLD .88 entry's last_seen is bumped to now -> it won't be "offline 2+ days"
        self.assertEqual(db["devices"]["OLD:MAC:88"]["last_seen"], "2026-11-28 11:14")

    def test_same_ip_new_mac_refreshes_old_entry(self):
        db = {"devices": {"OLD:MAC": {"first_seen": "2026-11-01 09:00", "last_seen": "2026-11-18 09:00",
                                      "ip": "192.168.0.65", "ips": ["192.168.0.65"],
                                      "names": ["Ankit"], "category": core.CAT_PC}},
              "ip_owner": {}, "scans": 5, "last_online_macs": []}
        devices = [_dev("192.168.0.65", "DIFPC:MAC", "Ankit-Laptop")]  # same IP, different name+mac
        core._update_db(db, _raw(), devices)
        self.assertEqual(db["devices"]["OLD:MAC"]["last_seen"], "2026-11-28 11:14")

    def test_truly_gone_device_not_refreshed(self):
        db = {"devices": {"DEAD:MAC": {"first_seen": "2026-10-01 09:00", "last_seen": "2026-11-18 09:00",
                                       "ip": "10.28.33.15", "ips": ["10.28.33.15"],
                                       "names": ["old-switch"], "category": core.CAT_NET}},
              "ip_owner": {}, "scans": 5, "last_online_macs": []}
        devices = [_dev("192.168.0.70", "NEW:MAC", "RAKESH-IT")]   # unrelated device online
        core._update_db(db, _raw(), devices)
        # the genuinely-gone switch on a different subnet/name is untouched -> stays offline
        self.assertEqual(db["devices"]["DEAD:MAC"]["last_seen"], "2026-11-18 09:00")


if __name__ == "__main__":
    unittest.main()
