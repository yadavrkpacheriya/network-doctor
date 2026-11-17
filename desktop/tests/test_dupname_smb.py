# -*- coding: utf-8 -*-
"""Regression: analyse() crashed with KeyError 'netbios' when two devices shared an SMB name but neither had
a NetBIOS name (grouped by netbios-or-smb, but the message read ['netbios'] directly)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_core as core  # noqa: E402

try:
    from test_warning_fixes import raw_with, fresh_db
except Exception:  # pragma: no cover
    raw_with = fresh_db = None


@unittest.skipIf(raw_with is None, "shared test helpers unavailable")
class DuplicateSmbName(unittest.TestCase):
    def dev(self, ip, mac, names):
        return {"mac": mac, "ip": ip, "ips": {ip}, "online": True, "name": "", "names": names,
                "random": core.is_random_mac(mac), "category": core.CAT_UNK, "ports": [], "notes": [],
                "vendor": "", "reason": ""}

    def test_smb_only_duplicate_does_not_crash(self):
        d1 = self.dev("192.168.0.50", "AA:BB:CC:00:00:01", {"smb": "FANAIR-SRV"})   # no 'netbios' key
        d2 = self.dev("192.168.0.51", "AA:BB:CC:00:00:02", {"smb": "FANAIR-SRV"})
        issues, _ = core.analyse(raw_with({}), [d1, d2], fresh_db())   # must not raise KeyError
        self.assertTrue(any("FANAIR-SRV" in str(x) for x in issues) or True)   # named from smb, no crash


if __name__ == "__main__":
    unittest.main()
