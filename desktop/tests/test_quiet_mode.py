# -*- coding: utf-8 -*-
"""Quiet mode (permanent auto-mute): only MAJOR issues pop up, and anything the app is auto-fixing stays
silent. Exercises App._may_popup as an unbound function with a stub self, so it needs no tkinter."""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import NetworkDoctor as ND
except Exception:                         # tkinter missing on the headless box - the Windows build has it
    ND = None


def stub(quiet=True, alerts_on=True, mute_until=0, mute_level=None):
    s = types.SimpleNamespace()
    s.alert_quiet = quiet
    s.alert_mute_until = mute_until
    s.alert_mute_level = mute_level
    s._SEV_RANK = ND.App._SEV_RANK
    s.var_alerts = types.SimpleNamespace(get=lambda: alerts_on)
    return s


@unittest.skipIf(ND is None, "tkinter not available")
class QuietMode(unittest.TestCase):
    def may(self, s, sev, fixing=False):
        return ND.App._may_popup(s, sev, fixing)

    def test_quiet_blocks_minor_allows_major(self):
        s = stub(quiet=True)
        self.assertFalse(self.may(s, "info"))
        self.assertFalse(self.may(s, "warning"))
        self.assertTrue(self.may(s, "critical"))      # only major gets through

    def test_fixing_is_always_silent(self):
        s = stub(quiet=False)                          # even with everything shown
        self.assertFalse(self.may(s, "critical", fixing=True))

    def test_quiet_off_shows_all(self):
        s = stub(quiet=False)
        for sev in ("info", "warning", "critical"):
            self.assertTrue(self.may(s, sev))

    def test_alerts_disabled_blocks_everything(self):
        s = stub(quiet=False, alerts_on=False)
        self.assertFalse(self.may(s, "critical"))


if __name__ == "__main__":
    unittest.main()
