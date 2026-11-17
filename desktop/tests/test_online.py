# -*- coding: utf-8 -*-
"""Fast internet-reachability check - lets offline background tasks skip long download attempts."""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_core as core  # noqa: E402


class Online(unittest.TestCase):
    def setUp(self):
        core._ONLINE.update(t=0.0, ok=False)        # clear the cache before each test

    def test_true_when_a_probe_connects(self):
        self.assertTrue(core.online(connect=lambda h, p: h == "1.1.1.1"))

    def test_false_when_nothing_connects(self):
        core._ONLINE.update(t=0.0, ok=False)
        self.assertFalse(core.online(connect=lambda h, p: False))

    def test_result_is_cached(self):
        calls = []

        def c(h, p):
            calls.append(h)
            return False
        core._ONLINE.update(t=0.0, ok=False)
        core.online(connect=c)
        n = len(calls)
        core.online(connect=c)                      # within 20s -> cached, no new probes
        self.assertEqual(len(calls), n)

    def test_offline_oui_returns_empty_fast(self):
        # with no cache file and offline, load_oui must not attempt downloads
        core._ONLINE.update(t=time.time(), ok=False)    # pretend we just checked: offline
        if os.path.exists(core.OUI_PATH):
            self.skipTest("OUI cache present on this machine")
        self.assertEqual(core.load_oui(), {})


if __name__ == "__main__":
    unittest.main()
