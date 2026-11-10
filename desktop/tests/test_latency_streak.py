# -*- coding: utf-8 -*-
"""3.22.6: nd_tools.latency_streak() - sustained high round-trip time to a watched device (Tools > Critical
devices) becomes its own "High latency" alert, fired once per incident (not every 30s check) via
NetworkDoctor.py's _on_watch(), alongside the existing down/up and mass-disconnect alerts."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_tools as T  # noqa: E402


class LatencyStreak(unittest.TestCase):
    def test_fast_reply_resets_to_zero(self):
        self.assertEqual(T.latency_streak(7, 3), 0)

    def test_device_not_answering_resets_to_zero_not_a_latency_problem(self):
        self.assertEqual(T.latency_streak(7, None), 0)

    def test_slow_reply_increments(self):
        self.assertEqual(T.latency_streak(2, 200), 3)

    def test_starts_at_one_on_the_first_slow_reply(self):
        self.assertEqual(T.latency_streak(0, 200), 1)

    def test_right_at_the_threshold_does_not_count_as_slow(self):
        self.assertEqual(T.latency_streak(3, 150, threshold_ms=150), 0)

    def test_custom_threshold(self):
        self.assertEqual(T.latency_streak(0, 60, threshold_ms=50), 1)
        self.assertEqual(T.latency_streak(0, 40, threshold_ms=50), 0)


if __name__ == "__main__":
    unittest.main()
