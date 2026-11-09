# -*- coding: utf-8 -*-
"""3.22.5: nd_tools.mass_disconnect() - several watched devices (Tools > Critical devices) going dark within a
few minutes of each other usually means a shared switch, AP, router or power strip failed, not that each one
broke on its own at the same moment. Raised as its own "Possible shared failure" alert, in NetworkDoctor.py's
_on_watch(), alongside (not instead of) the existing per-device "Critical device not answering" alerts."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_tools as T  # noqa: E402


class MassDisconnect(unittest.TestCase):
    def test_no_cluster_with_fewer_than_three_devices_down(self):
        self.assertEqual(T.mass_disconnect({"Switch": 1000, "NVR": 1010}, now=1020), [])

    def test_three_devices_down_within_the_window_is_a_cluster(self):
        down = {"Switch": 1000, "NVR": 1010, "Printer": 1030}
        self.assertEqual(T.mass_disconnect(down, now=1040), ["NVR", "Printer", "Switch"])

    def test_a_device_down_long_before_the_others_is_not_swept_in(self):
        # "Printer" has been down for hours - a fresh failure of the other two should not blame it too
        down = {"Switch": 9000, "NVR": 9010, "Printer": 100}
        self.assertEqual(T.mass_disconnect(down, now=9020), [])  # only 2 of the 3 are in the fresh cluster

    def test_empty_input_is_fine(self):
        self.assertEqual(T.mass_disconnect({}, now=1000), [])

    def test_exactly_at_the_window_edge_still_counts(self):
        down = {"A": 1000, "B": 1000, "C": 1300}  # 300s apart = the default window, inclusive
        self.assertEqual(T.mass_disconnect(down, now=1300, window=300), ["A", "B", "C"])

    def test_custom_min_count(self):
        down = {"A": 1000, "B": 1010}
        self.assertEqual(T.mass_disconnect(down, now=1020, min_count=2), ["A", "B"])


if __name__ == "__main__":
    unittest.main()
