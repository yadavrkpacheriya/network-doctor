# -*- coding: utf-8 -*-
"""3.22.2: nd_tools.tree_sort_key() - click-a-column-header sort for every list in the app. An IP sorts by its
real value, a number (with its usual units) sorts numerically, everything else sorts as case-insensitive text."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_tools as T  # noqa: E402


class TreeSortKey(unittest.TestCase):
    def test_ip_addresses_sort_by_real_value_not_text(self):
        ips = ["192.168.0.80", "192.168.0.9", "192.168.0.100", "192.168.0.3"]
        self.assertEqual(sorted(ips, key=T.tree_sort_key),
                         ["192.168.0.3", "192.168.0.9", "192.168.0.80", "192.168.0.100"])

    def test_plain_numbers_sort_numerically(self):
        self.assertEqual(sorted(["26", "118", "9", "3"], key=T.tree_sort_key), ["3", "9", "26", "118"])

    def test_numbers_with_commas_and_units_sort_numerically(self):
        # a real column's unit is consistent throughout (e.g. a whole "Download" column in Mbps) - the sort
        # itself only needs the number, not unit-aware conversion across different units
        vals = ["2.1 Mbps", "60 Mbps", "1,024 Mbps", "9 Mbps"]
        self.assertEqual(sorted(vals, key=T.tree_sort_key), ["2.1 Mbps", "9 Mbps", "60 Mbps", "1,024 Mbps"])

    def test_percent_and_ms_cells_sort_numerically(self):
        self.assertEqual(sorted(["89%", "5%", "128 ms", "12 ms"], key=T.tree_sort_key)[:2], ["5%", "12 ms"])

    def test_plain_text_sorts_case_insensitively(self):
        self.assertEqual(sorted(["sandeep", "HR", "es216g"], key=T.tree_sort_key), ["es216g", "HR", "sandeep"])

    def test_numbers_and_ips_sort_before_plain_text_in_the_same_column(self):
        mixed = ["NOT REACHABLE", "192.168.0.5", "OK"]
        self.assertEqual(sorted(mixed, key=T.tree_sort_key)[0], "192.168.0.5")

    def test_a_mac_address_is_not_mistaken_for_an_ip_or_a_number(self):
        # 6 hex groups is not a valid IPv6 address (needs 8, or "::"), and letters rule out the numeric path too
        self.assertEqual(T.tree_sort_key("6C:0B:84:E2:3A:3B"), (1, "6c:0b:84:e2:3a:3b"))

    def test_a_device_name_with_a_trailing_number_is_not_mistaken_for_a_plain_number(self):
        self.assertEqual(T.tree_sort_key("Camera .31")[0], 1)  # the whole cell must be numeric, not just a part

    def test_empty_cell_sorts_as_empty_text(self):
        self.assertEqual(T.tree_sort_key(""), (1, ""))
        self.assertEqual(T.tree_sort_key(None), (1, ""))

    def test_a_negative_number_still_sorts_numerically(self):
        self.assertEqual(sorted(["-5", "3", "-10"], key=T.tree_sort_key), ["-10", "-5", "3"])


class SortedOrder(unittest.TestCase):
    """The Tk-free half of click-a-column-header sort: given (row_id, cell_text) pairs, which order should the
    rows end up in. NetworkDoctor.py's tree_sort() is a thin wrapper that feeds a real Treeview's rows through
    this and repositions them - nothing about the sort decision itself needs a real window to test."""

    def test_ascending_by_default(self):
        rows = [("r1", "192.168.0.80"), ("r2", "192.168.0.9"), ("r3", "192.168.0.3")]
        self.assertEqual(T.sorted_order(rows), ["r3", "r2", "r1"])

    def test_reverse_flips_the_order(self):
        rows = [("r1", "9"), ("r2", "80"), ("r3", "3")]
        self.assertEqual(T.sorted_order(rows, reverse=True), ["r2", "r1", "r3"])

    def test_row_identity_is_preserved_not_just_the_text(self):
        rows = [("cam31", "Camera .31"), ("cam5", "Camera .5"), ("hr", "HR")]
        order = T.sorted_order(rows)
        self.assertEqual(set(order), {"cam31", "cam5", "hr"})
        self.assertEqual(len(order), 3)

    def test_empty_list_is_fine(self):
        self.assertEqual(T.sorted_order([]), [])


if __name__ == "__main__":
    unittest.main()
