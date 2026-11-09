# -*- coding: utf-8 -*-
"""3.22.3: nd_tools.row_matches() / filtered_rows() - the "Find" quick-filter box added to Fixed IPs, the
bandwidth plan list, Quarantined devices, the Audit log, Usage & crash reports, the IP-MAC binding list, DNS
filter categories, the critical-devices watch list and the WMI inventory. A row is shown while every typed
word matches somewhere in it, across every column, case-insensitively - clearing the box shows everything."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_tools as T  # noqa: E402


class RowMatches(unittest.TestCase):
    def test_empty_query_matches_everything(self):
        self.assertTrue(T.row_matches("", ["anything", "192.168.0.5"]))
        self.assertTrue(T.row_matches(None, []))
        self.assertTrue(T.row_matches("   ", ["x"]))

    def test_matches_a_substring_in_any_cell_case_insensitively(self):
        self.assertTrue(T.row_matches("cam", ["Front Cam 31", "192.168.0.31"]))
        self.assertTrue(T.row_matches("CAM", ["Front Cam 31", "192.168.0.31"]))

    def test_matches_across_different_cells_not_just_one(self):
        self.assertTrue(T.row_matches("192 cam", ["Front Cam 31", "192.168.0.31"]))  # "cam" in col 1, "192" in col 2

    def test_every_word_must_match_somewhere(self):
        self.assertFalse(T.row_matches("cam printer", ["Front Cam 31", "192.168.0.31"]))  # "printer" matches nothing

    def test_no_match_is_false(self):
        self.assertFalse(T.row_matches("router", ["Front Cam 31", "192.168.0.31"]))

    def test_none_cells_are_skipped_not_a_crash(self):
        self.assertTrue(T.row_matches("cam", ["Front Cam 31", None, ""]))

    def test_numbers_and_ips_are_matched_as_plain_text(self):
        self.assertTrue(T.row_matches("0.31", ["Front Cam", "192.168.0.31"]))


class FilteredRows(unittest.TestCase):
    def test_empty_query_returns_every_row_in_order(self):
        rows = [("r1", ["Cam 31", "192.168.0.31"]), ("r2", ["PC", "192.168.0.9"])]
        self.assertEqual(T.filtered_rows(rows, ""), ["r1", "r2"])

    def test_query_narrows_to_matching_rows_only(self):
        rows = [("r1", ["Cam 31", "192.168.0.31"]), ("r2", ["PC", "192.168.0.9"]), ("r3", ["Cam 5", "192.168.0.5"])]
        self.assertEqual(T.filtered_rows(rows, "cam"), ["r1", "r3"])

    def test_original_order_is_preserved_among_matches(self):
        rows = [("b", ["Beta"]), ("a", ["Alpha"]), ("c", ["Alpha2"])]
        self.assertEqual(T.filtered_rows(rows, "alpha"), ["a", "c"])

    def test_no_matches_gives_an_empty_list(self):
        rows = [("r1", ["Cam 31"])]
        self.assertEqual(T.filtered_rows(rows, "router"), [])

    def test_empty_rows_is_fine(self):
        self.assertEqual(T.filtered_rows([], "anything"), [])


if __name__ == "__main__":
    unittest.main()
