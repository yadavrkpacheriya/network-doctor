# -*- coding: utf-8 -*-
"""The Inventory 'PCs with details' filter must show ONLY computers, never cameras/NVRs/router that also
carry a 'model' from the scan. (Bug: the filter checked for a model but not the category.)"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_tools as T  # noqa: E402

# Cameras/NVR/router can carry a 'model' from the scan, but never a report_time (they never run PC details).
ROUTER = {"name": "MikroTik", "category": "Router / Gateway", "model": "Routerboard.com", "report_time": ""}
NVR = {"name": "Office NVR", "category": "CCTV cameras / DVR", "model": "Millennial Net", "report_time": ""}
CAM = {"name": "Motor Store", "category": "CCTV cameras / DVR", "model": "", "report_time": ""}
# A PC that ran the details report - note: its scan category may even be blank; report_time is what counts.
PC_FULL = {"name": "RAKESH", "category": "Computers / laptops", "model": "ThinkCentre", "report_time": "now"}
PC_NOCAT = {"name": "ACCOUNTS", "category": "", "model": "OptiPlex", "report_time": "now"}
PC_BARE = {"name": "Reception", "category": "Computers / laptops", "model": "", "report_time": ""}
PRINTER = {"name": "HP", "category": "Printer", "model": "HP LaserJet", "report_time": ""}


def shown(rows, which):
    """Rows the Inventory list keeps for a given 'Show' choice (mirrors the tab's keep condition)."""
    out = []
    for r in rows:
        hide = (which == "PCs with details" and not T.pc_has_details(r) or
                which == "PCs without details" and (r["model"] or not T.is_computer(r)))
        if not hide:
            out.append(r["name"])
    return out


class PcsWithDetails(unittest.TestCase):
    def test_only_reporting_pcs_are_shown_not_cameras(self):
        rows = [ROUTER, NVR, CAM, PC_FULL, PC_NOCAT, PC_BARE, PRINTER]
        self.assertEqual(shown(rows, "PCs with details"), ["RAKESH", "ACCOUNTS"])

    def test_a_camera_with_a_model_is_not_a_pc(self):
        self.assertFalse(T.pc_has_details(NVR))        # has a model from the scan, but no report
        self.assertFalse(T.pc_has_details(ROUTER))
        self.assertFalse(T.pc_has_details(PRINTER))
        self.assertTrue(T.pc_has_details(PC_FULL))
        self.assertTrue(T.pc_has_details(PC_NOCAT))    # a PC that reported, even with no scan category

    def test_without_details_lists_only_computers_that_did_not_report(self):
        rows = [NVR, PC_FULL, PC_BARE]
        self.assertEqual(shown(rows, "PCs without details"), ["Reception"])

    def test_count_of_pcs_with_details_excludes_cameras(self):
        rows = [ROUTER, NVR, CAM, PC_FULL, PC_NOCAT, PC_BARE, PRINTER]
        self.assertEqual(sum(1 for r in rows if T.pc_has_details(r)), 2)


if __name__ == "__main__":
    unittest.main()
