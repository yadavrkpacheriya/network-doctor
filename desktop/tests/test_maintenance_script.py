# -*- coding: utf-8 -*-
"""3.22.4: pc_fix_script()'s new "maint" option - a weekly Windows task that runs Optimize-Volume (Windows
itself picks TRIM for an SSD or defrag for a spinning disk) and Repair-Volume -Scan (an online NTFS health
check). On purpose this never calls a forced defrag or a live chkdsk repair - a disk that scan finds real
damage on is left for a person to decide on, never fixed automatically while the PC is in use."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_tools as T  # noqa: E402


def make(maint, **extra):
    opts = {"random_off": False, "renew": False, "lock_gw": False, "report": False, "daily": False, "maint": maint}
    opts.update(extra)
    return T.pc_fix_script(opts, "192.168.0.1", "", "", "")


class MaintenanceTask(unittest.TestCase):
    def test_off_by_default_is_guarded_by_the_maint_flag(self):
        """Like every other step in this script, the maintenance block is always in the text (one script
        covers every combination of options) but only runs when $opt.Maint is true at run time."""
        fix, _ = make(False)
        self.assertIn("Maint = $false", fix)
        self.assertIn("if ($opt.Maint)", fix)

    def test_on_registers_a_weekly_task(self):
        fix, _ = make(True)
        self.assertIn("Register-ScheduledTask", fix)
        self.assertIn("Network Doctor weekly maintenance", fix)
        self.assertIn("-Weekly", fix)

    def test_runs_optimize_volume_and_an_online_scan_only(self):
        fix, _ = make(True)
        self.assertIn("Optimize-Volume", fix)
        self.assertIn("Repair-Volume", fix)
        self.assertIn("-Scan", fix)

    def test_never_forces_a_live_repair_or_defrag(self):
        """The whole point of the correction: no -Defrag / -ReTrim flag (that decision is left to Windows
        itself, which already knows which drives are SSDs), and no chkdsk /f style forced fix anywhere."""
        fix, _ = make(True)
        self.assertNotIn("-Defrag", fix)
        self.assertNotIn("-ReTrim", fix)
        self.assertNotIn("chkdsk", fix.lower())
        self.assertNotIn("-SpotFix", fix)
        self.assertNotIn("-OfflineScanAndFix", fix)

    def test_undo_removes_the_task(self):
        _, undo = make(True)
        self.assertIn("Unregister-ScheduledTask", undo)
        self.assertIn("Network Doctor weekly maintenance", undo)


if __name__ == "__main__":
    unittest.main()
