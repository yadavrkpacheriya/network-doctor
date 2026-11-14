"""3.36: the PC Care page (This PC & Wi-Fi) - its rules, and on Windows the PowerShell engine itself."""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_core as core  # noqa: E402
import nd_pccare as PC  # noqa: E402
import nd_pcengine  # noqa: E402

ENGINE = nd_pcengine.ENGINE


class Rules(unittest.TestCase):
    def test_command_is_one_non_interactive_run_of_the_script(self):
        cmd = PC.build_command(r"C:\x\pccare_engine.ps1", "3", startup=True, winget=False)
        self.assertTrue(cmd[0].lower().endswith("powershell.exe"))
        self.assertIn("-NonInteractive", cmd)
        self.assertEqual(cmd[cmd.index("-File") + 1], r"C:\x\pccare_engine.ps1")
        self.assertEqual(cmd[cmd.index("-Choice") + 1], "3")
        self.assertEqual(cmd[cmd.index("-OptStartup") + 1], "1")
        self.assertEqual(cmd[cmd.index("-OptWinget") + 1], "0")

    def test_app_updates_are_off_unless_ticked(self):
        cmd = PC.build_command("s.ps1", "5", startup=False, winget=True)
        self.assertEqual(cmd[cmd.index("-OptStartup") + 1], "0")
        self.assertEqual(cmd[cmd.index("-OptWinget") + 1], "1")

    def test_unknown_or_unsafe_choice_is_refused(self):
        # "12" (remove user accounts) exists in the engine but is not offered by this page
        for bad in ("12", "9.1", "11.1", "", "1; Remove-Item C:\\"):
            with self.assertRaises(ValueError):
                PC.build_command("s.ps1", bad)

    def test_engine_lines_are_split_into_colour_and_text(self):
        self.assertEqual(PC.parse_line("@@Red@@   [High] Only 4 GB RAM\r\n"), ("fail", "   [High] Only 4 GB RAM"))
        self.assertEqual(PC.parse_line("@@@@plain text\n"), ("", "plain text"))
        self.assertEqual(PC.parse_line("@@Cyan@@=== 1. SCAN ===\n"), ("head", "=== 1. SCAN ==="))

    def test_tool_output_is_shown_as_it_is(self):
        self.assertEqual(PC.parse_line("Deployment Image Servicing and Management tool\r\n"),
                         ("", "Deployment Image Servicing and Management tool"))
        # a progress bar redrawn with carriage returns keeps only its last state
        self.assertEqual(PC.parse_line("[==   10%   ]\r[=====  60%  ]\r\n"), ("", "[=====  60%  ]"))
        self.assertEqual(PC.parse_line("\ufeffhello\n"), ("", "hello"))

    def test_engine_is_written_as_a_windows_text_file(self):
        folder = tempfile.mkdtemp()
        try:
            _, path = PC.write_engine(folder, lock=False)
            with open(path, "rb") as f:
                data = f.read()
            self.assertTrue(data.startswith(b"# Network Doctor - PC Care engine"))
            self.assertNotIn(b"\r\r\n", data)
            self.assertEqual(data.count(b"\r\n"), data.count(b"\n"))
            data.decode("ascii")
        finally:
            shutil.rmtree(folder, ignore_errors=True)


class EngineText(unittest.TestCase):
    def test_every_button_has_an_action_in_the_engine(self):
        body = ENGINE[ENGINE.index("function Invoke-Choice"):]
        cases = set(re.findall(r"^\s+'([\w.]+)'\s+\{", body, flags=re.M))
        self.assertEqual([c for c in PC.CHOICES if c not in cases], [])

    def test_parameters_come_first_and_it_never_asks(self):
        first = [ln for ln in ENGINE.splitlines() if ln.strip() and not ln.startswith("#")][0]
        self.assertTrue(first.startswith("param([string]$Choice"))
        self.assertIn("function Read-Host { param($Prompt, [switch]$AsSecureString) return '' }", ENGINE)
        self.assertNotIn("Windows.Forms", ENGINE)

    def test_no_private_account_names_are_published(self):
        self.assertIn("$removeUsers      = @()", ENGINE)

    def test_it_never_logs_in_to_the_router(self):
        for word in ("RouterOS", "mikrotik", "8728", "Invoke-RestMethod", "ssh "):
            self.assertNotIn(word.lower(), ENGINE.lower())


@unittest.skipUnless(core.IS_WIN, "the engine is a Windows PowerShell script")
class EngineOnWindows(unittest.TestCase):
    def _parse_errors(self, path):
        ps = ("$t = $null; $e = $null; "
              f"[void][System.Management.Automation.Language.Parser]::ParseFile('{path}', [ref]$t, [ref]$e); "
              "if ($e) { $e | ForEach-Object { $_.ToString() } }")
        r = subprocess.run([PC.powershell_exe(), "-NoProfile", "-Command", ps], capture_output=True, text=True,
                           errors="replace", timeout=120)
        return (r.stdout + r.stderr).strip()

    def test_powershell_can_parse_the_engine(self):
        folder, path = PC.write_engine(lock=False)
        try:
            self.assertEqual(self._parse_errors(path), "")
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_powershell_can_parse_the_restore_script_it_writes(self):
        m = re.search(r"\$restoreText = @'\n(.*?)\n'@", ENGINE, flags=re.S)
        self.assertIsNotNone(m)
        folder = tempfile.mkdtemp()
        try:
            path = os.path.join(folder, "Restore-Users.ps1")
            with open(path, "w", encoding="ascii", newline="\r\n") as f:
                f.write(m.group(1))
            self.assertEqual(self._parse_errors(path), "")
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_read_only_scan_runs_to_the_end(self):
        """The real thing, on this machine: Scan and report changes nothing, so it is safe to run in a test."""
        if not core.is_admin():
            self.skipTest("needs Administrator")
        folder, path = PC.write_engine()  # also proves the folder lock-down works
        try:
            r = subprocess.run(PC.build_command(path, "1"), capture_output=True, stdin=subprocess.DEVNULL,
                               timeout=600)
            out = r.stdout.decode("utf-8", errors="replace")
            lines = [PC.parse_line(ln)[1] for ln in out.splitlines()]
            text = "\n".join(lines)
            self.assertEqual(r.returncode, 0, text[-3000:])
            self.assertIn("1. SCAN AND REPORT", text)
            self.assertIn("WHAT THE SCAN FOUND", text)
            self.assertIn("System disk:", text)
            # a script error would show up as PowerShell's red error text
            for bad in ("CategoryInfo", "FullyQualifiedErrorId", "ParserError", "is not recognized as the name"):
                self.assertNotIn(bad, text, text[-3000:])
        finally:
            shutil.rmtree(folder, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
