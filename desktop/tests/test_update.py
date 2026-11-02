# -*- coding: utf-8 -*-
"""Tests for the self-updater (nd_update): version order, restart arguments, the source-file list."""

import os
import re
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import nd_update as U  # noqa: E402


class FakePopen:
    calls = []

    kws = []

    def __init__(self, cmd, **kw):
        FakePopen.calls.append(cmd)
        FakePopen.kws.append(kw)


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self._popen, self._call = U.subprocess.Popen, U.subprocess.call
        U.subprocess.Popen = FakePopen
        FakePopen.calls = []

    def tearDown(self):
        U.subprocess.Popen, U.subprocess.call = self._popen, self._call

    def test_version_order(self):
        self.assertGreater(U.parse_version("3.10.0"), U.parse_version("3.9.0"))
        self.assertGreater(U.parse_version("v3.9.1"), U.parse_version("3.9.0"))
        self.assertEqual(U.parse_version(""), (0,))

    def test_windows_helper_restarts_with_args(self):
        U.apply_exe(r"C:\x\NetworkDoctor.new.exe", ["--updated-from", "3.9.0", "--minimized"])
        bat = FakePopen.calls[-1][2]
        try:
            with open(bat) as f:
                txt = f.read()
        finally:
            os.remove(bat)
        start = [ln for ln in txt.splitlines() if ln.startswith("start ")]
        self.assertEqual(len(start), 1)
        self.assertTrue(start[0].endswith("--updated-from 3.9.0 --minimized"), start[0])

    def test_mac_helper_restarts_with_args(self):
        old = U.mac_bundle
        U.mac_bundle = lambda: "/Applications/Network Doctor.app"
        U.subprocess.call = lambda *a, **k: 1  # no ditto here: the zipfile fallback is used
        try:
            d = tempfile.mkdtemp()
            z = os.path.join(d, "a.zip")
            with zipfile.ZipFile(z, "w") as zf:
                zf.writestr("Network Doctor.app/Contents/MacOS/NetworkDoctor", "x")
            U.apply_mac(z, ["--updated-from", "3.9.0"])
            with open(FakePopen.calls[-1][1]) as f:
                lines = f.read().splitlines()
            self.assertIn('open "/Applications/Network Doctor.app" --args --updated-from 3.9.0', lines)
        finally:
            U.mac_bundle = old

    def test_mac_helper_without_args(self):
        old = U.mac_bundle
        U.mac_bundle = lambda: "/Applications/Network Doctor.app"
        U.subprocess.call = lambda *a, **k: 1
        try:
            d = tempfile.mkdtemp()
            z = os.path.join(d, "a.zip")
            with zipfile.ZipFile(z, "w") as zf:
                zf.writestr("Network Doctor.app/Contents/MacOS/NetworkDoctor", "x")
            U.apply_mac(z)
            with open(FakePopen.calls[-1][1]) as f:
                self.assertIn('open "/Applications/Network Doctor.app"', f.read().splitlines())
        finally:
            U.mac_bundle = old

    def test_restart_does_not_pass_pyinstaller_private_variables(self):
        """3.11.0: the restarted exe stopped with 'invalid originating onefile parent process (PID not found)'."""
        saved = dict(os.environ)
        os.environ.update({"_PYI_APPLICATION_HOME_DIR": "x", "_PYI_PARENT_PROCESS_LEVEL": "1", "_MEIPASS2": "y"})
        try:
            with tempfile.TemporaryDirectory() as d:
                U.apply_exe(os.path.join(d, "new.exe"), ["--minimized"])
                env = FakePopen.kws[-1]["env"]
                self.assertFalse([k for k in env if k.startswith(("_PYI", "_MEIPASS"))])
                self.assertEqual(env["PYINSTALLER_RESET_ENVIRONMENT"], "1")
                self.assertEqual(env.get("PATH"), os.environ.get("PATH"))
                with open(FakePopen.calls[-1][2]) as f:
                    self.assertIn("set PYINSTALLER_RESET_ENVIRONMENT=1", f.read())
        finally:
            os.environ.clear()
            os.environ.update(saved)

    def test_source_file_list_is_complete(self):
        """SOURCE_FILES.txt lets older copies fetch modules added later - it must list every module."""
        with open(os.path.join(HERE, "SOURCE_FILES.txt")) as f:
            listed = {x.strip() for x in f if x.strip()}
        self.assertEqual(listed, set(U.SOURCE_FILES))
        modules = {f for f in os.listdir(HERE) if re.fullmatch(r"(NetworkDoctor|nd_\w+)\.py", f)}
        self.assertEqual(modules, listed, "a desktop module is missing from SOURCE_FILES / SOURCE_FILES.txt")


if __name__ == "__main__":
    unittest.main()
