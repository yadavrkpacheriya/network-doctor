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


class PackagedLinuxAutoUpdate(unittest.TestCase):
    """The .deb install used to refuse every update (apply_linux's guard) and just point the user at a
    manual 'sudo apt install'. It can now update itself through apply_deb()/pkexec - these tests cover the
    pieces that are specific to that path: picking the versioned .deb asset, the pkexec availability check,
    and the helper script apply_deb() hands to a detached shell."""

    def setUp(self):
        self._is_linux, self._exe = U.IS_LINUX, sys.executable
        self._popen, self._call, self._which = U.subprocess.Popen, U.subprocess.call, U.shutil.which
        U.subprocess.Popen = FakePopen
        FakePopen.calls = []
        U.IS_LINUX = True
        sys.executable = "/opt/networkdoctor/NetworkDoctor"  # makes is_packaged_install() True

    def tearDown(self):
        U.IS_LINUX, sys.executable = self._is_linux, self._exe
        U.subprocess.Popen, U.subprocess.call, U.shutil.which = self._popen, self._call, self._which

    def test_deb_asset_name_carries_the_version(self):
        self.assertEqual(U.deb_asset_name("3.24.0"), "NetworkDoctor_3.24.0_amd64.deb")

    def test_pkexec_available_reflects_shutil_which(self):
        U.shutil.which = lambda name: "/usr/bin/pkexec" if name == "pkexec" else None
        self.assertTrue(U.pkexec_available())
        U.shutil.which = lambda name: None
        self.assertFalse(U.pkexec_available())

    def test_apply_update_routes_a_packaged_linux_install_to_apply_deb(self):
        U.shutil.which = lambda name: "/usr/bin/pkexec"
        with tempfile.TemporaryDirectory() as d:
            deb = os.path.join(d, "NetworkDoctor_3.24.0_amd64.deb")
            with open(deb, "w") as f:
                f.write("x")
            U.apply_update(deb, ["--updated-from", "3.23.10"])
        script = FakePopen.calls[-1][1]
        try:
            with open(script) as f:
                txt = f.read()
            self.assertIn(f'pkexec apt-get install -y "{deb}"', txt)
            self.assertIn('"/opt/networkdoctor/NetworkDoctor" --updated-from 3.23.10', txt)
        finally:
            os.remove(script)

    def test_apply_deb_without_pkexec_raises_and_removes_the_download(self):
        U.shutil.which = lambda name: None
        with tempfile.TemporaryDirectory() as d:
            deb = os.path.join(d, "NetworkDoctor_3.24.0_amd64.deb")
            with open(deb, "w") as f:
                f.write("x")
            with self.assertRaises(U.UpdateError) as ctx:
                U.apply_deb(deb)
            self.assertIn("pkexec", str(ctx.exception))
            self.assertFalse(os.path.exists(deb))
        self.assertFalse(FakePopen.calls)  # never got as far as starting the helper

    def test_check_picks_the_versioned_deb_asset_for_a_packaged_install(self):
        fake_data = {
            "tag_name": "v3.24.0", "body": "notes", "html_url": "https://x",
            "assets": [
                {"name": "NetworkDoctor_3.24.0_amd64.deb", "browser_download_url": "https://x/deb", "size": 123},
                {"name": "NetworkDoctor_3.24.0_amd64.deb.sha256", "browser_download_url": "https://x/sha"},
                {"name": "NetworkDoctor-Linux", "browser_download_url": "https://x/bin", "size": 456},
            ],
        }
        import json as _json
        import io

        class FakeResp:
            def __init__(self, data):
                self._data = data

            def read(self):
                return self._data

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        old_urlopen = U.urllib.request.urlopen
        U.urllib.request.urlopen = lambda *a, **k: FakeResp(_json.dumps(fake_data).encode())
        try:
            info = U.check("3.23.10")
        finally:
            U.urllib.request.urlopen = old_urlopen
        self.assertEqual(info["asset_name"], "NetworkDoctor_3.24.0_amd64.deb")
        self.assertEqual(info["exe_url"], "https://x/deb")
        self.assertEqual(info["sha_url"], "https://x/sha")

    def test_download_exe_targets_the_temp_dir_for_a_packaged_install(self):
        info = {"exe_url": "https://x/deb", "sha_url": "https://x/sha", "asset_name": "NetworkDoctor_3.24.0_amd64.deb",
                "version": "3.24.0"}
        payload = b"deb-bytes"
        import hashlib as _hashlib

        class FakeResp:
            def __init__(self, data):
                self._data = data
                self._sent = False

            def read(self, n=None):
                if self._sent:
                    return b""
                self._sent = True
                return self._data

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_get(url, timeout=60):
            return FakeResp(_hashlib.sha256(payload).hexdigest().encode() if "sha" in url else payload)
        old_get = U._get
        U._get = fake_get
        try:
            path = U.download_exe(info)
        finally:
            U._get = old_get
        try:
            self.assertEqual(os.path.dirname(path), U.tempfile.gettempdir())
            self.assertTrue(os.path.basename(path).endswith("_amd64.deb"))
            with open(path, "rb") as f:
                self.assertEqual(f.read(), payload)
        finally:
            U._rm(path)


if __name__ == "__main__":
    unittest.main()
