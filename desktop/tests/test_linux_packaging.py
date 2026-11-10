# -*- coding: utf-8 -*-
"""3.23.0: the Linux install stopped being "download a raw file, chmod +x, run it from a terminal with
sudo" - a real .deb package (linux/build_deb.sh) now gives it an app-menu entry, an icon, a `networkdoctor`
command, network capabilities without root (setcap), and a working "Start at login". These tests cover the
pure, call-time logic behind that: the XDG autostart .desktop content (nd_core.linux_autostart_entry), and
the self-updater's refusal to touch the apt-owned binary (nd_update.is_packaged_install / apply_linux)."""
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import nd_core as core  # noqa: E402
import nd_update as U  # noqa: E402


class LinuxAutostartEntry(unittest.TestCase):
    def test_contains_the_required_keys(self):
        txt = core.linux_autostart_entry(["/opt/networkdoctor/NetworkDoctor", "--minimized"])
        self.assertTrue(txt.startswith("[Desktop Entry]\n"))
        for line in ("Type=Application", "Name=Network Doctor", "Terminal=false",
                     "X-GNOME-Autostart-enabled=true"):
            self.assertIn(line, txt)

    def test_exec_line_joins_the_given_command(self):
        txt = core.linux_autostart_entry(["/opt/networkdoctor/NetworkDoctor", "--minimized"])
        self.assertIn("Exec=/opt/networkdoctor/NetworkDoctor --minimized", txt)

    def test_a_path_with_spaces_is_shell_quoted(self):
        # e.g. the portable binary run from a folder like "~/My Programs/NetworkDoctor-Linux"
        txt = core.linux_autostart_entry(["/home/alex/My Programs/NetworkDoctor-Linux", "--minimized"])
        exec_line = next(ln for ln in txt.splitlines() if ln.startswith("Exec="))
        self.assertEqual(exec_line, "Exec='/home/alex/My Programs/NetworkDoctor-Linux' --minimized")

    def test_autostart_file_path_is_under_the_xdg_autostart_directory(self):
        self.assertTrue(core.LINUX_AUTOSTART_FILE.startswith(core.LINUX_AUTOSTART_DIR))
        self.assertTrue(core.LINUX_AUTOSTART_DIR.endswith(os.path.join(".config", "autostart")))
        self.assertTrue(core.LINUX_AUTOSTART_FILE.endswith("networkdoctor.desktop"))


class PackagedInstallDetection(unittest.TestCase):
    """is_packaged_install() is a call-time check (not a module-load constant like core.IS_STORE), so a
    test can point sys.executable at a fake path without needing to reload the module."""

    def setUp(self):
        self._exe, self._linux = sys.executable, U.IS_LINUX
        U.IS_LINUX = True  # these tests simulate Linux regardless of the CI runner's real OS

    def tearDown(self):
        sys.executable, U.IS_LINUX = self._exe, self._linux

    def test_the_deb_install_path_is_detected(self):
        sys.executable = "/opt/networkdoctor/NetworkDoctor"
        self.assertTrue(U.is_packaged_install())

    def test_a_portable_binary_anywhere_else_is_not(self):
        sys.executable = "/home/alex/NetworkDoctor/NetworkDoctor-Linux"
        self.assertFalse(U.is_packaged_install())

    def test_not_linux_is_never_a_packaged_install(self):
        U.IS_LINUX = False
        sys.executable = "/opt/networkdoctor/NetworkDoctor"
        self.assertFalse(U.is_packaged_install())


class ApplyLinuxRefusesThePackagedInstall(unittest.TestCase):
    def setUp(self):
        self._exe, self._linux = sys.executable, U.IS_LINUX
        self._popen = U.subprocess.Popen
        U.IS_LINUX = True
        U.subprocess.Popen = lambda *a, **k: self.fail("must not start a replacement process")

    def tearDown(self):
        sys.executable, U.IS_LINUX, U.subprocess.Popen = self._exe, self._linux, self._popen

    def test_refuses_and_explains_instead_of_trying_to_overwrite_root_owned_file(self):
        sys.executable = "/opt/networkdoctor/NetworkDoctor"
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as f:
            new_path = f.name
        try:
            with self.assertRaises(U.UpdateError) as ctx:
                U.apply_linux(new_path)
            self.assertIn(".deb", str(ctx.exception))
            self.assertFalse(os.path.exists(new_path))  # the downloaded (would-be) update is cleaned up
        finally:
            if os.path.exists(new_path):
                os.remove(new_path)

    def test_a_portable_install_proceeds_past_the_guard(self):
        """The .deb guard is specific to /opt/networkdoctor - an ordinary, user-owned portable binary
        must still reach the normal swap-and-restart path untouched."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            exe = os.path.join(d, "NetworkDoctor-Linux")
            with open(exe, "w") as f:
                f.write("old")
            sys.executable = exe
            new_path = os.path.join(d, "NetworkDoctor.new")
            with open(new_path, "w") as f:
                f.write("new")
            calls = []
            U.subprocess.Popen = lambda cmd, **k: calls.append(cmd)
            U.apply_linux(new_path)
            self.assertTrue(calls)  # reached the restart step - the guard did not fire
            with open(exe) as f:
                self.assertEqual(f.read(), "new")  # the swap actually happened


class BuildDebScript(unittest.TestCase):
    """End-to-end smoke test: build_deb.sh is a real, runnable packaging step, not just a code review -
    this builds an actual .deb from a throwaway binary and checks what dpkg-deb put in it."""

    @classmethod
    def setUpClass(cls):
        if subprocess.call(["which", "dpkg-deb"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            raise unittest.SkipTest("dpkg-deb is not installed")

    def test_the_built_package_has_the_app_menu_entry_icon_and_bin_symlink(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            fake_bin = os.path.join(d, "NetworkDoctor-Linux")
            with open(fake_bin, "w") as f:
                f.write("#!/bin/sh\necho hi\n")
            os.chmod(fake_bin, 0o755)
            icon = os.path.join(HERE, "..", "mobile", "android", "app", "src", "main", "res",
                                "mipmap-xxxhdpi", "ic_launcher.png")
            out = os.path.join(d, "out.deb")
            r = subprocess.run([os.path.join(HERE, "linux", "build_deb.sh"), fake_bin, "9.9.9", icon, out],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(os.path.exists(out))
            contents = subprocess.run(["dpkg-deb", "--contents", out], capture_output=True, text=True).stdout
            self.assertIn("./opt/networkdoctor/NetworkDoctor", contents)
            self.assertIn("./usr/share/applications/networkdoctor.desktop", contents)
            self.assertIn("./usr/share/icons/hicolor/192x192/apps/networkdoctor.png", contents)
            self.assertIn("./usr/bin/networkdoctor -> /opt/networkdoctor/NetworkDoctor", contents)
            info = subprocess.run(["dpkg-deb", "--info", out], capture_output=True, text=True).stdout
            self.assertIn("Version: 9.9.9", info)
            self.assertIn("Package: networkdoctor", info)


if __name__ == "__main__":
    unittest.main()
