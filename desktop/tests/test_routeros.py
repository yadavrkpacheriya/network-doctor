# -*- coding: utf-8 -*-
"""MikroTik API client: wire format, login, scripts, terminal output (v7 and v6), password storage."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import nd_routeros as R  # noqa: E402
from fake_routeros import FakeRouter  # noqa: E402


class Wire(unittest.TestCase):
    def test_length_encoding_round_trip(self):
        for n in (0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000, 0xFFFFFFF, 0x10000000):
            b = R.enc_len(n)
            it = iter([b[i:i + 1] for i in range(len(b))])
            buf = bytearray(b)

            def recv(k):
                out = bytes(buf[:k])
                del buf[:k]
                return out
            self.assertEqual(R.read_len(recv), n, n)

    def test_quote(self):
        self.assertEqual(R.ros_quote('a "b" $c\\d'), '"a \\"b\\" \\$c\\\\d"')

    def test_endless_commands_get_a_limit(self):
        self.assertEqual(R.bounded("/tool torch interface=ether2"), "/tool torch interface=ether2 duration=10s")
        self.assertEqual(R.bounded("/ping 1.1.1.1"), "/ping 1.1.1.1 count=10")
        self.assertEqual(R.bounded("/ping 1.1.1.1 count=3"), "/ping 1.1.1.1 count=3")
        self.assertEqual(R.bounded("/interface ethernet monitor ether2"), "/interface ethernet monitor ether2 once")

    def test_password_storage(self):
        self.assertEqual(R.unprotect(R.protect("s3cr3t ü")), "s3cr3t ü")
        self.assertEqual(R.unprotect(""), "")


class Client(unittest.TestCase):
    def setUp(self):
        self.r = FakeRouter()

    def tearDown(self):
        self.r.close()

    def ros(self, pw="pw"):
        return R.RouterOS("127.0.0.1", "admin", pw, self.r.port, timeout=3)

    def test_login_and_read(self):
        with self.ros() as c:
            self.assertEqual(c.identity(), ("Office-Router", "7.15 (stable)"))
            self.assertEqual(c.leases()[0]["host-name"], "SALES-PC")

    def test_bad_password(self):
        with self.assertRaises(R.RosError) as e:
            self.ros("wrong").connect()
        self.assertIn("login refused", str(e.exception))

    def test_run_script_and_clean_up(self):
        with self.ros() as c:
            self.assertEqual(c.run_script("/ip dhcp-server lease add address=192.168.0.87"), "")
            self.assertIn("lease add", self.r.ran[-1])
            self.assertEqual(self.r.scripts, {})  # the temporary script is removed again
            self.assertIn("syntax error", c.run_script("fail-me"))

    def test_cli_output_v7(self):
        with self.ros() as c:
            self.assertEqual(c.run_cli("/system resource print"), "uptime: 1d\nversion: 7.15")
            self.assertEqual(c.run_cli("/tool torch interface=ether2"), "ran: /tool torch interface=ether2 duration=10s")

    def test_cli_output_v6_through_file(self):
        self.r.v7 = False
        with self.ros() as c:
            self.assertEqual(c.run_cli("/system resource print"), "uptime: 1d\nversion: 7.15")

    def test_settings(self):
        st = {"router_api": {"host": "", "user": "admin", "pw": R.protect("pw"), "port": self.r.port}}
        c = R.from_settings(st, gw="127.0.0.1")
        with c:
            self.assertEqual(c.identity()[0], "Office-Router")
        self.assertIsNone(R.from_settings({}, "1.1.1.1"))


if __name__ == "__main__":
    unittest.main()
