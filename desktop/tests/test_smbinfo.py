# -*- coding: utf-8 -*-
"""PC name from the SMB / NTLM challenge, against a fake Windows file-sharing server."""

import os
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_smbinfo as SI  # noqa: E402


def challenge(name="ACCOUNTS-PC", domain="FANAIR", dns="accounts-pc.fanair.local", build=22631):
    def av(i, v):
        b = v.encode("utf-16-le")
        return struct.pack("<HH", i, len(b)) + b
    info = av(2, domain) + av(1, name) + av(4, "fanair.local") + av(3, dns) + struct.pack("<HH", 0, 0)
    head = b"NTLMSSP\x00" + struct.pack("<I", 2) + struct.pack("<HHI", 0, 0, 56) + struct.pack("<I", 0xE2898215) + \
        b"\x11" * 8 + b"\x00" * 8 + struct.pack("<HHI", len(info), len(info), 56) + bytes([10, 0]) + \
        struct.pack("<H", build) + b"\x00\x00\x00\x0f"
    return head + info


class FakeSmb:
    def __init__(self):
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.port = self.srv.getsockname()[1]
        self.got = []
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        c, _ = self.srv.accept()
        with c:
            for reply in (b"\xfeSMB" + b"\x00" * 60 + b"negotiate-response",
                          b"\xfeSMB" + b"\x00" * 60 + b"\xa1\x81" + challenge()):
                n = struct.unpack("!I", c.recv(4))[0]
                data = b""
                while len(data) < n:
                    data += c.recv(n - len(data))
                self.got.append(data)
                c.sendall(struct.pack("!I", len(reply)) + reply)


class SmbInfo(unittest.TestCase):
    def test_name_domain_and_windows_version(self):
        f = FakeSmb()
        r = SI.smb_info("127.0.0.1", f.port, timeout=3)
        self.assertEqual(r["name"], "ACCOUNTS-PC")
        self.assertEqual(r["domain"], "FANAIR")
        self.assertEqual(r["dns_name"], "accounts-pc.fanair.local")
        self.assertEqual(r["os"], "Windows 11 23H2 (build 22631)")
        self.assertTrue(f.got[0].startswith(b"\xfeSMB"))
        self.assertIn(b"NTLMSSP\x00\x01\x00\x00\x00", f.got[1])  # only the first login step - no password

    def test_requests_are_well_formed(self):
        n = SI.negotiate_request()
        self.assertEqual(struct.unpack("!I", n[:4])[0], len(n) - 4)
        s = SI.session_request()
        off, ln = struct.unpack("<HH", s[4 + 64 + 12:4 + 64 + 16])
        self.assertEqual(off, 88)
        self.assertEqual(s[4 + off:4 + off + 1], b"\x60")  # SPNEGO token at the stated offset
        self.assertEqual(len(s) - 4 - off, ln)

    def test_no_server(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertIsNone(SI.smb_info("127.0.0.1", port, timeout=1))
        self.assertIsNone(SI.parse_challenge(b"nothing here"))
        self.assertEqual(SI.windows_name(10, 0, 19045), "Windows 10 22H2 (build 19045)")


if __name__ == "__main__":
    unittest.main()
