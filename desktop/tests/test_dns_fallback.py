# -*- coding: utf-8 -*-
"""The public-DNS fallback used when this PC's own DNS does not answer (update check 'getaddrinfo failed')."""

import os
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_core as core  # noqa: E402


def fake_dns_server(answer_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))

    def serve():
        data, addr = s.recvfrom(512)
        q_end = 12
        while data[q_end]:
            q_end += data[q_end] + 1
        q_end += 5
        hdr = data[:2] + struct.pack("!HHHHH", 0x8180, 1, 2, 0, 0)
        cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, 2) + b"\xc0\x0c"  # CNAME first, as GitHub's DNS does
        a = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(answer_ip)
        s.sendto(hdr + data[12:q_end] + cname + a, addr)
        s.close()
    threading.Thread(target=serve, daemon=True).start()
    return s.getsockname()


class DnsFallback(unittest.TestCase):
    def setUp(self):
        self.saved = (core.PUBLIC_DNS, core._orig_getaddrinfo)
        core._dns_cache.clear()

    def tearDown(self):
        core.PUBLIC_DNS, core._orig_getaddrinfo = self.saved

    def test_public_resolve_parses_cname_chain(self):
        core.PUBLIC_DNS = (fake_dns_server("140.82.112.5"),)
        self.assertEqual(core.public_resolve("api.github.com"), ["140.82.112.5"])

    def test_getaddrinfo_falls_back_only_after_failure(self):
        core.PUBLIC_DNS = (fake_dns_server("140.82.112.6"),)
        real = self.saved[1]

        def broken(host, *a):
            if host[0].isdigit():
                return real(host, *a)
            raise socket.gaierror(11001, "getaddrinfo failed")
        core._orig_getaddrinfo = broken
        res = socket.getaddrinfo("api.github.com", 443)
        self.assertEqual(res[0][4][0], "140.82.112.6")

    def test_lan_names_are_not_sent_outside(self):
        def broken(host, *a):
            raise socket.gaierror(11001, "getaddrinfo failed")
        core._orig_getaddrinfo = broken
        with self.assertRaises(socket.gaierror):
            socket.getaddrinfo("printer.local", 80)
        with self.assertRaises(socket.gaierror):
            socket.getaddrinfo("ACCOUNTS-PC", 80)


if __name__ == "__main__":
    unittest.main()
