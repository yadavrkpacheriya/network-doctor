# -*- coding: utf-8 -*-
"""Tests for the website firewall (nd_dnsfilter) with a fake upstream DNS server on localhost.
Run from desktop/:  python -m unittest discover -s tests"""

import os
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_dnsfilter as F  # noqa: E402
import nd_net as NT  # noqa: E402


class FakeUpstream:
    """Answers every A question with 93.184.216.34."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.addr = self.sock.getsockname()
        self.asked = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                data, client = self.sock.recvfrom(4096)
            except OSError:
                return
            _, _, name, qtype, end = F.parse_query(data)
            self.asked.append(name)
            self.sock.sendto(F.answer(data, qtype, end, ["93.184.216.34"]), client)

    def close(self):
        self.sock.close()


def ask(server, name, qtype="A"):
    r = NT.dns_query(name, qtype, server[0], timeout=2, port=server[1])
    return r.get("error") or [x["data"] for x in r["records"] if x["section"] == "answer"]


class Lists(unittest.TestCase):
    def test_parse_list(self):
        text = "# comment\n127.0.0.1 localhost\n0.0.0.0 ads.example.com\n0.0.0.0 Tracker.Example.NET # x\n" \
               "plain.example.org\n*.wild.example.com\n\n:: ip6-localhost\nnot a domain\n"
        self.assertEqual(F.parse_list(text), {"ads.example.com", "tracker.example.net", "plain.example.org",
                                              "wild.example.com"})

    def test_matches_parents(self):
        names = {"facebook.com", "ads.example.com"}
        self.assertTrue(F.matches("m.facebook.com", names))
        self.assertTrue(F.matches("FACEBOOK.com.", names))
        self.assertFalse(F.matches("notfacebook.com", names))
        self.assertFalse(F.matches("example.com", names))  # a blocked sub-domain does not block its parent

    def test_category_offline_and_cached(self):
        old = F.LIST_DIR
        F.LIST_DIR = os.path.join(os.path.dirname(__file__), "_tmp_lists")
        try:
            def offline(url):
                raise OSError("offline")
            self.assertIn("pornhub.com", F.load_category("adult", fetch=offline))
            hosts = "\n".join(f"0.0.0.0 bet{i}.example" for i in range(30))
            got = F.load_category("gambling", fetch=lambda url: hosts)
            self.assertIn("bet7.example", got)
            self.assertIn("bet365.com", got)  # built-in names stay
            self.assertIn("bet7.example", F.load_category("gambling", fetch=offline))  # cached copy
        finally:
            import shutil
            shutil.rmtree(F.LIST_DIR, ignore_errors=True)
            F.LIST_DIR = old


class Server(unittest.TestCase):
    def setUp(self):
        self.up = FakeUpstream()
        self.f = F.DnsFilter([self.up.addr], blocked={"facebook.com", "doubleclick.net"}, allowed={"business.facebook.com"},
                             host="127.0.0.1", port=0).start()
        self.addr = self.f.addr

    def tearDown(self):
        self.f.stop()
        self.up.close()

    def test_block_pass_allow(self):
        self.assertEqual(ask(self.addr, "www.facebook.com"), ["0.0.0.0"])
        self.assertEqual(ask(self.addr, "ad.doubleclick.net", "AAAA"), ["::"])
        self.assertEqual(ask(self.addr, "example.com"), ["93.184.216.34"])
        self.assertEqual(ask(self.addr, "business.facebook.com"), ["93.184.216.34"])  # allow list wins
        self.assertEqual(self.up.asked, ["example.com", "business.facebook.com"])  # blocked names never leave
        snap = self.f.snapshot()
        self.assertEqual((snap["queries"], snap["blocked"]), (4, 2))
        self.assertEqual(snap["blocked_clients"], {"127.0.0.1": 2})
        self.assertEqual(dict(snap["top"]), {"www.facebook.com": 1, "ad.doubleclick.net": 1})

    def test_safe_search(self):
        self.f.safe_search = True
        self.assertEqual(self.f.decide("www.google.com"), "safe")
        self.assertEqual(ask(self.addr, "www.google.com"), ["93.184.216.34"])  # the safe address, via upstream
        self.assertIn("forcesafesearch.google.com", self.up.asked)

    def test_garbage_is_ignored(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"\x00\x01garbage", self.addr)
        s.close()
        self.assertEqual(ask(self.addr, "example.com"), ["93.184.216.34"])

    def test_reply_shape(self):
        _, q = NT.build_query("x.example", 1, qid=4660)
        _, _, name, qtype, end = F.parse_query(q)
        r = NT.parse_response(F.blocked_reply(q, qtype, end))
        self.assertEqual((name, r["id"], r["rcode"], [x["data"] for x in r["records"]]), ("x.example", 4660, 0,
                                                                                       ["0.0.0.0"]))
        self.assertEqual(struct.unpack("!H", F.blocked_reply(q, qtype, end)[2:4])[0] & 0x8000, 0x8000)


if __name__ == "__main__":
    unittest.main()
