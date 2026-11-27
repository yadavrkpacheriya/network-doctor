# -*- coding: utf-8 -*-
"""Read the REAL site name from the TLS ClientHello (SNI), so sites are named from what the connection declares,
not guessed from the IP owner (Rakesh, 27 Nov: name every real site/app, don't assume). No decryption."""
import unittest
import nd_sni
import nd_usage as U
import tempfile
import os


def client_hello(host):
    """Minimal but valid TLS1.2 ClientHello carrying `host` in the SNI extension."""
    hb = host.encode()
    sni = b"\x00" + len(hb).to_bytes(2, "big") + hb           # name_type host_name + len + host
    snl = len(sni).to_bytes(2, "big") + sni                    # server_name_list
    ext = b"\x00\x00" + len(snl).to_bytes(2, "big") + snl      # ext type 0 (server_name) + len + body
    exts = len(ext).to_bytes(2, "big") + ext
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x00\x2f" + b"\x01\x00" + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


class ParseSni(unittest.TestCase):
    def test_reads_real_names(self):
        for h in ("instagram.com", "acronis.com", "docs.google.com", "tally.erp.in"):
            self.assertEqual(nd_sni.parse_sni(client_hello(h)), h)

    def test_non_tls_or_junk_returns_empty(self):
        for junk in (b"", b"GET / HTTP/1.1\r\n", b"\x16\x03\x01\x00", b"\x00" * 40, client_hello("x.com")[:18]):
            self.assertEqual(nd_sni.parse_sni(junk), "")

    def test_never_invents_an_ip_as_a_name(self):
        self.assertEqual(nd_sni.parse_sni(client_hello("10.0.0.1")), "")  # all-numeric -> not a hostname

    def test_never_raises(self):
        import os as _os
        for _ in range(200):
            nd_sni.parse_sni(_os.urandom(60))   # fuzz: must not throw


class SniNamesUsage(unittest.TestCase):
    def test_sni_feeds_the_real_site_name_into_usage(self):
        host = nd_sni.parse_sni(client_hello("instagram.com"))
        d = tempfile.mkdtemp()
        s = U.UsageStore(os.path.join(d, "u.db"))
        # the on_sni hook calls dns_seen(client, host, (dst_ip,))
        s.dns_seen("192.168.0.57", host, ("31.13.1.1",))
        name, _shared = s.name_for("192.168.0.57", "31.13.1.1")
        self.assertEqual(name, "instagram.com")   # named from SNI, not "CDN (various)"


if __name__ == "__main__":
    unittest.main()
