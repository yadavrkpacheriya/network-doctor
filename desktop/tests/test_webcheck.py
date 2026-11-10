# -*- coding: utf-8 -*-
"""Website / server check (Internet & Usage > Website check): a TLS handshake failure other than an
untrusted certificate used to show only the bare exception text (e.g. "[Errno 104] Connection reset by
peer") with nothing to act on. _tls_fail_hint() adds a short, concrete reason for the common cases."""
import os
import socket
import ssl
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_net as NT  # noqa: E402


class TlsFailHint(unittest.TestCase):
    def test_connection_reset_points_at_a_filter_or_firewall(self):
        hint = NT._tls_fail_hint(ConnectionResetError("[Errno 104] Connection reset by peer"))
        self.assertIn("filter", hint)
        self.assertIn("firewall", hint)

    def test_timeout_says_no_reply(self):
        hint = NT._tls_fail_hint(socket.timeout("timed out"))
        self.assertIn("no reply", hint)

    def test_generic_ssl_error_suggests_a_next_step(self):
        hint = NT._tls_fail_hint(ssl.SSLError("unexpected eof"))
        self.assertIn("Speed test", hint)

    def test_unknown_exception_gives_no_hint_rather_than_guessing(self):
        self.assertEqual(NT._tls_fail_hint(ValueError("something else")), "")


if __name__ == "__main__":
    unittest.main()
