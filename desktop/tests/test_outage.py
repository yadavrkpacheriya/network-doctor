# -*- coding: utf-8 -*-
"""v3.26: "is it down for everyone or just us" - reads the stage nd_net.web_check() got stuck on (DNS /
Connect / TLS / HTTP) as the diagnosis itself, plus official status for the services that publish one.
Only the pure logic (verdict(), preset data, the no-network-call paths) is tested here - web_check()
and official_status()'s HTTP call do real sockets/HTTP and are exercised by hand against real hosts,
same as nd_net.py's other I/O helpers."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_outage as O  # noqa: E402


class Verdict(unittest.TestCase):
    def test_dns_failure_points_at_this_network(self):
        level, msg = O.verdict([("DNS", "'foo' not found: ...", "critical")])
        self.assertEqual(level, "critical")
        self.assertIn("THIS", msg)

    def test_connect_failure_is_ambiguous_blocked_or_down(self):
        rows = [("DNS", "ok", "ok"), ("Connect", "port 443 closed", "critical")]
        level, msg = O.verdict(rows)
        self.assertEqual(level, "critical")
        self.assertIn("status page", msg)

    def test_tls_hard_failure_points_at_a_local_interceptor(self):
        rows = [("DNS", "ok", "ok"), ("Connect", "ok", "ok"), ("TLS", "failed: ...", "critical")]
        level, msg = O.verdict(rows)
        self.assertEqual(level, "warn")
        self.assertIn("proxy", msg)

    def test_http_no_answer_after_tls_points_at_the_service(self):
        """The key case this module exists for: got all the way through the network/security layers,
        but the site itself never answered - that's the strongest signal it's THEIR problem."""
        rows = [("DNS", "ok", "ok"), ("Connect", "ok", "ok"), ("TLS", "ok", "ok"),
                ("HTTP", "no answer: timed out", "critical")]
        level, msg = O.verdict(rows)
        self.assertEqual(level, "critical")
        self.assertIn("SERVICE", msg)
        self.assertIn("not this network", msg)

    def test_5xx_is_the_services_problem(self):
        rows = [("DNS", "ok", "ok"), ("Connect", "ok", "ok"), ("TLS", "ok", "ok"),
                ("HTTP", "HTTP/1.1 503 Service Unavailable  (first byte 120 ms)", "warning")]
        level, msg = O.verdict(rows)
        self.assertEqual(level, "critical")
        self.assertIn("service's problem", msg)

    def test_normal_response_means_no_outage(self):
        rows = [("DNS", "ok", "ok"), ("Connect", "ok", "ok"), ("TLS", "ok", "ok"),
                ("HTTP", "HTTP/1.1 200 OK  (first byte 42 ms)", "ok"), ("Total", "60 ms", "ok")]
        level, msg = O.verdict(rows)
        self.assertEqual(level, "ok")
        self.assertIn("no outage", msg)

    def test_untrusted_cert_warning_is_not_mistaken_for_a_tls_failure(self):
        """web_check() reports an untrusted (self-signed) cert as a TLS row with sev "warning", not
        "critical", and keeps going to HTTP - only a hard TLS failure (sev critical) should trigger the
        "local interceptor" verdict."""
        rows = [("DNS", "ok", "ok"), ("Connect", "ok", "ok"),
                ("TLS", "certificate NOT trusted: ...", "warning"),
                ("HTTP", "HTTP/1.1 200 OK  (first byte 10 ms)", "ok")]
        level, msg = O.verdict(rows)
        self.assertEqual(level, "ok")


class Presets(unittest.TestCase):
    def test_every_preset_without_a_public_api_has_a_manual_link(self):
        for name, (host, url) in O.STATUSPAGE_PRESETS.items():
            self.assertTrue(host)
            if url is None:
                self.assertIn(name, O.MANUAL_STATUS_LINKS, f"{name} has no public API and no manual link")
                self.assertTrue(O.MANUAL_STATUS_LINKS[name].startswith("http"))

    def test_microsoft_has_no_fabricated_public_api(self):
        """Microsoft 365's status page needs a work/school sign-in - there is no unauthenticated public
        JSON endpoint, so this must stay None rather than pointing at something that will just 401."""
        host, url = O.STATUSPAGE_PRESETS["Microsoft 365 / Outlook"]
        self.assertIsNone(url)
        self.assertIn("outlook", host)


class OfficialStatusUnknownName(unittest.TestCase):
    def test_unknown_name_is_unavailable_without_any_network_call(self):
        # Not a preset at all (e.g. the user typed an arbitrary hostname) - must short-circuit before
        # attempting any HTTP request.
        out = O.official_status("some-random-internal-app.local")
        self.assertEqual(out, {"available": False, "manual_link": ""})

    def test_known_name_without_a_public_api_reports_the_manual_link_without_a_network_call(self):
        out = O.official_status("Microsoft 365 / Outlook")
        self.assertFalse(out["available"])
        self.assertIn("downdetector", out["manual_link"])


if __name__ == "__main__":
    unittest.main()
