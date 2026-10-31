# -*- coding: utf-8 -*-
"""Slow website diagnosis: each cause, fed in as measurements, must come out first with the right fix."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_slow as S  # noqa: E402


def ping(loss=0, avg=1.0, jitter=0.3, mx=None):
    return {"sent": 20, "recv": 20 if loss < 100 else 0, "loss": loss, "avg": avg, "max": mx or avg * 2,
            "min": avg / 2, "jitter": jitter}


def run(total=600, ttfb=200, tls=80, connect=20, dns=10):
    return {"total": total, "ttfb": ttfb, "tls": tls, "connect": connect, "dns": dns}


def healthy(**kw):
    m = {"url": "https://docs.google.com/spreadsheets/", "host": "docs.google.com", "gw": "192.168.0.1",
         "device": {"name": "ACC-PC", "ip": "192.168.0.40", "category": "Computers", "down_bps": 0, "up_bps": 0,
                    "hw": {}, "links": []},
         "dev_ping": ping(), "gw_ping": ping(), "inet_ping": ping(avg=25, jitter=3),
         "dns": [{"label": "this PC's DNS", "server": "192.168.0.1", "ms": 20, "cached_ms": 2},
                 {"label": "public 1.1.1.1", "server": "1.1.1.1", "ms": 25, "cached_ms": 20}],
         "site_runs": [run(), run()], "ref_runs": [run(total=300, ttfb=60)], "mtu": 1500,
         "line": {"capacity_mbps": 100, "have_flows": True, "down_bps": 20e6, "up_bps": 2e6,
                  "top": [("CCTV-NVR", "192.168.0.20", 12e6)]},
         "router_cpu": 20, "context": []}
    m.update(kw)
    return m


def first(m):
    return S.judge(m)[0]


class Diagnosis(unittest.TestCase):
    def test_healthy_says_so_and_gives_the_compare_command(self):
        f = first(healthy())
        self.assertEqual(f["sev"], "ok")
        self.assertIn('curl.exe -o NUL', S.compare_command("https://docs.google.com/"))

    def test_weak_wifi_of_that_user(self):
        f = first(healthy(dev_ping=ping(loss=8, avg=45, jitter=40)))
        self.assertIn("ACC-PC's own connection is weak", f["title"])
        self.assertIn("Wi-Fi", f["title"])

    def test_line_full_names_who_and_offers_limit(self):
        m = healthy(line={"capacity_mbps": 50, "have_flows": True, "down_bps": 48e6, "up_bps": 3e6,
                          "top": [("STORE-PC", "192.168.0.41", 35e6), ("ACC-PC", "192.168.0.40", 3e6)]})
        f = first(m)
        self.assertIn("line is full", f["title"])
        self.assertEqual(f["action"], "limit:192.168.0.41")
        self.assertIn('target=192.168.0.41/32 max-limit=15M/15M', S.fix_script(f["action"], 50))

    def test_slow_dns(self):
        m = healthy(dns=[{"label": "this PC's DNS", "server": "192.168.0.1", "ms": 900, "cached_ms": 300},
                         {"label": "public 1.1.1.1", "server": "1.1.1.1", "ms": 30, "cached_ms": 25}])
        f = first(m)
        self.assertIn("Slow DNS", f["title"])
        self.assertEqual(f["action"], "dns_public")
        self.assertIn("servers=1.1.1.1,8.8.8.8", S.fix_script("dns_public"))

    def test_dead_dns(self):
        m = healthy(dns=[{"label": "this PC's DNS", "server": "192.168.0.99", "error": "no answer (timeout)"},
                         {"label": "public 1.1.1.1", "server": "1.1.1.1", "ms": 30}], dns_rogue=True)
        titles = [x["title"] for x in S.judge(m)]
        self.assertIn("does not answer", titles[0])
        self.assertTrue(any("not the office router" in t for t in titles))

    def test_poor_internet_line(self):
        f = first(healthy(inet_ping=ping(loss=7, avg=180, jitter=60)))
        self.assertIn("internet line itself is poor", f["title"])

    def test_office_network_unstable(self):
        f = first(healthy(gw_ping=ping(loss=6, avg=40, jitter=30), context=["Very high broadcast traffic (900/second)"]))
        self.assertIn("office network to the router is unstable", f["title"])
        self.assertEqual(f["action"], "open:rca")

    def test_mtu(self):
        f = first(healthy(mtu=1452))
        self.assertIn("MTU 1452", f["title"])
        self.assertIn("clamp-to-pmtu", S.fix_script("mss_clamp"))

    def test_site_itself_slow_google_sheets_advice(self):
        m = healthy(site_runs=[run(total=5200, ttfb=4500, tls=90)], ref_runs=[run(total=300, ttfb=60, tls=60)])
        f = first(m)
        self.assertIn("docs.google.com itself answers slowly", f["title"])
        self.assertTrue(any("IMPORTRANGE" in x for x in f["fixes"]))

    def test_weak_pc_and_busy_pc(self):
        dev = dict(healthy()["device"], hw={"ram_gb": "4", "disk_free_gb": "6"}, down_bps=30e6,
                   recent_apps=[("Windows Update", 900 * 1048576)])
        titles = [x["title"] for x in S.judge(healthy(device=dev))]
        self.assertTrue(any("PC itself is weak" in t for t in titles), titles)
        self.assertTrue(any("busy on the internet right now" in t for t in titles), titles)

    def test_bufferbloat_and_router_cpu(self):
        titles = [x["title"] for x in S.judge(healthy(loaded={"idle": 25, "busy": 380}, router_cpu=96))]
        self.assertTrue(any("bufferbloat" in t for t in titles))
        self.assertTrue(any("processor is busy (96%)" in t for t in titles))
        self.assertIn("pcq-download-default", S.fix_script("queue_fair", 100, "192.168.0.0/24"))
        self.assertIn("max-limit=90M/90M", S.fix_script("queue_fair", 100, "192.168.0.0/24"))

    def test_site_unreachable(self):
        m = healthy(site_runs=[{"error": "cannot connect to 1.2.3.4:443 (timed out)"}] * 2)
        self.assertIn("cannot be opened", first(m)["title"])

    def test_no_traffic_data_is_mentioned(self):
        titles = [x["title"] for x in S.judge(healthy(line={"have_flows": False}))]
        self.assertTrue(any("Cannot see whether the line is full" in t for t in titles))

    def test_router_silent_and_dns_failure_answers(self):
        f = first(healthy(gw_ping=ping(loss=100)))
        self.assertIn("router does not answer ping", f["title"])
        m = healthy(dns=[{"label": "this PC's DNS", "server": "192.168.0.1", "error": "answered: refused"},
                         {"label": "public 1.1.1.1", "server": "1.1.1.1", "error": "no answer (timeout)"}])
        self.assertTrue(any("DNS does not work" in x["title"] for x in S.judge(m)))

    def test_url(self):
        self.assertEqual(S.norm_url("docs.google.com"), "https://docs.google.com/")
        self.assertEqual(S.norm_url(""), "")


class Timing(unittest.TestCase):
    def test_http_timing_against_local_server(self):
        import http.server
        import threading
        srv = http.server.HTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            r = S.http_timing(f"http://127.0.0.1:{srv.server_port}/")
            self.assertNotIn("error", r)
            for k in ("dns", "connect", "ttfb", "total"):
                self.assertIn(k, r)
            self.assertTrue(r["status"].startswith("HTTP/"))
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
