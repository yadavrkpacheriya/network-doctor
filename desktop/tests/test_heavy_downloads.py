# -*- coding: utf-8 -*-
"""Per-site productivity + occasional heavy-download detection (Rakesh, 27 Nov): find movie/game download sites
used briefly but pulling large data, so they can be reviewed and blocked; and give per-site time/data/opens."""
import os
import tempfile
import time
import unittest
import nd_usage as U


def store():
    d = tempfile.mkdtemp()
    return U.UsageStore(os.path.join(d, "u.db"))


class HeavyDownloads(unittest.TestCase):
    def test_movie_grab_flagged_steady_worksite_not(self):
        s = store()
        now = time.time()
        # movie site: 3.2 GB down in 2 hours
        for i in range(2):
            s.add_flow("192.168.0.80", "5.6.7.8", 443, 6, 1_600_000_000, False, "tamilrockers.movie", now - i * 3600)
        # Google Sheets: modest data spread over 8 hours (steady work)
        for h in range(8):
            s.add_flow("192.168.0.80", "142.250.1.1", 443, 6, 20_000_000, False, "docs.google.com", now - h * 3600)
        hd = s.heavy_downloads(min_mb=500)
        sites = {r["site"]: r for r in hd}
        self.assertIn("tamilrockers.movie", sites)             # the grab is caught
        self.assertTrue(sites["tamilrockers.movie"]["suggest_block"])
        self.assertNotIn("docs.google.com", sites)             # steady work site is NOT a heavy-download grab

    def test_small_sites_ignored(self):
        s = store()
        s.add_flow("192.168.0.80", "1.2.3.4", 443, 6, 50_000_000, False, "small.site", time.time())
        self.assertEqual(s.heavy_downloads(min_mb=800), [])    # 50 MB < threshold


class SiteActivity(unittest.TestCase):
    def test_per_site_data_and_hours(self):
        s = store()
        now = time.time()
        for h in range(3):
            s.add_flow("192.168.0.57", "157.240.1.1", 443, 6, 100_000_000, False, "instagram.com", now - h * 3600)
        s.dns_seen("192.168.0.57", "instagram.com", ("157.240.1.1",))
        rows = {r["site"]: r for r in s.site_activity(dev="192.168.0.57")}
        self.assertIn("instagram.com", rows)
        self.assertGreaterEqual(rows["instagram.com"]["hours"], 1)
        self.assertGreater(rows["instagram.com"]["down"], 0)


if __name__ == "__main__":
    unittest.main()
