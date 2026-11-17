# -*- coding: utf-8 -*-
"""Monthly internet comparison report: per-day totals that reset at local midnight, and the per-device split
that explains a high day (e.g. cameras running overnight while PCs are off)."""
import datetime as dt
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_usage as U  # noqa: E402


def ts(day, hour=12):
    """A local-time epoch for a given 'YYYY-MM-DD' + hour (so add_flow files it on that calendar day)."""
    d = dt.datetime.strptime(day, "%Y-%m-%d").replace(hour=hour)
    return time.mktime(d.timetuple())


class DailySeries(unittest.TestCase):
    def test_each_day_is_its_own_bucket_and_resets_at_midnight(self):
        with _store() as s:
            s.add_flow("192.168.0.9", "5.5.5.5", 443, 6, 1_000_000_000, False, now=ts("2026-11-02"))
            s.add_flow("192.168.0.9", "5.5.5.5", 443, 6, 2_000_000_000, False, now=ts("2026-11-03"))
            ser = U.daily_series(s, month="2026-11", today=dt.date(2026, 11, 4))
        by = {d["day"]: d["total"] for d in ser}
        self.assertEqual(by["2026-11-02"], 1_000_000_000)
        self.assertEqual(by["2026-11-03"], 2_000_000_000)   # day 3 does NOT include day 2 -> nightly reset
        self.assertEqual(by["2026-11-01"], 0)               # a quiet day stays 0, not blank
        self.assertNotIn("2026-11-05", by)                  # future days omitted

    def test_future_months_and_today_boundary(self):
        with _store() as s:
            s.add_flow("192.168.0.9", "5.5.5.5", 443, 6, 10, False, now=ts("2026-11-10"))
            ser = U.daily_series(s, month="2026-11", today=dt.date(2026, 11, 10))
        self.assertEqual(ser[-1]["day"], "2026-11-10")      # stops at 'today'


class MonthReport(unittest.TestCase):
    def test_report_shows_which_device_drove_each_day(self):
        with _store() as s:
            s.devmap = {"192.168.0.64": ("CAM gate", "CAM gate", "CCTV"),
                        "192.168.0.57": ("Hitesh PC", "Hitesh PC", "Accounts")}
            # night: camera uploads a lot while the PC sends a little
            s.add_flow("192.168.0.64", "1.1.1.1", 554, 6, 8_000_000_000, True, now=ts("2026-11-15", 3))
            s.add_flow("192.168.0.57", "2.2.2.2", 443, 6, 200_000_000, True, now=ts("2026-11-15", 10))
            rep = U.month_report(s, month="2026-11", today=dt.date(2026, 11, 15))
        day = next(d for d in rep["days"] if d["day"] == "2026-11-15")
        self.assertEqual(day["top_dev"], "CAM gate")         # the report names the camera as the driver
        self.assertEqual(day["total"], 8_200_000_000)
        self.assertEqual(rep["devices"][0]["name"], "CAM gate")
        self.assertEqual(rep["busiest"]["day"], "2026-11-15")
        self.assertGreater(rep["total"], 8_000_000_000)

    def test_html_renders_and_embeds_data(self):
        with _store() as s:
            s.add_flow("192.168.0.9", "5.5.5.5", 443, 6, 500_000_000, False, now=ts("2026-11-07"))
            html = U.month_report_html(s, month="2026-11", today=dt.date(2026, 11, 7))
        self.assertIn("Internet usage this month", html)
        self.assertNotIn("/*DATA*/null", html)               # data was injected
        self.assertIn("2026-11-07", html)


import contextlib  # noqa: E402
import tempfile  # noqa: E402


@contextlib.contextmanager
def _store():
    # ignore_cleanup_errors: on Windows the SQLite file can still be held briefly at teardown (WinError 32)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        yield U.UsageStore(os.path.join(d, "u.db"))


if __name__ == "__main__":
    unittest.main()
