# -*- coding: utf-8 -*-
"""v3.25: asset-register tag fields (owner/serial/purchase/warranty), alert history trend-by-day rollup,
audit-log CSV export, and camera login sweep fetching + applying the device's own configured name
(Hikvision ISAPI already did; Dahua's web API now also asks for it)."""

import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import nd_alerts as AL  # noqa: E402
import nd_sweep as S  # noqa: E402
import nd_tools as T  # noqa: E402


class AssetFields(unittest.TestCase):
    def test_asset_fields_are_tag_fields(self):
        for f in ("owner", "serial", "purchase_date", "warranty_until"):
            self.assertIn(f, T.TAG_FIELDS)

    def test_asset_fields_round_trip_through_csv(self):
        db = {}
        T.set_tag(db, "AA:BB:CC:DD:EE:FF", name="Lobby camera", owner="Security", serial="SN-123",
                  purchase_date="2024-01-15", warranty_until="2027-01-15")
        csv_text = T.tags_to_csv([{"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.0.150"}], db)
        self.assertIn("SN-123", csv_text)
        self.assertIn("2027-01-15", csv_text)
        db2 = {}
        done, skipped = T.tags_from_csv(csv_text, db2)
        self.assertEqual((done, skipped), (1, 0))
        t2 = T.tags_of(db2)["AA:BB:CC:DD:EE:FF"]
        self.assertEqual(t2["serial"], "SN-123")
        self.assertEqual(t2["warranty_until"], "2027-01-15")


class AlertTrend(unittest.TestCase):
    def test_trend_by_day_fills_empty_days_too(self):
        now = time.time()
        items = [{"t": now, "kind": "dhcp_conflict"}, {"t": now, "kind": "dhcp_conflict"},
                  {"t": now, "kind": "malware"}, {"t": now - 2 * 86400, "kind": "loop"}]
        rows = AL.trend_by_day(items, days=5, now=now)
        self.assertEqual(len(rows), 5)
        today = rows[-1]
        self.assertEqual(today["total"], 3)
        self.assertEqual(AL.top_kind(today), "dhcp_conflict")  # 2 beats malware's 1
        two_days_ago = rows[-3]
        self.assertEqual(two_days_ago["total"], 1)
        empty_day = rows[0]
        self.assertEqual(empty_day["total"], 0)
        self.assertEqual(AL.top_kind(empty_day), "")

    def test_export_trend_csv(self):
        rows = AL.trend_by_day([{"t": time.time(), "kind": "torrent"}], days=1)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "trend.csv")
            AL.export_trend_csv(path, rows)
            with open(path, encoding="utf-8-sig") as f:
                text = f.read()
        self.assertIn("torrent", text)


class AuditExport(unittest.TestCase):
    def test_export_audit_csv(self):
        entries = [{"ts": "2026-11-13 10:00:00", "user": "admin", "role": "owner", "action": "tag",
                    "detail": "renamed a device", "result": "done", "ip": "console"}]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "audit.csv")
            T.export_audit_csv(path, entries)
            with open(path, encoding="utf-8-sig") as f:
                text = f.read()
        self.assertIn("renamed a device", text)


class CameraOwnNameFetch(unittest.TestCase):
    def test_dahua_system_info_asks_for_the_configured_name_too(self):
        """Regression: getSystemInfo/getSoftwareVersion never carried the camera's own configured name
        (MachineName), so a successful Dahua login could never offer to apply it as the tag name."""
        import inspect
        src = inspect.getsource(S.t_dahua)
        self.assertIn("getConfig&name=General", src)
        self.assertIn("MachineName", src)

    def test_hik_name_field_still_parsed(self):
        xml = ("<DeviceInfo><deviceName>Front Gate Cam</deviceName><model>DS-2CD2143</model>"
               "<serialNumber>SN1</serialNumber></DeviceInfo>")
        data = S.parse_hik(xml)
        self.assertEqual(data["name"], "Front Gate Cam")


if __name__ == "__main__":
    unittest.main()
