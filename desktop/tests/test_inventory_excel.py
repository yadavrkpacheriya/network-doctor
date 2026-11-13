"""Inventory -> Excel (.xlsx) -> edit -> import back (nd_xlsx.py, nd_tools.inventory_import)."""
import os
import tempfile
import unittest
import zipfile
from xml.etree import ElementTree as ET

import nd_tools as T
import nd_xlsx as X

MAC1, MAC2 = "AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"


def db():
    return {"devices": {}, "pc_reports": {}, "tags": {}, "labels": {}}


def devices():
    return [{"mac": MAC1, "ip": "192.168.0.30", "name": "Camera .30", "vendor": "Hikvision", "online": True,
             "category": "CCTV cameras / DVR / NVR", "names": {}},
            {"mac": MAC2, "ip": "192.168.0.31", "name": "ACCOUNTS-PC", "vendor": "Dell", "online": True,
             "category": "Computers / laptops", "names": {}}]


class Xlsx(unittest.TestCase):
    def test_every_part_is_well_formed_and_reads_back(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.xlsx")
            X.write(p, ["Name", "MAC", "RAM GB"], [["PC <1> & \x07co", MAC1, 8], ["", None, ""]], [20, 18, 8])
            with zipfile.ZipFile(p) as z:
                for n in z.namelist():
                    ET.fromstring(z.read(n))
            self.assertEqual(X.read(p)[:2], [["Name", "MAC", "RAM GB"], ["PC <1> & co", MAC1, "8"]])

    def test_column_names_and_excel_dates(self):
        self.assertEqual([X.col_name(i) for i in (0, 25, 26, 27)], ["A", "Z", "AA", "AB"])
        self.assertEqual(X.excel_date("45413"), "2024-05-01")
        self.assertEqual(X.excel_date("2024-05-01"), "2024-05-01")
        self.assertEqual(X.excel_date("12 May"), "12 May")


class RoundTrip(unittest.TestCase):
    def setUp(self):
        self.db = db()
        self.rows = T.inventory_rows(devices(), self.db)
        self.d = tempfile.TemporaryDirectory()
        self.p = os.path.join(self.d.name, "inv.xlsx")
        T.export_inventory_xlsx(self.p, self.rows)
        self.table = T.inventory_table(self.p)
        self.col = {h: i for i, h in enumerate(self.table[0])}

    def tearDown(self):
        self.d.cleanup()

    def row_of(self, mac):
        return next(r for r in self.table[1:] if r[self.col["MAC"]] == mac)

    def test_sheet_has_the_asset_columns(self):
        for h in ("Name", "MAC", "IP", "Owner", "Purchase date", "Warranty until", "Serial no.", "Last seen", "Notes"):
            self.assertIn(h, self.col)

    def test_unedited_sheet_changes_nothing(self):
        self.assertEqual(T.inventory_import(self.table, self.db, self.rows), (0, 0, 0))
        self.assertEqual(T.tags_of(self.db), {})          # automatic names were not frozen as typed names

    def test_edits_come_back_and_dates_typed_in_excel_are_understood(self):
        r = self.row_of(MAC1)
        r += [""] * (len(self.table[0]) - len(r))
        r[self.col["Name"]] = "Gate camera"
        r[self.col["Owner"]] = "Security"
        r[self.col["Serial no."]] = "DS-123"
        r[self.col["Purchase date"]] = "45413"
        devs, cells, skipped = T.inventory_import(self.table, self.db, self.rows)
        self.assertEqual((devs, cells, skipped), (1, 4, 0))
        t = T.tags_of(self.db)[MAC1]
        self.assertEqual((t["name"], t["owner"], t["serial"], t["purchase_date"]),
                         ("Gate camera", "Security", "DS-123", "2024-05-01"))
        self.assertNotIn(MAC2, T.tags_of(self.db))
        again = T.inventory_rows(devices(), self.db)
        self.assertEqual(next(x for x in again if x["mac"] == MAC1)["serial"], "DS-123")

    def test_unknown_mac_is_skipped_and_missing_mac_column_is_refused(self):
        self.table.append(["Stranger", "10.0.0.9", "11:22:33:44:55:66"])
        self.assertEqual(T.inventory_import(self.table, self.db, self.rows)[2], 1)
        with self.assertRaises(ValueError):
            T.inventory_import([["Name", "Owner"], ["x", "y"]], self.db, self.rows)

    def test_csv_export_reads_back_the_same_way(self):
        p = os.path.join(self.d.name, "inv.csv")
        T.export_inventory_csv(p, self.rows)
        self.assertEqual(T.inventory_import(T.inventory_table(p), self.db, self.rows), (0, 0, 0))


if __name__ == "__main__":
    unittest.main()
