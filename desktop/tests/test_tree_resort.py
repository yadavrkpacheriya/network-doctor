"""Clicking a column title in a grouped list (All devices) sorts the devices inside every group."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    import NetworkDoctor as ND
except Exception:  # noqa: BLE001 - no tkinter on the test machine: these tests skip
    ND = None


class FakeTv:
    def __init__(self, tree):
        self.kids = {"": list(tree)}
        self.val = {}
        for parent, rows in tree.items():
            self.kids[parent] = [r[0] for r in rows]
            for iid, ip in rows:
                self.val[iid] = ip
        self._sort = {"col": None, "rev": False}
        self.titles = {}

    def get_children(self, parent=""):
        return tuple(self.kids.get(parent, ()))

    def set(self, iid, col):
        return self.val.get(iid, "")

    def item(self, iid, what):
        return iid

    def move(self, iid, parent, pos):
        self.kids[parent].remove(iid)
        self.kids[parent].insert(pos, iid)

    def heading(self, c, text=None):
        self.titles[c] = text


@unittest.skipIf(ND is None, "tkinter not available")
class TreeResort(unittest.TestCase):
    def test_grouped_list_sorts_inside_groups_and_reverses(self):
        tv = FakeTv({"Cameras": [("c1", "192.168.0.80"), ("c2", "192.168.0.9"), ("c3", "192.168.0.100")],
                     "Computers": [("p1", "192.168.0.70"), ("p2", "192.168.0.26")]})
        ND.tree_sort(tv, "ip", {"ip": "IP"})
        self.assertEqual(tv.kids["Cameras"], ["c2", "c1", "c3"])
        self.assertEqual(tv.kids["Computers"], ["p2", "p1"])
        self.assertEqual(tv.kids[""], ["Cameras", "Computers"])
        self.assertTrue(tv.titles["ip"].endswith("▲"))
        ND.tree_sort(tv, "ip", {"ip": "IP"})
        self.assertEqual(tv.kids["Cameras"], ["c3", "c1", "c2"])
        self.assertTrue(tv.titles["ip"].endswith("▼"))
        tv.kids["Cameras"] = ["c1", "c2", "c3"]                 # the list was redrawn
        ND.tree_resort(tv)
        self.assertEqual(tv.kids["Cameras"], ["c3", "c1", "c2"])

    def test_flat_list_sorts_all_rows(self):
        tv = FakeTv({"": []})
        tv.kids = {"": ["a", "b"]}
        tv.val = {"a": "192.168.0.80", "b": "192.168.0.9"}
        ND.tree_sort(tv, "ip", {"ip": "IP"})
        self.assertEqual(tv.kids[""], ["b", "a"])


if __name__ == "__main__":
    unittest.main()
