"""Clicking a column title in a grouped list (All devices) sorts the devices inside every group."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    import NetworkDoctor as ND
except Exception:  # noqa: BLE001 - no tkinter on this machine
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


@pytest.mark.skipif(ND is None, reason="tkinter not available")
def test_grouped_list_sorts_inside_groups_and_reverses():
    tv = FakeTv({"Cameras": [("c1", "192.168.0.80"), ("c2", "192.168.0.9"), ("c3", "192.168.0.100")],
                 "Computers": [("p1", "192.168.0.70"), ("p2", "192.168.0.26")]})
    ND.tree_sort(tv, "ip", {"ip": "IP"})
    assert tv.kids["Cameras"] == ["c2", "c1", "c3"] and tv.kids["Computers"] == ["p2", "p1"]
    assert tv.kids[""] == ["Cameras", "Computers"] and tv.titles["ip"].endswith("▲")
    ND.tree_sort(tv, "ip", {"ip": "IP"})
    assert tv.kids["Cameras"] == ["c3", "c1", "c2"] and tv.titles["ip"].endswith("▼")
    tv.kids["Cameras"] = ["c1", "c2", "c3"]                 # the list was redrawn
    ND.tree_resort(tv)
    assert tv.kids["Cameras"] == ["c3", "c1", "c2"]


@pytest.mark.skipif(ND is None, reason="tkinter not available")
def test_flat_list_sorts_all_rows():
    tv = FakeTv({"": [("a", "192.168.0.80"), ("b", "192.168.0.9")]})
    tv.kids = {"": ["a", "b"]}
    ND.tree_sort(tv, "ip", {"ip": "IP"})
    assert tv.kids[""] == ["b", "a"]
