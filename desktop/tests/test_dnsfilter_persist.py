# -*- coding: utf-8 -*-
"""3.21.3: nd_toolstab.fw_load / fw_save / build_dns_filter - the website-firewall settings shared between the
Tools tab's manual 'Start firewall' and the persistent one Setup can keep running across restarts, so turning
either one on sees the same block lists and the other's live state.

nd_toolstab.py is a Tk window module and imports nd_tabs (another Tk window module) at load time; this sandbox
has no display / tkinter at all. Both are only needed here for their pure, non-UI helpers, so each test gets its
own fully-faked toolkit (mock.patch.dict'd into sys.modules, with nd_toolstab/nd_tabs re-imported fresh under it
and popped again in tearDown) - the same isolated-import pattern tests/test_sweeptab.py uses - so this file never
depends on, or leaks into, whatever another test file happened to stub tkinter as."""
import importlib
import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class Widget:
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, name):
        return lambda *a, **k: None


def fake_toolkit():
    tk = types.ModuleType("tkinter")
    ttk = types.ModuleType("tkinter.ttk")
    mb = types.ModuleType("tkinter.messagebox")
    fd = types.ModuleType("tkinter.filedialog")
    sd = types.ModuleType("tkinter.simpledialog")
    sd.askstring = lambda *a, **k: None
    for n in ("Tk", "Toplevel", "Frame", "Label", "Entry", "Text", "Scrollbar", "Button", "Menu", "Checkbutton",
             "Listbox", "Canvas", "PanedWindow", "StringVar", "BooleanVar", "IntVar"):
        setattr(tk, n, Widget)
    for n in ("Frame", "Label", "Button", "Entry", "Combobox", "Checkbutton", "Notebook", "Treeview", "Scrollbar",
              "LabelFrame", "Radiobutton"):
        setattr(ttk, n, Widget)
    mb.showinfo = mb.showwarning = mb.showerror = lambda *a, **k: None
    mb.askyesno = lambda *a, **k: True
    fd.asksaveasfilename = lambda **k: ""
    tk.ttk, tk.messagebox, tk.filedialog, tk.simpledialog = ttk, mb, fd, sd
    return {"tkinter": tk, "tkinter.ttk": ttk, "tkinter.messagebox": mb, "tkinter.filedialog": fd,
            "tkinter.simpledialog": sd}


MODULES = ("nd_toolstab", "nd_tabs", "nd_dnsfilter")


class Isolated(unittest.TestCase):
    """Shared setUp/tearDown: fresh nd_dnsfilter (DF) / nd_toolstab (TT) imported under a faked tkinter, cleaned
    up afterwards so other test files' real imports of these same modules are unaffected."""

    def setUp(self):
        self.patch = mock.patch.dict(sys.modules, fake_toolkit())
        self.patch.start()
        for m in MODULES:
            sys.modules.pop(m, None)
        self.TT = importlib.import_module("nd_toolstab")
        self.DF = importlib.import_module("nd_dnsfilter")

    def tearDown(self):
        self.patch.stop()
        for m in MODULES:
            sys.modules.pop(m, None)


class FwSettingsFile(Isolated):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "website_firewall.json")
        self.url_patch = mock.patch.object(self.DF, "SETTINGS", self.path)
        self.url_patch.start()

    def tearDown(self):
        self.url_patch.stop()
        super().tearDown()

    def test_load_with_nothing_saved_yet_gives_an_empty_dict(self):
        self.assertEqual(self.TT.fw_load(), {})

    def test_save_then_load_round_trips(self):
        cfg = {"categories": ["ads"], "safe_search": True, "blocked": ["example.com"], "allowed": ["work.example"]}
        self.TT.fw_save(cfg)
        self.assertEqual(self.TT.fw_load(), cfg)
        with open(self.path, encoding="utf-8") as f:
            self.assertEqual(json.load(f), cfg)

    def test_save_handles_a_missing_data_dir_by_creating_it(self):
        self.TT.fw_save({"blocked": ["x.com"]})
        self.assertTrue(os.path.isfile(self.path))


class BuildDnsFilter(Isolated):
    def test_defaults_to_the_usual_starter_categories_when_nothing_was_ever_saved(self):
        with mock.patch.object(self.DF, "load_category", side_effect=lambda key: set(self.DF.CATEGORIES[key][2])):
            fw = self.TT.build_dns_filter({})
        self.assertFalse(fw.safe_search is False)  # cfg.get default True
        self.assertIsInstance(fw, self.DF.DnsFilter)

    def test_uses_the_given_cfgs_categories_blocked_and_allowed_lists(self):
        with mock.patch.object(self.DF, "load_category", return_value={"catlist.example"}) as cat:
            fw = self.TT.build_dns_filter({"categories": ["ads"], "blocked": ["manual.example"],
                                           "allowed": ["ok.example"], "safe_search": False})
        cat.assert_called_once_with("ads")
        self.assertIn("catlist.example", fw.blocked)
        self.assertIn("manual.example", fw.blocked)
        self.assertIn("ok.example", fw.allowed)
        self.assertFalse(fw.safe_search)

    def test_a_category_that_fails_to_download_does_not_break_the_rest(self):
        with mock.patch.object(self.DF, "load_category", side_effect=OSError("no network")):
            fw = self.TT.build_dns_filter({"categories": ["ads"], "blocked": ["manual.example"]})
        self.assertIn("manual.example", fw.blocked)

    def test_never_calls_start_itself(self):
        """build_dns_filter only builds the object - binding port 53 is the caller's explicit .start()."""
        with mock.patch.object(self.DF.DnsFilter, "start") as st:
            self.TT.build_dns_filter({"categories": []})
        st.assert_not_called()


if __name__ == "__main__":
    unittest.main()
