"""3.20: the Login sweep page runs end to end with a fake window toolkit (no screen needed)."""
import importlib
import os
import queue
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_core as core  # noqa: E402


class Widget:
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, name):
        return lambda *a, **k: None


class Var:
    def __init__(self, master=None, value=None, **k):
        self.v = value

    def get(self):
        return self.v

    def set(self, v):
        self.v = v

    def trace_add(self, *a, **k):
        pass


class Tree:
    def __init__(self):
        self.rows = {}
        self.detached = set()
        self.sel = []

    def insert(self, parent, where, values=(), tags=()):
        iid = f"I{len(self.rows)}"
        self.rows[iid] = values
        return iid

    def delete(self, *ids):
        self.rows.clear()
        self.detached.clear()

    def get_children(self):
        return [i for i in self.rows if i not in self.detached]

    def detach(self, iid):
        self.detached.add(iid)

    def selection(self):
        return list(self.sel)

    def selection_set(self, *iids):
        self.sel = list(iids)

    def __getattr__(self, name):
        return lambda *a, **k: None


class Text(Widget):
    def __init__(self):
        self.text = ""

    def delete(self, *a):
        self.text = ""

    def insert(self, where, s, *tag):
        self.text += s

    def configure(self, **k):
        pass


def fake_toolkit():
    tk = types.ModuleType("tkinter")
    ttk = types.ModuleType("tkinter.ttk")
    mb = types.ModuleType("tkinter.messagebox")
    fd = types.ModuleType("tkinter.filedialog")
    sd = types.ModuleType("tkinter.simpledialog")
    sd.askstring = lambda *a, **k: None
    for n in ("Tk", "Toplevel", "Frame", "Label", "Entry", "Text", "Scrollbar", "Button", "Menu", "Checkbutton"):
        setattr(tk, n, Widget)
    tk.StringVar = tk.BooleanVar = Var
    for n in ("Frame", "Label", "Button", "Entry", "Combobox", "Checkbutton", "Notebook", "Treeview", "Scrollbar",
              "LabelFrame"):
        setattr(ttk, n, Widget)
    mb.asked = []
    mb.showinfo = mb.showwarning = mb.showerror = lambda *a, **k: mb.asked.append(a)
    mb.askyesno = lambda *a, **k: True
    fd.asksaveasfilename = lambda **k: fd.path
    fd.path = ""
    tk.ttk, tk.messagebox, tk.filedialog, tk.simpledialog = ttk, mb, fd, sd
    return {"tkinter": tk, "tkinter.ttk": ttk, "tkinter.messagebox": mb, "tkinter.filedialog": fd,
            "tkinter.simpledialog": sd}


def dev(ip, cat, name="", ports=(), **kw):
    d = {"ip": ip, "mac": "AA:BB:CC:00:00:%02X" % int(ip.split(".")[-1]), "category": cat, "online": True,
        "name": name, "ports": list(ports)}
    d.update(kw)
    return d


class SyncThread:
    """Runs the target immediately instead of in a background thread, so tests don't need to wait."""

    def __init__(self, target=None, daemon=None):
        self.target = target

    def start(self):
        if self.target:
            self.target()


class FakeApp:
    def __init__(self):
        self.devices = [dev("192.168.0.50", core.CAT_PC, "PC1", [445]), dev("192.168.0.20", core.CAT_CAM, "Cam1", [37777]),
                        dev("192.168.0.201", core.CAT_PHONE, "Phone1", [62078])]
        self.gw, self.net, self.db = "192.168.0.1", "192.168.0.0/24", {}
        self.q = queue.Queue()
        self.reports = []
        self.clip = ""
        self.login_ok = False
        self.opened = []
        self.telemetry = types.SimpleNamespace(note=lambda *a: None)

    def _settings(self):
        return {}

    def router_client(self, ask=True):
        return None

    def ip_type_of(self, d):
        return "DHCP"

    def _apply_report(self, ip, data, quiet=False):
        self.reports.append((ip, data))

    def clipboard_clear(self):
        self.clip = ""

    def clipboard_append(self, s):
        self.clip += s

    def open_web(self, d):
        self.opened.append(d.get("ip", ""))


class Page(unittest.TestCase):
    def setUp(self):
        self.patch = mock.patch.dict(sys.modules, fake_toolkit())
        self.patch.start()
        for m in ("nd_tabs", "nd_sweep", "nd_sweeptab"):
            sys.modules.pop(m, None)
        self.tabs = importlib.import_module("nd_tabs")
        self.tabs.UI.update(make_tree=lambda *a, **k: Tree(), text_box=lambda *a, **k: Text())
        self.st = importlib.import_module("nd_sweeptab")
        self.S = importlib.import_module("nd_sweep")
        self.app = FakeApp()
        self.page = self.st.SweepPage(self.app, Widget())

    def tearDown(self):
        self.patch.stop()
        for m in ("nd_tabs", "nd_sweep", "nd_sweeptab"):
            sys.modules.pop(m, None)

    def _drain(self):
        for _ in range(200):
            try:
                kind, fn = self.app.q.get(timeout=0.05)
                fn()
            except queue.Empty:
                break

    def test_plan_counts_devices_by_kind_without_any_login(self):
        self.page.do_plan()
        self.assertIn("1", self.page.var_sum.get())
        self.assertEqual(self.app.reports, [])  # nothing was contacted

    def test_start_without_creds_warns_and_does_not_run(self):
        self.page.do_start()
        self.assertTrue(self.app.q.empty())

    def test_full_run_saves_pc_and_camera_results_and_clears_password(self):
        self.page.var_user[0].set("admin")
        self.page.var_pw[0].set("secret")

        class FakeSweep:
            def __init__(self, creds, transports=None, force=False, **kw):
                self.creds, self.force, self.stop = creds, force, threading.Event()

            def run(self, targets, on_result=None):
                out = []
                for t in targets:
                    d = t["dev"]
                    m = t["methods"][0]
                    data = {"model": "M1", "serial": "S1", "cpu": "x", "ram_gb": 4, "disk_gb": 50, "os": "Win",
                            "firmware": "1.0", "identity": "R", "version": "7"}
                    r = {"ip": d["ip"], "mac": d["mac"], "name": d["name"], "category": d["category"], "method": m,
                        "status": self.__class__.OK if hasattr(self.__class__, "OK") else "OK", "data": data,
                        "detail": "", "missing": [], "login": 1}
                    out.append(r)
                    if on_result:
                        on_result(r)
                return out

        with mock.patch.object(self.st, "threading", types.SimpleNamespace(Thread=SyncThread, Event=threading.Event)), \
             mock.patch.object(self.S, "Sweep", FakeSweep):
            self.page.do_start()
        self._drain()
        self.assertEqual(self.page.var_pw[0].get(), "")  # password cleared after the run
        self.assertEqual(len(self.app.reports), 1)  # the PC went through _apply_report
        self.assertIn(self.app.devices[1]["mac"], self.app.db.get("sweep", {}))  # the camera was saved in db
        self.assertEqual(len(self.page.results), 2)
        self.assertFalse(self.page.running)

    def test_copy_refused_with_nothing_refused(self):
        self.page.copy_refused()  # should not raise with no results

    def test_copy_refused_list(self):
        self.page.results = [{"name": "Cam1", "ip": "192.168.0.20", "mac": "AA:BB", "method": "dahua",
                              "status": self.S.AUTH}]
        self.page.copy_refused()
        self.assertIn("192.168.0.20", self.app.clip)

    def test_export_csv_writes_a_file(self):
        self.page.results = [{"ip": "192.168.0.20", "mac": "AA:BB", "name": "Cam1", "category": core.CAT_CAM,
                              "method": "dahua", "status": self.S.OK, "data": {"model": "M"}, "detail": "", "missing": []}]
        path = os.path.join(tempfile.mkdtemp(), "out.csv")
        with mock.patch.object(self.st, "filedialog", types.SimpleNamespace(asksaveasfilename=lambda **k: path)):
            self.page.do_export()
        with open(path, encoding="utf-8-sig") as f:
            self.assertIn("Cam1", f.read())

    def test_phones_check_with_no_router_login_still_reports(self):
        self.page.do_phones()
        self.assertIn("No phone issues", self.page.txt_ph.text)

    def test_open_in_browser_with_nothing_selected_warns(self):
        self.st.messagebox.asked.clear()
        self.page.open_selected_web()
        self.assertEqual(self.app.opened, [])
        self.assertEqual(len(self.st.messagebox.asked), 1)  # showinfo told the person to select a row first

    def test_open_in_browser_opens_the_selected_devices_own_ip(self):
        r = {"ip": "192.168.0.20", "mac": self.app.devices[1]["mac"], "name": "Cam1", "category": core.CAT_CAM,
            "method": "dahua", "status": self.S.UNSUP, "data": {}, "detail": "web page has a login form", "missing": []}
        self.page._insert_row(r)
        iid = next(iter(self.page.rows))
        self.page.tv.selection_set(iid)
        self.page.open_selected_web()
        self.assertEqual(self.app.opened, ["192.168.0.20"])

    def test_open_in_browser_falls_back_to_the_row_ip_for_an_unknown_device(self):
        r = {"ip": "192.168.0.99", "mac": "", "name": "", "category": core.CAT_NET, "method": "web",
            "status": self.S.UNSUP, "data": {}, "detail": "", "missing": []}
        self.page._insert_row(r)
        self.page.tv.selection_set(next(iter(self.page.rows)))
        self.page.open_selected_web()
        self.assertEqual(self.app.opened, ["192.168.0.99"])

    def test_copy_selected_ip(self):
        r = {"ip": "192.168.0.20", "mac": "AA:BB", "name": "Cam1", "category": core.CAT_CAM, "method": "dahua",
            "status": self.S.OK, "data": {}, "detail": "", "missing": []}
        self.page._insert_row(r)
        self.page.tv.selection_set(next(iter(self.page.rows)))
        self.page.copy_selected_ip()
        self.assertEqual(self.app.clip, "192.168.0.20")

    def test_phones_check_flags_phone_sharing_camera_ip(self):
        self.app.devices.append(dev("192.168.0.20", core.CAT_PHONE, "Phone2", [], mac="AA:BB:CC:00:00:99"))
        self.page.do_phones()
        self.assertIn("shares", self.page.txt_ph.text)


if __name__ == "__main__":
    unittest.main()
