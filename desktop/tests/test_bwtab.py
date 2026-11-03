"""3.19: the Bandwidth plan page runs end to end with a fake window toolkit (no screen needed)."""
import importlib
import os
import queue
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_bandwidth as B  # noqa: E402
import nd_core as core  # noqa: E402


class Widget:
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, name):
        return lambda *a, **k: None


class Var:
    def __init__(self, master=None, value=None, **k):
        self.v = value
        self.cbs = []

    def get(self):
        return self.v

    def set(self, v):
        self.v = v
        for cb in self.cbs:
            cb()

    def trace_add(self, mode, cb):
        self.cbs.append(lambda: cb())


class Canvas(Widget):
    def __init__(self, *a, **k):
        self.items = []

    def winfo_width(self):
        return 900

    def winfo_height(self):
        return 600

    def delete(self, *a):
        self.items.clear()

    def create_line(self, *a, **k):
        self.items.append(("line", a, k))

    def create_rectangle(self, *a, **k):
        self.items.append(("rect", a, k))

    def create_text(self, *a, **k):
        self.items.append(("text", a, k))


class Tree:
    def __init__(self):
        self.rows, self.sel = {}, []

    def insert(self, parent, where, values=(), tags=()):
        iid = f"I{len(self.rows)}"
        self.rows[iid] = values
        return iid

    def delete(self, *ids):
        self.rows.clear()

    def get_children(self):
        return list(self.rows)

    def selection(self):
        return list(self.sel)

    def __getattr__(self, name):
        return lambda *a, **k: None


class Text(Widget):
    def __init__(self):
        self.text = ""

    def delete(self, *a):
        self.text = ""

    def insert(self, where, s):
        self.text += s

    def configure(self, **k):
        pass


def fake_toolkit():
    tk = types.ModuleType("tkinter")
    ttk = types.ModuleType("tkinter.ttk")
    mb = types.ModuleType("tkinter.messagebox")
    fd = types.ModuleType("tkinter.filedialog")
    sd = types.ModuleType("tkinter.simpledialog")
    for n in ("Tk", "Toplevel", "Frame", "Label", "Entry", "Text", "Scrollbar", "Button", "Menu", "Listbox", "PhotoImage",
              "Checkbutton"):
        setattr(tk, n, Widget)
    tk.StringVar = tk.BooleanVar = tk.IntVar = Var
    tk.Canvas = Canvas
    for n in ("Frame", "Label", "Button", "Entry", "Combobox", "Checkbutton", "Notebook", "Separator", "Treeview",
              "Scrollbar", "PanedWindow", "Style", "Radiobutton", "Progressbar", "LabelFrame", "Scale", "Spinbox"):
        setattr(ttk, n, Widget)
    mb.asked = []
    mb.showinfo = mb.showwarning = mb.showerror = lambda *a, **k: mb.asked.append(a)
    mb.askyesno = lambda *a, **k: True
    fd.asksaveasfilename = lambda **k: fd.path
    fd.path = ""
    sd.askstring = lambda *a, **k: None
    tk.ttk, tk.messagebox, tk.filedialog, tk.simpledialog = ttk, mb, fd, sd
    return {"tkinter": tk, "tkinter.ttk": ttk, "tkinter.messagebox": mb, "tkinter.filedialog": fd,
            "tkinter.simpledialog": sd}


def dev(ip, cat, name="", **kw):
    d = {"ip": ip, "mac": "AA:BB:CC:00:00:%02X" % int(ip.split(".")[-1]), "category": cat, "online": True, "name": name}
    d.update(kw)
    return d


class FakeApp:
    def __init__(self):
        self.devices = [dev("192.168.0.20", core.CAT_CAM, "Dahua DVR"), dev("192.168.0.105", core.CAT_CAM, "Camera .105"),
                        dev("192.168.0.106", core.CAT_CAM, "Camera .106"), dev("192.168.0.38", core.CAT_PC, "MUKESH-DESIGN"),
                        dev("192.168.0.9", core.CAT_PC, "HR"), dev("192.168.0.101", core.CAT_PHONE, "Phone")]
        self.gw, self.net, self.db, self.mon = "192.168.0.1", "192.168.0.0/24", {}, None
        self.q = queue.Queue()
        self.set = {}
        self.sent = []
        self.login = True
        self.saved = 0

    def after(self, ms, fn=None):
        pass

    def _settings(self):
        return self.set

    def _save_settings(self):
        self.saved += 1

    def router_client(self, ask=True):
        return object() if self.login else None

    def router_apply(self, script, what, done=None):
        self.sent.append((what, script))
        if done:
            done("")
        return True

    def ip_type_of(self, d):
        return "DHCP"

    def clipboard_clear(self):
        pass

    def clipboard_append(self, s):
        pass


class Page(unittest.TestCase):
    def setUp(self):
        self.patch = mock.patch.dict(sys.modules, fake_toolkit())
        self.patch.start()
        for m in ("nd_tabs", "nd_bwtab"):
            sys.modules.pop(m, None)
        self.tabs = importlib.import_module("nd_tabs")
        self.tabs.UI.update(make_tree=lambda *a, **k: Tree(), text_box=lambda *a, **k: Text())
        self.bw = importlib.import_module("nd_bwtab")
        self.app = FakeApp()
        self.page = self.bw.BandwidthPage(self.app, Widget())
        self.page.refresh()

    def tearDown(self):
        self.patch.stop()
        for m in ("nd_tabs", "nd_bwtab"):
            sys.modules.pop(m, None)

    def select(self, ip):
        iid = next(i for i, d in self.page.rows.items() if d["ip"] == ip)
        self.page.tv.sel = [iid]

    def test_groups_listed(self):
        self.assertEqual(len(self.page.rows), 6)
        self.assertEqual(self.page.counts, {"nvr": 1, "cam": 2, "pc": 2, "mobile": 1})

    def test_set_group_and_boost(self):
        self.select("192.168.0.9")
        self.page.set_group("vip")
        self.assertEqual(self.page.counts["vip"], 1)
        self.page.var_boost.set("1 hour")
        self.select("192.168.0.38")
        self.page.boost()
        s = self.page.st()
        self.assertAlmostEqual(s["boosts"][self.app.devices[3]["mac"]]["until"], time.time() + 3600, delta=5)
        self.assertEqual(self.page.counts["vip"], 2)
        self.page.unboost()
        self.assertEqual(self.page.counts["vip"], 1)

    def test_queue_script_uses_the_groups(self):
        self.page.var_wan.set("ether1")
        r = self.page.show_queues()
        self.assertTrue(r)
        a = r[0]
        self.assertIn("ND-NVR target=192.168.0.20/32", a)
        self.assertIn("ND-MOBILE target=192.168.0.101/32", a)
        self.assertIn("ND-PC target=192.168.0.0/24", a)
        self.assertNotIn("192.168.0.105/32", a)  # cameras are not in any queue: they get no internet

    def test_boost_is_resent_only_after_the_plan_was_applied(self):
        self.select("192.168.0.9")
        self.page.boost()
        self.assertEqual(self.app.sent, [])  # nothing applied yet
        self.page.apply_queues()
        self.assertTrue(self.page.st()["applied"])
        n = len(self.app.sent)
        self.select("192.168.0.38")
        self.page.boost()
        self.assertEqual(len(self.app.sent), n + 1)
        self.assertIn("ND-VIP target=192.168.0.9/32,192.168.0.38/32", self.app.sent[-1][1])

    def test_bad_numbers_are_refused(self):
        self.page.vars["nvr"].set("90")
        with mock.patch.object(self.bw.messagebox, "showwarning") as w:
            self.assertIsNone(self.page.show_queues())
            self.assertTrue(w.called)

    def test_ip_list_and_reservations(self):
        self.page.make_ips()
        self.assertEqual(len(self.page.plan_rows), 6)
        self.page.apply_ips()
        what, script = self.app.sent[-1]
        self.assertIn("Reserve IPs for 6 devices", what)
        self.assertIn('mac-address="AA:BB:CC:00:00:14"', script)
        self.assertEqual(len(self.app.db["bindings"]), 6)

    def test_move_phone_and_save_csv(self):
        self.page.var_move["mobile"].set(True)
        self.page.make_ips()
        row = next(r for r in self.page.plan_rows if r["group"] == "mobile")
        self.assertEqual(row["ip_new"], "192.168.0.200")
        path = os.path.join(tempfile.mkdtemp(), "ip.csv")
        self.bw.filedialog.path = path
        self.page.save_ips()
        self.assertIn("192.168.0.200", open(path, encoding="utf-8-sig").read())

    def test_camera_isolation_and_undo(self):
        self.page.apply_cams()
        what, script = self.app.sent[-1]
        self.assertIn("src-address-list=ND-CAM out-interface=ether1", script)
        self.assertIn("add list=ND-CAM address=192.168.0.105", script)
        self.assertNotIn("list=ND-CAM address=192.168.0.20", script)
        self.page.undo_cams()
        self.assertIn('comment~"^ND: camera"', self.app.sent[-1][1])

    def test_no_router_login_shows_message(self):
        self.app.login = False
        self.page.apply_queues()
        self.assertEqual(self.app.sent, [])
        self.assertIn("No router login", self.page.var_msg.get())

    def test_calculator_and_chart(self):
        self.page.calc()
        self.assertIn("reserve 35", self.page.var_calc.get())
        self.page.use_reserve()
        self.assertEqual(self.page.vars["nvr"].get(), "35")
        self.page.refresh_chart()
        kinds = [i[0] for i in self.page.cv.items]
        self.assertGreater(kinds.count("rect"), 5)
        self.assertGreater(kinds.count("line"), 5)
        path = os.path.join(tempfile.mkdtemp(), "c.svg")
        self.bw.filedialog.path = path
        self.page.save_chart()
        self.assertIn("NO INTERNET", open(path, encoding="utf-8").read())

    def test_sweep_ends_boost(self):
        self.select("192.168.0.9")
        self.page.boost()
        mac = self.app.devices[4]["mac"]
        self.page.st()["boosts"][mac]["until"] = time.time() - 5
        self.page.st()["applied"] = False
        self.page._sweep()
        self.assertNotIn(mac, self.page.st()["boosts"])


if __name__ == "__main__":
    unittest.main()
