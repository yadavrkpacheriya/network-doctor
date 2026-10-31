# -*- coding: utf-8 -*-
"""
Network Doctor - window parts for: Network map, IP-MAC binding, Commands, the tag editor and the
PC fix script. The main window sets UI["make_tree"] / UI["text_box"] before creating these.
"""

import os
import re
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog

import nd_core as core
import nd_tools as T

UI = {}
APP = "Network Doctor"

# colours: fill, outline
STYLE = {"cloud": ("#e8f1fb", "#0b6bcb"), "router": ("#dbeafe", "#1d4ed8"), "port": ("#f2f4f7", "#667085"),
         "gear": ("#e0f2fe", "#0369a1"), "dev": ("#ffffff", "#98a2b3"), "off": ("#f2f4f7", "#c0c5cc"),
         "group": ("#fff7e6", "#b54708")}
BAD = {"critical": ("#fdecea", "#d92d20"), "warning": ("#fff4e0", "#dc6803")}


def _sel_values(var):
    return var.get().strip()


# ==========================================================================
# tag editor (one or many devices)
# ==========================================================================
class TagDialog(tk.Toplevel):
    def __init__(self, app, devices):
        super().__init__(app)
        self.app, self.devs = app, [d for d in devices if d.get("mac")]
        many = len(self.devs) > 1
        self.title(f"Tag {len(self.devs)} devices" if many else f"Tag {self.devs[0].get('name') or self.devs[0].get('ip')}")
        self.transient(app)
        self.resizable(False, False)
        tags = T.tags_of(app.db)
        first = tags.get(self.devs[0]["mac"], {}) if not many else {}
        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)
        if many:
            ttk.Label(frm, text="Empty fields are left unchanged on the selected devices.",
                      foreground="#667085").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        else:
            d = self.devs[0]
            ttk.Label(frm, text=f"{d.get('ip', '')}   {d['mac']}   {d.get('vendor', '')}", foreground="#667085"
                      ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        depts = sorted({t.get("dept", "") for t in tags.values() if t.get("dept")})
        gear = [d for d in app.devices if d.get("mac") and T.is_gear(d, tags) and d not in self.devs]
        self.parent_opts = {"": "", "(router directly)": "__router__"}
        for g in gear:
            self.parent_opts[f"{g.get('name') or g.get('ip')} ({g.get('ip', '')})"] = g["mac"]
        ports = set(f"ether{i}" for i in range(1, 11)) | {t.get("router_port") for t in tags.values() if t.get("router_port")}
        if app.mon:
            ports |= set(app.mon.links_copy())
        self.vars = {}
        rows = [("name", "Name", "entry", None), ("dept", "Department", "combo", depts),
                ("location", "Location / room", "entry", None), ("kind", "Type", "combo_ro", T.KINDS),
                ("parent", "Connected to (switch / AP)", "combo_ro", list(self.parent_opts)),
                ("router_port", "Router port (for switches / APs / direct cables)", "combo", sorted(ports, key=T._natural)),
                ("switch_port", "Switch port number", "entry", None), ("notes", "Notes", "entry", None),
                ("watch", "Critical - alert if it stops answering", "combo_ro", ["", "Yes", "No"] if many else ["No", "Yes"])]
        for r, (key, label, typ, values) in enumerate(rows, start=1):
            ttk.Label(frm, text=label).grid(row=r, column=0, sticky="w", pady=3, padx=(0, 10))
            cur = first.get(key, "")
            if key == "watch":
                cur = "" if many else ("Yes" if cur == "1" else "No")
            if key == "parent" and cur:
                cur = next((k for k, v in self.parent_opts.items() if v == cur), "")
            v = tk.StringVar(value=cur)
            self.vars[key] = v
            if typ == "entry":
                w = ttk.Entry(frm, textvariable=v, width=40)
            else:
                w = ttk.Combobox(frm, textvariable=v, values=values or [], width=38,
                                 state="readonly" if typ == "combo_ro" else "normal")
            w.grid(row=r, column=1, sticky="w", pady=3)
        bar = ttk.Frame(frm)
        bar.grid(row=len(rows) + 1, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(bar, text="Save", command=self.save).pack(side="right")
        ttk.Button(bar, text="Cancel", command=self.destroy).pack(side="right", padx=6)
        if not many:
            ttk.Button(bar, text="Clear tag", command=self.clear).pack(side="left")
        self.bind("<Return>", lambda e: self.save())
        self.grab_set()

    def save(self):
        router = next((d for d in self.app.devices if d.get("ip") == self.app.gw and d.get("mac")), None)
        many = len(self.devs) > 1
        for d in self.devs:
            f = {}
            for k, v in self.vars.items():
                val = v.get().strip()
                if k == "parent":
                    val = self.parent_opts.get(val, "")
                    if val == "__router__":
                        val = router["mac"] if router else ""
                f[k] = (val or None) if many else val
                if k == "watch":
                    f[k] = "1" if val == "Yes" else "" if val == "No" else None
            T.set_tag(self.app.db, d["mac"], **f)
        core.save_db(self.app.db)
        self.destroy()
        self.app.after_tags_changed()
        if hasattr(self.app, "watch_now"):
            self.app.watch_now()

    def clear(self):
        T.set_tag(self.app.db, self.devs[0]["mac"], **{k: "" for k in T.TAG_FIELDS})
        core.save_db(self.app.db)
        self.destroy()
        self.app.after_tags_changed()


# ==========================================================================
# network map
# ==========================================================================
class MapTab:
    W, H, DX, DY = 190, 30, 228, 36

    def __init__(self, app, parent):
        self.app = app
        self.collapsed = {"offline"}  # old records stay folded until opened
        self.selected = None
        self.root = None
        self.boxes = {}
        top = ttk.Frame(parent, padding=(0, 6))
        top.pack(fill="x")
        ttk.Label(top, text="Find:").pack(side="left")
        self.var_q = tk.StringVar()
        e = ttk.Entry(top, textvariable=self.var_q, width=26)
        e.pack(side="left", padx=4)
        e.bind("<Return>", lambda ev: self.find())
        ttk.Button(top, text="Find", command=self.find).pack(side="left")
        self.var_bad = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Only problem paths", variable=self.var_bad, command=self.redraw).pack(side="left", padx=10)
        ttk.Button(top, text="Refresh", command=self.redraw).pack(side="left")
        ttk.Button(top, text="Import tags (CSV)", command=self.import_csv).pack(side="right")
        ttk.Button(top, text="Export tags (CSV)", command=self.export_csv).pack(side="right", padx=6)
        ttk.Label(top, text="Red = problem   Orange = warning   Grey = offline   Double-click = fold / unfold",
                  foreground="#667085").pack(side="right", padx=10)
        pw = ttk.PanedWindow(parent, orient="horizontal")
        pw.pack(fill="both", expand=True)
        left, right = ttk.Frame(pw), ttk.Frame(pw, padding=(8, 0))
        pw.add(left, weight=4)
        pw.add(right, weight=1)
        self.cv = tk.Canvas(left, bg="white", highlightthickness=1, highlightbackground="#d0d5dd")
        ys = ttk.Scrollbar(left, orient="vertical", command=self.cv.yview)
        xs = ttk.Scrollbar(left, orient="horizontal", command=self.cv.xview)
        self.cv.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.cv.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        self.cv.bind("<Button-1>", self.click)
        self._cw = 0
        self.cv.bind("<Configure>", self._resized)
        self.cv.bind("<Double-1>", self.dclick)
        self.cv.bind("<MouseWheel>", lambda ev: self.cv.yview_scroll(int(-ev.delta / 120), "units"))
        self.cv.bind("<Button-4>", lambda ev: self.cv.yview_scroll(-3, "units"))
        self.cv.bind("<Button-5>", lambda ev: self.cv.yview_scroll(3, "units"))
        self.var_info = tk.StringVar(value="Click a device on the map.")
        ttk.Label(right, textvariable=self.var_info, justify="left", wraplength=260).pack(anchor="w", fill="x")
        self.btns = ttk.Frame(right)
        self.btns.pack(anchor="w", pady=8, fill="x")
        for txt, fn in (("Tag (name, dept, where connected)...", self.tag), ("Analyse (root cause)", self.analyse),
                        ("Ping", self.ping), ("Open in browser", self.web), ("Commands for this device", self.cmds),
                        ("Show in Devices list", self.show_dev)):
            ttk.Button(self.btns, text=txt, command=fn).pack(fill="x", pady=2)
        ttk.Label(right, text="\nTracing tip: tag each switch / AP with the router port it is plugged into and "
                              "each PC with the switch it is on. Then a port that drops or a device that floods "
                              "the network lights up the whole path, and the department behind it.",
                  wraplength=260, foreground="#667085", justify="left").pack(anchor="w")

    # ---- data
    def problems(self):
        app = self.app
        bad = {}

        def put(k, sev):
            if k and (bad.get(k) != "critical"):
                bad[k] = sev
        for i in app.issues:
            if i["sev"] in ("critical", "warning"):
                for it in i["items"]:
                    for ip in re.findall(r"\d+\.\d+\.\d+\.\d+", it):
                        put(ip, i["sev"])
        for a in list(app.alerts_active.values()):
            for ip in re.findall(r"\d+\.\d+\.\d+\.\d+", a["title"]):
                put(ip, a["sev"])
        ports = {}
        if app.mon:
            for mac, _ in app.mon.top_broadcasters(600)[:3]:
                put(mac, "critical" if any(e["kind"] == "storm" for e in app.mon.events_copy()[-200:]) else "warning")
            now = time.time()
            for iface, lst in app.mon.links_copy().items():
                n = sum(1 for t, s in lst if s == "down" and t > now - 3600)
                if n:
                    ports[iface] = n
            for e in app.mon.events_copy()[-300:]:
                if e["kind"] == "arp_spoof":
                    put((e["data"] or {}).get("mac"), "critical")
        return bad, ports

    def _resized(self, ev):
        if abs(ev.width - self._cw) > 60:  # the matrix uses the window width
            self._cw = ev.width
            self.app.after_idle(self.redraw)

    def redraw(self):
        app = self.app
        bad, ports = self.problems()
        self.root = T.build_map(app.devices, app.db, app.gw, bad, ports)
        cv = self.cv
        cv.delete("all")
        self.boxes = {}
        if not app.devices:
            cv.create_text(20, 20, anchor="nw", text="Run a scan first - the map is built from the devices it finds.",
                           fill="#667085")
            return
        path = set(T.map_path(self.root, self.selected)) if self.selected else set()
        y = [10]

        def visible(n):
            return not self.var_bad.get() or n.get("child_bad") or n.get("bad") or n["kind"] in ("cloud", "router")

        cw = max(self.cv.winfo_width(), 900)
        gap = 10

        def line_col(c):
            return "#d92d20" if (c.get("child_bad") == "critical" or c.get("bad") == "critical") else \
                "#dc6803" if (c.get("child_bad") or c.get("bad")) else "#c0c5cc"

        def is_leaf(c):
            return not [k for k in c["children"] if visible(k)] or c["id"] in self.collapsed

        def place(n, depth):
            kids = [c for c in n["children"] if visible(c)] if n["id"] not in self.collapsed else []
            x = 10 + depth * self.DX
            branches = [c for c in kids if not is_leaf(c)]
            leaves = [c for c in kids if is_leaf(c)]
            if not kids:
                cy = y[0]
                y[0] += self.DY
                self.draw_node(n, x, cy, n["id"] in path)
                return cy
            ys_ = [place(c, depth + 1) for c in branches]
            mid = x + self.W + (self.DX - self.W) / 2
            gx = 10 + (depth + 1) * self.DX
            if len(leaves) > 3:  # many devices on one switch / port: a matrix instead of one long column
                cols = max(1, int((cw - gx) // (self.W + gap)))
                top = y[0]
                rows = []
                for i, c in enumerate(leaves):
                    r, k = divmod(i, cols)
                    if k == 0:
                        rows.append([])
                    rows[-1].append(c)
                    self.draw_node(c, gx + k * (self.W + gap), top + r * self.DY, c["id"] in path)
                y[0] = top + len(rows) * self.DY
                for r, row in enumerate(rows):
                    ry = top + r * self.DY + self.H / 2
                    col = next((line_col(c) for c in row if line_col(c) != "#c0c5cc"), "#c0c5cc")
                    cv.create_line(mid, ry, gx, ry, fill=col, width=2 if col != "#c0c5cc" else 1)
                    for k in range(1, len(row)):  # small bus under each row
                        bx = gx + k * (self.W + gap) - gap / 2
                        cv.create_line(bx - gap / 2, ry, bx + gap / 2, ry, fill="#c0c5cc")
                ys_.append(top)
                ys_.append(top + (len(rows) - 1) * self.DY)
            else:
                ys_ += [place(c, depth + 1) for c in leaves]
            cy = (min(ys_) + max(ys_)) / 2 if not leaves or len(leaves) <= 3 else min(ys_)
            for c in kids:
                if c["id"] not in self.boxes:
                    continue
                cx, ccy = self.boxes[c["id"]][0], self.boxes[c["id"]][1]
                if len(leaves) > 3 and c in leaves:
                    continue
                hot = c["id"] in path and n["id"] in path
                col = line_col(c)
                cv.create_line(x + self.W, cy + self.H / 2, mid, cy + self.H / 2, mid, ccy + self.H / 2, cx, ccy + self.H / 2,
                               fill="#1d4ed8" if hot else col, width=3 if hot else (2 if col != "#c0c5cc" else 1))
            if len(leaves) > 3:
                last = max(ys_)
                cv.create_line(x + self.W, cy + self.H / 2, mid, cy + self.H / 2, mid, last + self.H / 2, fill="#c0c5cc")
            self.draw_node(n, x, cy, n["id"] in path)
            return cy
        # the "Internet" root is not drawn: router, "not placed" and "offline" start at the left edge
        for top in [c for c in self.root["children"] if visible(c)]:
            place(top, 0)
            y[0] += 10
        cv.configure(scrollregion=(0, 0, max(10 + 5 * self.DX, cw), y[0] + 20))

    def draw_node(self, n, x, y, on_path):
        fill, line = STYLE.get(n["kind"], STYLE["dev"])
        sev = n.get("bad")
        if sev in BAD:
            fill, line = BAD[sev]
        width = 3 if (n["id"] == self.selected or on_path) else 1
        if n["id"] == self.selected:
            line = "#1d4ed8"
        cv = self.cv
        r = cv.create_rectangle(x, y, x + self.W, y + self.H, fill=fill, outline=line, width=width,
                                dash=(3, 2) if n.get("random") else None)
        icon = {"cloud": "☁", "router": "◉", "port": "▫", "gear": "≣", "group": "…"}.get(n["kind"], "")
        label = (icon + " " if icon else "") + n["label"]
        if n["children"] and n["kind"] not in ("dev", "off"):
            label += f"  ({n['count']})" + (" +" if n["id"] in self.collapsed else "")
        cv.create_text(x + 6, y + 9, anchor="w", text=label[:34], font=("Segoe UI", 9, "bold"),
                       fill="#98a2b3" if n["kind"] == "off" else "#1c2230")
        if n.get("sub"):
            cv.create_text(x + 6, y + 22, anchor="w", text=n["sub"][:40], font=("Segoe UI", 7), fill="#667085")
        self.boxes[n["id"]] = (x, y, n, r)

    # ---- interaction
    def hit(self, ev):
        x, y = self.cv.canvasx(ev.x), self.cv.canvasy(ev.y)
        for nid, (bx, by, n, _) in self.boxes.items():
            if bx <= x <= bx + self.W and by <= y <= by + self.H:
                return n
        return None

    def click(self, ev):
        n = self.hit(ev)
        if not n:
            return
        self.selected = n["id"]
        d = n.get("dev")
        if d:
            self.app.selected_device = d
            t = d.get("tag") or {}
            lines = [d.get("name") or "(no name)", f"IP {d.get('ip', '')}   MAC {d.get('mac') or '-'}",
                     d.get("vendor", ""), f"Type: {t.get('kind') or d.get('category', '')}",
                     f"Department: {t.get('dept') or '-'}   Location: {t.get('location') or '-'}",
                     f"Router port: {t.get('router_port') or '-'}   Switch port: {t.get('switch_port') or '-'}",
                     f"Status: {d.get('status', '')}"]
            if n.get("bad"):
                lines.append(f"\nPROBLEM: involved in a current {n['bad']} - see Problems / Root cause.")
            path = T.map_path(self.root, n["id"])
            names = [self.boxes[p][2]["label"] for p in path if p in self.boxes]
            lines.append("\nPath: " + " > ".join(names))
            self.var_info.set("\n".join(x for x in lines if x is not None))
        else:
            self.var_info.set(f"{n['label']}\n{n.get('sub', '')}\n{n['count']} device(s) behind it")
        self.redraw()

    def dclick(self, ev):
        n = self.hit(ev)
        if n and n["children"]:
            self.collapsed.symmetric_difference_update({n["id"]})
            self.redraw()

    def find(self):
        q = self.var_q.get().strip().lower()
        if not q or not self.root:
            return
        hits = []

        def walk(n):
            d = n.get("dev") or {}
            t = d.get("tag") or {}
            blob = " ".join([n["label"], n.get("sub", ""), d.get("mac") or "", d.get("vendor", ""), t.get("dept", ""),
                             t.get("location", ""), t.get("notes", "")]).lower()
            if q in blob:
                hits.append(n["id"])
            for c in n["children"]:
                walk(c)
        walk(self.root)
        if not hits:
            messagebox.showinfo(APP, f"Nothing on the map matches '{q}'.")
            return
        self.selected = hits[0]
        for p in T.map_path(self.root, hits[0]):
            self.collapsed.discard(p)
        self.redraw()
        bx, by = self.boxes[hits[0]][0], self.boxes[hits[0]][1]
        sr = [float(v) for v in str(self.cv.cget("scrollregion")).split()] or [0, 0, 1, 1]
        if sr[3] > 0:
            self.cv.yview_moveto(max(0, (by - 100) / sr[3]))
            self.cv.xview_moveto(max(0, (bx - 100) / max(sr[2], 1)))

    def _dev(self):
        d = self.app.selected_device
        if not d:
            messagebox.showinfo(APP, "Click a device on the map first.")
        return d

    def tag(self):
        d = self._dev()
        if d and d.get("mac"):
            TagDialog(self.app, [d])

    def analyse(self):
        d = self._dev()
        if d:
            self.app.open_device(d)

    def ping(self):
        d = self._dev()
        if d:
            self.app.ping_device(d)

    def web(self):
        d = self._dev()
        if d:
            self.app.open_web(d)

    def cmds(self):
        if self._dev():
            self.app.show_tab("commands")

    def show_dev(self):
        d = self._dev()
        if d:
            self.app.show_tab("devices")
            self.app.var_q.set(d.get("mac") or d.get("ip"))

    def export_csv(self):
        p = filedialog.asksaveasfilename(initialdir=core.REPORT_DIR, initialfile="network-doctor-tags.csv",
                                         defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if p:
            with open(p, "w", encoding="utf-8-sig", newline="") as f:
                f.write(T.tags_to_csv(self.app.devices, self.app.db))
            self.app.var_status.set(f"Tags saved to {p} - edit in Excel and import again.")

    def import_csv(self):
        p = filedialog.askopenfilename(initialdir=core.REPORT_DIR, filetypes=[("CSV", "*.csv")])
        if not p:
            return
        try:
            with open(p, encoding="utf-8-sig", errors="replace") as f:
                n, skipped = T.tags_from_csv(f.read(), self.app.db)
        except Exception as e:
            messagebox.showerror(APP, f"Could not import: {e}")
            return
        core.save_db(self.app.db)
        self.app.after_tags_changed()
        messagebox.showinfo(APP, f"{n} device tag(s) imported" + (f", {skipped} row(s) without a valid MAC skipped." if skipped else "."))


# ==========================================================================
# IP-MAC binding
# ==========================================================================
class BindingTab:
    def __init__(self, app, parent):
        self.app = app
        self.checked = set()
        self.rows = {}
        info = ("Bind = the router always gives each device the same IP (DHCP reservation). Devices stay on "
                "'automatic' - no static IPs on PCs, which is what causes conflicts. Tick devices; double-click an IP "
                "to choose the IP you want for that device; then press 'Bind on the router now' - Network Doctor sends it to "
                "the router itself (router login in Setup). No WinBox or copy / paste needed.")
        ttk.Label(parent, text=info, wraplength=1100, foreground="#344054", padding=(0, 6)).pack(anchor="w")
        top = ttk.Frame(parent)
        top.pack(fill="x")
        ttk.Button(top, text="Tick all that can be bound", command=self.tick_all).pack(side="left")
        ttk.Button(top, text="Untick all", command=self.untick_all).pack(side="left", padx=6)
        self.var_strict = tk.BooleanVar(value=False)
        self.var_block = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Strict mode: devices with a hand-typed IP cannot use the network",
                        variable=self.var_strict).pack(side="left", padx=10)
        ttk.Checkbutton(top, text="Block randomized MACs", variable=self.var_block).pack(side="left")
        self.var_rebind = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Moved devices: bind their NEW IP", variable=self.var_rebind).pack(side="left",
                                                                                                  padx=(10, 0))
        ttk.Label(top, text="Bridge name:").pack(side="left", padx=(10, 2))
        self.var_bridge = tk.StringVar(value="bridge")
        ttk.Entry(top, textvariable=self.var_bridge, width=10).pack(side="left")
        ttk.Button(top, text="Bind on the router now", style="Big.TButton", command=self.bind_now).pack(side="right")
        ttk.Button(top, text="Only show commands", command=self.make).pack(side="right", padx=6)
        ttk.Button(top, text="PC fix script...", command=lambda: FixScriptDialog(app)).pack(side="right", padx=6)
        pw = ttk.PanedWindow(parent, orient="vertical")
        pw.pack(fill="both", expand=True, pady=(6, 0))
        a, b = ttk.Frame(pw), ttk.Frame(pw)
        pw.add(a, weight=3)
        pw.add(b, weight=2)
        self.tv = UI["make_tree"](a, ("bind", "name", "dept", "ip", "mac", "type", "note"),
                                  ("Bind", "Name", "Department", "IP", "MAC", "IP type now", "Note"),
                                  (50, 200, 130, 115, 140, 110, 420), first=None)
        self.tv.bind("<Button-1>", self.toggle)
        self.tv.bind("<Double-1>", self.edit_ip)
        self.want = {}  # mac -> IP chosen by the user for the reservation
        bar = ttk.Frame(b, padding=(0, 4))
        bar.pack(fill="x")
        ttk.Button(bar, text="Copy commands", command=lambda: self.copy(self.apply)).pack(side="left")
        ttk.Button(bar, text="Copy UNDO commands", command=lambda: self.copy(self.undo)).pack(side="left", padx=6)
        ttk.Button(bar, text="Apply on router", style="Big.TButton", command=self.apply_router).pack(side="left",
                                                                                                    padx=6)
        ttk.Button(bar, text="Save as .rsc file", command=self.save).pack(side="left")
        ttk.Button(bar, text="Set IP of selected...", command=self.edit_ip).pack(side="left", padx=6)
        ttk.Button(bar, text="Forget binding of selected", command=self.forget).pack(side="left")
        self.var_sum = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.var_sum, foreground="#667085").pack(side="left", padx=10)
        self.txt = UI["text_box"](b)
        self.txt.configure(font=("Consolas", 9))
        self.apply = self.undo = ""

    def refresh(self):
        app = self.app
        tags = T.tags_of(app.db)
        with core.DB_LOCK:
            binds = dict(app.db.get("bindings") or {})
        self.cands = T.binding_candidates(app.devices, app.issues, app.gw)
        tv = self.tv
        tv.delete(*tv.get_children())
        self.rows = {}
        for c in self.cands:
            d = c["dev"]
            t = tags.get(d["mac"], {})
            if d.get("self"):
                self.checked.add(d["mac"])
            typ = app.ip_type_of(d)
            note = c["why"] or ("this PC - always bound (keeps your WinBox access in strict mode)" if d.get("self")
                                else "manual IP: bind it, then switch the device to automatic" if "tatic" in typ else "")
            b = binds.get(d["mac"])
            if b and b.get("ip") and b["ip"] != d["ip"]:
                user = self._ip_user(b["ip"], d["mac"])
                note = (f"BOUND to {b['ip']} but now on {d['ip']}. " +
                        (f"{b['ip']} is now used by {user} - tick 'Moved devices: bind their NEW IP'." if user else
                         "Commands keep " + b["ip"] + " (paste them, then renew the device's IP), or tick 'Moved "
                         "devices: bind their NEW IP'.")) + (" " + note if note else "")
            elif b:
                note = f"bound to {b['ip']} ({b.get('time', '')})" + (" - " + note if note else "")
            w = self.want.get(d["mac"])
            if w:
                note = f"will be bound to {w} (chosen) - renew the device's IP after applying" + (
                    " - " + c["why"] if c["why"] else "")
            iid = tv.insert("", "end", values=("☑" if d["mac"] in self.checked and c["ok"] else ("☐" if c["ok"] else "—"),
                                               t.get("name") or d.get("name") or "-", t.get("dept", ""),
                                               f"{w}  (now {d['ip']})" if w else d["ip"], d["mac"],
                                               typ, note), tags=() if c["ok"] else ("warning",))
            self.rows[iid] = c
        self.var_sum.set(f"{len(self.checked & {c['dev']['mac'] for c in self.cands if c['ok']})} of "
                         f"{sum(1 for c in self.cands if c['ok'])} bindable devices ticked")

    def _ip_user(self, ip, mac):
        """Name / MAC of another online device using ip, or ''."""
        for d in self.app.devices:
            if d.get("online") and d.get("mac") != mac and ip in (d.get("ips") or {d.get("ip")}):
                return d.get("name") or d.get("mac") or ip
        return ""

    def check_ip(self, ip, mac):
        """'' when ip may be reserved for mac, otherwise the reason."""
        import ipaddress
        try:
            a = ipaddress.IPv4Address(ip)
        except ValueError:
            return "that is not an IP address"
        try:
            net = ipaddress.ip_network(self.app.net, strict=False)
        except ValueError:
            net = None
        if net and a not in net:
            return f"it is outside this network ({net})"
        if net and a in (net.network_address, net.broadcast_address):
            return "it is the network / broadcast address"
        if ip == self.app.gw:
            return "it is the router's own IP"
        user = self._ip_user(ip, mac)
        if user:
            return f"{user} is using it now"
        with core.DB_LOCK:
            other = next((m for m, b in (self.app.db.get("bindings") or {}).items() if b.get("ip") == ip and m != mac),
                         None)
        other = other or next((m for m, w in self.want.items() if w == ip and m != mac), None)
        if other:
            return f"it is already reserved for {other}"
        return ""

    def edit_ip(self, ev=None):
        if ev is not None:
            iid = self.tv.identify_row(ev.y)
            if iid:
                self.tv.selection_set(iid)
        sel = [i for i in self.tv.selection() if i in self.rows]
        if not sel:
            messagebox.showinfo(APP, "Select (highlight) a device first, or double-click its row.")
            return "break"
        c = self.rows[sel[0]]
        d = c["dev"]
        if not c["ok"]:
            messagebox.showinfo(APP, f"This device cannot be bound yet: {c['why']}.")
            return "break"
        cur = self.want.get(d["mac"]) or ((self.app.db.get("bindings") or {}).get(d["mac"]) or {}).get("ip") or d["ip"]
        while True:
            ip = simpledialog.askstring(APP, f"IP to reserve for {d.get('name') or d['mac']} ({d['mac']}).\n"
                                             f"Now on {d['ip']}. Empty = use its current IP.",
                                        initialvalue=cur, parent=self.app)
            if ip is None:
                return "break"
            ip = ip.strip()
            if not ip or ip == d["ip"]:
                self.want.pop(d["mac"], None)
                break
            why = self.check_ip(ip, d["mac"])
            if not why:
                self.want[d["mac"]] = ip
                break
            messagebox.showwarning(APP, f"{ip} cannot be used: {why}.")
            cur = ip
        self.checked.add(d["mac"])
        self.refresh()
        return "break"

    def bind_now(self):
        """Ticked devices -> reservations on the router directly (no WinBox, no copy / paste)."""
        if not self.app.router_client(ask=False):
            self.make()
            if self.apply and messagebox.askyesno(
                    APP, "No router login is saved yet, so Network Doctor cannot send this to the router itself.\n\n"
                         "Open Setup to save the router login now? (The commands are shown below meanwhile.)"):
                self.app.show_tab("setup")
            return
        self.apply = ""
        self.apply_router()

    def apply_router(self):
        if not self.apply:
            self.make()
        if self.apply:
            self.app.router_apply(self.apply, f"IP-MAC binding ({self.apply.count('mac-address=')} devices)",
                                  done=lambda err: None if err else self.app.var_status.set(
                                      "Binding applied. Renew the IP on moved devices (unplug / re-plug, or "
                                      "'ipconfig /renew'), then scan again."))

    def forget(self):
        sel = [self.rows[i]["dev"]["mac"] for i in self.tv.selection() if i in self.rows]
        with core.DB_LOCK:
            b = self.app.db.get("bindings") or {}
            gone = [m for m in sel if m in b]
            for m in gone:
                del b[m]
        if not gone:
            messagebox.showinfo(APP, "Select (highlight) one or more bound devices in the list first.")
            return
        core.save_db(self.app.db)
        self.refresh()
        self.app.var_status.set(f"Forgot {len(gone)} binding(s). Network Doctor no longer warns about them. To also "
                                "remove the reservation on the router, use 'Copy UNDO commands' or delete the lease "
                                "in WinBox > IP > DHCP Server > Leases.")

    def toggle(self, ev):
        iid = self.tv.identify_row(ev.y)
        c = self.rows.get(iid)
        if not c or not c["ok"] or self.tv.identify_column(ev.x) not in ("#1",):
            return
        mac = c["dev"]["mac"]
        if c["dev"].get("self"):
            return
        self.checked.symmetric_difference_update({mac})
        self.refresh()

    def tick_all(self):
        self.checked |= {c["dev"]["mac"] for c in self.cands if c["ok"]}
        self.refresh()

    def untick_all(self):
        self.checked = {c["dev"]["mac"] for c in self.cands if c["dev"].get("self")}
        self.refresh()

    def make(self):
        rows = [c["dev"] for c in self.cands if c["ok"] and c["dev"]["mac"] in self.checked]
        # A bound device that shows up on another IP keeps its reserved IP (that is what the warning asks for),
        # unless the user chose to move the binding, or the reserved IP is now taken by another device.
        with core.DB_LOCK:
            binds = dict(self.app.db.get("bindings") or {})
        kept = []
        rows = [dict(d, ip=self.want[d["mac"]]) if self.want.get(d["mac"]) else d for d in rows]
        if not self.var_rebind.get():
            out = []
            for d in rows:
                b = binds.get(d["mac"])
                if (not self.want.get(d["mac"]) and b and b.get("ip") and b["ip"] != d["ip"]
                        and not self._ip_user(b["ip"], d["mac"])):
                    d = dict(d, ip=b["ip"])
                    kept.append(d)
                out.append(d)
            rows = out
        if not rows:
            messagebox.showinfo(APP, "Tick at least one device.")
            return
        if self.var_strict.get() and not messagebox.askyesno(
                APP, "Strict mode: after pasting, ONLY the ticked devices and devices that get their IP from the "
                     "router can talk to the router. A printer / camera with a hand-typed IP that is NOT ticked "
                     "loses network.\n\nTick every device that must keep working (the list ticks this PC for you). "
                     "Keep the undo commands ready.\n\nContinue?"):
            return
        if self.var_block.get() and not messagebox.askyesno(
                APP, "Block randomized MACs: phones and laptops using a private / random Wi-Fi address will get no "
                     "network until they switch to their device MAC for this Wi-Fi.\n\nContinue?"):
            return
        self.apply, self.undo = T.binding_commands(rows, T.tags_of(self.app.db), self.var_strict.get(),
                                                   self.var_block.get(), self.var_bridge.get().strip() or "bridge")
        with core.DB_LOCK:
            b = self.app.db.setdefault("bindings", {})
            for d in rows:
                b[d["mac"]] = {"ip": d["ip"], "time": core.now_s()}
        core.save_db(self.app.db)
        t = self.txt
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", self.apply)
        t.insert("end", "\n# ------------------------------- UNDO (keep these) -------------------------------\n")
        t.insert("end", self.undo)
        t.configure(state="disabled")
        self.var_sum.set(f"Commands for {len(rows)} devices ready - Copy and paste them in WinBox > New Terminal. "
                         "Network Doctor will warn if a bound device later shows up on another IP." +
                         (f" {len(kept)} moved device(s) keep their reserved IP - renew their IP after pasting."
                          if kept else ""))

    def copy(self, text):
        if not text:
            messagebox.showinfo(APP, "Press 'Make router commands' first.")
            return
        self.app.clipboard_clear()
        self.app.clipboard_append(text)
        self.app.var_status.set("Copied - paste in WinBox > New Terminal.")

    def save(self):
        if not self.apply:
            messagebox.showinfo(APP, "Press 'Make router commands' first.")
            return
        os.makedirs(core.REPORT_DIR, exist_ok=True)
        p = filedialog.asksaveasfilename(initialdir=core.REPORT_DIR, initialfile=time.strftime("ndbind-%Y%m%d.rsc"),
                                         defaultextension=".rsc", filetypes=[("RouterOS script", "*.rsc")])
        if p:
            name = T.write_rsc(p, self.apply, self.undo)
            messagebox.showinfo(APP, T.RSC_HOWTO.format(file=name, undo=name[:-4] + "-undo.rsc"))
            self.app.var_status.set(f"Saved {p} and its undo file.")


# ==========================================================================
# PC fix script
# ==========================================================================
class FixScriptDialog(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("PC fix script - run on every office PC")
        self.transient(app)
        f = ttk.Frame(self, padding=14)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="Creates NetworkDoctor-PC-Fix.cmd. Run it once on each Windows PC (double-click, from a "
                          "shared folder, or a domain login script). It asks for administrator rights itself.",
                  wraplength=560, justify="left").pack(anchor="w", pady=(0, 8))
        self.v = {k: tk.BooleanVar(value=val) for k, val in
                  (("random_off", True), ("renew", True), ("lock_gw", False), ("report", True), ("daily", True))}
        ttk.Checkbutton(f, text="Turn off random (private) MAC addresses for Wi-Fi - the PC keeps one MAC",
                        variable=self.v["random_off"]).pack(anchor="w")
        row = ttk.Frame(f)
        row.pack(anchor="w", pady=2)
        ttk.Label(row, text="Manually typed IP found on the PC:").pack(side="left")
        self.var_dhcp = tk.StringVar(value="ask")
        for val, txt in (("ask", "ask the person"), ("yes", "switch to automatic"), ("no", "leave it")):
            ttk.Radiobutton(row, text=txt, value=val, variable=self.var_dhcp).pack(side="left", padx=6)
        ttk.Checkbutton(f, text="Renew the IP and clear old ARP / DNS caches (a few seconds offline)",
                        variable=self.v["renew"]).pack(anchor="w")
        gwd = next((d for d in app.devices if d.get("ip") == app.gw and d.get("mac")), None)
        self.gw_mac = gwd["mac"] if gwd else ""
        ttk.Checkbutton(f, text=f"Lock the router's MAC {self.gw_mac or '(scan first)'} - stops NetCut / ARP spoofing "
                                "(use the Undo script if the router is ever replaced)",
                        variable=self.v["lock_gw"]).pack(anchor="w")
        ttk.Checkbutton(f, text=f"Report the PC's name, user, MAC and hardware (model, serial, CPU, RAM, SSD, printers, mouse, keyboard, antivirus, drivers) "
                                f"to this Network Doctor ({app.lip}) - fills the Inventory and tags it on the map", variable=self.v["report"]).pack(anchor="w")
        ttk.Checkbutton(f, text="Keep the details up to date: the PC reports again every day by itself (a small Windows "
                                "task; the Undo script removes it)", variable=self.v["daily"]).pack(anchor="w", padx=(20, 0))
        ttk.Label(f, text="\nFor an unattended login script choose 'switch to automatic' or 'leave it' (nobody is "
                          "there to answer). Run from \\\\server\\share or a local copy - not a mapped drive letter, "
                          "which disappears when Windows asks for admin rights.", wraplength=560, foreground="#667085",
                  justify="left").pack(anchor="w")
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=(10, 0))
        ttk.Button(bar, text="Create scripts", style="Big.TButton", command=self.create).pack(side="right")
        ttk.Button(bar, text="Cancel", command=self.destroy).pack(side="right", padx=6)
        ttk.Button(bar, text="Inventory only (changes nothing)", command=self.inventory_only).pack(side="left")

    def inventory_only(self):
        """Only read the PC details (RAM, SSD, printers, antivirus...) and report them; no network changes."""
        for k in ("random_off", "renew", "lock_gw"):
            self.v[k].set(False)
        self.v["report"].set(True)
        self.v["daily"].set(True)
        self.var_dhcp.set("no")
        self.create()

    def create(self):
        app = self.app
        opts = {k: v.get() for k, v in self.v.items()}
        opts["to_dhcp"] = self.var_dhcp.get()
        if opts["lock_gw"] and not self.gw_mac:
            messagebox.showerror(APP, "Run a scan first so the router's MAC is known.")
            return
        key = app.enable_reports() if opts["report"] else ""
        url = f"http://{app.lip}:8787/api/report" if opts["report"] else ""
        fix, undo = T.pc_fix_script(opts, app.gw, self.gw_mac, url, key)
        folder = os.path.join(core.REPORT_DIR, "PC fix")
        os.makedirs(folder, exist_ok=True)
        for name, text in (("NetworkDoctor-PC-Fix.cmd", fix), ("NetworkDoctor-PC-Undo.cmd", undo)):
            with open(os.path.join(folder, name), "w", encoding="ascii", errors="replace", newline="") as fh:
                fh.write(text)
        self.destroy()
        messagebox.showinfo(APP, f"Created in:\n{folder}\n\n- NetworkDoctor-PC-Fix.cmd: run on each PC\n"
                                 "- NetworkDoctor-PC-Undo.cmd: reverses it\n\n"
                                 + ("Each PC reports back here and gets tagged with its name. Keep Network Doctor "
                                    "open while the scripts run." if opts["report"] else ""))
        app.open_folder(folder)


# ==========================================================================
# command library
# ==========================================================================
class CommandsTab:
    def __init__(self, app, parent):
        self.app = app
        top = ttk.Frame(parent, padding=(0, 6))
        top.pack(fill="x")
        ttk.Label(top, text="Device:").pack(side="left")
        self.var_dev = tk.StringVar()
        self.cb = ttk.Combobox(top, textvariable=self.var_dev, width=46)
        self.cb.pack(side="left", padx=4)
        self.devmap = {}
        Suggest(self.cb, lambda: list(self.devmap), on_pick=lambda v: self.pick_dev())
        self.cb.bind("<<ComboboxSelected>>", lambda e: self.pick_dev())
        ttk.Label(top, text="Brand / type:").pack(side="left", padx=(10, 0))
        self.var_grp = tk.StringVar(value="All")
        self.cb_grp = ttk.Combobox(top, textvariable=self.var_grp, width=34, state="readonly")
        self.cb_grp.pack(side="left", padx=4)
        self.cb_grp.bind("<<ComboboxSelected>>", lambda e: self.refresh())
        ttk.Label(top, text="Find:").pack(side="left", padx=(6, 0))
        self.var_cq = tk.StringVar()
        ent = ttk.Entry(top, textvariable=self.var_cq, width=16)
        ent.pack(side="left", padx=4)
        ent.bind("<KeyRelease>", lambda e: self.refresh())
        ttk.Button(top, text="Delete my command", command=self.delete).pack(side="right")
        ttk.Button(top, text="Add my own command...", command=self.add).pack(side="right", padx=6)
        ttk.Button(top, text="PC fix script...", command=lambda: FixScriptDialog(app)).pack(side="right")
        pw = ttk.PanedWindow(parent, orient="vertical")
        pw.pack(fill="both", expand=True)
        a, b = ttk.Frame(pw), ttk.Frame(pw)
        pw.add(a, weight=3)
        pw.add(b, weight=1)
        self.tv = UI["make_tree"](a, ("where", "cmd"), ("Run on", "Command"), (130, 650), first=("What it does", 380))
        self.tv.bind("<<TreeviewSelect>>", self.show)
        self.tv.bind("<Double-1>", lambda e: self.run())
        bar = ttk.Frame(b, padding=(0, 6))
        bar.pack(fill="x")
        ttk.Button(bar, text="Copy", style="Big.TButton", command=self.copy).pack(side="left")
        self.btn_run = ttk.Button(bar, text="Run on this PC", command=self.run)
        self.btn_run.pack(side="left", padx=6)
        self.btn_router = ttk.Button(bar, text="Run on router", command=self.run_router)
        self.btn_router.pack(side="left")
        self.var_cmd = tk.StringVar(value="")
        ttk.Entry(bar, textvariable=self.var_cmd, font=("Consolas", 10)).pack(side="left", fill="x", expand=True, padx=6)
        self.var_use = tk.StringVar(value="Select a command.")
        ttk.Label(b, textvariable=self.var_use, wraplength=1100, justify="left").pack(anchor="w")
        self.items = {}

    def all_commands(self):
        mine = [tuple(c) for c in self.app._settings().get("custom_cmds", [])]
        return [("My commands",) + c[1:] if c[0] != "My commands" else c for c in mine] + list(T.COMMANDS)

    def refresh(self):
        devs = [d for d in self.app.devices if d.get("online")]
        self.devmap = {f"{d.get('name') or '-'}  {d.get('ip', '')}  {d.get('mac') or ''}": d for d in devs}
        self.cb.configure(values=list(self.devmap))
        sd = self.app.selected_device
        if sd:
            key = next((k for k, d in self.devmap.items() if d is sd or (d.get("mac") and d.get("mac") == sd.get("mac"))), "")
            self.var_dev.set(key)
        tv = self.tv
        tv.delete(*tv.get_children())
        self.items = {}
        groups = {}
        allc = self.all_commands()
        names = list(dict.fromkeys(c[0] for c in allc))
        self.cb_grp.configure(values=["All"] + names)
        want, q = self.var_grp.get(), self.var_cq.get().strip().lower()
        for c in allc:
            cat = c[0]
            if want not in ("All", "") and cat != want:
                continue
            if q and q not in " ".join(c).lower():
                continue
            if cat not in groups:
                groups[cat] = tv.insert("", "end", text=cat, open=True, tags=("cat",))
            iid = tv.insert(groups[cat], "end", text=c[2], values=(c[1], c[3].replace("\n", "  ;  ")))
            self.items[iid] = c
        self.show()

    def select_group(self, name):
        self.var_grp.set(name)
        self.refresh()

    def pick_dev(self):
        self.app.selected_device = self.devmap.get(self.var_dev.get())
        self.show()

    def values(self):
        app = self.app
        gwd = next((d for d in app.devices if d.get("ip") == app.gw and d.get("mac")), None)
        return T.command_values(app.selected_device, app.gw, gwd["mac"] if gwd else "", app.lip)

    def current(self):
        sel = self.tv.selection()
        return self.items.get(sel[0]) if sel else None

    def show(self, _=None):
        c = self.current()
        if not c:
            return
        text, missing = T.fill(c[3], self.values())
        self.var_cmd.set(text)
        where = {"This PC": "Runs on this PC (Run button) - or copy it to another PC.",
                 "Router": "Run on router (router login in Setup) - or paste it in WinBox > New Terminal.",
                 "Each PC": "Run on the PC concerned."}.get(
            c[1], "Paste it in that device's console (SSH / Telnet / serial) or follow it on its web page. "
                  "Check the model's manual: commands differ a little between firmware versions.")
        self.var_use.set(f"{c[2]}\n{c[4]}\n{where}" + (f"\nStill to fill: {', '.join(missing)} (asked when you run it)"
                                                       if missing else "")
                         + (f"\n\nPaste these lines one after the other:\n{text}" if "\n" in text else ""))
        can = c[1] == "This PC" and ((c[0] == "Mac") == core.IS_MAC or c[0] == "My commands")
        self.btn_run.configure(state="normal" if can else "disabled")
        self.btn_router.configure(state="normal" if c[1] == "Router" else "disabled")

    def _final(self):
        text = self.var_cmd.get().strip()
        for k in sorted(set(re.findall(r"\{(\w+)\}", text))):
            hint = {"adapter": " (adapter name from 'ipconfig', e.g. Ethernet or Wi-Fi)",
                    "tcpport": " (TCP port, e.g. 80, 443, 445, 3389, 1433)", "host": " (a name, e.g. google.com)",
                    "limit": " (speed, e.g. 5M or 512k)", "port": " (router port, e.g. ether2)"}.get(k, "")
            v = simpledialog.askstring(APP, f"Value for {{{k}}}" + hint, parent=self.app)
            if not v:
                return None
            text = text.replace("{" + k + "}", v)
        return text

    def copy(self):
        text = self._final()
        if text:
            self.app.clipboard_clear()
            self.app.clipboard_append(text)
            self.app.var_status.set("Command copied.")

    def run(self):
        c = self.current()
        if not c or str(self.btn_run["state"]) == "disabled":
            return
        text = self._final()
        if not text:
            return
        try:
            if core.IS_WIN:
                # one plain string: cmd would mangle quotes like name="Ethernet" if Python quoted the pieces
                subprocess.Popen(f"cmd /k {text}", creationflags=0x00000010)  # new console window
            elif core.IS_MAC:
                esc = text.replace("\\", "\\\\").replace('"', '\\"')
                subprocess.Popen(["osascript", "-e", f'tell application "Terminal" to do script "{esc}"',
                                  "-e", 'tell application "Terminal" to activate'])
            else:
                subprocess.Popen(["x-terminal-emulator", "-e", "sh", "-c", text + "; exec sh"])
        except Exception as e:
            messagebox.showerror(APP, str(e))

    def run_router(self):
        c = self.current()
        if not c or c[1] != "Router":
            return
        text = self._final()
        if not text:
            return
        if re.search(r"\b(add|set|remove|disable|enable|reboot|reset)\b", text) and not messagebox.askyesno(
                APP, f"This changes the router:\n\n{text}\n\nRun it now?"):
            return
        self.app.router_cli(text, c[2])

    def add(self):
        name = simpledialog.askstring(APP, "What does the command do? (short name)", parent=self.app)
        if not name:
            return
        cmd = simpledialog.askstring(APP, "Command (you can use {ip} {mac} {name} {gw} {port}):", parent=self.app)
        if not cmd:
            return
        where = "Router" if messagebox.askyesno(APP, "Is it a router (WinBox terminal) command?\n\nNo = runs on this PC") \
            else "This PC"
        use = simpledialog.askstring(APP, "When to use it (optional):", parent=self.app) or ""
        st = self.app._settings()
        st.setdefault("custom_cmds", []).append(["My commands", where, name, cmd, use])
        self.app._save_settings()
        self.refresh()

    def delete(self):
        c = self.current()
        if not c or c[0] != "My commands":
            messagebox.showinfo(APP, "Select one of your own commands (under 'My commands').")
            return
        st = self.app._settings()
        st["custom_cmds"] = [x for x in st.get("custom_cmds", []) if tuple(x)[1:] != tuple(c)[1:]]
        self.app._save_settings()
        self.refresh()


# ==========================================================================
# usage: apps, websites, devices, productivity, advice
# ==========================================================================
class Suggest:
    """Type-to-search for a combobox: a list of matches drops down under it while typing (name, IP, MAC)."""

    def __init__(self, cb, values, on_pick=None):
        self.cb, self.values, self.on_pick = cb, values, on_pick
        self.pop = None
        cb.bind("<KeyRelease>", self.key, add="+")
        cb.bind("<FocusOut>", lambda e: cb.after(200, self.close), add="+")

    def key(self, ev):
        if ev.keysym in ("Return", "KP_Enter"):
            if self.pop and self.lb.size():
                self.pick(0)
            return
        if ev.keysym in ("Escape",):
            self.close()
            return
        if ev.keysym in ("Up", "Down", "Tab", "Shift_L", "Shift_R", "Control_L", "Control_R"):
            if ev.keysym == "Down" and self.pop:
                self.lb.focus_set()
                self.lb.selection_set(0)
            return
        q = self.cb.get().strip().lower()
        words = q.split()
        hits = [v for v in self.values() if words and all(w in v.lower() for w in words)][:15]
        if not hits:
            self.close()
            return
        if not self.pop:
            self.pop = tk.Toplevel(self.cb)
            self.pop.overrideredirect(True)
            try:
                self.pop.attributes("-topmost", True)
            except Exception:
                pass
            self.lb = tk.Listbox(self.pop, font=("Segoe UI", 10), activestyle="none", relief="solid", borderwidth=1)
            self.lb.pack(fill="both", expand=True)
            self.lb.bind("<ButtonRelease-1>", lambda e: self.pick(self.lb.nearest(e.y)))
            self.lb.bind("<Return>", lambda e: self.pick((self.lb.curselection() or (0,))[0]))
            self.lb.bind("<Escape>", lambda e: self.close())
        self.lb.delete(0, "end")
        for h in hits:
            self.lb.insert("end", h)
        self.lb.configure(height=min(len(hits), 10))
        x, y = self.cb.winfo_rootx(), self.cb.winfo_rooty() + self.cb.winfo_height()
        self.pop.geometry(f"{max(self.cb.winfo_width(), 320)}x{min(len(hits), 10) * 20 + 4}+{x}+{y}")

    def pick(self, i):
        try:
            v = self.lb.get(i)
        except Exception:
            return
        self.cb.set(v)
        self.close()
        self.cb.icursor("end")
        if self.on_pick:
            self.on_pick(v)

    def close(self):
        if self.pop:
            try:
                self.pop.destroy()
            except Exception:
                pass
            self.pop = None


_UNITS = {"b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12, "bps": 1, "kbps": 1e3, "mbps": 1e6, "gbps": 1e9}


def _sort_key(v):
    """'1.4 GB' / '5 h 20' / '75%' / '12 min' / names -> something that sorts the way a person expects."""
    t = str(v).strip().lower()
    m = re.fullmatch(r"(\d+) h (\d+)", t)
    if m:
        return (0, int(m.group(1)) * 60 + int(m.group(2)))
    m = re.fullmatch(r"(\d+) min", t)
    if m:
        return (0, int(m.group(1)))
    m = re.fullmatch(r"([\d.,]+)\s*([kmgt]?b(?:ps)?)?%?", t)
    if m:
        try:
            return (0, float(m.group(1).replace(",", "")) * _UNITS.get(m.group(2) or "b", 1))
        except ValueError:
            pass
    return (1, t)


def sortable(tv):
    """Click a column title to sort by it (numbers / sizes biggest first, names A-Z); click again to reverse."""
    state = {}

    def by(col):
        rev = state.get(col, None)
        rev = (col != "#0") if rev is None else not rev
        state.clear()
        state[col] = rev
        items = list(tv.get_children(""))
        items.sort(key=lambda i: _sort_key(tv.item(i, "text") if col == "#0" else tv.set(i, col)), reverse=rev)
        for pos, i in enumerate(items):
            tv.move(i, "", pos)
    tv.heading("#0", command=lambda: by("#0"))
    for c in tv["columns"]:
        tv.heading(c, command=lambda c=c: by(c))


class UsageTab:
    PERIODS = {"Today": 1, "Last 7 days": 7, "Last 30 days": 30}

    def __init__(self, app, parent):
        import nd_usage as US
        self.US = US
        self.app = app
        top = ttk.Frame(parent, padding=(0, 6))
        top.pack(fill="x")
        ttk.Label(top, text="Period:").pack(side="left")
        self.var_period = tk.StringVar(value="Today")
        cb = ttk.Combobox(top, textvariable=self.var_period, values=list(self.PERIODS), state="readonly", width=13)
        cb.pack(side="left", padx=4)
        cb.bind("<<ComboboxSelected>>", lambda e: self.refresh())
        ttk.Label(top, text="Device:").pack(side="left", padx=(10, 0))
        self.var_dev = tk.StringVar(value="All devices")
        self.cb_dev = ttk.Combobox(top, textvariable=self.var_dev, state="readonly", width=34)
        self.cb_dev.pack(side="left", padx=4)
        self.cb_dev.bind("<<ComboboxSelected>>", lambda e: self.refresh())
        ttk.Button(top, text="Refresh", command=self.refresh).pack(side="left", padx=4)
        ttk.Button(top, text="Open dashboard (charts)", style="Big.TButton", command=self.dashboard).pack(side="right")
        ttk.Button(top, text="Export (Excel CSV)", command=self.export).pack(side="right", padx=6)
        self.var_kpi = tk.StringVar(value="")
        ttk.Label(parent, textvariable=self.var_kpi, font=("Segoe UI", 11, "bold"), padding=(0, 2)).pack(anchor="w")
        cat = ttk.Frame(parent)
        cat.pack(fill="x", pady=(0, 4))
        ttk.Label(cat, text="Selected app / website is:", foreground="#344054").pack(side="left")
        for c in (US.WORK, US.NEUTRAL, US.PERSONAL):
            ttk.Button(cat, text=US.CAT_LABEL[c], command=lambda c=c: self.set_cat(c)).pack(side="left", padx=3)
        ttk.Button(cat, text="Built-in rule", command=lambda: self.set_cat(None)).pack(side="left", padx=3)
        ttk.Label(cat, text="  for").pack(side="left")
        self.var_for = tk.StringVar(value="Everyone")
        self.cb_for = ttk.Combobox(cat, textvariable=self.var_for, state="readonly", width=18)
        self.cb_for.pack(side="left", padx=4)
        ttk.Button(cat, text="App list (all apps and their websites)...", command=lambda: AppListDialog(self)).pack(
            side="left", padx=8)
        ttk.Label(cat, text="(remembered, and applied to the history too)", foreground="#667085").pack(side="left")
        flt = ttk.Frame(parent)
        flt.pack(fill="x", pady=(0, 4))
        ttk.Label(flt, text="Find (user, app, website):").pack(side="left")
        self.var_find = tk.StringVar()
        e = ttk.Entry(flt, textvariable=self.var_find, width=24)
        e.pack(side="left", padx=4)
        e.bind("<KeyRelease>", lambda ev: self.fill())
        ttk.Label(flt, text="Category:").pack(side="left", padx=(8, 0))
        self.var_cat = tk.StringVar(value="All")
        cb = ttk.Combobox(flt, textvariable=self.var_cat, state="readonly", width=14,
                          values=["All"] + [US.CAT_LABEL[c] for c in (US.WORK, US.NEUTRAL, US.PERSONAL)])
        cb.pack(side="left", padx=4)
        cb.bind("<<ComboboxSelected>>", lambda e: self.fill())
        ttk.Label(flt, text="Department:").pack(side="left", padx=(8, 0))
        self.var_dept = tk.StringVar(value="All")
        self.cb_dept = ttk.Combobox(flt, textvariable=self.var_dept, state="readonly", width=14, values=["All"])
        self.cb_dept.pack(side="left", padx=4)
        self.cb_dept.bind("<<ComboboxSelected>>", lambda e: self.fill())
        ttk.Label(flt, text="Click a column title to sort (e.g. Traffic = biggest first)",
                  foreground="#667085").pack(side="left", padx=8)
        ttk.Button(flt, text="Get exact website names...", command=self.exact_names).pack(side="right")
        pw = ttk.PanedWindow(parent, orient="vertical")
        pw.pack(fill="both", expand=True)
        up, down = ttk.PanedWindow(pw, orient="horizontal"), ttk.PanedWindow(pw, orient="horizontal")
        pw.add(up, weight=3)
        pw.add(down, weight=2)
        a, b, c, d = ttk.Frame(up), ttk.Frame(up), ttk.Frame(down), ttk.Frame(down)
        up.add(a, weight=1)
        up.add(b, weight=1)
        down.add(c, weight=1)
        down.add(d, weight=1)
        self.tv_apps = UI["make_tree"](a, ("group", "cat", "bytes", "mins", "devs"),
                                       ("Group", "Category", "Traffic", "Active time", "Devices"),
                                       (120, 95, 85, 80, 55), first=("App", 190))
        self.tv_devs = UI["make_tree"](b, ("dept", "bytes", "work", "personal", "score", "top"),
                                       ("Dept", "Traffic", "Productive", "Unproductive", "Productivity",
                                        "Top unproductive"), (90, 80, 85, 90, 80, 150), first=("Device / user", 170))
        self.tv_devs.bind("<Double-1>", self._pick_dev)
        self.tv_sites = UI["make_tree"](c, ("app", "cat", "bytes", "visits"), ("App", "Category", "Traffic", "Visits"),
                                        (150, 100, 85, 60), first=("Website", 210))
        self.txt = UI["text_box"](d)
        for tv in (self.tv_apps, self.tv_devs, self.tv_sites):
            sortable(tv)
        self.devkeys = {}
        self.rows_apps, self.rows_sites = {}, {}
        self.last = None

    def refresh(self):
        store = self.app.usage
        if not store:
            self.var_kpi.set("Usage history is not available on this PC (the usage database could not be opened).")
            return
        days = self.PERIODS.get(self.var_period.get(), 1)
        names = store.names()
        self.devkeys = {"All devices": None}
        for k, v in sorted(names.items(), key=lambda kv: (kv[1].get("name") or kv[0]).lower()):
            self.devkeys[f"{v.get('name') or k}  {v.get('ip', '')}"] = k
        self.cb_dev.configure(values=list(self.devkeys))
        self.cb_for.configure(values=["Everyone"] + self.departments())
        dev = self.devkeys.get(self.var_dev.get())
        s = store.summary(days, dev)
        self.last = s
        fb = self.US.fmt_bytes
        tot = sum(s["cats"].values())
        work = sum(x["work"] for x in s["devices"])
        pers = sum(x["personal"] for x in s["devices"])
        score = self.US.productivity(work, pers)
        self.var_kpi.set(f"{fb(tot)} internet traffic  |  productive {self._m(work)}, unproductive {self._m(pers)}"
                         + (f"  |  productivity {score}%" if score is not None else "")
                         + f"  |  {len(s['devices'])} device(s)  |  {s['start']} to {s['end']}")
        self.cb_dept.configure(values=["All"] + sorted({x["dept"] for x in s["devices"] if x.get("dept")}))
        self.fill()
        self._advisor(store, tot)

    def fill(self):
        """The three tables, with the Find / Category / Department filters."""
        s = self.last
        if not s:
            return
        fb = self.US.fmt_bytes
        lab = self.US.CAT_LABEL
        q = self.var_find.get().strip().lower()
        want = self.var_cat.get()
        dept = self.var_dept.get()

        def keep(x, *texts):
            if want != "All" and lab.get(x.get("cat")) != want:
                return False
            return not q or any(q in str(t).lower() for t in texts)
        for tv in (self.tv_apps, self.tv_devs, self.tv_sites):
            tv.delete(*tv.get_children())
        self.rows_apps, self.rows_sites = {}, {}
        for x in s["apps"]:
            if not keep(x, x["app"], x.get("group", "")):
                continue
            iid = self.tv_apps.insert("", "end", text=x["app"], values=(x.get("group", ""), lab[x["cat"]], fb(x["bytes"]),
                                                                         self._m(x["minutes"]), x["devices"]),
                                      tags=(x["cat"],))
            self.rows_apps[iid] = x
        for x in s["devices"]:
            if dept != "All" and x.get("dept") != dept or q and not any(
                    q in str(t).lower() for t in (x["name"], x["dept"], x["top"], x["dev"])):
                continue
            self.tv_devs.insert("", "end", text=x["name"], iid="dev:" + x["dev"],
                                values=(x["dept"], fb(x["bytes"]), self._m(x["work"]), self._m(x["personal"]),
                                        "-" if x["score"] is None else f"{x['score']}%", x["top"]))
        for x in s["sites"]:
            site = self.US.pretty_site(x["site"])
            if not keep(x, site, x["site"], x["app"]):
                continue
            iid = self.tv_sites.insert("", "end", text=site, values=(x["app"], lab[x["cat"]], fb(x["bytes"]),
                                                                           x["visits"] or ""), tags=(x["cat"],))
            self.rows_sites[iid] = x
        for tv in (self.tv_apps, self.tv_sites):
            tv.tag_configure("personal", foreground="#c2410c")
            tv.tag_configure("work", foreground="#1d4ed8")

    def exact_names(self):
        messagebox.showinfo(
            APP, "Google, Meta and Akamai run hundreds of services on the same servers, so the traffic alone cannot "
                 "say Sheets or Search. The exact name comes from each device's DNS question.\n\n"
                 "Chrome / Edge 'secure DNS' sends those questions straight to Google or Cloudflare, so the router never "
                 "sees them. Network guard > 'All DNS through the router' sends every DNS question through the router "
                 "and blocks that bypass (browsers switch back to normal DNS by themselves). After that, usage shows "
                 "docs.google.com, mail.google.com, youtube.com ... per user.\n\nThe Network guard opens now.")
        self.app.show_tab("tools")
        self.app.tools.show("guard")
        try:
            for k, v in self.app.tools.g.items():
                if k in ("dns", "dhcp", "torrent", "random"):
                    v.set(k == "dns")
        except Exception:
            pass

    def _advisor(self, store, tot):
        t = self.txt
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", "What the advisor learned\n", "h")
        for i in store.insights():
            t.insert("end", f"\n{i['title']}\n", "warn" if i["sev"] == "warning" else "h")
            t.insert("end", i["text"] + "\n")
            if i["action"]:
                t.insert("end", "What to do: " + i["action"] + "\n", "ok")
        if not tot:
            t.insert("end", "\nNo traffic recorded for this period yet. Usage needs: 1) NetFlow from the router (Setup > "
                            "Copy router commands, or Apply router settings now), 2) the Live monitor running. Website "
                            "names: router login in Setup (reads the router's DNS cache) or the website firewall.\n",
                     "warn")
        t.configure(state="disabled")

    @staticmethod
    def _m(minutes):
        m = int(minutes or 0)
        return f"{m} min" if m < 60 else f"{m // 60} h {m % 60:02d}"

    def _pick_dev(self, _=None):
        sel = self.tv_devs.selection()
        if sel and sel[0].startswith("dev:"):
            key = sel[0][4:]
            self.var_dev.set(next((k for k, v in self.devkeys.items() if v == key), "All devices"))
            self.refresh()

    def departments(self):
        depts = {t.get("dept") for t in T.tags_of(self.app.db).values() if t.get("dept")}
        if self.app.usage:
            depts |= {v.get("dept") for v in self.app.usage.names().values() if v.get("dept")}
        return sorted(depts)

    def dept_choice(self):
        v = self.var_for.get()
        return "" if v in ("", "Everyone") else v

    def set_cat(self, cat):
        sa = [self.rows_apps[i] for i in self.tv_apps.selection() if i in self.rows_apps]
        ss = [self.rows_sites[i] for i in self.tv_sites.selection() if i in self.rows_sites]
        if not sa and not ss:
            messagebox.showinfo(APP, "Select an app or a website in the lists first.")
            return
        dept = self.dept_choice()
        for x in sa:
            self.app.usage.set_category("app", x["app"], cat, dept)
        for x in ss:  # a website's choice is for everyone; per department, choose its app
            self.app.usage.set_category("site", x["site"], cat)
        self.refresh()

    def dashboard(self):
        if not self.app.usage:
            return
        os.makedirs(core.REPORT_DIR, exist_ok=True)
        path = os.path.join(core.REPORT_DIR, "usage-dashboard.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.US.dashboard_html(self.app.usage, 30))
        try:
            import webbrowser
            webbrowser.open("file:///" + path.replace("\\", "/"))
        except Exception:
            pass
        self.app.var_status.set(f"Dashboard saved: {path}")

    def export(self):
        if not self.last:
            self.refresh()
        s = self.last
        os.makedirs(core.REPORT_DIR, exist_ok=True)
        p = filedialog.asksaveasfilename(initialdir=core.REPORT_DIR, initialfile=time.strftime("usage-%Y%m%d.csv"),
                                         defaultextension=".csv", filetypes=[("Excel CSV", "*.csv")])
        if not p or not s:
            return
        import csv
        lab = self.US.CAT_LABEL
        with open(p, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow([f"Usage {s['start']} to {s['end']}"])
            w.writerow([])
            w.writerow(["Device / user", "Department", "IP", "Traffic MB", "Productive min", "Neutral min",
                        "Unproductive min", "Productivity %", "Top unproductive app"])
            for x in s["devices"]:
                w.writerow([x["name"], x["dept"], x["ip"], round(x["bytes"] / 1048576, 1), x["work"], x["neutral"],
                            x["personal"], "" if x["score"] is None else x["score"], x["top"]])
            w.writerow([])
            w.writerow(["App", "Category", "Traffic MB", "Active min", "Devices"])
            for x in s["apps"]:
                w.writerow([x["app"], lab[x["cat"]], round(x["bytes"] / 1048576, 1), x["minutes"], x["devices"]])
            w.writerow([])
            w.writerow(["Website", "App", "Category", "Traffic MB", "Visits"])
            for x in s["sites"]:
                w.writerow([x["site"], x["app"], lab[x["cat"]], round(x["bytes"] / 1048576, 1), x["visits"]])
        self.app.var_status.set(f"Usage saved: {p}")


class AppListDialog(tk.Toplevel):
    """Every app Network Doctor knows, the websites that belong to it, and its category (per department too)."""

    def __init__(self, tab):
        super().__init__(tab.app)
        self.tab, self.store = tab, tab.app.usage
        self.US = tab.US
        self.title("App list - which websites belong to which app")
        self.geometry("1150x640")
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="Search:").pack(side="left")
        self.var_q = tk.StringVar()
        e = ttk.Entry(top, textvariable=self.var_q, width=24)
        e.pack(side="left", padx=4)
        e.bind("<KeyRelease>", lambda ev: self.fill())
        ttk.Label(top, text="   Selected app is:").pack(side="left")
        for c in (self.US.WORK, self.US.NEUTRAL, self.US.PERSONAL):
            ttk.Button(top, text=self.US.CAT_LABEL[c], command=lambda c=c: self.set(c)).pack(side="left", padx=2)
        ttk.Button(top, text="Built-in", command=lambda: self.set(None)).pack(side="left", padx=2)
        ttk.Label(top, text=" for").pack(side="left")
        self.var_for = tk.StringVar(value=tab.var_for.get() or "Everyone")
        ttk.Combobox(top, textvariable=self.var_for, state="readonly", width=18,
                     values=["Everyone"] + tab.departments()).pack(side="left", padx=4)
        ttk.Button(top, text="Export (Excel CSV)", command=self.export).pack(side="right")
        ttk.Label(self, text="An app is recognised by the end of the website name it uses (m.facebook.com ends in "
                             "facebook.com). Facebook, Instagram, WhatsApp and Messenger are separate apps even though "
                             "they run on the same company's servers. 'For' a department: e.g. WhatsApp Productive for "
                             "Sales, Neutral for everyone else.", wraplength=1100, foreground="#667085",
                  padding=(8, 0)).pack(anchor="w")
        fr = ttk.Frame(self, padding=8)
        fr.pack(fill="both", expand=True)
        self.tv = UI["make_tree"](fr, ("group", "cat", "builtin", "depts", "domains"),
                                  ("Group", "Category now", "Built-in", "Per department", "Websites (endings)"),
                                  (150, 105, 95, 190, 560), first=("App", 210))
        self.fill()

    def fill(self):
        q = self.var_q.get().strip().lower()
        lab = self.US.CAT_LABEL
        tv = self.tv
        tv.delete(*tv.get_children())
        self.rows = {}
        for x in sorted(self.store.app_list(), key=lambda r: (r["group"], r["app"].lower())):
            if q and q not in (x["app"] + " " + x["group"] + " " + " ".join(x["domains"])).lower():
                continue
            now = x["chosen"] or x["builtin"]
            iid = tv.insert("", "end", text=x["app"], tags=(now,),
                            values=(x["group"], lab[now] + (" *" if x["chosen"] else ""), lab[x["builtin"]],
                                    ", ".join(f"{d}: {lab[c]}" for d, c in sorted(x["depts"].items())),
                                    ", ".join(x["domains"])))
            self.rows[iid] = x
        tv.tag_configure("personal", foreground="#c2410c")
        tv.tag_configure("work", foreground="#1d4ed8")

    def set(self, cat):
        sel = [self.rows[i] for i in self.tv.selection() if i in self.rows]
        if not sel:
            messagebox.showinfo(APP, "Select one or more apps (Ctrl / Shift + click).", parent=self)
            return
        v = self.var_for.get()
        dept = "" if v in ("", "Everyone") else v
        for x in sel:
            self.store.set_category("app", x["app"], cat, dept)
        self.fill()
        self.tab.refresh()

    def export(self):
        os.makedirs(core.REPORT_DIR, exist_ok=True)
        p = filedialog.asksaveasfilename(parent=self, initialdir=core.REPORT_DIR, initialfile="app-list.csv",
                                         defaultextension=".csv", filetypes=[("Excel CSV", "*.csv")])
        if not p:
            return
        import csv
        lab = self.US.CAT_LABEL
        with open(p, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["App", "Group", "Category now", "Built-in", "Per department", "Websites (endings)"])
            for x in sorted(self.store.app_list(), key=lambda r: (r["group"], r["app"].lower())):
                w.writerow([x["app"], x["group"], lab[x["chosen"] or x["builtin"]], lab[x["builtin"]],
                            "; ".join(f"{d}: {lab[c]}" for d, c in sorted(x["depts"].items())),
                            " ".join(x["domains"])])
        self.tab.app.var_status.set(f"App list saved: {p}")


# ==========================================================================
# slow website for one person: measure every link, name the cause, fix it
# ==========================================================================
class SlowTab:
    def __init__(self, app, parent):
        import nd_slow as S
        self.S, self.app = S, app
        self.stop = None
        self.result = None
        intro = ("Someone says a website is slow (Google Sheets, Gmail, a portal)? Choose that person's device, the "
                 "website, and press Find the cause. Network Doctor tests every link - their Wi-Fi / cable, the office "
                 "network, the router, the internet line, DNS, the website itself, whether the line is full and who "
                 "fills it - and tells you the cause and the fix (about 1 minute).")
        ttk.Label(parent, text=intro, wraplength=1250, foreground="#344054", padding=(0, 6)).pack(anchor="w")
        r1 = ttk.Frame(parent)
        r1.pack(fill="x", pady=2)
        ttk.Label(r1, text="User / device:").pack(side="left")
        self.var_dev = tk.StringVar()
        self.cb_dev = ttk.Combobox(r1, textvariable=self.var_dev, width=44)
        self.cb_dev.pack(side="left", padx=4)
        self.devmap = {}
        Suggest(self.cb_dev, lambda: list(self.devmap) or self._all_names())
        ttk.Label(r1, text="  Website:").pack(side="left")
        self.var_url = tk.StringVar(value=S.COMMON_SITES[0][1])
        ttk.Entry(r1, textvariable=self.var_url, width=42).pack(side="left", padx=4)
        ttk.Label(r1, text="  Internet plan:").pack(side="left")
        self.var_mbps = tk.StringVar(value=str(app._settings().get("line_mbps") or 100))
        ttk.Entry(r1, textvariable=self.var_mbps, width=6).pack(side="left", padx=2)
        ttk.Label(r1, text="Mbps").pack(side="left")
        r2 = ttk.Frame(parent)
        r2.pack(fill="x", pady=2)
        ttk.Label(r2, text="Quick:").pack(side="left")
        for label, url in S.COMMON_SITES:
            ttk.Button(r2, text=label, command=lambda u=url: self.var_url.set(u)).pack(side="left", padx=2)
        self.var_load = tk.BooleanVar(value=False)
        ttk.Checkbutton(r2, text="Also test delay while the line is busy (uses the internet for 10 s)",
                        variable=self.var_load).pack(side="left", padx=10)
        r3 = ttk.Frame(parent)
        r3.pack(fill="x", pady=(4, 2))
        self.btn = ttk.Button(r3, text="Find the cause", style="Big.TButton", command=self.start)
        self.btn.pack(side="left")
        ttk.Button(r3, text="Stop", command=lambda: self.stop and self.stop.set()).pack(side="left", padx=6)
        self.var_prog = tk.StringVar(value="")
        ttk.Label(r3, textvariable=self.var_prog, foreground="#5b21b6").pack(side="left", padx=8)
        self.btn_fix = ttk.Button(r3, text="Fix this on the router", command=self.fix, state="disabled")
        self.btn_fix.pack(side="right")
        ttk.Button(r3, text="Copy report", command=self.copy).pack(side="right", padx=6)
        pw = ttk.PanedWindow(parent, orient="horizontal")
        pw.pack(fill="both", expand=True, pady=(6, 0))
        a, b = ttk.Frame(pw), ttk.Frame(pw)
        pw.add(a, weight=2)
        pw.add(b, weight=3)
        self.tv = UI["make_tree"](a, ("conf",), ("Likely?",), (80,), first=("Cause (most likely first)", 380))
        self.tv.bind("<<TreeviewSelect>>", lambda e: self.show())
        for sev, col in (("critical", "#b42318"), ("warning", "#b54708"), ("ok", "#1f7a3d"), ("info", "#667085")):
            self.tv.tag_configure(sev, foreground=col)
        self.txt = UI["text_box"](b)
        self.items = {}
        self.findings = []

    def refresh(self):
        devs = sorted([d for d in self.app.devices if d.get("online")],
                      key=lambda d: ((d.get("name") or "~").lower(), core.ip_key(d.get("ip", ""))))
        self.devmap = {f"{d.get('name') or '-'}  {d.get('ip', '')}  {d.get('mac') or ''}".strip(): d for d in devs}
        self.cb_dev.configure(values=list(self.devmap))

    def _all_names(self):
        self.refresh()
        return list(self.devmap)

    def _device(self):
        v = self.var_dev.get().strip()
        if v in getattr(self, "devmap", {}):
            return self.devmap[v]
        low = v.lower()
        for d in self.app.devices:  # typed: an IP, a MAC or part of a name
            if v and (d.get("ip") == v or low in (d.get("name") or "").lower() or low == (d.get("mac") or "").lower()):
                return d
        hits = [d for k, d in self.devmap.items() if all(w in k.lower() for w in low.split())]
        return hits[0] if len(hits) == 1 else None

    def start(self):
        url = self.S.norm_url(self.var_url.get())
        if not url:
            messagebox.showinfo(APP, "Type the website, for example docs.google.com")
            return
        dev = self._device()
        if self.var_dev.get().strip() and not dev:
            messagebox.showinfo(APP, "That device is not in the last scan. Choose it from the list (Scan first), or "
                                     "leave it empty to test only the office network and the website.")
            return
        try:
            mbps = float(self.var_mbps.get()) if self.var_mbps.get().strip() else None
        except ValueError:
            mbps = None
        st = self.app._settings()
        if mbps:
            st["line_mbps"] = mbps
            self.app._save_settings()
        self.stop = threading.Event()
        self.btn.configure(state="disabled")
        self.btn_fix.configure(state="disabled")
        self.tv.delete(*self.tv.get_children())
        self.txt.configure(state="normal")
        self.txt.delete("1.0", "end")
        self.txt.configure(state="disabled")
        ctx = {"gw": self.app.gw, "lip": self.app.lip, "mon": self.app.mon, "usage": self.app.usage,
               "db": self.app.db, "raw": self.app.raw, "issues": list(self.app.issues),
               "devices": list(self.app.devices), "router": self.app.router_client(ask=False), "line_mbps": mbps}
        loaded = self.var_load.get()
        q = self.app.q

        def prog(pct, text):
            q.put(("call", lambda: self.var_prog.set(f"{pct}%  {text}")))

        def work():
            try:
                m = self.S.measure(url, dev, ctx, prog, self.stop, loaded)
                m["gw"] = self.app.gw
                f = self.S.judge(m)
            except Exception as e:
                m, f = {"url": url}, [{"sev": "critical", "title": f"The check failed: {type(e).__name__}: {e}",
                                       "conf": "", "evidence": [], "fixes": [], "action": None, "score": 0}]
            q.put(("call", lambda: self.done(m, f, mbps)))
        threading.Thread(target=work, daemon=True).start()

    def done(self, m, findings, mbps):
        self.btn.configure(state="normal")
        self.result, self.findings, self.mbps = m, findings, mbps
        self.var_prog.set(f"Finished {time.strftime('%H:%M:%S')} - {len(findings)} finding(s)")
        self.tv.delete(*self.tv.get_children())
        self.items = {}
        for f in findings:
            iid = self.tv.insert("", "end", text=f["title"], values=(f["conf"],), tags=(f["sev"],))
            self.items[iid] = f
        kids = self.tv.get_children()
        if kids:
            self.tv.selection_set(kids[0])
        self.show()
        dev = m.get("device") or {}
        self.app._health_log("Slow website", "info", f"{m.get('host')} for {dev.get('name') or 'office'}: "
                                                     + (findings[0]["title"] if findings else "no finding"))

    def show(self):
        sel = self.tv.selection()
        f = self.items.get(sel[0]) if sel else None
        t = self.txt
        t.configure(state="normal")
        t.delete("1.0", "end")
        if f:
            t.insert("end", f["title"] + "\n", "h")
            if f.get("conf"):
                t.insert("end", f"How likely: {f['conf']}\n\n")
            if f["evidence"]:
                t.insert("end", "What was measured\n", "h")
                for e in f["evidence"]:
                    t.insert("end", f"  - {e}\n")
            if f["fixes"]:
                t.insert("end", "\nHow to fix it\n", "h")
                for x in f["fixes"]:
                    t.insert("end", f"  -> {x}\n", "ok")
            a = f.get("action") or ""
            scr = self.S.fix_script(a, self.mbps, self._lan()) if a and not a.startswith("open:") else ""
            if scr:
                t.insert("end", "\nRouter commands for this fix (or press 'Fix this on the router'):\n", "h")
                t.insert("end", scr)
                if a.startswith("limit:"):
                    t.insert("end", "(If the limit seems ignored: Commands > Turn off FastTrack.)\n")
        m = self.result or {}
        if m:
            t.insert("end", "\nAll measurements\n", "h")
            for line in self._numbers(m):
                t.insert("end", f"  {line}\n")
            t.insert("end", "\nCompare on the user's own PC (Command Prompt), then compare with the numbers above:\n", "h")
            t.insert("end", self.S.compare_command(m.get("url", "")) + "\n")
        t.configure(state="disabled")
        a = (f or {}).get("action") or ""
        self.btn_fix.configure(state="normal" if a else "disabled",
                               text="Open the right tool" if a.startswith("open:") else "Fix this on the router")

    def _lan(self):
        try:
            import ipaddress
            return str(ipaddress.ip_network(self.app.net, strict=False))
        except Exception:
            return ""

    def _numbers(self, m):
        out = []
        for key, label in (("dev_ping", "user's device"), ("gw_ping", "router"), ("inet_ping", "internet 1.1.1.1")):
            p = m.get(key)
            if p:
                out.append(f"ping {label}: " + (f"loss {p['loss']:.0f}%, avg {p['avg']:.0f} ms, max {p['max']:.0f} ms, "
                                                f"jitter {p['jitter']:.0f} ms" if p.get("recv") else "no answer"))
        for d in m.get("dns") or []:
            out.append(f"DNS {d.get('label')} {d.get('server')}: " + (d["error"] if d.get("error") else
                                                                      f"{d.get('ms', 0):.0f} ms (repeat "
                                                                      f"{d.get('cached_ms') or 0:.0f} ms)"))
        for x in m.get("site_summary") or []:
            out.append(x)
        if m.get("mtu"):
            out.append(f"largest packet (MTU): {m['mtu']}")
        ln = m.get("line") or {}
        if ln.get("have_flows"):
            out.append(f"line now: {ln['down_bps'] / 1e6:.1f} Mbps in use" +
                       (f" of {ln['capacity_mbps']:.0f}" if ln.get("capacity_mbps") else ""))
        if m.get("router_cpu") is not None:
            out.append(f"router CPU: {m['router_cpu']}%")
        if (m.get("loaded") or {}).get("busy"):
            out.append(f"delay idle {m['loaded']['idle']:.0f} ms, while busy {m['loaded']['busy']:.0f} ms")
        return out

    def fix(self):
        sel = self.tv.selection()
        f = self.items.get(sel[0]) if sel else None
        a = (f or {}).get("action") or ""
        if a.startswith("open:"):
            where = a[5:]
            if where in ("website", "guard", "wifi"):
                self.app.show_tab("tools")
                self.app.tools.show(where)
            else:
                self.app.show_tab(where)
            return
        if a == "queue_fair" and not self.mbps:
            messagebox.showinfo(APP, "Type your internet plan speed (Mbps) first, then run the check again.")
            return
        scr = self.S.fix_script(a, self.mbps, self._lan())
        if scr:
            self.app.router_apply(scr, f"Slow website fix: {f['title']}")

    def copy(self):
        m, fs = self.result, self.findings
        if not m:
            return
        dev = (m.get("device") or {}).get("name") or "office"
        lines = [f"Slow website check: {m.get('url')} for {dev}  ({time.strftime('%d %b %Y %H:%M')})", ""]
        for f in fs:
            lines.append(f"[{f['sev'].upper()}] {f['title']} ({f['conf']})")
            lines += [f"   measured: {e}" for e in f["evidence"]] + [f"   fix: {x}" for x in f["fixes"]]
        lines += ["", "Measurements:"] + [f"   {x}" for x in self._numbers(m)]
        self.app.clipboard_clear()
        self.app.clipboard_append("\n".join(lines))
        self.app.var_status.set("Report copied.")


# ---------------------------------------------------------------- alerts: history, priority, fixes, troubleshoot
import nd_alerts as AL  # noqa: E402

PRIO_COLORS = {1: "#b42318", 2: "#c4320a", 3: "#1d4ed8", 4: "#667085"}


class AlertsTab:
    """Every alert with time, priority, device and fix; Troubleshoot fixes it or walks you through it."""

    def __init__(self, app, parent):
        self.app = app
        top = ttk.Frame(parent, padding=(0, 6))
        top.pack(fill="x")
        ttk.Label(top, text="Show:").pack(side="left")
        self.var_show = tk.StringVar(value="Open alerts")
        cb = ttk.Combobox(top, textvariable=self.var_show, state="readonly", width=16,
                          values=["Open alerts", "All alerts", "Fixed"])
        cb.pack(side="left", padx=4)
        cb.bind("<<ComboboxSelected>>", lambda e: self.refresh())
        ttk.Label(top, text="Priority:").pack(side="left", padx=(8, 0))
        self.var_prio = tk.StringVar(value="All")
        cb = ttk.Combobox(top, textvariable=self.var_prio, state="readonly", width=20,
                          values=["All"] + list(AL.PRIO.values()))
        cb.pack(side="left", padx=4)
        cb.bind("<<ComboboxSelected>>", lambda e: self.refresh())
        ttk.Label(top, text="Find:").pack(side="left", padx=(8, 0))
        self.var_q = tk.StringVar()
        e = ttk.Entry(top, textvariable=self.var_q, width=18)
        e.pack(side="left", padx=4)
        e.bind("<KeyRelease>", lambda ev: self.refresh())
        ttk.Button(top, text="Export to Excel (CSV)", command=lambda: self.export("csv")).pack(side="right")
        self.var_auto = tk.BooleanVar(value=app._settings().get("auto_fix", True))

        def _auto():
            app._settings()["auto_fix"] = self.var_auto.get()
            app._save_settings()
        ttk.Checkbutton(top, text="Auto-fix when the same alert repeats 5 times (safe fixes only)",
                        variable=self.var_auto, command=_auto).pack(side="right", padx=10)
        ttk.Button(top, text="Export report (HTML)", command=lambda: self.export("html")).pack(side="right", padx=6)
        self.var_sum = tk.StringVar(value="")
        ttk.Label(parent, textvariable=self.var_sum, foreground="#5b21b6").pack(anchor="w")
        act = ttk.Frame(parent, padding=(0, 6, 0, 0))
        act.pack(fill="x", side="bottom")
        ttk.Button(act, text="Troubleshoot", style="Big.TButton", command=self.troubleshoot).pack(side="left")
        ttk.Button(act, text="Mark fixed", command=lambda: self.mark("fixed")).pack(side="left", padx=6)
        ttk.Button(act, text="Re-open", command=lambda: self.mark("open")).pack(side="left")
        ttk.Button(act, text="Copy", command=self.copy).pack(side="left", padx=6)
        ttk.Label(act, text="Double-click an alert to troubleshoot it", foreground="#667085").pack(side="left", padx=8)
        cols = ("prio", "device", "alert", "fix", "times", "status")
        heads = ("Priority", "Device", "Alert", "Fix", "Times", "Status")
        widths = (120, 170, 430, 420, 55, 110)
        self.tv = UI["make_tree"](parent, cols, heads, widths, first=("Time", 140), selectmode="extended")
        for p, c in PRIO_COLORS.items():
            self.tv.tag_configure(f"p{p}", foreground=c)
        self.tv.tag_configure("fixed", foreground="#12b76a")
        self.tv.bind("<Double-1>", lambda e: self.troubleshoot())
        self.rows = {}

    def names(self):
        return {d.get("ip"): (d.get("tag") or {}).get("name") or d.get("name") or "" for d in self.app.devices}

    def items(self):
        show, prio, q = self.var_show.get(), self.var_prio.get(), self.var_q.get().strip().lower()
        out = []
        for x in self.app.alert_log.recent(3000):
            if show == "Open alerts" and x.get("status") != "open" or show == "Fixed" and x.get("status") != "fixed":
                continue
            if prio != "All" and AL.PRIO[x["prio"]] != prio:
                continue
            if q and q not in (x["text"] + x["fix"] + x.get("ip", "")).lower():
                continue
            out.append(x)
        return out

    def refresh(self):
        tv = self.tv
        sel = set(tv.selection())
        tv.delete(*tv.get_children())
        self.rows = {}
        names = self.names()
        xs = self.items()
        xs.sort(key=lambda x: (x.get("status") != "open", x["prio"], -x["last"]))
        for x in xs[:1500]:
            dev = (names.get(x.get("ip")) or "-") + (f"  {x['ip']}" if x.get("ip") else "")
            iid = tv.insert("", "end", iid=x["id"], text=time.strftime("%d-%b %H:%M:%S", time.localtime(x["t"])),
                            values=(AL.PRIO[x["prio"]], dev, x["text"], x["fix"], x.get("count", 1),
                                    x.get("status", "")),
                            tags=("fixed",) if x.get("status") == "fixed" else (f"p{x['prio']}",))
            self.rows[iid] = x
        for i in sel:
            if tv.exists(i):
                tv.selection_add(i)
        allx = self.app.alert_log.recent(3000)
        op = [x for x in allx if x.get("status") == "open"]
        self.var_sum.set(f"{len(op)} open  |  P1 fix now: {sum(x['prio'] == 1 for x in op)}  |  "
                         f"P2 today: {sum(x['prio'] == 2 for x in op)}  |  {len(allx)} alerts kept  |  "
                         "the same alert within an hour is counted, not repeated")

    def selected(self):
        return [self.rows[i] for i in self.tv.selection() if i in self.rows]

    def mark(self, status):
        sel = self.selected()
        if sel:
            self.app.alert_log.set_status({x["id"] for x in sel}, status)
            self.app.alert_log.save()
            self.refresh()

    def copy(self):
        sel = self.selected() or self.items()[:30]
        lines = [f"{time.strftime('%d-%b %H:%M', time.localtime(x['t']))}  {AL.PRIO[x['prio']]}  {x['text']}"
                 f"\n    Fix: {x['fix']}" for x in sel]
        self.app.clipboard_clear()
        self.app.clipboard_append("\n".join(lines))
        self.app.var_status.set(f"Copied {len(sel)} alert(s) with their fixes.")

    def export(self, kind):
        os.makedirs(core.REPORT_DIR, exist_ok=True)
        ext = ".csv" if kind == "csv" else ".html"
        p = filedialog.asksaveasfilename(initialdir=core.REPORT_DIR, defaultextension=ext,
                                         initialfile=time.strftime(f"network-alerts-%Y%m%d-%H%M{ext}"),
                                         filetypes=[("Excel CSV", "*.csv")] if kind == "csv" else [("Web page",
                                                                                                    "*.html")])
        if not p:
            return
        xs = self.selected() if len(self.selected()) > 1 else self.items()
        (AL.export_csv if kind == "csv" else AL.export_html)(p, xs, self.names())
        self.app.var_status.set(f"{len(xs)} alerts saved: {p}")
        if kind == "html":
            try:
                import webbrowser
                webbrowser.open("file:///" + p.replace("\\", "/"))
            except Exception:
                pass
        else:
            self.app.open_folder(os.path.dirname(p))

    def troubleshoot(self, alert=None):
        x = alert or (self.selected() or [None])[0]
        if not x:
            messagebox.showinfo(APP, "Select an alert first.")
            return
        TroubleshootWindow(self.app, x)

    def open_latest(self):
        xs = self.app.alert_log.recent(1, only_open=True)
        if xs:
            self.troubleshoot(xs[0])


class TroubleshootWindow(tk.Toplevel):
    """One alert: what it means, automatic fixes (router / this PC), numbered steps with tick boxes, re-check."""

    def __init__(self, app, alert):
        super().__init__(app)
        self.app, self.alert = app, alert
        r = self.r = AL.explain(alert["text"], alert["sev"], app.lip, app.gw)
        self.title("Troubleshoot - " + r["title"][:60])
        self.geometry("820x640")
        self.transient(app)
        f = ttk.Frame(self, padding=14)
        f.pack(fill="both", expand=True)
        head = ttk.Frame(f)
        head.pack(fill="x")
        tk.Label(head, text=f" {r['prio_text']} ", bg=PRIO_COLORS[r["prio"]], fg="white",
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Label(head, text="  " + time.strftime("%d-%b-%Y %H:%M:%S", time.localtime(alert["t"]))
                  + (f"   ({alert.get('count', 1)} times, last "
                     f"{time.strftime('%H:%M', time.localtime(alert['last']))})" if alert.get("count", 1) > 1 else ""),
                  foreground="#667085").pack(side="left")
        ttk.Label(f, text=r["title"], font=("Segoe UI", 13, "bold"), wraplength=780, justify="left").pack(
            anchor="w", pady=(8, 2))
        ttk.Label(f, text=alert["text"], foreground="#667085", wraplength=780, justify="left").pack(anchor="w")
        ttk.Label(f, text=r["why"], wraplength=780, justify="left").pack(anchor="w", pady=(8, 0))
        ttk.Label(f, text="Fix: " + r["fix"], font=("Segoe UI", 10, "bold"), wraplength=780, justify="left").pack(
            anchor="w", pady=(6, 6))
        if r["auto"] or r.get("app"):
            box = ttk.LabelFrame(f, text="Fix it automatically", padding=8)
            box.pack(fill="x", pady=(0, 6))
            for a in r["auto"]:
                where = {"router": "on the router", "router_read": "reads the router", "pc": "on this PC"}.get(
                    a["where"], "")
                ttk.Button(box, text=f"{a['label']}  ({where})", style="Big.TButton",
                           command=lambda a=a: self.run(a)).pack(anchor="w", pady=2)
            if r.get("app"):
                ttk.Button(box, text=r["app"][0], command=lambda: self.go(r["app"][1])).pack(anchor="w", pady=2)
            ttk.Label(box, text="Router fixes need the router login (Setup) and ask before changing anything. "
                                "Without a login, 'Show commands' gives them to paste in WinBox > New Terminal.",
                      foreground="#667085", wraplength=760, justify="left").pack(anchor="w")
            if any(a["where"] == "router" for a in r["auto"]):
                ttk.Button(box, text="Show commands", command=self.show_cmds).pack(anchor="w", pady=(4, 0))
        sb = ttk.LabelFrame(f, text="Step by step (tick each step when done)", padding=8)
        sb.pack(fill="both", expand=True)
        self.ticks = []
        for i, s in enumerate(r["steps"], 1):
            v = tk.BooleanVar(value=False)
            ttk.Checkbutton(sb, text=f"{i}.  {s}", variable=v).pack(anchor="w", pady=2)
            self.ticks.append(v)
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=(8, 0))
        self.var_res = tk.StringVar(value="")
        ttk.Button(bar, text="Close", command=self.destroy).pack(side="right")
        ttk.Button(bar, text="Mark fixed", command=self.fixed).pack(side="right", padx=6)
        ttk.Button(bar, text="Re-check now", command=self.recheck).pack(side="right")
        ttk.Button(bar, text="Copy steps", command=self.copy).pack(side="left")
        ttk.Label(bar, textvariable=self.var_res, foreground="#027a48").pack(side="left", padx=8)

    def script(self, a):
        cmd = a["cmd"]
        if cmd in ("@torrent_guard", "@dhcp_guard"):
            key = "torrent" if cmd == "@torrent_guard" else "dhcp"
            cmd = T.guard_commands({key: True}, [], self.app.lip, "bridge")[0]
        return cmd

    def run(self, a):
        if a["where"] == "pc":
            if not core.IS_WIN:
                messagebox.showinfo(APP, f"Run this on a Windows PC:\n\n{a['cmd']}")
                return
            try:
                subprocess.Popen(f"cmd /k {a['cmd']}", creationflags=0x00000010)
                self.var_res.set("Started in a new window on this PC.")
            except Exception as e:
                messagebox.showerror(APP, str(e))
            return
        if a["where"] == "router_read":
            self.app.router_cli(a["cmd"], a["label"])
            return

        def done(err):
            if not err:
                self.var_res.set(f"Done: {a['label']}. Re-check in a few minutes.")
                self.app.alert_log.set_status({self.alert["id"]}, "fixed", "automatic fix: " + a["label"])
                self.app.alert_log.save()
                self.app.alerts_tab.refresh()
        if not self.app.router_apply(self.script(a), a["label"], done):
            self.show_cmds()

    def show_cmds(self):
        txt = "\n\n".join(f"# {a['label']}\n{self.script(a)}" for a in self.r["auto"] if a["where"] == "router")
        w = tk.Toplevel(self)
        w.title("Commands - paste in WinBox > New Terminal")
        w.geometry("760x420")
        t = UI["text_box"](w)
        t.configure(state="normal")
        t.insert("1.0", txt)
        ttk.Button(w, text="Copy", command=lambda: (self.app.clipboard_clear(), self.app.clipboard_append(txt))).pack(
            anchor="e", padx=8, pady=6)

    def go(self, where):
        self.destroy()
        self.app.deiconify()
        if where == "rca":
            self.app.show_tab("rca")
            self.app.run_rca()
        else:
            self.app.show_tab(where)

    def recheck(self):
        self.var_res.set("Checking the network again... (results in Problems and here)")
        try:
            self.app.start_quick(manual=True)
        except TypeError:
            self.app.start_quick()

    def fixed(self):
        self.app.alert_log.set_status({self.alert["id"]}, "fixed")
        self.app.alert_log.save()
        self.app.alerts_tab.refresh()
        self.destroy()

    def copy(self):
        r = self.r
        txt = (f"{r['prio_text']}: {r['title']}\n{self.alert['text']}\n\n{r['why']}\n\nFix: {r['fix']}\n"
               + "\n".join(f"{i}. {s}" for i, s in enumerate(r["steps"], 1)))
        self.app.clipboard_clear()
        self.app.clipboard_append(txt)
        self.var_res.set("Copied.")


# ---------------------------------------------------------------- navigation: coloured sections with sub-tabs
SECTIONS = [  # key, title, colour, light colour, [(page, title), ...]
    ("home", "Home", "#334155", "#e2e8f0", [("home", "Overview")]),
    ("alerts_s", "Alerts", "#c2410c", "#ffedd5", [("alerts", "Alerts"), ("problems", "Problems"),
                                                  ("rca", "Root cause"), ("checks", "Health checks")]),
    ("devices_s", "Devices", "#1d4ed8", "#dbeafe", [("devices", "All devices"), ("inventory", "Inventory"),
                                                    ("map", "Network map"), ("binding", "IP-MAC binding"),
                                                    ("t_switch", "Switches (SNMP)"), ("t_ports", "Port scanner"),
                                                    ("t_mac", "MAC lookup"), ("t_wol", "Wake-on-LAN")]),
    ("internet_s", "Internet & Usage", "#047857", "#d1fae5", [("monitor", "Live monitor"), ("usage", "Usage"),
                                                              ("slow", "Slow website?"), ("t_speed", "Speed test"),
                                                              ("t_web", "Website check"), ("t_dns", "DNS test")]),
    ("security_s", "Security", "#7c3aed", "#ede9fe", [("t_guard", "Network guard"), ("t_website", "Website firewall"),
                                                      ("t_watch", "Critical devices")]),
    ("fix_s", "Fix & Commands", "#b45309", "#fef3c7", [("commands", "Commands"), ("t_lan", "LAN speed (PC to PC)"),
                                                       ("t_wifi", "Wi-Fi analyzer"), ("t_nic", "Network adapters"),
                                                       ("t_mtu", "MTU finder"), ("t_subnet", "Subnet calculator")]),
    ("setup_s", "Setup", "#475569", "#e2e8f0", [("setup", "Setup"), ("t_ready", "What is missing"),
                                                ("activate", "Pro / Activate")]),
]


class SectionNav:
    """Two rows of coloured buttons (section, then its pages) above one page area. Pages are created up front
    (page(key) -> frame) and shown with select(key); on_change(key) runs after every switch."""

    def __init__(self, master, on_change=None):
        self.on_change = on_change
        self.top = tk.Frame(master, bg="#f8fafc")
        self.top.pack(fill="x", padx=10, pady=(2, 0))
        self.strip = tk.Frame(master, height=4, bg="#334155")
        self.strip.pack(fill="x", padx=10)
        self.sub = tk.Frame(master, bg="#e2e8f0")
        self.sub.pack(fill="x", padx=10)
        self.body = ttk.Frame(master)
        self.body.pack(fill="both", expand=True, padx=10, pady=(4, 6))
        self.pages, self.labels, self.sec_btn, self.sub_btn = {}, {}, {}, {}
        self.sec_of, self.last = {}, {}
        self.cur, self.cur_sec = None, None
        for key, title, col, light, subs in SECTIONS:
            b = tk.Label(self.top, text=f"  {title}  ", font=("Segoe UI", 11, "bold"), fg=col, bg="#f8fafc",
                         padx=10, pady=7, cursor="hand2")
            b.pack(side="left", padx=(0, 2))
            b.bind("<Button-1>", lambda e, k=key: self.select_section(k))
            self.sec_btn[key] = b
            for p, t in subs:
                self.sec_of[p] = key
                self.labels[p] = t
            self.last[key] = subs[0][0]

    def section(self, key):
        return next(s for s in SECTIONS if s[0] == key)

    def page(self, key):
        """The frame for one page (created once)."""
        if key not in self.pages:
            self.pages[key] = ttk.Frame(self.body)
        return self.pages[key]

    def current(self):
        return self.cur

    def set_label(self, key, text):
        self.labels[key] = text
        b = self.sub_btn.get(key)
        if b is not None:
            b.configure(text=f" {text} ")
        if key == "alerts" and "alerts_s" in self.sec_btn:  # the open-alert count also on the section
            n = re.search(r"\((\d+)\)", text)
            self.sec_btn["alerts_s"].configure(text=f"  Alerts ({n.group(1)})  " if n else "  Alerts  ")

    def select_section(self, key):
        self.select(self.last.get(key) or self.section(key)[4][0][0])

    def select(self, key):
        if key not in self.sec_of:
            return
        sec = self.sec_of[key]
        _, _, col, light, subs = self.section(sec)
        if sec != self.cur_sec:
            for k, b in self.sec_btn.items():
                s = self.section(k)
                b.configure(bg=s[2] if k == sec else "#f8fafc", fg="white" if k == sec else s[2])
            self.strip.configure(bg=col)
            for w in self.sub.winfo_children():
                w.destroy()
            self.sub.configure(bg=light)
            self.sub_btn = {}
            for p, _t in subs:
                b = tk.Label(self.sub, text=f" {self.labels[p]} ", font=("Segoe UI", 10), bg=light, fg="#1f2937",
                             padx=10, pady=5, cursor="hand2")
                b.pack(side="left")
                b.bind("<Button-1>", lambda e, k=p: self.select(k))
                self.sub_btn[p] = b
            self.cur_sec = sec
        for p, b in self.sub_btn.items():
            on = p == key
            b.configure(bg="white" if on else light, fg=col if on else "#1f2937",
                        font=("Segoe UI", 10, "bold" if on else "normal"))
        if self.cur and self.cur in self.pages:
            self.pages[self.cur].pack_forget()
        self.page(key).pack(fill="both", expand=True)
        self.cur = key
        self.last[sec] = key
        if self.on_change:
            self.on_change(key)


# Pro build: add the advanced-security pages into the existing coloured sections.
if core.IS_PRO:
    _PRO_PAGES = {
        "security_s": [("defense", "Auto-defense"), ("vuln", "Security check"), ("expose", "Internet exposure")],
        "fix_s": [("capture", "Packet capture")],
        "setup_s": [("accounts", "Users & sign-in"), ("audit", "Audit log")],
    }
    for _s in SECTIONS:
        _s[4].extend(_PRO_PAGES.get(_s[0], []))
