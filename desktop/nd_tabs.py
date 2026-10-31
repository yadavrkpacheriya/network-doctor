# -*- coding: utf-8 -*-
"""
Network Doctor - window parts for: Network map, IP-MAC binding, Commands, the tag editor and the
PC fix script. The main window sets UI["make_tree"] / UI["text_box"] before creating these.
"""

import os
import re
import subprocess
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

        def place(n, depth):
            kids = [c for c in n["children"] if visible(c)] if n["id"] not in self.collapsed else []
            if not kids:
                cy = y[0]
                y[0] += self.DY
            else:
                ys_ = [place(c, depth + 1) for c in kids]
                cy = (ys_[0] + ys_[-1]) / 2
            x = 10 + depth * self.DX
            for c in kids:
                cx, ccy = self.boxes[c["id"]][0], self.boxes[c["id"]][1]
                hot = c["id"] in path and n["id"] in path
                col = "#d92d20" if (c.get("child_bad") == "critical" or c.get("bad") == "critical") else \
                    "#dc6803" if (c.get("child_bad") or c.get("bad")) else "#c0c5cc"
                mid = x + self.W + (self.DX - self.W) / 2
                cv.create_line(x + self.W, cy + self.H / 2, mid, cy + self.H / 2, mid, ccy + self.H / 2, cx, ccy + self.H / 2,
                               fill="#1d4ed8" if hot else col, width=3 if hot else (2 if col != "#c0c5cc" else 1))
            self.draw_node(n, x, cy, n["id"] in path)
            return cy
        # the "Internet" root is not drawn: router, "not placed" and "offline" start at the left edge
        for top in [c for c in self.root["children"] if visible(c)]:
            place(top, 0)
            y[0] += 10
        cv.configure(scrollregion=(0, 0, 10 + 5 * self.DX, y[0] + 20))

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
                "to choose the IP you want for that device; then 'Make router commands' and 'Apply on router' (router "
                "login in Setup) or paste them in WinBox > New Terminal.")
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
        ttk.Button(top, text="Make router commands", style="Big.TButton", command=self.make).pack(side="right")
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
                  (("random_off", True), ("renew", True), ("lock_gw", False), ("report", True))}
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
        ttk.Checkbutton(f, text=f"Report the PC's name, user, MAC and hardware (model, serial, CPU, RAM, disk, Windows) "
                                f"to this Network Doctor ({app.lip}) - fills the Inventory and tags it on the map", variable=self.v["report"]).pack(anchor="w")
        ttk.Label(f, text="\nFor an unattended login script choose 'switch to automatic' or 'leave it' (nobody is "
                          "there to answer). Run from \\\\server\\share or a local copy - not a mapped drive letter, "
                          "which disappears when Windows asks for admin rights.", wraplength=560, foreground="#667085",
                  justify="left").pack(anchor="w")
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=(10, 0))
        ttk.Button(bar, text="Create scripts", style="Big.TButton", command=self.create).pack(side="right")
        ttk.Button(bar, text="Cancel", command=self.destroy).pack(side="right", padx=6)

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
        self.cb = ttk.Combobox(top, textvariable=self.var_dev, width=46, state="readonly")
        self.cb.pack(side="left", padx=4)
        self.cb.bind("<<ComboboxSelected>>", lambda e: self.pick_dev())
        ttk.Label(top, text="  {ip} {mac} {name} {port} in a command are filled from this device",
                  foreground="#667085").pack(side="left")
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
        for c in self.all_commands():
            cat = c[0]
            if cat not in groups:
                groups[cat] = tv.insert("", "end", text=cat, open=True, tags=("cat",))
            iid = tv.insert(groups[cat], "end", text=c[2], values=(c[1], c[3]))
            self.items[iid] = c
        self.show()

    def pick_dev(self):
        self.app.selected_device = self.devmap.get(self.var_dev.get())
        self.show()

    def values(self):
        app = self.app
        gwd = next((d for d in app.devices if d.get("ip") == app.gw and d.get("mac")), None)
        return T.command_values(app.selected_device, app.gw, gwd["mac"] if gwd else "")

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
                 "Each PC": "Run on the PC concerned."}.get(c[1], "")
        self.var_use.set(f"{c[2]}\n{c[4]}\n{where}" + (f"\nStill to fill: {', '.join(missing)} (asked when you run it)"
                                                       if missing else ""))
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
        ttk.Label(cat, text="  (your choice is remembered and applied to the history too)", foreground="#667085").pack(
            side="left")
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
        self.tv_apps = UI["make_tree"](a, ("cat", "bytes", "mins", "devs"), ("Category", "Traffic", "Active time",
                                                                              "Devices"), (100, 90, 85, 60),
                                       first=("App", 190))
        self.tv_devs = UI["make_tree"](b, ("dept", "bytes", "work", "personal", "score", "top"),
                                       ("Dept", "Traffic", "Productive", "Unproductive", "Productivity",
                                        "Top unproductive"), (90, 80, 85, 90, 80, 150), first=("Device / user", 170))
        self.tv_devs.bind("<Double-1>", self._pick_dev)
        self.tv_sites = UI["make_tree"](c, ("app", "cat", "bytes", "visits"), ("App", "Category", "Traffic", "Visits"),
                                        (150, 100, 85, 60), first=("Website", 210))
        self.txt = UI["text_box"](d)
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
        lab = self.US.CAT_LABEL
        for tv in (self.tv_apps, self.tv_devs, self.tv_sites):
            tv.delete(*tv.get_children())
        self.rows_apps, self.rows_sites = {}, {}
        for x in s["apps"]:
            iid = self.tv_apps.insert("", "end", text=x["app"], values=(lab[x["cat"]], fb(x["bytes"]), self._m(x["minutes"]),
                                                                         x["devices"]), tags=(x["cat"],))
            self.rows_apps[iid] = x
        for x in s["devices"]:
            self.tv_devs.insert("", "end", text=x["name"], iid="dev:" + x["dev"],
                                values=(x["dept"], fb(x["bytes"]), self._m(x["work"]), self._m(x["personal"]),
                                        "-" if x["score"] is None else f"{x['score']}%", x["top"]))
        for x in s["sites"]:
            iid = self.tv_sites.insert("", "end", text=x["site"], values=(x["app"], lab[x["cat"]], fb(x["bytes"]),
                                                                           x["visits"] or ""), tags=(x["cat"],))
            self.rows_sites[iid] = x
        for tv in (self.tv_apps, self.tv_sites):
            tv.tag_configure("personal", foreground="#c2410c")
            tv.tag_configure("work", foreground="#1d4ed8")
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

    def set_cat(self, cat):
        sa = [self.rows_apps[i] for i in self.tv_apps.selection() if i in self.rows_apps]
        ss = [self.rows_sites[i] for i in self.tv_sites.selection() if i in self.rows_sites]
        if not sa and not ss:
            messagebox.showinfo(APP, "Select an app or a website in the lists first.")
            return
        for x in sa:
            self.app.usage.set_category("app", x["app"], cat)
        for x in ss:
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
