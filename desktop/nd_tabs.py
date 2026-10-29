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
                ("switch_port", "Switch port number", "entry", None), ("notes", "Notes", "entry", None)]
        for r, (key, label, typ, values) in enumerate(rows, start=1):
            ttk.Label(frm, text=label).grid(row=r, column=0, sticky="w", pady=3, padx=(0, 10))
            cur = first.get(key, "")
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
            T.set_tag(self.app.db, d["mac"], **f)
        core.save_db(self.app.db)
        self.destroy()
        self.app.after_tags_changed()

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
                "'automatic' - no static IPs on PCs, which is what causes conflicts. Tick devices, choose options, "
                "then 'Make router commands' and paste them once in WinBox > New Terminal.")
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
        bar = ttk.Frame(b, padding=(0, 4))
        bar.pack(fill="x")
        ttk.Button(bar, text="Copy commands", command=lambda: self.copy(self.apply)).pack(side="left")
        ttk.Button(bar, text="Copy UNDO commands", command=lambda: self.copy(self.undo)).pack(side="left", padx=6)
        ttk.Button(bar, text="Save as .rsc file", command=self.save).pack(side="left")
        self.var_sum = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.var_sum, foreground="#667085").pack(side="left", padx=10)
        self.txt = UI["text_box"](b)
        self.txt.configure(font=("Consolas", 9))
        self.apply = self.undo = ""

    def refresh(self):
        app = self.app
        tags = T.tags_of(app.db)
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
            iid = tv.insert("", "end", values=("☑" if d["mac"] in self.checked and c["ok"] else ("☐" if c["ok"] else "—"),
                                               t.get("name") or d.get("name") or "-", t.get("dept", ""), d["ip"], d["mac"],
                                               typ, note), tags=() if c["ok"] else ("warning",))
            self.rows[iid] = c
        self.var_sum.set(f"{len(self.checked & {c['dev']['mac'] for c in self.cands if c['ok']})} of "
                         f"{sum(1 for c in self.cands if c['ok'])} bindable devices ticked")

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
                         "Network Doctor will warn if a bound device later shows up on another IP.")

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
        p = filedialog.asksaveasfilename(initialdir=core.REPORT_DIR, initialfile=time.strftime("ip-mac-binding-%Y%m%d.rsc"),
                                         defaultextension=".rsc", filetypes=[("RouterOS script", "*.rsc")])
        if p:
            with open(p, "w", encoding="utf-8") as f:
                f.write(self.apply + "\n# UNDO\n" + "\n".join("# " + x for x in self.undo.splitlines()) + "\n")
            self.app.var_status.set(f"Saved {p} (drag into WinBox Files, then /import file-name=...)")


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
        ttk.Checkbutton(f, text=f"Report the PC's name, user and MAC to this Network Doctor ({app.lip}) - tags it "
                                "automatically on the map", variable=self.v["report"]).pack(anchor="w")
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
                 "Router": "Paste in WinBox > New Terminal on the router.",
                 "Each PC": "Run on the PC concerned."}.get(c[1], "")
        self.var_use.set(f"{c[2]}\n{c[4]}\n{where}" + (f"\nStill to fill: {', '.join(missing)} (asked when you run it)"
                                                       if missing else ""))
        can = c[1] == "This PC" and ((c[0] == "Mac") == core.IS_MAC or c[0] == "My commands")
        self.btn_run.configure(state="normal" if can else "disabled")

    def _final(self):
        text = self.var_cmd.get().strip()
        for k in sorted(set(re.findall(r"\{(\w+)\}", text))):
            v = simpledialog.askstring(APP, f"Value for {{{k}}}" + (" (adapter name from 'ipconfig', e.g. Ethernet or Wi-Fi)"
                                                                     if k == "adapter" else ""), parent=self.app)
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
