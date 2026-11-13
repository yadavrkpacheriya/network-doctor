# -*- coding: utf-8 -*-
"""
Network Doctor - page "Login sweep" (Devices): one admin login (up to three) is tried ONCE on every PC, camera /
NVR / DVR and router / switch; what each one reports is saved, and devices whose login was refused, that could not
be reached, or that answered with data missing are listed. Also checks phones without logging in to them, so the
same IP / block mix-up that cut phones off (3.19.1) does not come back.
The rules are in nd_sweep.py; this file is only the window.
"""
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import nd_bandwidth as B
import nd_core as core
import nd_sweep as S
import nd_tabs
import nd_tools as T

APP = "Network Doctor"
KIND_LABEL = (("pc", "Windows PCs"), ("cam", "Cameras / NVR / DVR"), ("net", "Routers, switches, printers"))
STATUS_TAG = {S.OK: "pass", S.AUTH: "fail", S.UNREACH: "skip", S.UNSUP: "warn", S.BLOCKED: "warn", S.ERR: "fail",
             S.SKIP: "skip"}
FILTERS = ("All", "Needs attention", S.OK, S.AUTH, S.UNREACH, S.BLOCKED, S.UNSUP, S.ERR, S.SKIP)


class SweepPage:
    def __init__(self, app, parent):
        self.app = app
        self.sweep = None
        self.results = []
        self.rows = {}
        self.running = False

        info = ttk.Frame(parent, padding=(0, 0, 0, 6))
        info.pack(fill="x")
        ttk.Label(info, text="Give the SAME admin user name and password you already use on your PCs / cameras / "
                             "router, and this scans every one of them with it (no need to run anything by hand on "
                             "each device). Up to 3 logins can be tried. Every login is tried only ONCE on each "
                             "device: if the first few devices of a kind all refuse it, the rest are skipped so an "
                             "account does not get locked.", wraplength=1100, foreground="#344054",
                  justify="left").pack(anchor="w")

        cred = ttk.LabelFrame(parent, text="Logins to try (used once per device, never saved)", padding=8)
        cred.pack(fill="x", pady=(4, 6))
        self.var_user, self.var_pw = [], []
        for i in range(3):
            ttk.Label(cred, text=f"{i + 1}.").grid(row=i, column=0, sticky="w", padx=(0, 4))
            u = tk.StringVar(value="admin" if i == 0 else "")
            p = tk.StringVar(value="")
            self.var_user.append(u)
            self.var_pw.append(p)
            ttk.Label(cred, text="User name").grid(row=i, column=1, sticky="e")
            ttk.Entry(cred, textvariable=u, width=22).grid(row=i, column=2, sticky="w", padx=(4, 16))
            ttk.Label(cred, text="Password").grid(row=i, column=3, sticky="e")
            ttk.Entry(cred, textvariable=p, width=22, show="*").grid(row=i, column=4, sticky="w", padx=4)

        bar = ttk.Frame(parent)
        bar.pack(fill="x", pady=(0, 6))
        self.var_kind = {}
        for key, label in KIND_LABEL:
            v = tk.BooleanVar(value=True)
            self.var_kind[key] = v
            ttk.Checkbutton(bar, text=label, variable=v).pack(side="left", padx=(0, 14))
        self.var_force = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Keep trying anyway (can lock an account)", variable=self.var_force).pack(
            side="left", padx=(10, 0))

        bar2 = ttk.Frame(parent)
        bar2.pack(fill="x", pady=(0, 6))
        ttk.Button(bar2, text="Plan (see what will be scanned - no login sent)", command=self.do_plan).pack(
            side="left")
        ttk.Button(bar2, text="Start scan", command=self.do_start).pack(side="left", padx=6)
        ttk.Button(bar2, text="Stop", command=self.do_stop).pack(side="left")
        ttk.Button(bar2, text="Check phones", command=self.do_phones).pack(side="left", padx=(16, 0))
        ttk.Button(bar2, text="Export CSV", command=self.do_export).pack(side="left", padx=6)
        ttk.Button(bar2, text="Use device's own name as its tag", command=self.apply_fetched_names).pack(
            side="left", padx=(16, 0))
        ttk.Button(bar2, text="Copy 'login refused' list", command=self.copy_refused).pack(side="left")
        ttk.Button(bar2, text="Open in browser", command=self.open_selected_web).pack(side="left", padx=(16, 0))

        filt = ttk.Frame(parent)
        filt.pack(fill="x", pady=(0, 4))
        ttk.Label(filt, text="Show:").pack(side="left")
        self.var_filter = tk.StringVar(value="All")
        ttk.Combobox(filt, textvariable=self.var_filter, values=FILTERS, width=20, state="readonly").pack(
            side="left", padx=6)
        self.var_filter.trace_add("write", lambda *_: self._redraw())
        self.var_sum = tk.StringVar(value="Give the login(s) above and press Start scan, or Plan to see counts first.")
        ttk.Label(filt, textvariable=self.var_sum, foreground="#667085").pack(side="left", padx=12)
        ttk.Label(filt, text="Not supported here? Double-click its row (or right-click > Open in browser) to sign "
                             "in by hand.", foreground="#667085").pack(side="right", padx=4)

        self.tv = nd_tabs.UI["make_tree"](
            parent, ("name", "ip", "mac", "type", "method", "result", "login", "fetched", "model", "serial",
                     "missing", "detail"),
            ("Name", "IP", "MAC", "Type", "Checked as", "Result", "Login #", "Name on the device", "Model",
             "Serial", "Missing data", "Detail"),
            (150, 110, 140, 150, 130, 100, 60, 170, 130, 120, 140, 300), None, selectmode="extended")
        self.tv.bind("<Double-1>", self.open_selected_web)
        self.menu = tk.Menu(self.tv, tearoff=False)
        self.menu.add_command(label="Open in browser (web login)", command=self.open_selected_web)
        self.menu.add_command(label="Copy IP", command=self.copy_selected_ip)
        self.tv.bind("<Button-3>", self._popup_menu)

        self.ph = ttk.LabelFrame(parent, text="Phones - checked without any login", padding=6)
        self.ph.pack(fill="x", pady=(6, 0))
        self.txt_ph = nd_tabs.UI["text_box"](self.ph)
        self.txt_ph.configure(font=("Consolas", 9), height=7)

    # ------------------------------------------------------------------ helpers
    def _kinds(self):
        return tuple(k for k, v in self.var_kind.items() if v.get())

    def _creds(self):
        return [(u.get().strip(), p.get()) for u, p in zip(self.var_user, self.var_pw) if u.get().strip()]

    def _clear_passwords(self):
        for p in self.var_pw:
            p.set("")

    def do_plan(self):
        targets = S.plan(self.app.devices, kinds=self._kinds())
        by_kind = {}
        for t in targets:
            k = S.kind_of(t["methods"][0])
            by_kind[k] = by_kind.get(k, 0) + 1
        parts = ", ".join(f"{by_kind.get(k, 0)} {lbl.lower()}" for k, lbl in KIND_LABEL if by_kind.get(k))
        self.var_sum.set(f"Would scan {len(targets)} device(s): {parts or 'none matching'}.")

    def do_start(self):
        if self.running:
            return
        creds = self._creds()
        if not creds:
            messagebox.showinfo(APP, "Type at least one user name and password above.")
            return
        targets = S.plan(self.app.devices, kinds=self._kinds())
        if not targets:
            messagebox.showinfo(APP, "No matching devices found to scan. Tick a device type above.")
            return
        if not messagebox.askyesno(
                APP, f"Try {len(creds)} login(s) on {len(targets)} device(s) now?\n\nEach login is tried ONLY ONCE "
                     "per device. If it is wrong on the first few devices of a kind, the rest of that kind are "
                     "skipped automatically (tick 'Keep trying anyway' first if you want every device tried "
                     "regardless - this can lock an account on some devices)."):
            return
        self.results, self.rows = [], {}
        self.tv.delete(*self.tv.get_children())
        self.running = True
        self.app.telemetry.note("login_sweep")
        self.var_sum.set(f"Scanning 0 of {len(targets)}...")
        force = self.var_force.get()
        sw = self.sweep = S.Sweep(creds, force=force)
        done = {"n": 0}

        def on_result(r):
            self.app.q.put(("call", lambda: self._add_row(r, len(targets), done)))

        def work():
            try:
                sw.run(targets, on_result=on_result)
            finally:
                self.app.q.put(("call", self._finish))
        threading.Thread(target=work, daemon=True).start()

    def do_stop(self):
        if self.sweep:
            self.sweep.stop.set()
            self.var_sum.set("Stopping...")

    def _add_row(self, r, total, done):
        self.results.append(r)
        done["n"] += 1
        self._insert_row(r)
        refused = len(S.refused(self.results))
        self.var_sum.set(f"Scanning {done['n']} of {total}... ({refused} login(s) refused so far)")
        self._save_result(r)

    def _save_result(self, r):
        if r["status"] != S.OK:
            return
        if r["method"] == "wmi":
            data = {"hostname": r["data"].get("hostname") or r["name"] or r["ip"], "user": r["data"].get("user", ""),
                    "os": r["data"].get("os", ""), "hw": r["data"].get("hw"),
                    "adapters": [{"mac": r["mac"]}], "actions": ["login sweep"]}
            try:
                self.app._apply_report(r["ip"], data, quiet=True)
            except Exception:
                pass
        else:
            with core.DB_LOCK:
                self.app.db.setdefault("sweep", {})[r["mac"] or r["ip"]] = {
                    "time": core.now_s(), "ip": r["ip"], "name": r["name"], "method": r["method"], "data": r["data"]}
            core.save_db(self.app.db)

    def _finish(self):
        self.running = False
        self._clear_passwords()
        n_ok = sum(1 for r in self.results if r["status"] == S.OK)
        n_bad = len(S.needs_attention(self.results))
        self.var_sum.set(f"Done: {n_ok} of {len(self.results)} read OK, {n_bad} need attention. Passwords cleared.")

    def _insert_row(self, r):
        d = r["data"]
        vals = (r["name"] or r["ip"], r["ip"], r["mac"], r["category"], S.METHOD_TITLE.get(r["method"], r["method"]),
                r["status"], r.get("login", ""), d.get("name", ""), d.get("model", ""), d.get("serial", ""),
                ", ".join(r["missing"]), r["detail"] or d.get("note", ""))
        iid = self.tv.insert("", "end", values=vals, tags=(STATUS_TAG.get(r["status"], ""),))
        self.rows[iid] = r
        self._apply_filter(iid, r)

    def _apply_filter(self, iid, r):
        want = self.var_filter.get()
        show = want in ("All",) or (want == "Needs attention" and (r["status"] != S.OK or r["missing"])) or want == r["status"]
        if not show:
            self.tv.detach(iid)

    def _redraw(self):
        self.tv.delete(*self.tv.get_children())
        self.rows = {}
        for r in self.results:
            self._insert_row(r)

    # ------------------------------------------------------------------ open the device's own web page by hand
    def _dev_for(self, r):
        """The full device dict (with its known ports) for a sweep row - login sweep only automates methods it
        recognises (WMI, ONVIF, Dahua/Hikvision APIs, RouterOS); a device that answers only with a plain web login
        page comes back 'NOT SUPPORTED' so the person can sign in by hand instead, same as anywhere else in the app."""
        for d in self.app.devices:
            if r.get("mac") and d.get("mac") == r["mac"]:
                return d
            if d.get("ip") == r.get("ip"):
                return d
        return {"ip": r.get("ip", ""), "ports": []}

    def _selected_rows(self):
        return [self.rows[iid] for iid in self.tv.selection() if iid in self.rows]

    def _popup_menu(self, ev):
        iid = self.tv.identify_row(ev.y)
        if iid:
            if iid not in self.tv.selection():
                self.tv.selection_set(iid)
            self.menu.tk_popup(ev.x_root, ev.y_root)

    def open_selected_web(self, event=None):
        rows = self._selected_rows()
        if not rows:
            messagebox.showinfo(APP, "Select a device in the list first (or double-click its row).")
            return
        if len(rows) > 5 and not messagebox.askyesno(
                APP, f"Open {len(rows)} browser tabs, one per selected device?"):
            return
        for r in rows:
            if r.get("ip"):
                self.app.open_web(self._dev_for(r))

    def copy_selected_ip(self):
        rows = self._selected_rows()
        if not rows:
            return
        self.app.clipboard_clear()
        self.app.clipboard_append("\n".join(r["ip"] for r in rows if r.get("ip")))

    def copy_refused(self):
        bad = S.refused(self.results)
        if not bad:
            messagebox.showinfo(APP, "Nothing has a refused login yet.")
            return
        text = "\n".join(f"{r['name'] or r['ip']}\t{r['ip']}\t{r['mac']}\t{S.METHOD_TITLE.get(r['method'], r['method'])}"
                         for r in bad)
        self.app.clipboard_clear()
        self.app.clipboard_append(text)
        messagebox.showinfo(APP, f"Copied {len(bad)} device(s) whose login was refused.")

    def apply_fetched_names(self):
        """For every camera/NVR that answered its own configured name (Hikvision ISAPI, Dahua web API),
        set that as the device's tag name - so you don't have to open each one's web page to find out
        what it's labelled, then type it in by hand."""
        hits = [r for r in self.results if r["status"] == S.OK and (r["data"].get("name") or "").strip()
                and r.get("mac")]
        if not hits:
            messagebox.showinfo(APP, "No device answered with its own configured name yet - run the scan "
                                     "first (Hikvision and Dahua cameras/NVRs report this; others don't).")
            return
        if not messagebox.askyesno(APP, f"Set the tag name of {len(hits)} device(s) to the name stored on the "
                                        f"device itself? This replaces any tag name already set for them."):
            return
        n = 0
        for r in hits:
            T.set_tag(self.app.db, r["mac"], name=r["data"]["name"].strip()[:60])
            n += 1
        core.save_db(self.app.db)
        self.app.after_tags_changed()
        messagebox.showinfo(APP, f"Named {n} device(s) from what's stored on them.")

    def do_export(self):
        if not self.results:
            messagebox.showinfo(APP, "Nothing scanned yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                                            initialfile="login-sweep.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            f.write(S.csv_text(self.results))
        messagebox.showinfo(APP, f"Saved: {path}")

    # ------------------------------------------------------------------ phones
    def do_phones(self):
        tags = T.tags_of(self.app.db)
        rng = B.default_ranges(str(getattr(self.app, "net", "") or "192.168.0.0/24"))
        bw = (self.app._settings().get("bandwidth") or {}) if hasattr(self.app, "_settings") else {}
        rng.update({k: tuple(v) for k, v in (bw.get("ranges") or {}).items() if isinstance(v, (list, tuple)) and len(v) == 2})
        c = self.app.router_client(ask=False) if hasattr(self.app, "router_client") else None
        if not c:
            self._show_phones(S.phone_health(self.app.devices, tags, ranges=rng, ip_type_of=getattr(self.app, "ip_type_of", None)))
            return

        def work():
            filter_rows, lease_rows = [], []
            try:
                with c:
                    for p in ("/ip firewall filter", "/interface bridge filter"):
                        filter_rows += c.cmd(p.replace(" ", "/") + "/print")
                    lease_rows = c.cmd("/ip/dhcp-server/lease/print")
            except Exception:
                pass
            findings = S.phone_health(self.app.devices, tags, filter_rows=filter_rows, lease_rows=lease_rows,
                                      gw_ip=self.app.gw, ranges=rng, ip_type_of=getattr(self.app, "ip_type_of", None))
            self.app.q.put(("call", lambda: self._show_phones(findings)))
        threading.Thread(target=work, daemon=True).start()

    def _show_phones(self, findings):
        self.txt_ph.delete("1.0", "end")
        if not findings:
            self.txt_ph.insert("end", "No phone issues found - IPs, blocks and labels all look fine.\n", "ok")
            return
        for f in findings:
            tag = "crit" if f["level"] == "critical" else ("warn" if f["level"] == "warning" else "mute")
            self.txt_ph.insert("end", f"{f['name']} ({f['ip']})  {f['text']}\n", tag)
            self.txt_ph.insert("end", f"    fix: {f['fix']}\n", "mute")
