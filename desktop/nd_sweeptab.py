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
        ttk.Button(bar2, text="Line up cameras (fixed IPs in one block)...", command=self.open_camline).pack(
            side="left", padx=(16, 0))
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
                                     "first (Hikvision, Dahua and XMeye cameras/NVRs report this; others don't).")
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

    def open_camline(self):
        CamLineWindow(self)

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


class CamLineWindow(tk.Toplevel):
    """Line up the cameras: one fixed IP each, in order, inside the camera block. The rules are in nd_camline.py."""

    def __init__(self, page):
        super().__init__(page.app)
        import nd_camline as CL
        self.CL, self.page, self.app = CL, page, page.app
        self.rows, self.busy = [], False
        self.title("Line up cameras - one fixed IP each, in order")
        self.geometry("980x620")
        self.transient(page.app)
        f = ttk.Frame(self, padding=12)
        f.pack(fill="both", expand=True)
        ttk.Label(f, wraplength=940, justify="left", foreground="#667085", text=(
            "Each camera gets one fixed IP inside the camera block, in order, so a camera that stops working is a "
            "visible gap. For every camera: the router reserves the new IP, the camera is switched to automatic "
            "(DHCP) with the login from the scan, and the app waits until it answers on the new IP. One camera "
            "at a time; the run stops at the first camera that does not come back.\n"
            "The NVR / DVR stores each camera's IP. A Hikvision, Dahua or XMeye recorder that accepted a login in the "
            "scan is given the camera's new IP automatically, right after the camera has moved; for any other "
            "recorder type it by hand (Save old -> new list). Until the recorder has the new IP that channel "
            "shows no picture. So: move ONE camera first, check its picture on the recorder, and only then "
            "move the rest. Recorders themselves are never moved here."
        )).pack(anchor="w")
        top = ttk.Frame(f)
        top.pack(fill="x", pady=(8, 4))
        rng = self._range()
        ttk.Label(top, text="Camera block:").pack(side="left")
        self.var_lo, self.var_hi = tk.StringVar(value=rng[0]), tk.StringVar(value=rng[1])
        ttk.Entry(top, textvariable=self.var_lo, width=15).pack(side="left", padx=(6, 2))
        ttk.Label(top, text="to").pack(side="left")
        ttk.Entry(top, textvariable=self.var_hi, width=15).pack(side="left", padx=(2, 10))
        ttk.Button(top, text="Make the list (changes nothing)", command=self.make).pack(side="left")
        self.b_one = ttk.Button(top, text="Move ONE camera (test first)", command=lambda: self.go(1))
        self.b_one.pack(side="left", padx=6)
        self.b_all = ttk.Button(top, text="Move all the rest, one by one", command=lambda: self.go(None))
        self.b_all.pack(side="left")
        ttk.Button(top, text="Save old -> new list (CSV)", command=self.save_csv).pack(side="left", padx=6)
        self.tv = nd_tabs.UI["make_tree"](
            f, ("name", "now", "new", "brand", "action", "note"),
            ("Name", "IP now", "IP after", "Brand", "What happens", "Note / result"),
            (170, 110, 110, 90, 110, 360), None)
        self.protocol("WM_DELETE_WINDOW", lambda: None if self.busy else self.destroy())
        self.var_msg = tk.StringVar(value="Run the Login sweep for cameras first, then press 'Make the list'.")
        ttk.Label(f, textvariable=self.var_msg, wraplength=940, justify="left").pack(anchor="w", pady=(6, 0))
        self.make()

    def _saved(self):
        return self.app._settings().setdefault("bandwidth", {}).setdefault("ranges", {})

    def _range(self):
        r = self._saved().get("cam")
        if isinstance(r, (list, tuple)) and len(r) == 2:
            return tuple(r)
        return B.default_ranges(str(getattr(self.app, "net", "") or "192.168.0.0/24")).get("cam", ("", ""))

    def make(self):
        if self.busy:
            return
        net = str(getattr(self.app, "net", "") or "192.168.0.0/24")
        ranges = B.default_ranges(net)
        ranges.update({k: tuple(v) for k, v in self._saved().items() if isinstance(v, (list, tuple)) and len(v) == 2})
        lo, hi = self.var_lo.get().strip(), self.var_hi.get().strip()
        try:
            if B._ipkey(lo) > B._ipkey(hi) or not (S.is_lan(lo) and S.is_lan(hi)):
                raise ValueError
        except Exception:
            messagebox.showerror(APP, "The camera block needs two IPs of this network, the lower one first.",
                                 parent=self)
            return
        ranges["cam"] = (lo, hi)
        s = self.app._settings().setdefault("bandwidth", {})
        over = B.effective_over(s.get("over", {}), s.get("boosts", {}))
        self.rows = self.CL.line_plan(self.app.devices, self.app.gw, net, ranges, self.page.results,
                                      T.tags_of(self.app.db), over)
        self._draw()
        n = {a: sum(1 for r in self.rows if r["action"] == a) for a in ("move", "keep", "manual", "skip")}
        self.var_msg.set(f"{len(self.rows)} cameras / recorders: {n['move']} can be moved by the app, {n['keep']} stay, "
                         f"{n['manual']} need the IP typed by hand, {n['skip']} skipped (see the note). "
                         "Nothing has been changed yet.")

    def _draw(self):
        tags = T.tags_of(self.app.db)
        self.tv.delete(*self.tv.get_children())
        label = {"move": "will be moved", "keep": "stays", "manual": "by hand", "skip": "skipped"}
        for i, r in enumerate(self.rows):
            d = r["dev"]
            name = tags.get(d["mac"], {}).get("name") or d.get("name") or ""
            self.tv.insert("", "end", iid=str(i), values=(
                name, r["ip_now"], r["ip_new"] if r["action"] in ("move", "manual") else "",
                self.CL.BRAND.get(r["method"], ""),
                label.get(r["action"], r["action"]), r.get("result") or r["why"]))

    def go(self, limit):
        if self.busy:
            return
        todo = [r for r in self.rows if r["action"] == "move" and not r.get("moved")]
        if not todo:
            messagebox.showinfo(APP, "No camera to move. Press 'Make the list' (after a Login sweep for cameras).",
                                parent=self)
            return
        creds = self.page._creds()
        if not creds:
            messagebox.showinfo(APP, "Type the camera login(s) again in the Login sweep page, in the same order "
                                     "as for the scan - they are cleared after every scan.", parent=self)
            return
        c = self.app.router_client(ask=True)
        if not c:
            return
        n = 1 if limit else len(todo)
        first = todo[0]
        if not messagebox.askyesno(
                APP, f"Move {n} camera(s) now?\n\nFirst: {first['ip_now']} -> {first['ip_new']}\n\nEach moved camera "
                     "shows NO PICTURE on the NVR / DVR until the recorder has its new IP ("
                     + (f"{len(self.CL.recorders(self.rows))} recorder(s) will be updated automatically"
                        if self.CL.recorders(self.rows) else "no recorder accepted a login in the scan, so type "
                        "it there by hand") + "). The run stops at the first camera that does not answer on its "
                     "new IP.", parent=self):
            return
        tags = T.tags_of(self.app.db)

        def reserve(row):
            apply, _undo = T.binding_commands([dict(row["dev"], ip=row["ip_new"])], tags)
            try:
                with c:
                    err = c.run_script(apply)
                    if err:
                        return err
                    got = [x for x in c.cmd("/ip/dhcp-server/lease/print", q_mac_address=row["dev"]["mac"])
                           if x.get("address") == row["ip_new"] and str(x.get("dynamic", "")).lower() != "true"]
            except Exception as e:  # noqa: BLE001 - shown in the row
                return str(e)
            return "" if got else "the router did not keep the reservation (IP already reserved for another device?)"

        def alive(ip):
            return any(core.tcp_open(ip, p, 1.0) for p in (80, 8000, 554, 37777, 443)) or core.ping(ip) is not None

        nvrs = self.CL.recorders(self.rows)

        def after_move(row, cred):
            return self.CL.update_recorders(nvrs, creds, row["ip_now"], row["ip_new"], cred)

        self.busy = True
        for b in (self.b_one, self.b_all):
            b.configure(state="disabled")
        self.var_msg.set("Working - one camera at a time. Do not close this window...")

        def work():
            def on_row(r, ok):
                self.app.q.put(("call", lambda: self.winfo_exists() and self._draw()))
            done = 0
            try:
                done = self.CL.run(todo, creds, reserve, alive, on_row=on_row, limit=limit, after_move=after_move)
            finally:
                self.app.q.put(("call", lambda: self._finished(done, todo)))
        threading.Thread(target=work, daemon=True).start()

    def _finished(self, done, todo):
        self.busy = False
        if not self.winfo_exists():
            return
        for b in (self.b_one, self.b_all):
            b.configure(state="normal")
        with core.DB_LOCK:
            bind = self.app.db.setdefault("bindings", {})
            for r in todo:
                if r.get("moved"):
                    bind[r["dev"]["mac"]] = {"ip": r["ip_new"], "time": core.now_s()}
        core.save_db(self.app.db)
        self._draw()
        failed = next((r for r in todo if r.get("result", "").startswith(("FAILED", "not moved"))), None)
        self.var_msg.set(
            (f"{done} camera(s) moved. " if done else "No camera was moved. ")
            + (f"STOPPED at {failed['ip_now']}: {failed['result']}" if failed else
               "Check the picture of each moved camera on the NVR / DVR (the Note column says whether the "
               "recorder took the new IP, or needs it typed by hand), then run a Scan so the device list shows "
               "the new IPs."))

    def save_csv(self):
        if not self.rows:
            return
        p = filedialog.asksaveasfilename(parent=self, defaultextension=".csv", filetypes=[("CSV (Excel)", "*.csv")],
                                         initialfile="camera-ip-list.csv")
        if not p:
            return
        try:
            with open(p, "w", encoding="utf-8-sig", newline="") as fh:
                fh.write(self.CL.old_new_csv(self.rows, T.tags_of(self.app.db)))
        except OSError as e:
            messagebox.showerror(APP, f"Could not save the file: {e}", parent=self)
