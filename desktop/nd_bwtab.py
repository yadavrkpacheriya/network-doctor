# -*- coding: utf-8 -*-
"""
Network Doctor - page "Bandwidth plan" (Internet & Usage): who is in which group, how much internet each group and
each user gets, fixed IPs that survive a power cut, CCTV cameras without internet, and the camera chart.
The rules are in nd_bandwidth.py; this file is only the window.
"""
import os
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

import nd_bandwidth as B
import nd_core as core
import nd_reset as RS
import nd_routeros as RO
import nd_tabs
import nd_tools as T

APP = "Network Doctor"
SET_GROUPS = (("NVR / DVR", "nvr"), ("Camera", "cam"), ("VIP PC", "vip"), ("Mobile", "mobile"), ("Office PC", "pc"),
              ("Other", "other"))
PLAN_FIELDS = (("down", "Internet download (Mbps)"), ("up", "Internet upload (Mbps)"),
               ("headroom", "Keep free (%)"), ("nvr", "NVR / DVR remote viewing (Mbps)"),
               ("mobile", "All mobiles together (Mbps)"), ("vip", "VIP PCs guaranteed (Mbps)"),
               ("pc_user", "Each office PC up to (Mbps)"), ("mobile_user", "Each mobile up to (Mbps)"),
               ("vip_user", "VIP guaranteed floor each (Mbps)"))
BOOST_HOURS = {"1 hour": 1, "4 hours": 4, "8 hours": 8, "Until I stop it": None}


def _num(text, default):
    try:
        return float(str(text).replace(",", ".").strip())
    except ValueError:
        return default


class BandwidthPage:
    def __init__(self, app, parent):
        self.app = app
        self.rows = {}  # tree row -> device
        self.ip_rows = {}  # tree row (page 3) -> IP plan row
        self.want = {}  # mac -> IP the person chose for that device
        self.plan_rows = []
        self.q_apply = self.q_undo = self.c_apply = self.c_undo = self.r_apply = self.r_undo = ""
        self.spec = None
        top = ttk.Frame(parent)
        top.pack(fill="x", pady=(2, 4))
        self.var_msg = tk.StringVar(value="")
        self.var_warn = tk.StringVar(value="")
        ttk.Label(top, textvariable=self.var_warn, foreground="#b42318", wraplength=1100,
                  font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Label(top, text="Steps: 1 check the groups  >  2 set the bandwidth  >  3 fixed IPs  >  4 cameras. "
                            "Nothing changes on the router until you press an Apply button; every Apply has an Undo.",
                  foreground="#344054", wraplength=1100).pack(anchor="w")
        ttk.Label(top, textvariable=self.var_msg, foreground="#b54708").pack(anchor="w")
        nb = ttk.Notebook(parent)
        nb.pack(fill="both", expand=True)
        self.nb = nb
        self.f1, self.f2, self.f3, self.f4, self.f5 = (ttk.Frame(nb, padding=6) for _ in range(5))
        for f, t in ((self.f1, "1. Groups and boost"), (self.f2, "2. Bandwidth per user"), (self.f3, "3. Fixed IPs"),
                     (self.f4, "4. Cameras and chart"), (self.f5, "5. Reset (safety)")):
            nb.add(f, text=t)
        self._build_groups(self.f1)
        self._build_plan(self.f2)
        self._build_ips(self.f3)
        self._build_cams(self.f4)
        self._build_reset(self.f5)
        self.app.after(5000, self._sweep)

    # ------------------------------------------------------------------ saved choices
    def st(self):
        s = self.app._settings().setdefault("bandwidth", {})
        for k, v in (("over", {}), ("boosts", {}), ("plan", {}), ("move", []), ("ranges", {}), ("wan", ""),
                     ("applied", False)):
            s.setdefault(k, v)
        return s

    def save(self):
        self.app._save_settings()

    def tags(self):
        return T.tags_of(self.app.db)

    def over(self):
        s = self.st()
        return B.effective_over(s["over"], s["boosts"])

    def devices(self):
        return B.live_devices(self.app.devices, self.app.gw)

    def refresh(self):
        if not self.st().get("wan") and not getattr(self, "_wan_tried", False):
            self._wan_tried = True
            self.detect_wan(silent=True)  # fills the internet port from the router when a login is saved
        self.refresh_groups()
        self.refresh_live()
        self.refresh_chart()
        self.fill_cam_defaults()

    # ------------------------------------------------------------------ 1. groups
    def _build_groups(self, f):
        ttk.Label(f, text="Every device is put in a group from what Network Doctor knows (phones = Mobiles, PCs = Office "
                          "PCs, CCTV with 'DVR / NVR' in its name = NVR / DVR). Select devices (Ctrl / Shift + click) "
                          "and change their group if it is wrong. VIP = directors' PCs or your PC that need faster "
                          "internet.", wraplength=1100, foreground="#344054").pack(anchor="w")
        bar = ttk.Frame(f, padding=(0, 6))
        bar.pack(fill="x")
        ttk.Label(bar, text="Set group of selected:").pack(side="left")
        for title, key in SET_GROUPS:
            ttk.Button(bar, text=title, command=lambda k=key: self.set_group(k)).pack(side="left", padx=2)
        ttk.Button(bar, text="Automatic", command=lambda: self.set_group(None)).pack(side="left", padx=(8, 2))
        bar2 = ttk.Frame(f, padding=(0, 0, 0, 6))
        bar2.pack(fill="x")
        ttk.Label(bar2, text="Faster internet for the selected devices (uploading a backup...):").pack(side="left")
        self.var_boost = tk.StringVar(value="4 hours")
        ttk.Combobox(bar2, textvariable=self.var_boost, values=list(BOOST_HOURS), width=14, state="readonly").pack(
            side="left", padx=6)
        ttk.Button(bar2, text="Boost now", command=self.boost).pack(side="left")
        ttk.Button(bar2, text="Stop boost", command=self.unboost).pack(side="left", padx=4)
        ttk.Label(bar2, text="(a boost makes the device a VIP; it is sent to the router when it starts and when it ends)",
                  foreground="#667085").pack(side="left", padx=8)
        self.tv = nd_tabs.UI["make_tree"](f, ("name", "ip", "mac", "group", "note"),
                                          ("Name", "IP", "MAC address", "Group", "Note"), (220, 120, 150, 230, 380),
                                          None, selectmode="extended", search=True)
        self.var_cnt = tk.StringVar(value="")
        ttk.Label(f, textvariable=self.var_cnt, foreground="#667085").pack(anchor="w", pady=(4, 0))

    def refresh_groups(self):
        tags, s = self.tags(), self.st()
        over = self.over()
        self.tv.delete(*self.tv.get_children())
        self.rows = {}
        count = {}
        for d in sorted(self.devices(), key=lambda x: B._ipkey(x["ip"])):
            g = B.group_of(d, tags, over)
            count[g] = count.get(g, 0) + 1
            t = tags.get(d["mac"], {})
            note = ""
            b = s["boosts"].get(d["mac"])
            if b:
                note = "BOOST " + ("until " + time.strftime("%H:%M", time.localtime(b["until"])) if b.get("until")
                                   else "until you stop it")
            elif d["mac"] in s["over"]:
                note = "group chosen by you"
            iid = self.tv.insert("", "end", values=(t.get("name") or d.get("name") or "-", d["ip"], d["mac"],
                                                    B.GROUP_TITLE.get(g, g), note))
            self.rows[iid] = d
        self.var_warn.set(self.clash_text())
        self.var_cnt.set("   ".join(f"{B.GROUP_TITLE[g].split(' (')[0]}: {count[g]}" for g in B.GROUPS if g in count))
        self.counts = count

    def clash_text(self):
        """Warning when two devices answer for one IP (a phone that took the recorder's old IP, for example)."""
        clash = B.find_conflicts(self.app.devices)
        if not clash:
            return ""
        tags = self.tags()
        parts = []
        for ip in sorted(clash, key=B._ipkey):
            names = " and ".join((tags.get(d["mac"], {}).get("name") or d.get("name") or d["mac"]) for d in clash[ip])
            parts.append(f"{ip} is answered by {names}")
        return ("IP CLASH: " + "; ".join(parts) + ". These IPs are left out of every rule until fixed: page 3 > Make the IP "
                "list > select the device that should move > Change IP of selected.")

    def _selected(self):
        sel = [self.rows[i] for i in self.tv.selection() if i in self.rows]
        if not sel:
            messagebox.showinfo(APP, "Select (highlight) one or more devices first.")
        return sel

    def set_group(self, key):
        sel = self._selected()
        if not sel:
            return
        s = self.st()
        for d in sel:
            if key is None:
                s["over"].pop(d["mac"], None)
            else:
                s["over"][d["mac"]] = key
        self.save()
        self.var_msg.set("Group changed. Press Apply again on pages 2 and 4 so the router uses it.")
        self.refresh_groups()

    def boost(self):
        sel = self._selected()
        if not sel:
            return
        hours = BOOST_HOURS.get(self.var_boost.get())
        s = self.st()
        until = time.time() + hours * 3600 if hours else None
        for d in sel:
            s["boosts"][d["mac"]] = {"until": until, "ip": d["ip"]}
        self.save()
        self.refresh_groups()
        self._push_plan(f"Boost for {len(sel)} device(s)")

    def unboost(self):
        sel = self._selected()
        if not sel:
            return
        s = self.st()
        for d in sel:
            s["boosts"].pop(d["mac"], None)
        self.save()
        self.refresh_groups()
        self._push_plan(f"Stop boost for {len(sel)} device(s)")

    # ------------------------------------------------------------------ 2. bandwidth plan
    def _build_plan(self, f):
        ttk.Label(f, text="Cameras use the local network only. The internet line is shared: a fixed part for the NVR / DVR "
                          "(so the camera app and clip downloads stay smooth), one for mobiles, a small one for VIP PCs, and "
                          "the rest for office PCs. Inside each part every user is capped, so one heavy user can never slow "
                          "the others. Unused bandwidth is lent to whoever needs it.", wraplength=1100,
                  foreground="#344054").pack(anchor="w")
        g = ttk.Frame(f, padding=(0, 6))
        g.pack(fill="x")
        self.vars = {}
        st = self.st()["plan"]
        for i, (key, label) in enumerate(PLAN_FIELDS):
            ttk.Label(g, text=label).grid(row=i // 3, column=(i % 3) * 2, sticky="w", padx=(0, 6), pady=2)
            v = tk.StringVar(value=f"{st.get(key, B.DEFAULT_PLAN[key]):g}")
            v.trace_add("write", lambda *a: self._plan_changed())
            ttk.Entry(g, textvariable=v, width=8).grid(row=i // 3, column=(i % 3) * 2 + 1, sticky="w", padx=(0, 18))
            self.vars[key] = v
        r = ttk.Frame(f)
        r.pack(fill="x")
        self.var_borrow = tk.BooleanVar(value=bool(st.get("borrow", True)))
        ttk.Checkbutton(r, text="Let a group use bandwidth the others are not using (recommended)",
                        variable=self.var_borrow, command=self._plan_changed).pack(side="left")
        ttk.Label(r, text="   Internet port of the router:").pack(side="left")
        self.var_wan = tk.StringVar(value=self.st().get("wan") or "ether1")
        ttk.Entry(r, textvariable=self.var_wan, width=12).pack(side="left", padx=4)
        ttk.Button(r, text="Read from router", command=self.detect_wan).pack(side="left")
        self.var_pools = tk.StringVar(value="")
        ttk.Label(f, textvariable=self.var_pools, font=("Segoe UI", 10, "bold"), wraplength=1100,
                  foreground="#1d4ed8").pack(anchor="w", pady=6)
        bar = ttk.Frame(f)
        bar.pack(fill="x")
        for txt, cmd in (("Show commands", self.show_queues), ("Apply on router", self.apply_queues),
                         ("Remove the plan from the router", self.undo_queues), ("Copy commands", self.copy_queues)):
            ttk.Button(bar, text=txt, command=cmd).pack(side="left", padx=(0, 6))
        self.tv_live = nd_tabs.UI["make_tree"](f, ("group", "n", "pool", "each", "now"),
                                               ("Group", "Devices", "Guaranteed", "Each user up to", "Used now (10 min)"),
                                               (260, 80, 110, 130, 150), None, height=6)
        self.txt_q = nd_tabs.UI["text_box"](f)
        self.txt_q.configure(font=("Consolas", 9), height=8)
        self._plan_changed()

    def plan(self):
        p = {k: _num(v.get(), B.DEFAULT_PLAN[k]) for k, v in self.vars.items()}
        p["borrow"] = bool(self.var_borrow.get())
        return p

    def _plan_changed(self):
        if not hasattr(self, "var_pools"):
            return
        c = getattr(self, "counts", {})
        pl = B.compute_pools(self.plan(), c)
        s = self.st()
        s["plan"] = self.plan()
        if pl["errors"]:
            self.var_pools.set("Cannot use these numbers: " + " ".join(pl["errors"]))
            return
        busy = f"; with everyone busy each office PC gets {pl['pc_busy']:g} Mbps" if pl.get("pc_busy") else ""
        self.var_pools.set(f"Usable {pl['usable']:g} Mbps: NVR / DVR {pl['nvr']:g}  |  VIP {pl['vip']:g}  |  "
                           f"mobiles {pl['mobile']:g}  |  office PCs {pl['pc']:g}{busy}." +
                           ("  " + " ".join(pl["warnings"]) if pl["warnings"] else ""))

    def detect_wan(self, silent=False):
        c = self.app.router_client(ask=not silent)
        if not c:
            return

        def work():
            try:
                with c:
                    rows = c.cmd("/ip/route/print", q_dst_address="0.0.0.0/0")
                wan = B.detect_wan(rows)
                err = "" if wan else "the default route has no interface name"
            except Exception as e:  # noqa: BLE001 - shown to the person
                wan, err = "", str(e)
            self.app.q.put(("call", lambda: done(wan, err)))

        def done(wan, err):
            if wan:
                self.var_wan.set(wan)
                self.st()["wan"] = wan
                self.save()
                self._plan_changed()
                self.var_msg.set(f"Internet port read from the router: {wan}")
            elif not silent:
                messagebox.showwarning(APP, f"Could not read the internet port ({err}). Type it in (for example ether1).")
        threading.Thread(target=work, daemon=True).start()

    def _send(self, script, what, done=None):
        """Sends a script to the router (after the app's own Yes/No); False when there is no router login."""
        if not self.app.router_client(ask=False):
            self.var_msg.set("No router login saved (Setup > Router login): the commands are shown, paste them in "
                             "WinBox > New Terminal.")
            return False
        return self.app.router_apply(script, what, done=done or (lambda err: None))

    def _show_text(self, title, text):
        win = tk.Toplevel(self.app)
        win.title(title)
        win.geometry("900x520")
        t = nd_tabs.UI["text_box"](win)
        t.configure(font=("Consolas", 9))
        t.insert("end", text)
        ttk.Button(win, text="Copy", command=lambda: (self.app.clipboard_clear(), self.app.clipboard_append(text))).pack(
            pady=4)

    def lan(self):
        return str(getattr(self.app, "net", "") or "192.168.0.0/24")

    def build_queues(self):
        tags, over = self.tags(), self.over()
        extra = B.extra_ips(self.plan_rows)
        grp = B.groups_ips(self.app.devices, tags, over, extra, self.app.gw)
        self.st()["wan"] = self.var_wan.get().strip()
        return B.queue_commands(self.plan(), grp, self.lan(), self.var_wan.get().strip())

    def _make(self, builder, what):
        try:
            return builder()
        except ValueError as e:
            messagebox.showwarning(APP, f"{what}: {e}")
            return None

    def show_queues(self):
        r = self._make(self.build_queues, "Bandwidth plan")
        if r:
            self.q_apply, self.q_undo = r
            self.txt_q.delete("1.0", "end")
            self.txt_q.insert("end", self.q_apply + "\n\n" + self.q_undo)
        return r

    def copy_queues(self):
        if self.show_queues():
            self.app.clipboard_clear()
            self.app.clipboard_append(self.q_apply)
            self.var_msg.set("Commands copied. Paste them in WinBox > New Terminal.")

    def apply_queues(self):
        if not self.show_queues():
            return
        self._send(self.q_apply, "Bandwidth plan (caps per group and per user)", self._applied)

    def _applied(self, err):
        if not err:
            self.st()["applied"] = True
            self.save()
            self.var_msg.set("Bandwidth plan applied. Check it in WinBox: Queues > Simple Queues, and watch the CPU.")

    def undo_queues(self):
        if not self.show_queues():
            return
        self._send(self.q_undo, "REMOVE the bandwidth plan (all ND queues, FastTrack back on)",
                   lambda err: None if err else self._unapplied())

    def _unapplied(self):
        self.st()["applied"] = False
        self.save()

    def refresh_live(self):
        if not hasattr(self, "tv_live"):
            return
        pl = B.compute_pools(self.plan(), getattr(self, "counts", {}))
        if pl["errors"]:
            return
        used = {}
        try:
            rates = self.app.mon.traffic.rates(600) if getattr(self.app, "mon", None) else {}
        except Exception:  # noqa: BLE001
            rates = {}
        tags, over = self.tags(), self.over()
        for d in self.devices():
            r = rates.get(d["ip"])
            if r:
                g = B.group_of(d, tags, over)
                used[g] = used.get(g, 0.0) + (r["down_bps"] + r["up_bps"]) / 1e6
        self.tv_live.delete(*self.tv_live.get_children())
        cnt = getattr(self, "counts", {})
        given = sum(pl[k] for k in ("nvr", "vip", "mobile") if cnt.get(k))
        for g, pool, each in (("nvr", pl["nvr"], "-"), ("vip", pl["vip"], "full line (uncapped)"),
                              ("mobile", pl["mobile"], f"{pl['mobile_user']:g} Mbps"),
                              ("pc", round(pl["usable"] - given, 2), f"{pl['pc_user']:g} Mbps"),
                              ("cam", 0, "no internet")):
            self.tv_live.insert("", "end", values=(B.GROUP_TITLE[g], cnt.get(g, 0), f"{pool:g} Mbps" if pool else "-",
                                                   each, f"{used.get(g, 0.0):.2f} Mbps"))

    def _sweep(self):
        """Once a minute: a boost that ended is removed and the router is updated (the app must be running)."""
        try:
            s = self.st()
            now = time.time()
            gone = [m for m, b in s["boosts"].items() if b.get("until") and b["until"] <= now]
            for m in gone:
                s["boosts"].pop(m, None)
            if gone:
                self.save()
                self.refresh_groups()
                if s.get("applied"):
                    self._push_plan("Boost ended", silent=True)
        except Exception:  # noqa: BLE001
            pass
        self.app.after(60000, self._sweep)

    def _push_plan(self, what, silent=False):
        """Sends the plan again (a group changed). Only when it was applied before; otherwise says what to do."""
        s = self.st()
        if not s.get("applied"):
            self.var_msg.set(f"{what}: saved. It reaches the router when you press 'Apply on router' on page 2.")
            return
        r = self._make(self.build_queues, "Bandwidth plan") if not silent else self._quiet(self.build_queues)
        if not r:
            return
        if not silent:
            self.q_apply, self.q_undo = r
            self._send(self.q_apply, what + " (the plan is sent again)")
            return
        c = RO.from_settings(self.app._settings(), self.app.gw)
        if not c:
            return

        def work():
            try:
                with c:
                    err = c.run_script(r[0])
            except RO.RosError as e:
                err = str(e)
            self.app.q.put(("call", lambda: self.var_msg.set(f"{what}: " + (f"router refused: {err}" if err else
                                                                              "plan updated on the router."))))
        threading.Thread(target=work, daemon=True).start()

    @staticmethod
    def _quiet(builder):
        try:
            return builder()
        except ValueError:
            return None

    # ------------------------------------------------------------------ 3. fixed IPs
    def _build_ips(self, f):
        ttk.Label(f, text="Every device keeps the same IP: the router reserves it for the device's MAC address (DHCP "
                          "reservation). After a power cut the cameras, NVR and PCs come back with the SAME IPs, "
                          "because the router remembers them. By default nothing moves: today's IPs are simply "
                          "reserved. Moving devices into their group's block is optional. Do NOT move cameras unless "
                          "you will re-add them in the NVR (the NVR stores every camera's IP). A device with a hand-typed "
                          "IP must also be changed on the device itself. Best for cameras: reserve the IP here AND type "
                          "the same IP in the camera - it then also survives a late router start.",
                  wraplength=1100, foreground="#344054").pack(anchor="w")
        g = ttk.Frame(f, padding=(0, 6))
        g.pack(fill="x")
        self.var_move = {}
        self.var_rng = {}
        mv = set(self.st()["move"])
        rng = B.default_ranges(self.lan())
        rng.update({k: tuple(v) for k, v in self.st()["ranges"].items() if isinstance(v, (list, tuple)) and len(v) == 2})
        for i, key in enumerate(("nvr", "vip", "pc", "mobile", "cam")):
            self.var_move[key] = tk.BooleanVar(value=key in mv)
            ttk.Checkbutton(g, text=f"Move {B.GROUP_TITLE[key].split(' (')[0]} into", variable=self.var_move[key]).grid(
                row=i, column=0, sticky="w")
            lo, hi = rng.get(key, ("", ""))
            a, b = tk.StringVar(value=lo), tk.StringVar(value=hi)
            self.var_rng[key] = (a, b)
            ttk.Entry(g, textvariable=a, width=15).grid(row=i, column=1, padx=4)
            ttk.Label(g, text="to").grid(row=i, column=2)
            ttk.Entry(g, textvariable=b, width=15).grid(row=i, column=3, padx=4)
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=4)
        for txt, cmd in (("Make the IP list", self.make_ips), ("Change IP of selected...", self.change_ip),
                         ("Reserve on the router now", self.apply_ips),
                         ("Show commands", self.show_ips), ("Undo (remove these reservations)", self.undo_ips),
                         ("Save IP list (Excel CSV)", self.save_ips)):
            ttk.Button(bar, text=txt, command=cmd).pack(side="left", padx=(0, 6))
        self.tv_ip = nd_tabs.UI["make_tree"](f, ("group", "name", "now", "new", "act", "why"),
                                             ("Group", "Name", "IP now", "IP to use", "Action", "Note"),
                                             (200, 200, 120, 120, 90, 420), None, search=True)
        self.txt_i = nd_tabs.UI["text_box"](f)
        self.txt_i.configure(font=("Consolas", 9), height=7)

    def change_ip(self):
        """Gives one device (for example the phone that sits on the recorder's IP) another fixed IP."""
        sel = [self.ip_rows[i] for i in self.tv_ip.selection() if i in self.ip_rows]
        if not sel:
            messagebox.showinfo(APP, "Press 'Make the IP list', then select (highlight) one device in the list.")
            return
        d = sel[0]["dev"]
        name = self.tags().get(d["mac"], {}).get("name") or d.get("name") or d["mac"]
        ip = simpledialog.askstring(APP, f"New IP for {name} ({d['mac']}), now on {d['ip']}.\nEmpty = keep its IP.",
                                    initialvalue=self.want.get(d["mac"], ""), parent=self.app)
        if ip is None:
            return
        ip = ip.strip()
        if not ip or ip == d["ip"]:
            self.want.pop(d["mac"], None)
        else:
            self.want[d["mac"]] = ip
        self.make_ips()

    def make_ips(self):
        s = self.st()
        move, ranges = set(), {}
        for key, v in self.var_move.items():
            a, b = self.var_rng[key]
            ranges[key] = (a.get().strip(), b.get().strip())
            if v.get():
                move.add(key)
        s["move"], s["ranges"] = sorted(move), {k: list(v) for k, v in ranges.items()}
        self.save()
        if "cam" in move and not messagebox.askyesno(
                APP, "You chose to MOVE the cameras.\n\nThe NVR / DVR stores each camera's IP, so every moved camera "
                     "must be added again in the NVR / DVR. Continue?"):
            self.var_move["cam"].set(False)
            move.discard("cam")
        self.plan_rows = B.ip_plan(self.app.devices, self.app.gw, ranges, move, self.tags(), self.over(),
                                   self.app.ip_type_of, self.lan(), self.want)
        tv = self.tv_ip
        tv.delete(*tv.get_children())
        self.ip_rows = {}
        for r in self.plan_rows:
            d = r["dev"]
            t = self.tags().get(d["mac"], {})
            iid = tv.insert("", "end", values=(B.GROUP_TITLE.get(r["group"], r["group"]), t.get("name") or d.get("name") or "-",
                                         r["ip_now"], r["ip_new"], r["action"], r["why"]),
                      tags=("warning",) if r["action"] == "skip" else ())
            self.ip_rows[iid] = r
        self.var_warn.set(self.clash_text())
        n = sum(1 for r in self.plan_rows if r["action"] in ("keep", "move"))
        m = sum(1 for r in self.plan_rows if r["action"] == "move")
        self.var_msg.set(f"IP list ready: {n} devices reserved, {m} moved, "
                         f"{sum(1 for r in self.plan_rows if r['action'] == 'skip')} skipped (see Note).")
        return True

    def _ip_commands(self):
        if not self.plan_rows:
            self.make_ips()
        self.r_apply, self.r_undo = B.reservation_commands(self.plan_rows, self.tags())
        return self.r_apply

    def show_ips(self):
        self._ip_commands()
        self.txt_i.delete("1.0", "end")
        self.txt_i.insert("end", self.r_apply + "\n\n" + self.r_undo)

    def apply_ips(self):
        n = len(B.reservation_rows(self.plan_rows)) if self.plan_rows else 0
        self._ip_commands()
        self.show_ips()
        self._send(self.r_apply, f"Reserve IPs for {n} devices (DHCP reservations)",
                   lambda err: None if err else self._ips_done())

    def _ips_done(self):
        with core.DB_LOCK:
            b = self.app.db.setdefault("bindings", {})
            for r in self.plan_rows:
                if r["action"] in ("keep", "move"):
                    b[r["dev"]["mac"]] = {"ip": r["ip_new"], "time": core.now_s()}
        core.save_db(self.app.db)
        moved = sum(1 for r in self.plan_rows if r["action"] == "move")
        self.var_msg.set("IPs reserved on the router." + (f" {moved} moved device(s) take the new IP when restarted, or "
                                                          "after 'ipconfig /renew'." if moved else ""))

    def undo_ips(self):
        self._ip_commands()
        self._send(self.r_undo, "REMOVE the ND reservations made by this plan")

    def save_ips(self):
        if not self.plan_rows:
            self.make_ips()
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="ip-list.csv",
                                            filetypes=[("Excel CSV", "*.csv")])
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as fh:
                fh.write(B.ip_list_csv(self.plan_rows, self.tags()))
            self.var_msg.set(f"IP list saved: {path}")

    # ------------------------------------------------------------------ 4. cameras
    def _build_cams(self, f):
        left = ttk.Frame(f)
        left.pack(side="left", fill="y", padx=(0, 10))
        ttk.Label(left, text="Many cameras have no setting to stop their internet access, so the ROUTER stops it:\n"
                             "  - cameras cannot go to the internet (only to the NVR / DVR)\n"
                             "  - nothing from the internet can start a connection to a camera or NVR / DVR\n"
                             "  - the router's port-forwards to them are switched off (they can be switched on again)\n"
                             "The NVR / DVR keeps its own outbound link to the maker's cloud: that is how the phone app "
                             "works from anywhere without an open port.", justify="left", wraplength=430,
                  foreground="#344054").pack(anchor="w")
        bar = ttk.Frame(left, padding=(0, 6))
        bar.pack(fill="x")
        for txt, cmd in (("Block cameras on the router", self.apply_cams), ("Show commands", self.show_cams),
                         ("Undo", self.undo_cams)):
            ttk.Button(bar, text=txt, command=cmd).pack(side="left", padx=(0, 6))
        self.var_cams = tk.StringVar(value="")
        ttk.Label(left, textvariable=self.var_cams, foreground="#667085", wraplength=430).pack(anchor="w")
        ttk.Label(left, text="A device shows the wrong name (a phone listed as the DVR), or the DVR got a new IP? An old "
                             "port-forward or auto-defense block still points at the OLD IP and hits whoever has it now.",
                  justify="left", wraplength=430, foreground="#b54708").pack(anchor="w", pady=(8, 2))
        bar4 = ttk.Frame(left)
        bar4.pack(fill="x")
        for txt, cmd in (("Check port-forwards", self.check_forwards), ("Release auto-defense blocks", self.release_blocks),
                         ("Undo the release", self.undo_release)):
            ttk.Button(bar4, text=txt, command=cmd).pack(side="left", padx=(0, 6))
        ttk.Separator(left).pack(fill="x", pady=8)
        ttk.Label(left, text="How much internet do the NVR / DVRs need?", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        g = ttk.Frame(left)
        g.pack(fill="x", pady=4)
        self.sz = {}
        for i, (k, lab, d) in enumerate((("cams", "Cameras", "50"), ("nvrs", "NVR / DVR", "2"), ("viewers", "People viewing at once", "3"),
                                         ("per", "Cameras each opens", "9"), ("sub", "Sub-stream (Mbps)", "0.5"),
                                         ("main", "Main stream (Mbps)", "3"), ("dl", "A clip download (Mbps)", "8"))):
            ttk.Label(g, text=lab).grid(row=i // 2, column=(i % 2) * 2, sticky="w", pady=2)
            v = tk.StringVar(value=d)
            ttk.Entry(g, textvariable=v, width=7).grid(row=i // 2, column=(i % 2) * 2 + 1, padx=(4, 14))
            self.sz[k] = v
        b2 = ttk.Frame(left)
        b2.pack(fill="x")
        ttk.Button(b2, text="Calculate", command=self.calc).pack(side="left")
        ttk.Button(b2, text="Use this for the NVR / DVR in the plan", command=self.use_reserve).pack(side="left", padx=6)
        self.var_calc = tk.StringVar(value="")
        ttk.Label(left, textvariable=self.var_calc, justify="left", wraplength=430).pack(anchor="w", pady=6)
        right = ttk.Frame(f)
        right.pack(side="left", fill="both", expand=True)
        bar3 = ttk.Frame(right)
        bar3.pack(fill="x")
        ttk.Label(bar3, text="How cameras, NVR / DVR and the app connect", font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Button(bar3, text="Save chart (.svg)", command=self.save_chart).pack(side="right")
        self.cv = tk.Canvas(right, bg="white", highlightthickness=1, highlightbackground="#d0d5dd")
        self.cv.pack(fill="both", expand=True, pady=4)
        self.cv.bind("<Configure>", lambda e: self.draw_chart())

    def fill_cam_defaults(self):
        c = getattr(self, "counts", {})
        if c.get("cam") and self.sz["cams"].get() in ("50", ""):
            self.sz["cams"].set(str(c["cam"]))
        if c.get("nvr") and self.sz["nvrs"].get() in ("2", ""):
            self.sz["nvrs"].set(str(c["nvr"]))

    def cam_ips(self):
        g = B.groups_ips(self.app.devices, self.tags(), self.over(), B.extra_ips(self.plan_rows), self.app.gw)
        return g["cam"], g["nvr"]

    def build_cams(self):
        cams, nvrs = self.cam_ips()
        self.var_cams.set(f"{len(cams)} cameras and {len(nvrs)} NVR / DVR found online. A camera that is switched off "
                          "now is added after the next scan + Apply.")
        return B.camera_block_commands(cams, nvrs, self.var_wan.get().strip())

    def show_cams(self):
        r = self._make(self.build_cams, "Camera isolation")
        if r:
            self.c_apply, self.c_undo = r
            self._show_text("Camera isolation commands", self.c_apply + "\n\n" + self.c_undo)
        return r

    def apply_cams(self):
        r = self._make(self.build_cams, "Camera isolation")
        if not r:
            return
        self.c_apply, self.c_undo = r
        self._send(self.c_apply, "Cameras: no internet, only the NVR / DVR may reach the cloud")

    def undo_cams(self):
        r = self._make(self.build_cams, "Camera isolation")
        if r:
            self._send(r[1], "REMOVE the camera internet block (port-forwards switched on again)")

    def check_forwards(self):
        c = self.app.router_client(ask=False)
        if not c:
            self.var_msg.set("No router login saved (Setup > Router login).")
            return

        def work():
            try:
                with c:
                    rows, err = c.cmd("/ip/firewall/nat/print"), ""
            except Exception as e:  # noqa: BLE001 - shown to the person
                rows, err = [], str(e)
            self.app.q.put(("call", lambda: show(rows, err)))

        def show(rows, err):
            if err:
                messagebox.showwarning(APP, f"Could not read the router's port-forwards: {err}")
                return
            rep = B.portforward_report(rows, self.app.devices, self.tags(), self.over())
            lines = [f"{'STATUS':8} {'PORT':8} {'TO IP':16} WHO HAS THAT IP NOW   (rule)"]
            lines += [f"{r['status']:8} {r['port']:8} {r['to']:16} {r['who']}   ({r['rule']})" for r in rep]
            stale = sum(1 for r in rep if r["status"] == "STALE")
            lines += ["", (f"{len(rep)} port-forward(s); {stale} point at a device that is not a camera / recorder."
                           if rep else "No active port-forwards on the router."),
                      "STALE = the forward now exposes some other device (the recorder moved to another IP). 'Block "
                      "cameras on the router' (above) closes every forward of a camera port and every forward to a "
                      "camera / recorder; its Undo puts them back."]
            self._show_text("Port-forwards on the router", "\n".join(lines))
        threading.Thread(target=work, daemon=True).start()

    def release_blocks(self):
        a, u = B.release_blocks_commands()

        def done(err):
            if err:
                return
            d = getattr(self.app, "defense", None)
            for k in list(getattr(d, "active", None) or {}):
                d.release(k)
            self.var_msg.set("Auto-defense blocks switched off on the router. 'Undo the release' switches them on again.")
        self._send(a, "Release ALL auto-defense / phone blocks on the router (kept, switched off)", done)

    def undo_release(self):
        self._send(B.release_blocks_commands()[1], "Switch the released auto-defense blocks ON again")

    # ------------------------------------------------------------------ 5. reset
    def _build_reset(self, f):
        ttk.Label(f, text="Put the router back to how it was before Network Doctor changed it. ONLY things the app made are "
                          "removed (every one is named or commented 'ND ...'); the ISP / owner configuration, router users, "
                          "services, interfaces, the bridge, the DHCP server and NAT masquerade are never touched. Rules the "
                          "app only switched off (port-forwards, FastTrack) are switched on again. Before it starts, the "
                          "router saves its configuration to the file nd-before-reset.rsc.", wraplength=1100,
                  foreground="#344054", justify="left").pack(anchor="w")
        bar = ttk.Frame(f, padding=(0, 8))
        bar.pack(fill="x")
        for txt, cmd in (("1. Show what the app changed (read only)", self.reset_scan),
                         ("2. Reset blocks, limits and rules", lambda: self.reset_router(("limits",))),
                         ("Reset fixed-IP reservations", lambda: self.reset_router(("ips",))),
                         ("Reset EVERYTHING", lambda: self.reset_router(("limits", "ips")))):
            ttk.Button(bar, text=txt, command=cmd).pack(side="left", padx=(0, 6))
        ttk.Label(f, text="Changes of single router settings cannot be put back by the app (the router does not remember the "
                          "old value). If you used these fixes, check them by hand in WinBox:", foreground="#b54708",
                  wraplength=1100).pack(anchor="w", pady=(6, 2))
        self.txt_r = nd_tabs.UI["text_box"](f)
        self.txt_r.configure(font=("Consolas", 9), height=16)
        self._reset_text(RS.global_text())

    def _reset_text(self, text):
        self.txt_r.delete("1.0", "end")
        self.txt_r.insert("end", text)

    def reset_scan(self):
        """Read-only: lists what a reset would switch on again and what it would remove."""
        c = self.app.router_client(ask=False)
        if not c:
            self.var_msg.set("No router login saved (Setup > Router login).")
            return

        def work():
            tables, err = {}, ""
            try:
                with c:
                    for p in RS.READ_PATHS:
                        tables[p] = c.cmd(p.replace(" ", "/") + "/print")
            except Exception as e:  # noqa: BLE001 - shown to the person
                err = str(e)
            self.app.q.put(("call", lambda: show(tables, err)))

        def show(tables, err):
            if err:
                messagebox.showwarning(APP, f"Could not read the router: {err}")
                return
            self._reset_text(RS.report_text(RS.classify(tables)) + "\n\nNOT undone by a reset (check by hand):\n" +
                             RS.global_text())
            self.var_msg.set("This is what a reset would do. Nothing was changed.")
        threading.Thread(target=work, daemon=True).start()

    def reset_router(self, scopes):
        try:
            script, notes = RS.reset_commands(scopes)
        except ValueError as e:
            messagebox.showwarning(APP, str(e))
            return
        if not self.app.router_client(ask=False):
            self._reset_text(script)
            self.var_msg.set("No router login saved: the reset commands are shown, paste them in WinBox > New Terminal.")
            return
        if not messagebox.askyesno(APP, "\n\n".join(notes) + "\n\nReset now?"):
            return
        self._reset_text(script + "\n" + "\n".join(notes))

        def done(err):
            if err:
                return
            if "limits" in scopes:
                self.st()["applied"] = False
                self.st()["boosts"] = {}
                self.save()
                d = getattr(self.app, "defense", None)
                for k in list(getattr(d, "active", None) or {}):
                    d.release(k)
            if "ips" in scopes:
                with core.DB_LOCK:
                    self.app.db["bindings"] = {}
                core.save_db(self.app.db)
            self.var_msg.set("Reset done: " + ", ".join(RS.SCOPE_TITLE[x] for x in scopes) +
                             ". The router configuration before the reset is in the file nd-before-reset.rsc on the router.")
        self._send(script, "RESET everything Network Doctor made: " + ", ".join(RS.SCOPE_TITLE[x] for x in scopes), done)

    def calc(self):
        n = lambda k, d: _num(self.sz[k].get(), d)  # noqa: E731
        s = B.nvr_sizing(int(n("cams", 50)), int(n("nvrs", 2)), n("sub", 0.5), n("main", 3), int(n("viewers", 3)),
                         int(n("per", 9)), n("dl", 8))
        self.size = s
        mins = B.download_minutes(n("main", 3), 60, s["reserve"])
        self.var_calc.set(
            f"One camera, sub-stream: {s['per_cam_sub']:g} Mbps (with overhead); main stream {s['per_cam_main']:g}.\n"
            f"{self.sz['viewers'].get()} people x {self.sz['per'].get()} cameras live: {s['live_need']:g} Mbps -> reserve "
            f"{s['reserve_live']:g} Mbps.\nPlus one clip download: {s['with_download']:g} Mbps -> reserve {s['reserve']:g} "
            f"Mbps ({s['per_nvr']:g} per NVR / DVR).\nAll {s['cams']} cameras at once on sub-stream: {s['all_sub']:g} Mbps. "
            f"On main stream: {s['all_main']:g} Mbps (do not do this over the internet).\n10 Mbps shows about "
            f"{s['cams_in_10']} cameras at once; 20 Mbps about {s['cams_in_20']}.\nRecording stays on the local network: "
            f"{s['recording']:g} Mbps from all cameras -> use gigabit PoE switches.\nOne hour of video from a "
            f"{n('main', 3):g} Mbps camera downloads in about {mins:g} min at {s['reserve']:g} Mbps.\n"
            "Bitrates are typical: read the real ones in the NVR under Camera > Encode.")

    def use_reserve(self):
        if not hasattr(self, "size"):
            self.calc()
        self.vars["nvr"].set(f"{self.size['reserve']:g}")
        self.nb.select(self.f2)
        self.var_msg.set(f"NVR / DVR reserve set to {self.size['reserve']:g} Mbps. Check the other numbers add up, then Apply.")

    # ------------------------------------------------------------------ the chart
    def refresh_chart(self):
        c = getattr(self, "counts", {})
        pl = self.plan()
        self.spec = B.diagram_spec(c.get("cam", 0), c.get("nvr", 0), c.get("pc", 0), c.get("mobile", 0),
                                   min(pl.get("down", 100), pl.get("up", 100)), pl.get("nvr", 10))
        self.draw_chart()

    def draw_chart(self):
        if not self.spec:
            return
        cv = self.cv
        cv.delete("all")
        sp = self.spec
        sc = min(max(cv.winfo_width(), 300) / sp["w"], max(cv.winfo_height(), 200) / (sp["h"] + 56))
        fill, line = B._FILL, B._LINE
        for x1, y1, x2, y2, label, kind in B.diagram_lines(sp):
            col = "#b91c1c" if kind == "blocked" else "#15803d"
            cv.create_line(x1 * sc, y1 * sc, x2 * sc, y2 * sc, fill=col, width=2, arrow="last",
                           dash=(6, 4) if kind == "blocked" else ())
        for _i, title, lines, x, y, w, h, style in sp["nodes"]:
            cv.create_rectangle(x * sc, y * sc, (x + w) * sc, (y + h) * sc, fill=fill[style], outline=line[style], width=2)
            cv.create_text((x + 8) * sc, (y + 8) * sc, text=title, anchor="nw", fill=line[style],
                           font=("Segoe UI", max(7, int(10 * sc)), "bold"))
            for i, ln in enumerate(lines):
                cv.create_text((x + 8) * sc, (y + 28 + i * 15) * sc, text=ln, anchor="nw", fill="#344054",
                               font=("Segoe UI", max(6, int(8 * sc))))
        for x1, y1, x2, y2, label, kind in B.diagram_lines(sp):  # labels last, on a white box
            if label:
                mx, my = B.label_pos(x1, y1, x2, y2, kind)
                t = cv.create_text(mx * sc, my * sc, text=label, fill="#b91c1c" if kind == "blocked" else "#15803d",
                                   font=("Segoe UI", max(7, int(9 * sc)), "bold"))
                bb = cv.bbox(t)
                if bb:
                    r = cv.create_rectangle(bb[0] - 3, bb[1] - 2, bb[2] + 3, bb[3] + 2, fill="white", outline="")
                    cv.tag_lower(r, t)
        for i, ln in enumerate(sp["notes"]):
            cv.create_text(20 * sc, (sp["h"] + 6 + i * 18) * sc, text=ln, anchor="nw", fill="#475467",
                           font=("Segoe UI", max(6, int(8 * sc))))

    def save_chart(self):
        if not self.spec:
            self.refresh_chart()
        path = filedialog.asksaveasfilename(defaultextension=".svg", initialfile="camera-network-chart.svg",
                                            filetypes=[("SVG picture", "*.svg")])
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(B.diagram_svg(self.spec))
            self.var_msg.set(f"Chart saved: {os.path.basename(path)} (open it in any browser, or insert in Word).")
