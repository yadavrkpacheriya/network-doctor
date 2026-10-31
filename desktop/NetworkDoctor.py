#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Doctor - standalone network scanner, live monitor and root-cause tool for Windows and Mac.

Files: NetworkDoctor.py (this window), nd_core.py (scan engine), nd_monitor.py (monitor / traffic / RCA),
nd_tools.py + nd_tabs.py (tags, map, IP-MAC binding, commands), nd_net.py + nd_toolstab.py (engineer tools).
Build a single exe with Build_NetworkDoctor_EXE.bat.
"""

import csv
import ctypes
import datetime as dt
import html
import ipaddress
import json
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from collections import Counter, deque

import nd_core as core
import nd_monitor as M
import nd_update as U
import nd_share as SH
import nd_alerts as AL
import nd_tabs
import nd_tools as T
import nd_net as NT
import nd_toolstab
import nd_routeros as RO
import nd_usage as US
import nd_home

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, messagebox, filedialog

# a windowed exe has no console: give libraries somewhere harmless to print
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")
# sharp text on high-DPI laptop screens (must happen before the first window is created)
if core.IS_WIN:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

APP = "Network Doctor"
VERSION = "3.16.0"
SEV_ORDER = {"critical": 0, "warning": 1, "info": 2, "debug": 3}


def setup_tags(tv):
    tv.tag_configure("cat", font=("Segoe UI", 10, "bold"), background="#eef2f7")
    tv.tag_configure("critical", foreground="#b42318", background="#fdecea")
    tv.tag_configure("warning", foreground="#8a4b00", background="#fff4e0")
    tv.tag_configure("info", foreground="#0b5cad")
    tv.tag_configure("off", foreground="#98a2b3")
    tv.tag_configure("pass", foreground="#1f7a3d")
    tv.tag_configure("fail", foreground="#b42318", background="#fdecea")
    tv.tag_configure("warn", foreground="#8a4b00")
    tv.tag_configure("skip", foreground="#98a2b3")
    tv.tag_configure("hot", foreground="#5b21b6", background="#f3ecff")


def make_tree(parent, cols, heads, widths, first, height=None, selectmode="browse"):
    fr = ttk.Frame(parent)
    fr.pack(fill="both", expand=True)
    kw = {"height": height} if height else {}
    tv = ttk.Treeview(fr, columns=cols, show="tree headings" if first else "headings", selectmode=selectmode, **kw)
    if first:
        tv.heading("#0", text=first[0])
        tv.column("#0", width=first[1], stretch=False)
    for c, h, w in zip(cols, heads, widths):
        tv.heading(c, text=h)
        tv.column(c, width=w, stretch=(c == cols[-1]))
    ys = ttk.Scrollbar(fr, orient="vertical", command=tv.yview)
    xs = ttk.Scrollbar(fr, orient="horizontal", command=tv.xview)
    tv.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
    tv.grid(row=0, column=0, sticky="nsew")
    ys.grid(row=0, column=1, sticky="ns")
    xs.grid(row=1, column=0, sticky="ew")
    fr.rowconfigure(0, weight=1)
    fr.columnconfigure(0, weight=1)
    setup_tags(tv)
    return tv


def text_box(parent, **kw):
    fr = ttk.Frame(parent)
    fr.pack(fill="both", expand=True)
    t = tk.Text(fr, wrap="word", font=("Segoe UI", 10), padx=12, pady=10, relief="flat", **kw)
    ys = ttk.Scrollbar(fr, orient="vertical", command=t.yview)
    t.configure(yscrollcommand=ys.set)
    t.grid(row=0, column=0, sticky="nsew")
    ys.grid(row=0, column=1, sticky="ns")
    fr.rowconfigure(0, weight=1)
    fr.columnconfigure(0, weight=1)
    t.tag_configure("h1", font=("Segoe UI", 14, "bold"))
    t.tag_configure("h", font=("Segoe UI", 11, "bold"))
    t.tag_configure("crit", foreground="#b42318", font=("Segoe UI", 10, "bold"))
    t.tag_configure("warn", foreground="#8a4b00", font=("Segoe UI", 10, "bold"))
    t.tag_configure("ok", foreground="#1f7a3d")
    t.tag_configure("mute", foreground="#667085")
    t.tag_configure("mono", font=("Consolas", 10))
    return t


nd_tabs.UI.update(make_tree=make_tree, text_box=text_box)


# ==========================================================================
# Ping window with live graph
# ==========================================================================
class PingWindow(tk.Toplevel):
    def __init__(self, master, ip, name):
        super().__init__(master)
        self.title(f"Ping {name or ''} {ip}")
        self.geometry("720x380")
        self.ip = ip
        self.q = queue.Queue()
        self.res = []
        self.alive = True
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        self.var = tk.StringVar(value="starting...")
        ttk.Label(top, textvariable=self.var, font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Button(top, text="Open in browser", command=lambda: webbrowser.open(f"http://{ip}")).pack(side="right")
        self.cv = tk.Canvas(self, bg="white", height=260, highlightthickness=0)
        self.cv.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        threading.Thread(target=self._run, daemon=True).start()
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.after(300, self._poll)

    def _run(self):
        while self.alive:
            t0 = time.time()
            cmd = core.ping_cmd(self.ip, 1000)
            out = core.run(cmd, 4)
            m = re.search(r"time[=<]\s*([\d.]+)", out)
            self.q.put(float(m.group(1)) if (m and re.search("ttl", out, re.I)) else None)
            time.sleep(max(0.1, 1 - (time.time() - t0)))

    def _poll(self):
        if not self.alive:
            return
        while not self.q.empty():
            self.res.append(self.q.get())
        self.res = self.res[-300:]
        ok = [x for x in self.res if x is not None]
        n = len(self.res)
        if n:
            loss = 100 * (n - len(ok)) / n
            jit = (sum(abs(a - b) for a, b in zip(ok, ok[1:])) / (len(ok) - 1)) if len(ok) > 1 else 0
            self.var.set(f"Sent {n}  Lost {n - len(ok)} ({loss:.0f}%)   " +
                         (f"min {min(ok):.0f} / avg {sum(ok) / len(ok):.1f} / max {max(ok):.0f} ms   jitter {jit:.1f} ms"
                          if ok else "no replies (device off, or its firewall blocks ping)"))
            self._draw()
        self.after(500, self._poll)

    def _draw(self):
        c = self.cv
        c.delete("all")
        w, h = max(c.winfo_width(), 300), max(c.winfo_height(), 150)
        data = self.res[-120:]
        mx = max([x for x in data if x is not None] + [10])
        c.create_text(6, 6, anchor="nw", text=f"{mx:.0f} ms", fill="#667085")
        c.create_line(40, h - 20, w - 8, h - 20, fill="#d0d5dd")
        step = (w - 50) / max(len(data), 1)
        for i, v in enumerate(data):
            x = 42 + i * step
            if v is None:
                c.create_line(x, 20, x, h - 20, fill="#f04438", width=max(1, step - 1))
            else:
                y = h - 20 - (h - 40) * v / mx
                c.create_rectangle(x, y, x + max(1, step - 1), h - 20, fill="#2e90fa", outline="")
        c.create_text(6, h - 16, anchor="nw", text="red = lost", fill="#f04438")

    def _close(self):
        self.alive = False
        try:
            if self.usage:
                self.usage.flush(force=True)
        except Exception:
            pass
        self.destroy()


class CommandWindow(tk.Toplevel):
    """Runs tracert (or any command) and streams the output."""
    def __init__(self, master, title, cmd):
        super().__init__(master)
        self.title(title)
        self.geometry("720x420")
        self.t = text_box(self)
        self.t.configure(font=("Consolas", 10))
        self.q = queue.Queue()
        self.p = None
        self.closed = False
        threading.Thread(target=self._run, args=(cmd,), daemon=True).start()
        self.after(200, self._poll)
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _run(self, cmd):
        try:
            kw = {"creationflags": 0x08000000} if core.IS_WIN else {}
            self.p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", **kw)
            for line in self.p.stdout:
                self.q.put(line)
            self.q.put("\n[finished]\n")
        except Exception as e:
            self.q.put(f"error: {e}\n")

    def _poll(self):
        if self.closed:
            return
        try:
            while True:
                self.t.insert("end", self.q.get_nowait())
                self.t.see("end")
        except queue.Empty:
            pass
        self.after(200, self._poll)

    def _close(self):
        self.closed = True
        try:
            if self.p and self.p.poll() is None:
                self.p.kill()
        except Exception:
            pass
        self.destroy()


# ==========================================================================
# Device analysis (root cause for one device)
# ==========================================================================
class DeviceWindow(tk.Toplevel):
    def __init__(self, app, d):
        super().__init__(app)
        self.app, self.d = app, d
        self.title(f"Analyse {d['name'] or d['ip']} - {d['ip']}")
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{min(1150, sw - 60)}x{min(760, sh - 100)}+40+30")
        bar = ttk.Frame(self, padding=8)
        bar.pack(fill="x")
        ip = d["ip"]
        ttk.Button(bar, text="Ping (live graph)", command=lambda: PingWindow(app, ip, d["name"])).pack(side="left")
        ttk.Button(bar, text="Open in browser", command=lambda: app.open_web(d)).pack(side="left", padx=4)
        ttk.Button(bar, text="Traceroute", command=lambda: app.trace(d)).pack(side="left")
        if core.IS_WIN:
            ttk.Button(bar, text="Shared folders", command=lambda: subprocess.Popen(["explorer", f"\\\\{ip}"])).pack(side="left", padx=4)
            ttk.Button(bar, text="Remote Desktop", command=lambda: subprocess.Popen(["mstsc", f"/v:{ip}"])).pack(side="left")
        ttk.Button(bar, text="Refresh", command=self.refresh).pack(side="right")
        pw = ttk.PanedWindow(self, orient="vertical")
        pw.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        a, b = ttk.Frame(pw), ttk.Frame(pw)
        pw.add(a, weight=3)
        pw.add(b, weight=2)
        self.t = text_box(a)
        ttk.Label(b, text="Internet destinations of this device (from traffic data)", padding=(0, 4),
                  font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.tv = make_tree(b, ("port", "app", "org", "down", "up", "conns", "risk"),
                            ("Port", "App / service", "Organisation / name", "Download", "Upload", "Conns", "Risk"),
                            (60, 220, 260, 90, 90, 60, 300), first=("Remote address", 140))
        self.ping = None
        threading.Thread(target=self._quick_ping, daemon=True).start()
        self.local_apps = None
        if d.get("self"):
            threading.Thread(target=self._apps, daemon=True).start()
        self.refresh()
        self.after(4000, self._auto)

    def _auto(self):
        if self.winfo_exists():
            self.refresh()
            self.after(8000, self._auto)

    def _quick_ping(self):
        res = []
        for _ in range(10):
            res.append(core.ping(self.d["ip"], 1000))
        ok = [x for x in res if x is not None]
        self.ping = res

    def _apps(self):
        self.local_apps = M.local_pc_apps()

    def refresh(self):
        d, app = self.d, self.app
        mon = app.mon
        a = M.analyse_device(d, mon, app.orgs)
        typ, ev = M.ip_type(d, mon, app.db, app.raw)
        t = self.t
        y = t.yview()[0]
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", f"{d['name'] or '(no name)'}\n", "h1")
        t.insert("end", f"{d['ip']}   {d.get('mac') or ''}   {d.get('vendor') or ''}\n", "mono")
        t.insert("end", f"Category: {d['category']}  -  {d.get('reason', '')}\n")
        t.insert("end", f"IP address type: ", "h")
        t.insert("end", f"{typ}", "warn" if "tatic" in typ else "ok" if "DHCP" in typ else "mute")
        t.insert("end", f"   ({ev})\n")
        if d.get("ports"):
            t.insert("end", "Open services: " + ", ".join(core.PORTS.get(p, str(p)) for p in d["ports"]) + "\n")
        risky_open = [p for p in d.get("ports", []) if p in (23, 21, 5900)]
        if risky_open:
            t.insert("end", "Insecure services open on the device: " + ", ".join(core.PORTS[p] for p in risky_open) +
                     " - disable them or change default passwords.\n", "warn")
        if self.ping is not None:
            ok = [x for x in self.ping if x is not None]
            t.insert("end", "Ping test (10): ", "h")
            if ok:
                t.insert("end", f"{10 - len(ok)} lost, avg {sum(ok) / len(ok):.1f} ms, max {max(ok):.0f} ms\n",
                         "warn" if len(ok) < 10 or max(ok) > 50 else "ok")
            else:
                t.insert("end", "no replies (device off or blocks ping)\n", "mute")
        t.insert("end", "\nBandwidth\n", "h")
        if not mon or not mon.last_flow:
            t.insert("end", "No traffic data yet. Bandwidth, apps and sites need the router to send traffic data to "
                            "this PC (Setup tab, one time). Until then only the local checks above are available.\n", "mute")
        elif not a["rate"]:
            t.insert("end", "No internet traffic from this device since the monitor started.\n", "ok")
        else:
            r = a["rate"]
            u10, d10 = a.get("last10", (0, 0))
            t.insert("end", f"Now (2 min avg): {M.fmt_rate(r['down_bps'])} download, {M.fmt_rate(r['up_bps'])} upload   "
                            f"-   rank {a['rank'][0]} of {a['rank'][1]} devices\n")
            t.insert("end", f"Last 10 min: {M.fmt_bytes(d10)} down, {M.fmt_bytes(u10)} up   -   since monitor start: "
                            f"{M.fmt_bytes(r['down_total'])} down, {M.fmt_bytes(r['up_total'])} up\n")
        if a["has_flows"]:
            t.insert("end", "\nWhy it uses bandwidth\n", "h")
            for x in a["reasons"]:
                t.insert("end", "  - " + x + "\n")
            t.insert("end", "\nTop apps / services\n", "h")
            tot = sum(b for _, b in a["apps"]) or 1
            for name, b in a["apps"][:8]:
                t.insert("end", f"  {name:<45} {M.fmt_bytes(b):>10}  {b / tot * 100:4.0f}%\n", "mono")
            t.insert("end", "\nSafety check\n", "h")
            if a["risks"]:
                for sev, msg in a["risks"][:12]:
                    t.insert("end", ("  DANGER  " if sev == "critical" else "  CHECK   ") + msg + "\n",
                             "crit" if sev == "critical" else "warn")
            else:
                t.insert("end", f"  No dangerous destinations among {a['distinct']} internet addresses "
                                f"(checked against {app.threat.status}).\n", "ok")
            t.insert("end", "\nNote: HTTPS hides exact web pages; names come from the address owner, its DNS name "
                            "and the port used.\n", "mute")
        if self.local_apps is not None:
            t.insert("end", "\nPrograms on this PC with internet connections now\n", "h")
            for name, n, ips in self.local_apps[:15]:
                t.insert("end", f"  {name:<35} {n:>3} connection(s)  {', '.join(ips[:3])}\n", "mono")
        t.configure(state="disabled")
        t.yview_moveto(y)
        tv = self.tv
        tv.delete(*tv.get_children())
        for x in a["dests"][:150]:
            tag = (x["risk"][0],) if x["risk"] and x["risk"][0] in ("critical", "warning") else ()
            tv.insert("", "end", text=x["remote"], tags=tag,
                      values=(x["port"], x["app"], x["org"] or x["ptr"], M.fmt_bytes(x["down"]), M.fmt_bytes(x["up"]),
                              x["conns"], x["risk"][1] if x["risk"] else ""))


# ==========================================================================
# main window
# ==========================================================================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP} {VERSION}")
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{min(1360, sw - 40)}x{min(820, sh - 80)}+10+10")
        if core.IS_WIN:
            if sw < 1400:
                try:
                    self.state("zoomed")
                except Exception:
                    pass
        st = ttk.Style(self)
        for th in (("vista", "winnative", "clam") if core.IS_WIN else ("aqua", "clam") if core.IS_MAC else ("clam",)):
            try:
                st.theme_use(th)
                break
            except Exception:
                pass
        try:
            line = tkfont.nametofont("TkDefaultFont").metrics("linespace")
        except Exception:
            line = 16
        st.configure("Treeview", rowheight=max(22, line + 8))
        st.configure("Big.TButton", font=("Segoe UI", 10, "bold"), padding=(14, 4))
        self.q = queue.Queue()
        self.stop_ev = threading.Event()
        self.db = core.load_db()
        self.oui = {}
        self.raw = None
        try:
            self.usage = US.UsageStore(os.path.join(core.DATA_DIR, "usage.db"))
        except Exception:
            self.usage = None
        self._dns_poll_t = 0
        self.devices, self.issues, self.checks = [], [], []
        self.gw, self.lip = core.detect_network()
        try:
            self.net = NT.scan_network_for(self.lip, NT.local_prefix(self.lip))
        except Exception:
            self.net = str(ipaddress.ip_network(f"{self.lip}/24", strict=False))
        self.threat = M.ThreatIntel()
        self.orgs = M.OrgLookup()
        self.mon = None
        self.ev_seen = 0
        self.rca_cache = None
        self.selected_device = None
        self.tabs = {}
        self._nb_count = 0
        self._auto_init()
        self.watch_state = {}
        self.watch_wake = threading.Event()
        self.alive = True
        self._build()
        self.after(100, self._poll)
        self.after(2000, self._tick)
        threading.Thread(target=self._bg_load, daemon=True).start()
        self.last_scan_t = 0
        self.after(800, self.start_monitor)
        self.after(2500, self.start_scan)
        U.cleanup_leftovers()
        self.share = None
        if self.var_share.get() or self._settings().get("reports_enabled"):
            self.after(1200, self._ensure_share)
        self._self_inv_t = time.time() - 86400 + 45  # this PC's own inventory 45 s after start, then daily
        self.after(20000, self._daily_update)  # checks now only if today's 15:00 check was missed
        self.after(3000, self._after_update_note)
        threading.Thread(target=self._watch_loop, daemon=True).start()
        self.protocol("WM_DELETE_WINDOW", self._on_close_button)
        if "--minimized" in sys.argv:  # started automatically at login
            self.after(600, self.iconify)

    def _bg_load(self):
        self.q.put(("scapy", core.scapy_ok()))
        self.oui = core.load_oui(lambda m: self.q.put(("status", m)))
        self.reload_threats(False)

    def reload_threats(self, force):
        self.threat.load(force=force)
        mon = self.mon
        if mon:
            mon.traffic.recheck_all()
        self.q.put(("threat",))

    # ---------------------------------------------------------------- layout
    def _build(self):
        top = ttk.Frame(self, padding=(10, 8))
        top.pack(fill="x")
        ttk.Label(top, text="Network:").pack(side="left")
        self.var_net = tk.StringVar(value=self._settings().get("scan_nets") or self.net)
        ttk.Entry(top, textvariable=self.var_net, width=34).pack(side="left", padx=(4, 8))
        self.btn_scan = ttk.Button(top, text="Scan", style="Big.TButton", command=self.start_scan)
        self.btn_scan.pack(side="left")
        self.btn_stop = ttk.Button(top, text="Stop", command=self.stop_scan, state="disabled")
        self.btn_stop.pack(side="left", padx=6)
        self.var_deep = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Deep packet tests", variable=self.var_deep).pack(side="left", padx=6)
        self.var_fast = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Fast", variable=self.var_fast).pack(side="left")
        self.var_autoinfo = tk.StringVar(value="Auto checks: starting...")
        ttk.Label(top, textvariable=self.var_autoinfo, foreground="#1f7a3d").pack(side="left", padx=8)
        if core.IS_WIN and not core.is_admin():
            ttk.Button(top, text="Restart as Administrator (full tests)", command=self.elevate).pack(side="right")
        elif core.is_admin():
            ttk.Label(top, text="Administrator: full tests on", foreground="#1f7a3d").pack(side="right")
        else:
            ttk.Label(top, text="Standard tests (IP-conflict rounds need administrator)",
                      foreground="#8a4b00").pack(side="right")
        self.btn_update = ttk.Button(top, text=f"Updates (v{VERSION})", command=self.update_now)
        self.btn_update.pack(side="right", padx=6)
        self.var_mon = tk.StringVar(value="Live monitor: off")
        ttk.Label(top, textvariable=self.var_mon, foreground="#5b21b6").pack(side="right", padx=12)

        bar = ttk.Frame(self, padding=(10, 0))
        bar.pack(fill="x")
        self.pb = ttk.Progressbar(bar, maximum=100)
        self.pb.pack(fill="x", side="left", expand=True)
        self.var_status = tk.StringVar(value=f"This PC {self.lip}, gateway {self.gw}. Press Scan.")
        ttk.Label(bar, textvariable=self.var_status, width=62).pack(side="left", padx=10)
        self.var_sum = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.var_sum, padding=(10, 5), font=("Segoe UI", 10, "bold")).pack(fill="x")

        bot = ttk.Frame(self, padding=(10, 0, 10, 8))
        bot.pack(fill="x", side="bottom")
        ttk.Button(bot, text="Export report (HTML)", command=self.exp_html).pack(side="left")
        ttk.Button(bot, text="Export devices (Excel CSV)", command=self.exp_csv).pack(side="left", padx=6)
        ttk.Button(bot, text="Forget offline devices", command=self.forget_offline).pack(side="left")

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self._tab_home()
        self._tab_devices()
        self._tab_map()
        self._tab_monitor()
        self._tab_usage()
        self._tab_slow()
        self._tab_rca()
        self._tab_problems()
        self._tab_checks()
        self._tab_binding()
        self._tab_commands()
        self._tab_tools()
        self._tab_inventory()
        self._tab_alerts()
        self._tab_setup()
        names = ["home", "alerts", "devices", "inventory", "map", "monitor", "usage", "slow", "rca", "problems", "checks", "binding", "commands", "tools", "setup"]
        self.tabs = dict(zip(names, self.nb.tabs()))
        self._refresh_alerts()
        self.nb.bind("<<NotebookTabChanged>>", self._tab_changed)

    def _tab_devices(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Devices  ")
        sf = ttk.Frame(f, padding=(0, 6))
        sf.pack(fill="x")
        sf2 = ttk.Frame(f)
        sf2.pack(fill="x")
        ttk.Label(sf2, text='Search tips: several words must all match; dept:accounts  port:ether3  loc:"2nd floor"  '
                            'vendor:hikvision  type:printer', foreground="#667085").pack(side="left")
        ttk.Label(sf, text="Search:").pack(side="left")
        self.var_q = tk.StringVar()
        self.var_q.trace_add("write", lambda *a: self.fill_devices())
        ttk.Entry(sf, textvariable=self.var_q, width=34).pack(side="left", padx=6)
        self.var_fdept, self.var_floc, self.var_fshow = tk.StringVar(value="All"), tk.StringVar(value="All"), \
            tk.StringVar(value=T.SHOW[0])
        for label, var, field in (("Department:", self.var_fdept, "dept"), ("Location:", self.var_floc, "location")):
            ttk.Label(sf, text=label).pack(side="left", padx=(6, 0))
            cb = ttk.Combobox(sf, textvariable=var, width=14, state="readonly", values=["All"])
            cb.configure(postcommand=lambda cb=cb, field=field: cb.configure(
                values=["All"] + T.tag_values(self.devices, field)))
            cb.bind("<<ComboboxSelected>>", lambda e: self.fill_devices())
            cb.pack(side="left", padx=4)
        cb = ttk.Combobox(sf, textvariable=self.var_fshow, width=22, state="readonly", values=T.SHOW)
        cb.bind("<<ComboboxSelected>>", lambda e: self.fill_devices())
        cb.pack(side="left", padx=4)
        self.var_sort_bw = tk.BooleanVar(value=False)
        ttk.Checkbutton(sf, text="Sort by bandwidth", variable=self.var_sort_bw,
                        command=self.fill_devices).pack(side="left", padx=8)
        act = ttk.Frame(f, padding=(0, 6, 0, 0))
        act.pack(fill="x", side="bottom")
        self.var_sel = tk.StringVar(value="Select a device:")
        ttk.Label(act, textvariable=self.var_sel, width=42, font=("Segoe UI", 10, "bold")).pack(side="left")
        for txt, cmd in (("Analyse (root cause)", lambda: self.act("analyse")), ("Ping", lambda: self.act("ping")),
                         ("Open in browser", lambda: self.act("web")), ("Traceroute", lambda: self.act("trace")),
                         ("Tag...", lambda: self.act("label")), ("Show on map", lambda: self.act("map")),
                         ("Commands", lambda: self.act("cmds"))):
            ttk.Button(act, text=txt, command=cmd).pack(side="left", padx=3)
        cols = ("status", "dept", "ip", "iptype", "mac", "vendor", "bw", "services", "why", "notes")
        heads = ("Status", "Department", "IP", "IP type", "MAC address", "Vendor", "Bandwidth now", "Services",
                 "Why this category", "Notes")
        widths = (100, 110, 115, 105, 140, 170, 150, 200, 240, 220)
        self.tv = make_tree(f, cols, heads, widths, first=("Name", 210), selectmode="extended")
        ttk.Label(sf2, text="   Ctrl / Shift + click several devices, then Tag... to tag them all at once",
                  foreground="#667085").pack(side="left", padx=8)
        self.tv.bind("<Button-3>", self._menu)
        self.tv.bind("<Double-1>", lambda e: self.act("analyse"))
        self.tv.bind("<<TreeviewSelect>>", self._sel)
        self.row_dev = {}

    def _tab_map(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Network map  ")
        self.map = nd_tabs.MapTab(self, f)

    def _tab_home(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Home  ")
        self.M = M
        self.home = nd_home.HomeTab(self, f)

    def _tab_slow(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Slow website?  ")
        self.slow = nd_tabs.SlowTab(self, f)

    def _tab_usage(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Usage  ")
        self.usage_tab = nd_tabs.UsageTab(self, f)

    def _tab_binding(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  IP-MAC binding  ")
        self.binding = nd_tabs.BindingTab(self, f)

    def _tab_commands(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Commands  ")
        self.commands = nd_tabs.CommandsTab(self, f)

    def _tab_tools(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Tools  ")
        self.tools = nd_toolstab.ToolsTab(self, f)

    def _tab_alerts(self):
        f = ttk.Frame(self.nb)
        self.nb.insert(1, f, text="  Alerts  ")  # right after Home
        self.alerts_tab = nd_tabs.AlertsTab(self, f)

    def _tab_inventory(self):
        f = ttk.Frame(self.nb, padding=(0, 6, 0, 0))
        self.nb.insert(2, f, text="  Inventory  ")  # right after Devices
        self.tools._build_inventory(f)

    def show_tab(self, name):
        if name in self.tabs:
            self.nb.select(self.tabs[name])

    def _tab_changed(self, _=None):
        cur = self.nb.select()
        try:
            if cur == self.tabs.get("map"):
                self.map.redraw()
            elif cur == self.tabs.get("binding"):
                self.binding.refresh()
            elif cur == self.tabs.get("usage"):
                self.usage_tab.refresh()
            elif cur == self.tabs.get("home"):
                self.home.refresh()
            elif cur == self.tabs.get("slow"):
                self.slow.refresh()
            elif cur == self.tabs.get("commands"):
                self.commands.refresh()
            elif cur == self.tabs.get("tools"):
                self.tools.refresh_watch()
            elif cur == self.tabs.get("alerts"):
                self.alerts_tab.refresh()
            elif cur == self.tabs.get("inventory"):
                self.tools._inv_done(None, "")
        except Exception:
            pass

    def after_tags_changed(self):
        T.apply_tags(self.devices, self.db, self.mon.neighbors_copy() if self.mon else {})
        self._usage_devices()
        self.fill_devices()
        self._tab_changed()

    def open_device(self, d):
        DeviceWindow(self, d)

    def ping_device(self, d):
        PingWindow(self, d["ip"], d.get("name"))

    def ip_type_of(self, d):
        typ, _ = M.ip_type(d, self.mon, self.db, self.raw) if d.get("online") else ("", "")
        return "Not known yet" if typ == "Unknown" else typ

    def open_folder(self, path):
        try:
            if core.IS_WIN:
                os.startfile(path)
            else:
                subprocess.Popen(["open" if core.IS_MAC else "xdg-open", path])
        except Exception:
            pass

    def _tab_monitor(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Live monitor  ")
        top = ttk.Frame(f, padding=(0, 6))
        top.pack(fill="x")
        self.btn_mon = ttk.Button(top, text="Stop monitor", command=self.toggle_monitor)
        self.btn_mon.pack(side="left")
        self.mon_labels = {}
        g = ttk.Frame(top)
        g.pack(side="left", padx=14)
        for i, (k, lab) in enumerate((("flows", "Traffic data (bandwidth):"), ("syslog", "Router log (ether2 etc):"),
                                      ("sniffer", "Packet sniffer:"), ("health", "Right now:"))):
            ttk.Label(g, text=lab, font=("Segoe UI", 9, "bold")).grid(row=i // 2, column=(i % 2) * 2, sticky="w", padx=(0, 4))
            v = tk.StringVar(value="-")
            ttk.Label(g, textvariable=v, width=48).grid(row=i // 2, column=(i % 2) * 2 + 1, sticky="w")
            self.mon_labels[k] = v
        self.cv = tk.Canvas(f, bg="white", height=130, highlightthickness=1, highlightbackground="#d0d5dd")
        self.cv.pack(fill="x", pady=(2, 6))
        self.cv.bind("<Configure>", lambda e: self.mon and self._graph())
        pw = ttk.PanedWindow(f, orient="horizontal")
        pw.pack(fill="both", expand=True)
        a, b = ttk.Frame(pw), ttk.Frame(pw)
        pw.add(a, weight=1)
        pw.add(b, weight=1)
        ttk.Label(a, text="Top bandwidth users (double-click to analyse)", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.tt = make_tree(a, ("ip", "down", "up", "ten", "app", "site", "risk"),
                            ("IP", "Download", "Upload", "Last 10 min", "Main app", "Main website", "Risk"),
                            (105, 80, 80, 85, 150, 170, 150), first=("Device", 150))
        self.tt.bind("<Double-1>", self._talker_open)
        ttk.Label(b, text="Events timeline (newest first)", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.te = make_tree(b, ("sev", "src", "ev"), ("Level", "Source", "Event"), (70, 110, 520), first=("Time", 80))

    def _tab_rca(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Root cause  ")
        top = ttk.Frame(f, padding=(0, 6))
        top.pack(fill="x")
        ttk.Button(top, text="Run root cause analysis", style="Big.TButton", command=self.run_rca).pack(side="left")
        ttk.Label(top, text="Combines the scan, the live monitor timeline, router log and traffic data. "
                            "Leave the monitor running so intermittent problems (like ether2 restarting) are captured.",
                  foreground="#667085").pack(side="left", padx=10)
        self.trca = text_box(f)

    def _tab_problems(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Problems  ")
        pw = ttk.PanedWindow(f, orient="vertical")
        pw.pack(fill="both", expand=True)
        a, b = ttk.Frame(pw), ttk.Frame(pw)
        pw.add(a, weight=2)
        pw.add(b, weight=3)
        self.tp = make_tree(a, ("sev", "count"), ("Severity", "Devices"), (100, 80), first=("Problem", 700))
        self.tp.bind("<<TreeviewSelect>>", self._show_issue)
        self.txt = text_box(b)
        self.row_issue = {}

    def _tab_checks(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Health checks  ")
        self.tc = make_tree(f, ("res", "det"), ("Result", "Details"), (100, 800), first=("Check", 300))

    def _tab_setup(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Setup  ")
        top = ttk.Frame(f, padding=(0, 6))
        top.pack(fill="x")
        ttk.Button(top, text="Copy router commands", command=self.copy_setup).pack(side="left")
        ttk.Button(top, text="Allow in Windows Firewall", command=self.firewall).pack(side="left", padx=6)
        ttk.Button(top, text="Update threat lists", command=lambda: threading.Thread(
            target=self.reload_threats, args=(True,), daemon=True).start()).pack(side="left")
        self.var_threat = tk.StringVar(value="Threat lists: loading...")
        ttk.Label(top, textvariable=self.var_threat).pack(side="left", padx=10)
        up = ttk.Frame(f, padding=(0, 0, 0, 6))
        up.pack(fill="x")
        ttk.Button(up, text="Check for updates", command=lambda: self.check_updates(False)).pack(side="left")
        ttk.Label(up, text="   New versions:").pack(side="left")
        self.var_updmode = tk.StringVar(value=self._update_mode())
        cbu = ttk.Combobox(up, textvariable=self.var_updmode, values=list(self.UPDATE_MODES), width=34, state="readonly")
        cbu.pack(side="left", padx=4)

        def _mode(_=None):
            self._settings()["update_mode"] = self.UPDATE_MODES[self.var_updmode.get()]
            self._save_settings()
            if self.UPDATE_MODES[self.var_updmode.get()] != "off":
                self.check_updates(True, force=True)
        cbu.bind("<<ComboboxSelected>>", _mode)
        self.var_upd = tk.StringVar(value=f"Version {VERSION}")
        ttk.Label(up, textvariable=self.var_upd).pack(side="left", padx=10)
        ttk.Button(up, text="Release page", command=lambda: webbrowser.open(U.RELEASES_PAGE)).pack(side="right")
        au = ttk.LabelFrame(f, text="Automatic checks (24/7)", padding=(8, 4))
        au.pack(fill="x", pady=(0, 6))
        st = self._settings()
        ttk.Label(au, text="Full scan every").pack(side="left")
        self.var_full_min = tk.StringVar(value=str(st.get("auto_full_min", 30)))
        cb1 = ttk.Combobox(au, textvariable=self.var_full_min, values=["off", "15", "30", "60", "120"], width=5,
                           state="readonly")
        cb1.pack(side="left", padx=(4, 2))
        ttk.Label(au, text="min      Loop / conflict check every").pack(side="left")
        self.var_quick_min = tk.StringVar(value=str(st.get("auto_quick_min", 5)))
        cb2 = ttk.Combobox(au, textvariable=self.var_quick_min, values=["off", "2", "5", "10", "15"], width=5,
                           state="readonly")
        cb2.pack(side="left", padx=(4, 2))
        ttk.Label(au, text="min").pack(side="left")
        for cb in (cb1, cb2):
            cb.bind("<<ComboboxSelected>>", lambda e: self._save_auto())
        self.var_alerts = tk.BooleanVar(value=st.get("alerts", True))
        ttk.Checkbutton(au, text="Pop-up + sound for new problems", variable=self.var_alerts,
                        command=self._save_auto).pack(side="left", padx=12)
        self.var_alert_new = tk.BooleanVar(value=st.get("alert_new", True))
        ttk.Checkbutton(au, text="Alert when a new device joins", variable=self.var_alert_new,
                        command=self._save_auto).pack(side="left", padx=4)
        self.var_autostart = tk.BooleanVar(value=self._autostart_enabled())
        ttk.Checkbutton(au, text="Start with Windows" if core.IS_WIN else "Start at login",
                        variable=self.var_autostart, command=self.toggle_autostart).pack(side="left", padx=4)
        ttk.Button(au, text="Health log", command=self.open_health_log).pack(side="right")
        ttk.Button(au, text="Run check now", command=lambda: self.start_quick(manual=True)).pack(side="right", padx=6)
        ph = ttk.LabelFrame(f, text="Phone app link (office LAN only)", padding=(8, 4))
        ph.pack(fill="x", pady=(0, 6))
        self.var_share = tk.BooleanVar(value=self._settings().get("share_enabled", False))
        ttk.Checkbutton(ph, text="Allow the Network Doctor phone app to connect", variable=self.var_share,
                        command=self.toggle_share).pack(side="left")
        self.var_share_info = tk.StringVar(value="off")
        ttk.Label(ph, textvariable=self.var_share_info, font=("Segoe UI", 10, "bold")).pack(side="left", padx=12)
        ttk.Button(ph, text="Remove paired phones", command=self.forget_phones).pack(side="right")
        ttk.Button(ph, text="New pairing code", command=self.new_share_code).pack(side="right", padx=6)
        ro = ttk.LabelFrame(f, text="Router login (optional) - lets Network Doctor apply its own changes on a MikroTik "
                                    "and run router commands", padding=(8, 4))
        ro.pack(fill="x", pady=(0, 6))
        r = st.get("router_api") or {}
        self.var_ro_host = tk.StringVar(value=r.get("host") or self.gw or "")
        self.var_ro_user = tk.StringVar(value=r.get("user", ""))
        self.var_ro_pw = tk.StringVar(value=RO.unprotect(r.get("pw", "")) if r.get("pw") else "")
        self.var_ro_ssl = tk.BooleanVar(value=bool(r.get("ssl")))
        for lbl, var, w, show in (("Router IP", self.var_ro_host, 15, ""), ("User", self.var_ro_user, 12, ""),
                                  ("Password", self.var_ro_pw, 14, "*")):
            ttk.Label(ro, text=lbl + ":").pack(side="left", padx=(6, 2))
            ttk.Entry(ro, textvariable=var, width=w, show=show).pack(side="left")
        ttk.Checkbutton(ro, text="API-SSL (8729)", variable=self.var_ro_ssl).pack(side="left", padx=6)
        ttk.Button(ro, text="Save + test", command=self.router_save_test).pack(side="left", padx=4)
        ttk.Button(ro, text="Apply router settings now", command=lambda: self.router_apply(
            M.router_setup_commands(self.lip), "Router settings (NetFlow, log, SNMP, loop protection)")).pack(
            side="left", padx=4)
        ttk.Button(ro, text="Forget login", command=self.router_forget).pack(side="right")
        self.var_ro_info = tk.StringVar(value="saved - " + (r.get("ident") or "") if r.get("user") else
                                        "not set: commands are shown to paste in WinBox instead")
        ttk.Label(f, textvariable=self.var_ro_info, foreground="#5b21b6").pack(anchor="w", padx=8)
        self.tsetup = text_box(f)
        self._fill_setup()

    # ---------------------------------------------------------------- router access (optional)
    def router_save_test(self):
        user = self.var_ro_user.get().strip()
        if not user:
            messagebox.showinfo(APP, "Type the router user name and password first.\n\nTip: make a separate user "
                                     "for Network Doctor in WinBox > System > Users (group 'full', or 'write' + api), "
                                     "and in IP > Services allow 'api' only from this PC's IP.")
            return
        st = self._settings()
        st["router_api"] = {"host": self.var_ro_host.get().strip(), "user": user,
                            "pw": RO.protect(self.var_ro_pw.get()), "ssl": self.var_ro_ssl.get()}
        self._save_settings()
        self.var_ro_info.set("testing...")
        c = RO.from_settings(st, self.gw)

        def work():
            try:
                with c:
                    name, ver = c.identity()
                res = (True, f"connected to '{name}' (RouterOS {ver})")
            except RO.RosError as e:
                res = (False, str(e))
            self.q.put(("call", lambda: done(*res)))

        def done(ok, text):
            if ok:
                st["router_api"]["ident"] = text
                self._save_settings()
            self.var_ro_info.set(("saved - " if ok else "NOT working: ") + text)
            (messagebox.showinfo if ok else messagebox.showerror)(APP, ("Router login works: " if ok else "") + text)
        threading.Thread(target=work, daemon=True).start()

    def _router_fetch(self):
        """For the scan (worker thread): the router's ARP table and DHCP leases, with the names devices gave."""
        c = RO.from_settings(self._settings(), self.gw)
        if not c:
            return None
        try:
            with c:
                leases = c.leases()
                arp = c.cmd("/ip/arp/print")
        except RO.RosError as e:
            return {"error": str(e)}
        out_l = {}
        for x in leases:
            mac = core.norm_mac(x.get("mac-address", ""))
            if mac:
                out_l[mac] = {"host": (x.get("host-name") or "").strip()[:40], "ip": x.get("address", ""),
                              "static": x.get("dynamic") != "true", "status": x.get("status", "")}
        out_a = {}
        for x in arp:
            mac = core.norm_mac(x.get("mac-address", ""))
            if mac and x.get("address") and x.get("invalid") != "true" and not core.is_bad_mac(mac):
                out_a[x["address"]] = mac
        return {"leases": out_l, "arp": out_a}

    def router_forget(self):
        self._settings().pop("router_api", None)
        self._save_settings()
        self.var_ro_pw.set("")
        self.var_ro_info.set("not set: commands are shown to paste in WinBox instead")

    def router_client(self, ask=True):
        c = RO.from_settings(self._settings(), self.gw)
        if not c and ask:
            messagebox.showinfo(APP, "No router login is saved.\n\nSetup > Router login (user + password), or copy "
                                     "the commands and paste them in WinBox > New Terminal.")
        return c

    def router_apply(self, script, what, done=None):
        """Runs a RouterOS script on the router in the background; reports the result."""
        c = self.router_client()
        if not c:
            return False
        if not messagebox.askyesno(APP, f"Apply on the router now?\n\n{what}\n\nKeep the UNDO commands at hand."):
            return False
        self.var_status.set(f"{what}: sending to the router...")

        def work():
            try:
                with c:
                    err = c.run_script(script)
            except RO.RosError as e:
                err = str(e)
            self.q.put(("call", lambda: finish(err)))

        def finish(err):
            m = re.search(r"line (\d+)", err or "")
            lines = script.splitlines()
            if m and 0 < int(m.group(1)) <= len(lines):  # show the line the router refused
                err += f"\n\nLine {m.group(1)}:\n{lines[int(m.group(1)) - 1][:300]}"
            self._health_log("Router", "warning" if err else "info", f"{what}: " + (err or "applied").splitlines()[0])
            if err:
                self.var_status.set(f"{what}: the router reported a problem")
                messagebox.showerror(APP, f"{what}\n\nThe router refused the commands:\n{err}\n\nA line the router "
                                          "cannot read stops the whole script, so nothing was applied. Please report "
                                          "this line; meanwhile copy the commands and paste them in WinBox > New "
                                          "Terminal (there only that one line fails).")
            else:
                self.var_status.set(f"{what}: applied on the router.")
                messagebox.showinfo(APP, f"{what}: applied on the router.")
            if done:
                done(err)
        threading.Thread(target=work, daemon=True).start()
        return True

    def router_cli(self, command, title="Router"):
        """Runs one router command and shows its output in a window."""
        c = self.router_client()
        if not c:
            return
        win = tk.Toplevel(self)
        win.title(f"{title}: {command[:60]}")
        win.geometry("900x520")
        t = text_box(win)
        t.configure(font=("Consolas", 10))
        t.insert("end", f"[{c.host}] {RO.bounded(command)}\n\nrunning...\n")

        def work():
            try:
                with c:
                    out = c.run_cli(command)
            except RO.RosError as e:
                out = "Failed: " + str(e)
            self.q.put(("call", lambda: show(out)))

        def show(out):
            if not win.winfo_exists():
                return
            t.delete("3.0", "end")
            t.insert("end", (out.strip() or "(done - no output)") + "\n")
        threading.Thread(target=work, daemon=True).start()

    def _fill_setup(self):
        t = self.tsetup
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", "What works without any setup\n", "h")
        t.insert("end", "Scan, categories, IP conflicts, duplicate names, rogue DHCP, broadcast storms seen by this PC, "
                        "router ping stability, per-device ping / browser / traceroute.\n\n")
        t.insert("end", "What needs the router to SEND data to this PC (one time, 2 minutes)\n", "h")
        t.insert("end", "On a switched network a PC cannot see other devices' traffic or the router's ports. The router "
                        "is the only place that sees both, so it sends two standard feeds to this PC. Network Doctor "
                        "stays a separate app: without a router login (below) it never logs in to the router.\n")
        t.insert("end", "  - Traffic data (NetFlow, UDP 2055): bandwidth per device, apps / sites, dangerous destinations\n")
        t.insert("end", f"  - Router log (syslog, UDP {M.SYSLOG_PORT}): ether2 up/down, loops, DHCP vs static, IP conflicts\n\n")
        t.insert("end", f"Use a PC that stays on, with a fixed IP. This PC: {self.lip}\n", "warn")
        t.insert("end", "\nMikroTik commands (WinBox > New Terminal, paste once):\n", "h")
        t.insert("end", M.router_setup_commands(self.lip), "mono")
        t.insert("end", "\nOther brands: enable 'NetFlow v5/v9' or 'IPFIX' export to this PC port 2055, and "
                        f"'remote syslog' to this PC port {M.SYSLOG_PORT}.\n")
        t.insert("end", "\nOptional - packet sniffer (loop echo test, who sends the broadcasts, ARP-spoofing / NetCut "
                        "detection, DHCP requests): install Npcap from https://npcap.com and build the exe with Scapy.\n")
        t.configure(state="disabled")

    # ---------------------------------------------------------------- monitor
    def start_monitor(self):
        if self.mon and self.mon.running:
            return
        if core.IS_WIN and core.is_admin():  # in the background: netsh + PowerShell take a few seconds
            threading.Thread(target=self.firewall, kwargs={"quiet": True}, daemon=True).start()
        try:
            nets = core.parse_nets(self.var_net.get())
            local = next((n for n in nets if core.in_net(self.lip, n)), nets[0])
            lan = ", ".join(str(n) for n in [local] + [n for n in nets if n != local])  # this PC's network first
        except ValueError:
            lan = self.net
        self.mon = M.Monitor(lan, self.gw, self.lip, self.threat, self.orgs)
        if self.usage:
            self.mon.traffic.sink = self.usage.add_flow
            M.NAME_APP = self.usage.app_for
        self._feed_monitor()
        self.mon.start()
        self.ev_seen = 0
        self.te.delete(*self.te.get_children())
        self.btn_mon.configure(text="Stop monitor")

    def _feed_monitor(self):
        """Give the monitor what the scan learned: the router's real MAC and the DHCP lease time."""
        if not self.mon:
            return
        gwd = next((d for d in self.devices if d.get("online") and d.get("ip") == self.gw and d.get("mac")), None)
        if gwd:
            self.mon.gw_mac = gwd["mac"]
        if self.raw:
            self.mon.lease_time = M._lease_from_raw(self.raw) or self.raw["meta"].get("self_lease")

    def toggle_monitor(self):
        if self.mon and self.mon.running:
            self.mon.stop()
            self.btn_mon.configure(text="Start monitor")
            self._tick_once()
        else:
            self.start_monitor()

    def _tick(self):
        try:
            self._tick_once()
        except Exception:
            pass
        try:
            if self.nb.select() == self.tabs.get("home"):
                self.home.refresh()
            if time.time() - getattr(self, "_upd_tick_t", 0) > 60:  # daily 15:00 update check
                self._upd_tick_t = time.time()
                self._daily_update()
            if time.time() - getattr(self, "_self_inv_t", 0) > 86400:
                self._self_inventory()
            if time.time() - getattr(self, "_checklist_t", 0) > 10:  # for the phone app (read on another thread)
                self._checklist_t = time.time()
                self._checklist_cache = [{"ok": ok, "title": t, "detail": d}
                                         for ok, t, d, _, _ in self.home.checklist()]
        except Exception:
            pass
        try:
            self._share_label()
        except Exception:
            pass
        try:
            self._auto_tick()
        except Exception:
            pass
        try:
            nbs = len(self.mon.neighbors) if self.mon else 0
            if nbs != getattr(self, "_nb_count", 0) and self.devices:
                self._nb_count = nbs
                self.after_tags_changed()
        except Exception:
            pass
        self.after(2000, self._tick)

    def _note_feeds(self, mon):
        """Remembers that the router log / NetFlow arrived (and at which PC IP), at most every 10 minutes."""
        changed = False
        with core.DB_LOCK:
            seen = self.db.setdefault("feeds_seen", {})
            for k, last in (("syslog", mon.last_syslog), ("flow", mon.last_flow)):
                h = seen.get(k) or {}
                if last and (last - h.get("ts", 0) > 600 or h.get("lip") != mon.lip):
                    seen[k] = {"ts": last, "lip": mon.lip}
                    changed = True
        if changed:
            core.save_db(self.db)

    def _self_inventory(self):
        """This PC's own details for the inventory (Windows; PowerShell in the background, once a day)."""
        if not core.IS_WIN or getattr(self, "_self_inv_running", False):
            return
        self._self_inv_running = True
        self._self_inv_t = time.time()

        def work():
            try:
                out = core.run(T.local_inventory_cmd(), 180)
                hw = json.loads(out[out.find("{"):out.rfind("}") + 1]) if "{" in out else {}
                mac = core.local_mac(self.lip) or ""
                data = {"hostname": socket.gethostname(), "user": os.environ.get("USERNAME", ""),
                        "os": hw.get("os_name", ""), "hw": hw, "adapters": [{"mac": mac}] if mac else [],
                        "actions": ["details of the Network Doctor PC itself"]}
                if hw:
                    self.q.put(("call", lambda: self._apply_report(self.lip, data, quiet=True)))
            except Exception:
                pass
            finally:
                self._self_inv_running = False
        threading.Thread(target=work, daemon=True).start()

    def _usage_devices(self):
        """Tells the usage history which MAC / name is behind each IP (after a scan or a tag change)."""
        if self.usage:
            try:
                self.usage.set_devices(self.devices, T.tags_of(self.db))
            except Exception:
                pass

    def _usage_tick(self):
        """Saves usage every minute; every 3 minutes reads the router's DNS cache (names of internet addresses)."""
        if not self.usage:
            return
        try:
            self.usage.flush()
        except Exception:
            pass
        if time.time() - self._dns_poll_t < 60:  # router DNS cache: names of the sites each address belongs to
            return
        self._dns_poll_t = time.time()
        c = RO.from_settings(self._settings(), self.gw)
        if not c:
            return

        def work():
            try:
                with c:
                    rows = c.cmd("/ip/dns/cache/all/print")
                self.usage.learn_names(US.cache_pairs(rows))
            except Exception:
                pass
        threading.Thread(target=work, daemon=True).start()

    def _tick_once(self):
        mon = self.mon
        if not mon:
            return
        fs = mon.feed_status()
        self._note_feeds(mon)
        self._usage_tick()
        self.mon_labels["flows"].set(fs["flows"])
        self.mon_labels["syslog"].set(fs["syslog"])
        self.mon_labels["sniffer"].set(fs["sniffer"])
        b = f"{fs['bcast']:.0f}" if fs["bcast"] is not None else "?"
        g = (f"{fs['gw_avg']:.0f} ms avg, {fs['gw_max']:.0f} max" if fs["gw_avg"] is not None else
             "not answering" if fs["gw"] else "no router found")
        mc = f"  |  multicast {fs['mcast']:.0f}/s" if fs.get("mcast") is not None else ""
        bl = "broadcast+multicast" if fs.get("bcast_mixed") else "broadcasts"
        self.mon_labels["health"].set(f"{bl} {b}/s{mc}  |  router {g}, loss {fs['gw_loss']:.0f}%")
        rt = fs["runtime"]
        self.var_mon.set(f"Live monitor: {'ON' if mon.running else 'stopped'} {rt // 3600}h{rt % 3600 // 60:02d}m"
                         + (f" | {fs['bcast']:.0f} bc/s" if fs["bcast"] is not None else ""))
        # events
        for e in mon.events_since(self.ev_seen):
            self.ev_seen = e["seq"]
            if e["sev"] == "debug":
                continue
            self.te.insert("", 0, text=M.tstr(e["t"]), values=(e["sev"].upper(), e["src"], e["text"]),
                           tags=(e["sev"],))
            self._event_alert(e)
        kids = self.te.get_children()
        if len(kids) > 1500:
            self.te.delete(*kids[1500:])
        self._graph()
        self._talkers()
        if self.var_sort_bw.get() or mon.last_flow:
            self._update_bw_column()

    def _graph(self):
        c = self.cv
        c.delete("all")
        w, h = max(c.winfo_width(), 400), max(c.winfo_height(), 100)
        now = time.time()
        span = 600
        data = self.mon.samples_copy(now - span)
        x0 = 50
        sx = lambda t: x0 + (w - x0 - 10) * (t - (now - span)) / span
        c.create_line(x0, h - 18, w - 10, h - 18, fill="#d0d5dd")
        mb = max([s[1] for s in data if s[1] is not None] + [100])
        ml = max([s[2] for s in data if s[2] is not None] + [20])
        c.create_text(4, 4, anchor="nw", fill="#2e90fa", text=f"bcast {mb:.0f}/s")
        c.create_text(4, 18, anchor="nw", fill="#f79009", text=f"ping {ml:.0f} ms")
        c.create_text(x0, h - 4, anchor="sw", fill="#667085", text="10 min ago")
        c.create_text(w - 10, h - 4, anchor="se", fill="#667085", text="now")
        if mb > M.STORM_PPS:
            y300 = h - 18 - (h - 30) * M.STORM_PPS / mb
            c.create_line(x0, y300, w - 10, y300, fill="#fda29b", dash=(4, 3))
            c.create_text(w - 12, y300 - 2, anchor="se", fill="#f04438", text=f"storm level {M.STORM_PPS}/s")
        for iface, lst in self.mon.links_copy().items():
            for t, s in lst:
                if t >= now - span and s == "down":
                    x = sx(t)
                    c.create_line(x, 10, x, h - 18, fill="#f04438", width=2)
                    c.create_text(x + 2, 10, anchor="nw", fill="#f04438", text=f"{iface} down")
        pb, pl = [], []
        for t, b, ms in data:
            x = sx(t)
            if b is not None:
                pb += [x, h - 18 - (h - 30) * b / mb]
            if ms is not None:
                pl += [x, h - 18 - (h - 30) * ms / ml]
            else:
                c.create_line(x, h - 18, x, h - 26, fill="#f04438")
        if len(pb) >= 4:
            c.create_line(*pb, fill="#2e90fa", width=2)
        if len(pl) >= 4:
            c.create_line(*pl, fill="#f79009", width=1)

    def _talkers(self):
        tv = self.tt
        mon = self.mon
        if not mon.last_flow:
            if not tv.exists("wait"):
                tv.delete(*tv.get_children())
                tv.insert("", "end", iid="wait", text="Waiting for traffic data from the router",
                          values=("", "", "", "", "See Setup tab", ""))
            return
        if tv.exists("wait"):
            tv.delete("wait")
        rates = mon.traffic.rates(120)
        names = {d["ip"]: d for d in self.devices if d.get("online")}
        top = sorted(rates.items(), key=lambda x: -(x[1]["down_bps"] + x[1]["up_bps"]))[:30]
        cache = getattr(self, "_app_cache", {})
        now = time.time()
        keep = set()
        for pos, (ip, r) in enumerate(top):
            c = cache.get(ip)
            if not c or now - c[0] > 15:  # main app / risk summary refreshed every 15 s per device
                rem, threats, risks = mon.traffic.remotes(ip)
                rem.sort(key=lambda x: -(x[1][0] + x[1][1]))
                app_c, site_c = Counter(), Counter()
                for n, ((remote, svc, proto, inbound), v) in enumerate(rem[:300]):
                    info = self.orgs.get(remote) if n < 5 else self.orgs.cache_peek(remote)
                    known = self.usage.app_for(ip, remote) if (self.usage and not inbound) else None
                    app_c[known or M.classify(remote, svc, proto, info, inbound, ip)[0]] += v[0] + v[1]
                    site_c[self._site_name(ip, remote, info, svc, inbound)] += v[0] + v[1]
                main = app_c.most_common(1)[0][0] if app_c else ""
                site_c.pop("", None)
                main_site = site_c.most_common(1)[0][0] if site_c else ""
                bad = [k for k, v in threats.items() if v[1] != "tor" and not v[2]]
                risk = ("MALWARE: " + bad[0]) if bad else (sorted(risks)[0] if risks else "")
                c = cache[ip] = (now, main, risk, bool(bad), bool(risks), main_site)
            _, main, risk, bad, risky, main_site = c
            u10, d10 = mon.traffic.window_total(ip, 600)
            d = names.get(ip)
            tag = ("critical",) if bad else ("warning",) if risky else ("hot",) if r["down_bps"] + r["up_bps"] > 1.25e6 else ()
            iid = "t" + ip
            keep.add(iid)
            vals = (ip, M.fmt_rate(r["down_bps"]), M.fmt_rate(r["up_bps"]), M.fmt_bytes(u10 + d10), main, main_site,
                    risk)
            text = d["name"] if d and d["name"] else "-"
            if tv.exists(iid):
                tv.item(iid, text=text, values=vals, tags=tag)
                tv.move(iid, "", pos)
            else:
                tv.insert("", pos, iid=iid, text=text, values=vals, tags=tag)
        for iid in tv.get_children():
            if iid not in keep:
                tv.delete(iid)
        self._app_cache = cache

    def _site_name(self, lan, remote, info, port, inbound):
        """The website a device talks to: its DNS name when known, else the server's reverse name / owner."""
        if inbound:
            return ""
        name = ""
        if self.usage:
            try:
                name, _ = self.usage.name_for(lan, remote)
            except Exception:
                name = ""
        site = US.site_of(name) if name else ""
        if not site and port in M.P2P_PORTS:
            site = "peer-to-peer (torrent)"
        if not site:
            ptr, org = (info or {}).get("ptr", ""), (info or {}).get("org", "")
            site = US.pretty_site(f"{ptr} {org}".strip()) if (ptr or org) else ""
        return site

    def _talker_open(self, _):
        sel = self.tt.selection()
        if not sel:
            return
        ip = self.tt.item(sel[0], "values")[0]
        d = next((x for x in self.devices if x.get("ip") == ip), None)
        if d is None:
            d = {"ip": ip, "mac": "", "name": "", "category": core.CAT_UNK, "reason": "seen only in traffic data",
                 "ports": [], "vendor": "", "online": True, "names": {}, "notes": [], "ips": {ip}, "random": False}
        DeviceWindow(self, d)

    def _update_bw_column(self):
        if not self.mon or not self.mon.last_flow:
            return
        rates = self.mon.traffic.rates(120)
        for iid, d in self.row_dev.items():
            r = rates.get(d["ip"])
            if r and self.tv.exists(iid):
                self.tv.set(iid, "bw", f"\u2193 {M.fmt_rate(r['down_bps'])}  \u2191 {M.fmt_rate(r['up_bps'])}")

    # ---------------------------------------------------------------- scan
    def start_scan(self, auto=False):
        if getattr(self, "scanning", False):
            return
        if self.quick_running:  # the loop / conflict check finishes first (a few seconds)
            self.pending_scan = True
            self.var_status.set("Scan will start when the running check finishes...")
            return
        try:
            nets = core.parse_nets(self.var_net.get())
        except ValueError as e:
            messagebox.showerror(APP, "Enter one or more networks, separated by commas, like\n"
                                      "192.168.0.0/24, 192.168.1.0/24\n\n" + str(e))
            return
        net = ", ".join(map(str, nets))
        st = self._settings()
        if net != self.net:
            st["scan_nets"] = net  # remembered: the next start and the automatic scans use the same networks
        else:
            st.pop("scan_nets", None)
        self._save_settings()
        self.stop_ev.clear()
        self.scanning = True
        self._scan_is_auto = auto
        self.btn_scan.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        opts = {"deep": self.var_deep.get(), "fast": self.var_fast.get(),
                "router_snmp": self._settings().get("router_snmp") or None,
                "router_fetch": self._router_fetch if RO.from_settings(self._settings(), self.gw) else None}
        threading.Thread(target=self._worker, args=(net, opts), daemon=True).start()

    def stop_scan(self):
        self.stop_ev.set()
        self.var_status.set("Stopping...")

    def _worker(self, net, opts):
        try:
            t0 = time.time()
            raw = core.scan(net, opts, lambda p, s: self.q.put(("prog", p, s)), self.stop_ev)
            raw["meta"]["duration"] = int(time.time() - t0)
            if not self.oui:
                self.oui = core.load_oui()
            devices = core.build_devices(raw, self.oui, self.db)
            issues, checks = core.analyse(raw, devices, self.db)
            before = set(self.db.get("devices") or {})
            raw["meta"]["new_macs"] = [d["mac"] for d in devices if d.get("online") and d.get("mac")
                                       and d["mac"] not in before] if before else []
            core.update_db(self.db, raw, devices)
            self.q.put(("done", raw, devices, issues, checks))
        except core.Stopped:
            self.q.put(("stopped",))
        except Exception as e:
            import traceback
            self.q.put(("error", f"{e}\n\n{traceback.format_exc()[-1500:]}"))

    def _poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                k = msg[0]
                if k == "call":  # a background job's result, run here in the window's thread
                    msg[1]()
                elif k == "prog":
                    self.pb["value"] = msg[1]
                    self.var_status.set(msg[2])
                elif k == "status":
                    self.var_status.set(msg[1])
                elif k == "threat":
                    self.var_threat.set("Threat lists: " + self.threat.status)
                elif k == "scapy":
                    self.var_deep.set(bool(msg[1]))
                elif k == "upd":
                    self._on_update_info(*msg[1:])
                elif k in ("upd_prog", "upd_err", "upd_ready"):
                    self._on_update_msg(msg)
                elif k == "remote_scan":
                    self.start_scan()
                elif k == "done":
                    self.raw, self.devices, self.issues, self.checks = msg[1:]
                    self._finish()
                elif k == "stopped":
                    self._reset("Scan stopped.")
                elif k == "error":
                    self._reset("Scan failed.")
                    self.last_scan_t = time.time()  # the automatic scan tries again after the normal interval
                    self._health_log("Full scan", "warning", "scan failed: " + msg[1].splitlines()[0][:200])
                    if not getattr(self, "_scan_is_auto", False):  # unattended runs never block on a dialog
                        messagebox.showerror(APP, msg[1])
                    if self.pending_scan:
                        self.pending_scan = False
                elif k == "watch":
                    self._on_watch(*msg[1:])
                elif k == "pc_report":
                    self._apply_report(*msg[1:])
                elif k == "quick_done":
                    self._on_quick(*msg[1:])
                elif k == "quick_err":
                    self.quick_running = False
                    self.quick_summary = "check failed"
                    self._health_log("Loop / conflict check", "warning", "check failed: " + msg[1][:200])
                    self._auto_label()
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _reset(self, text):
        self.scanning = False
        self.btn_scan.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.pb["value"] = 0
        self.var_status.set(text)

    def _finish(self):
        m = self.raw["meta"]
        self._reset(f"Scan finished in {m['duration']} s at {m['finished']}.")
        self.pb["value"] = 100
        self.last_scan_t = time.time()
        self._feed_monitor()
        T.apply_tags(self.devices, self.db, self.mon.neighbors_copy() if self.mon else {})
        self._usage_devices()
        self.issues = self.issues + T.binding_issues(self.devices, self.db) + T.report_issues(self.db)
        self._new_devices(self.raw["meta"].get("new_macs") or [])
        conflict_ips = set()
        for i in self.issues:
            mm = re.match(r"IP conflict on (\S+)", i["title"])
            if mm:
                conflict_ips.add(mm.group(1))
        for d in self.devices:
            d["conflict"] = d["ip"] in conflict_ips
        on = sum(1 for d in self.devices if d["online"])
        c = Counter(i["sev"] for i in self.issues)
        cats = Counter(d["category"] for d in self.devices if d["online"])
        self.var_sum.set(f"{on} devices online   |   {c['critical']} critical   {c['warning']} warnings   {c['info']} notes"
                         "   |   " + "  ".join(f"{k.split(' (')[0].split(' /')[0]}: {v}" for k, v in
                                               sorted(cats.items(), key=lambda x: core.CAT_ORDER.index(x[0]))))
        self.fill_devices()
        self.fill_problems()
        self.fill_checks()
        if self.mon:
            self.mon.self_mac = self.raw.get("self_mac")
        self._evaluate("Full scan", self.issues, dhcp_tested=True)
        self._auto_label()
        self._tab_changed()

    # ---------------------------------------------------------------- tables
    def fill_devices(self):
        tv = self.tv
        tv.delete(*tv.get_children())
        qy = self.var_q.get().strip().lower()
        bad = {}
        for i in self.issues:
            if i["sev"] in ("critical", "warning"):
                for it in i["items"]:
                    for ip in re.findall(r"\d+\.\d+\.\d+\.\d+", it):
                        bad.setdefault(ip, i["sev"])
        rates = self.mon.traffic.rates(120) if self.mon and self.mon.last_flow else {}
        self.row_dev = {}
        for c in core.CAT_ORDER:
            ds = T.filter_devices([d for d in self.devices if d["category"] == c], qy,
                                  "" if self.var_fdept.get() == "All" else self.var_fdept.get(),
                                  "" if self.var_floc.get() == "All" else self.var_floc.get(), self.var_fshow.get())
            if self.var_sort_bw.get():
                ds.sort(key=lambda d: -sum((rates.get(d["ip"]) or {}).get(k, 0) for k in ("down_bps", "up_bps")))
            if not ds:
                continue
            parent = tv.insert("", "end", text=f"{c}  ({len(ds)})", open=True, tags=("cat",))
            for d in ds:
                svc = ", ".join(core.PORTS.get(p, str(p)) for p in d["ports"])
                up = d.get("upnp") or {}
                if up.get("modelName"):
                    svc = (svc + "; " if svc else "") + "UPnP: " + up["modelName"]
                elif d["http"] and (d["http"].get("title") or d["http"].get("server")):
                    svc = (svc + "; " if svc else "") + "web: " + (d["http"].get("title") or d["http"].get("server"))
                typ, _ = M.ip_type(d, self.mon, self.db, self.raw) if d["online"] else ("", "")
                typ = "Not known yet" if typ == "Unknown" else typ
                r = rates.get(d["ip"])
                bw = f"\u2193 {M.fmt_rate(r['down_bps'])}  \u2191 {M.fmt_rate(r['up_bps'])}" if r else ""
                tag = "off" if not d["online"] else bad.get(d["ip"], "")
                iid = tv.insert(parent, "end", text=d["name"] or "-", tags=(tag,) if tag else (),
                                values=(d["status"], d.get("dept", ""), ", ".join(sorted(d["ips"], key=core.ip_key)), typ,
                                        d["mac"] or "-",
                                        d["vendor"], bw, svc, d["reason"], "; ".join(d["notes"])))
                self.row_dev[iid] = d

    def fill_problems(self):
        tv = self.tp
        tv.delete(*tv.get_children())
        self.row_issue = {}
        if not self.issues:
            tv.insert("", "end", text="No problems found by the scan", tags=("pass",))
        for i in self.issues:
            iid = tv.insert("", "end", text=i["title"], values=(i["sev"].upper(), len(i["items"]) or ""), tags=(i["sev"],))
            self.row_issue[iid] = i
        kids = tv.get_children()
        if kids:
            tv.selection_set(kids[0])

    def _show_issue(self, _=None):
        sel = self.tp.selection()
        i = self.row_issue.get(sel[0]) if sel else None
        t = self.txt
        t.configure(state="normal")
        t.delete("1.0", "end")
        if i:
            t.insert("end", i["title"] + "\n", "h1")
            t.insert("end", "\n" + i["detail"] + "\n\n")
            t.insert("end", "How to fix: " + i["fix"] + "\n\n", "ok")
            for it in i["items"]:
                t.insert("end", "  - " + it + "\n", "mono")
        t.configure(state="disabled")

    def fill_checks(self):
        tv = self.tc
        tv.delete(*tv.get_children())
        lab = {"pass": "PASS", "fail": "FAIL", "warn": "CHECK", "skip": "SKIPPED"}
        for n, s, d in self.checks:
            tv.insert("", "end", text=n, values=(lab[s], d), tags=(s,))

    # ---------------------------------------------------------------- RCA
    def run_rca(self):
        finds, missing = M.rca_network(self.mon, self.devices, self.issues, self.db)
        self.rca_cache = (finds, missing)
        t = self.trca
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", f"Root cause analysis - {time.strftime('%d-%b-%Y %H:%M')}\n", "h1")
        if not self.raw:
            t.insert("end", "Tip: run a Scan too, so devices have names in the findings.\n", "mute")
        if not finds:
            t.insert("end", "\nNo problem pattern found in the data collected so far.\n", "ok")
        for n, f in enumerate(finds, 1):
            t.insert("end", f"\n{n}. {f['title']}\n", "h")
            t.insert("end", f"   Confidence: {f['conf']}\n", "crit" if f["conf"] == "High" else "warn")
            t.insert("end", "   Evidence:\n", "mute")
            for e in f["evidence"]:
                t.insert("end", f"     - {e}\n", "mono")
            t.insert("end", "   What to do:\n", "mute")
            for a in f["actions"]:
                t.insert("end", f"     > {a}\n", "ok")
        if missing:
            t.insert("end", "\nTo make this analysis more complete\n", "h")
            for m in missing:
                t.insert("end", f"  - {m}\n", "warn")
        t.configure(state="disabled")

    # ---------------------------------------------------------------- device actions
    def _sel(self, _=None):
        sel = [self.row_dev[i] for i in self.tv.selection() if i in self.row_dev]
        d = sel[0] if sel else None
        if d:
            self.selected_device = d
        self.var_sel.set((f"{len(sel)} devices selected" if len(sel) > 1 else f"{d['name'] or '-'}  {d['ip']}")
                         if d else "Select a device:")

    def _menu(self, ev):
        iid = self.tv.identify_row(ev.y)
        if iid not in self.row_dev:
            return
        if iid not in self.tv.selection():
            self.tv.selection_set(iid)
        m = tk.Menu(self, tearoff=0)
        for lab, k in (("Analyse (root cause)", "analyse"), ("Ping (live graph)", "ping"), ("Open in browser", "web"),
                       ("Traceroute", "trace"), (None, None), ("Tag (name, department, where connected)...", "label"),
                       ("Show on network map", "map"), ("Commands for this device", "cmds"),
                       ("Port scan", "ports"), ("Website / server check", "webcheck"),
                       ("Watch: alert if it stops answering", "watch"),
                       ("Open shared folders", "share"), ("Remote Desktop", "rdp"), ("Wake on LAN", "wol"),
                       (None, None), ("Copy IP", "cip"), ("Copy MAC", "cmac"), ("Copy all details", "call")):
            if lab is None:
                m.add_separator()
            else:
                m.add_command(label=lab, command=lambda k=k: self.act(k))
        m.tk_popup(ev.x_root, ev.y_root)

    def open_web(self, d):
        port = (d.get("http") or {}).get("port")
        if not port:
            for p in (80, 443, 8080, 8000, 8443):
                if p in d.get("ports", []):
                    port = p
                    break
        port = port or 80
        webbrowser.open(("https" if port in (443, 8443) else "http") + f"://{d['ip']}" +
                        ("" if port in (80, 443) else f":{port}"))

    def trace(self, d):
        cmd = ["tracert", "-d", "-w", "700", "-h", "15", d["ip"]] if core.IS_WIN else ["traceroute", "-n", d["ip"]]
        CommandWindow(self, f"Traceroute {d['ip']}", cmd)

    def act(self, what):
        sel = self.tv.selection()
        d = self.row_dev.get(sel[0]) if sel else None
        if not d:
            messagebox.showinfo(APP, "Select a device in the list first.")
            return
        ip, mac = d["ip"], d["mac"]
        try:
            if what == "analyse":
                DeviceWindow(self, d)
            elif what == "ping":
                PingWindow(self, ip, d["name"])
            elif what == "web":
                self.open_web(d)
            elif what == "trace":
                self.trace(d)
            elif what == "label":
                many = [self.row_dev[i] for i in self.tv.selection() if i in self.row_dev and self.row_dev[i].get("mac")]
                if not many:
                    messagebox.showinfo(APP, "This device has no MAC address to remember it by.")
                    return
                nd_tabs.TagDialog(self, many)
            elif what == "map":
                self.selected_device = d
                self.map.selected = d.get("mac") or d.get("ip")
                self.show_tab("map")
            elif what == "cmds":
                self.selected_device = d
                self.show_tab("commands")
            elif what == "share" and core.IS_WIN:
                subprocess.Popen(["explorer", f"\\\\{ip}"])
            elif what == "share" and core.IS_MAC:
                subprocess.Popen(["open", f"smb://{ip}"])
            elif what == "rdp" and core.IS_WIN:
                subprocess.Popen(["mstsc", f"/v:{ip}"])
            elif what == "wol" and mac:
                pre = int(self.net.split("/")[1]) if "/" in self.net else 24
                _, sent = NT.wake_on_lan(mac, self.lip, pre, ip)
                self.var_status.set(f"Wake-on-LAN sent to {mac} ({len(sent)} packets)")
            elif what == "ports":
                self.selected_device = d
                self.show_tab("tools")
                self.tools.show("ports")
                self.tools.var_ptarget.set(ip)
            elif what == "webcheck":
                self.show_tab("tools")
                self.tools.show("web")
                port = (d.get("http") or {}).get("port") or 80
                self.tools.var_url.set(("https://" if port in (443, 8443) else "http://") + ip +
                                       ("" if port in (80, 443) else f":{port}"))
            elif what == "watch" and mac:
                T.set_tag(self.db, mac, watch="1")
                core.save_db(self.db)
                self.watch_now()
                self.var_status.set(f"{d['name'] or ip} is now watched (Tools > Critical devices).")
            elif what in ("cip", "cmac", "call"):
                txt = ip if what == "cip" else mac if what == "cmac" else \
                    f"{d['name']}\t{', '.join(sorted(d['ips'], key=core.ip_key))}\t{mac}\t{d['vendor']}\t{d['category']}"
                self.clipboard_clear()
                self.clipboard_append(txt or "")
                self.var_status.set("Copied.")
        except Exception as e:
            messagebox.showerror(APP, str(e))

    # ---------------------------------------------------------------- misc
    def copy_setup(self):
        self.clipboard_clear()
        self.clipboard_append(M.router_setup_commands(self.lip))
        self.var_status.set("Router commands copied - paste them in WinBox > New Terminal.")

    def firewall(self, quiet=False):
        if not core.IS_WIN:
            return
        if not core.is_admin():
            if not quiet:
                messagebox.showinfo(APP, "Restart as Administrator first (button at top right).")
            return
        # Always re-create the rules, so ports added in newer versions are included.
        name = "Network Doctor receivers"
        core.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"], 10)
        core.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in", "action=allow",
                  "protocol=UDP", f"localport={M.FLOW_PORT},{M.SYSLOG_PORT},5678,8788", "profile=any"], 10)
        tname = "Network Doctor LAN (phone link, PC reports, speed test)"
        core.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={tname}"], 10)
        core.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={tname}", "dir=in", "action=allow",
                  "protocol=TCP", f"localport=8787,{NT.LAN_PORT}", "remoteip=localsubnet", "profile=any"], 10)
        # Clicking Cancel in Windows' "allow this app" prompt silently adds BLOCK rules for the exe. A block rule
        # wins over every allow rule, so the router log / NetFlow / phone link never arrive. Remove those.
        exe = sys.executable.replace("'", "''")
        removed = core.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                            f"$r=Get-NetFirewallApplicationFilter -Program '{exe}' -ErrorAction SilentlyContinue | "
                            "Get-NetFirewallRule -ErrorAction SilentlyContinue | "
                            "Where-Object {$_.Direction -eq 'Inbound' -and $_.Action -eq 'Block'}; "
                            "$n=@($r).Count; if($n){$r | Remove-NetFirewallRule}; $n"], 30).strip()
        self._settings()["fw_ok"] = time.time()
        self._save_settings()
        if not quiet:
            extra = (f"\n\nAlso removed {removed} Windows rule(s) that were BLOCKING Network Doctor (created when "
                     "Windows asked to allow the app and Cancel was clicked)." if removed.isdigit() and int(removed) else "")
            messagebox.showinfo(APP, f"Windows Firewall now allows the router feeds (UDP {M.FLOW_PORT}, {M.SYSLOG_PORT}) "
                                     f"and, from the office network only, the phone link / PC reports / LAN speed test "
                                     f"(TCP 8787, {NT.LAN_PORT})." + extra)

    def forget_offline(self):
        off = [d["mac"] for d in self.devices if not d["online"] and d["mac"]]
        if not off:
            messagebox.showinfo(APP, "No offline devices in memory.")
            return
        if messagebox.askyesno(APP, f"Forget {len(off)} offline device(s)? Labels are kept."):
            for mac in off:
                self.db["devices"].pop(mac, None)
            core.save_db(self.db)
            self.devices = [d for d in self.devices if d["online"]]
            self.fill_devices()

    def _ask_path(self, ext, kind):
        if not self.raw:
            messagebox.showinfo(APP, "Run a scan first.")
            return None
        os.makedirs(core.REPORT_DIR, exist_ok=True)
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
        return filedialog.asksaveasfilename(initialdir=core.REPORT_DIR, initialfile=f"network_{kind}_{stamp}{ext}",
                                            defaultextension=ext, filetypes=[(ext.upper()[1:], "*" + ext)])

    def exp_html(self):
        p = self._ask_path(".html", "report")
        if not p:
            return
        core.export_html(p, self.raw, self.devices, self.issues, self.checks)
        finds, missing = M.rca_network(self.mon, self.devices, self.issues, self.db)
        e = lambda x: html.escape(str(x))
        sec = ["<h2>Root cause analysis</h2>"]
        for f in finds:
            sev = "critical" if f["conf"] == "High" else "warning"
            sec.append(f"<div class='i {sev}'><span class='s {sev}'>{e(f['conf'])}</span><b>{e(f['title'])}</b><ul>" +
                       "".join(f"<li>{e(x)}</li>" for x in f["evidence"]) + "</ul><p class=fix>" +
                       "<br>".join(e(a) for a in f["actions"]) + "</p></div>")
        if not finds:
            sec.append("<div class=i>No problem pattern found.</div>")
        if self.mon and self.mon.last_flow:
            sec.append("<h2>Top bandwidth users (last 10 min)</h2><div class=c><table><tr><th>IP</th><th>Download</th>"
                       "<th>Upload</th></tr>")
            r = self.mon.traffic.rates(600)
            for ip, v in sorted(r.items(), key=lambda x: -(x[1]["down_bps"] + x[1]["up_bps"]))[:15]:
                sec.append(f"<tr><td>{e(ip)}</td><td>{e(M.fmt_rate(v['down_bps']))}</td><td>{e(M.fmt_rate(v['up_bps']))}</td></tr>")
            sec.append("</table></div>")
        with open(p, encoding="utf-8") as fh:
            doc = fh.read()
        doc = doc.replace("<h2>Problems</h2>", "".join(sec) + "<h2>Problems</h2>", 1)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(doc)
        webbrowser.open("file://" + os.path.abspath(p))

    def exp_csv(self):
        p = self._ask_path(".csv", "devices")
        if not p:
            return
        import csv
        rates = self.mon.traffic.rates(600) if self.mon and self.mon.last_flow else {}
        with open(p, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["Category", "Status", "Name", "IP", "All IPs", "IP type", "IP type evidence", "MAC", "Randomized",
                        "Vendor", "Download (10 min avg)", "Upload (10 min avg)", "Services", "Why category",
                        "Computer name", "First seen", "Notes"])
            for d in self.devices:
                typ, ev = M.ip_type(d, self.mon, self.db, self.raw) if d["online"] else ("", "")
                r = rates.get(d["ip"]) or {}
                w.writerow([d["category"], d["status"], d["name"], d["ip"], " ".join(sorted(d["ips"], key=core.ip_key)),
                            typ, ev, d["mac"], "yes" if d["random"] else "", d["vendor"],
                            M.fmt_rate(r["down_bps"]) if r else "", M.fmt_rate(r["up_bps"]) if r else "",
                            ", ".join(core.PORTS.get(x, str(x)) for x in d["ports"]), d["reason"],
                            d["names"].get("netbios", ""), d.get("first_seen", ""), "; ".join(d["notes"])])
        self.var_status.set(f"Saved {p}")

    def elevate(self):
        try:
            if getattr(sys, "frozen", False):
                exe, params = sys.executable, ""
            else:
                exe = sys.executable.replace("python.exe", "pythonw.exe") if sys.executable.endswith("python.exe") else sys.executable
                params = f'"{os.path.abspath(__file__)}"'
            os.environ.clear()  # the new copy must not inherit this one-file exe's private variables
            os.environ.update(U.clean_env())
            if ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, core.HERE, 1) > 32:
                self._close()
        except Exception as e:
            messagebox.showerror(APP, str(e))

    # ---------------------------------------------------------------- automatic checks (24/7) and alerts
    # monitor events that deserve a pop-up (critical / warning only); stp_tc is only logged
    ALERT_KINDS = {"storm", "loop", "loop_echo", "mac_flap", "gw_down", "arp_spoof", "threat", "conflict",
                   "rogue_dhcp", "router_power", "link_down", "exposed", "login_fail"}
    TASK_NAME = "Network Doctor"
    PLIST_ID = "io.github.yadavrkpacheriya.networkdoctor"

    def _auto_init(self):
        self.quick_running = False
        self.pending_scan = False
        self.last_quick_t = 0
        self.last_dhcp_probe = 0
        self.alerts_active = {}   # problem key -> {"title","sev","first","last","source"}
        self.alert_cool = {}      # monitor-event key -> time of last pop-up
        self.alert_mute_until = 0
        self.alert_win = None
        self.alert_lines = []
        self.alert_log = AL.AlertLog(os.path.join(core.DATA_DIR, "alerts.json"))
        self.quick_summary = "not run yet"

    @staticmethod
    def _interval(var):
        v = var.get().strip()
        return None if v == "off" or not v.isdigit() else int(v) * 60

    def _save_auto(self):
        st = self._settings()
        st["auto_full_min"] = self.var_full_min.get()
        st["auto_quick_min"] = self.var_quick_min.get()
        st["alerts"] = self.var_alerts.get()
        st["alert_new"] = self.var_alert_new.get()
        self._save_settings()
        self._auto_label()

    def _auto_label(self):
        f, q = self.var_full_min.get(), self.var_quick_min.get()
        txt = f"Auto: scan {'off' if f == 'off' else f + 'm'} \u00b7 check {'off' if q == 'off' else q + 'm'}"
        if self.quick_running:
            txt += " \u00b7 checking..."
        elif self.last_quick_t:
            txt += f" \u00b7 {time.strftime('%H:%M', time.localtime(self.last_quick_t))} {self.quick_summary}"
        n = len(self.alerts_active)
        self.var_autoinfo.set(txt + (f" \u00b7 {n} open" if n else ""))

    def _auto_tick(self):
        now = time.time()
        full, quick = self._interval(self.var_full_min), self._interval(self.var_quick_min)
        busy = getattr(self, "scanning", False) or self.quick_running
        if busy:
            return
        if full and self.last_scan_t and now - self.last_scan_t > full:
            self.start_scan(auto=True)
        elif quick and self.devices and now - max(self.last_quick_t, self.last_scan_t) > quick:
            self.start_quick()

    def start_quick(self, manual=False):
        if self.quick_running or getattr(self, "scanning", False):
            if manual:
                messagebox.showinfo(APP, "A scan or check is already running.")
            return
        if not self.devices:
            if manual:
                messagebox.showinfo(APP, "Run a full scan first - the check tests the devices it found.")
            return
        self.quick_running = True
        known = sorted({ip for d in self.devices if d.get("online") for ip in d.get("ips", [])}, key=core.ip_key)
        do_dhcp = manual or time.time() - self.last_dhcp_probe > 1800
        if do_dhcp:
            self.last_dhcp_probe = time.time()
        opts = {"deep": self.var_deep.get(), "dhcp": do_dhcp}
        net = self.var_net.get().strip() or self.net
        self._auto_label()
        threading.Thread(target=self._quick_worker, args=(net, known, opts), daemon=True).start()

    def _quick_worker(self, net, known, opts):
        try:
            raw = core.quick_check(net, known, opts)
            issues, checks = core.analyse_quick(raw, list(self.devices), self.db)
            self.q.put(("quick_done", raw, issues, checks, opts))
        except Exception as e:
            self.q.put(("quick_err", f"{type(e).__name__}: {e}"))

    def _on_quick(self, raw, issues, checks, opts):
        self.quick_running = False
        self.last_quick_t = time.time()
        # DHCP only counts as tested when replies could actually be received (Windows often blocks the listener)
        dhcp = bool(opts.get("dhcp")) and raw["meta"]["tests"].get("dhcp") is not None
        # the Problems and Health checks tabs always show the latest result of these checks
        keep = [i for i in self.issues if not core.QUICK_TITLES.search(i["title"])
                or (not dhcp and "dhcp" in i["title"].lower())]
        order = {"critical": 0, "warning": 1, "info": 2}
        self.issues = sorted(keep + issues, key=lambda i: order.get(i["sev"], 3))
        if not dhcp:
            checks = [c for c in checks if "DHCP" not in c[0]]
        names = {c[0] for c in checks}
        self.checks = [c for c in self.checks if c[0] not in names] + checks
        conflict_ips = {m.group(1) for i in self.issues for m in [re.match(r"IP conflict on (\S+)", i["title"])] if m}
        changed = False
        for d in self.devices:
            c = d["ip"] in conflict_ips
            changed = changed or (bool(d.get("conflict")) != c)
            d["conflict"] = c
        self.fill_problems()
        self.fill_checks()
        if changed:
            self.fill_devices()
        bad = [i for i in issues if i["sev"] in ("critical", "warning")]
        self.quick_summary = "OK" if not bad else f"{len(bad)} problem(s)"
        self._health_log("Loop / conflict check", "ok" if not bad else max((i["sev"] for i in bad), key=lambda s: order[s] * -1),
                         "OK - no loop, conflict or instability found" if not bad else
                         "; ".join(i["title"] for i in bad))
        self._evaluate("Loop / conflict check", issues, dhcp_tested=dhcp)
        self._auto_label()
        if self.pending_scan:
            self.pending_scan = False
            self.start_scan()

    @staticmethod
    def _akey(title):
        # numbers that change from check to check (e.g. "2500/second") must not make a "new" problem; IPs stay
        return re.sub(r"(?<![\d.])\d+(?:\.\d+)?(?![\d.])", "#", title)

    def _evaluate(self, source, issues, dhcp_tested=True):
        """Pop-up for problems that are new, a 'resolved' note for problems that went away."""
        now = time.time()
        found = {}
        for i in issues:
            if i["sev"] == "critical" or (i["sev"] == "warning" and core.QUICK_TITLES.search(i["title"])):
                found[self._akey(i["title"])] = i
        for k, i in found.items():
            if k not in self.alerts_active:
                self.alerts_active[k] = {"title": i["title"], "sev": i["sev"], "first": now, "source": source}
                self._raise_alert(i["sev"], i["title"], i["items"][:3], source)
            self.alerts_active[k]["last"] = now
        full = source == "Full scan"
        for k in list(self.alerts_active):
            a = self.alerts_active[k]
            if a.get("source") == "Device watch":
                continue  # the device watch resolves its own alerts
            covered = full or bool(core.QUICK_TITLES.search(a["title"]))
            if covered and not dhcp_tested and "dhcp" in a["title"].lower():
                covered = False
            if covered and k not in found:
                del self.alerts_active[k]
                self._log_event("info", f"Resolved: {a['title']}", source)
                if self.alert_log.resolve(a["title"]):
                    self.alert_log.save()
                    self._refresh_alerts()

    def _event_alert(self, e):
        if e["src"] == "Auto check" or e["sev"] not in ("critical", "warning") or e["kind"] not in self.ALERT_KINDS:
            return
        d = e.get("data") or {}
        key = (e["kind"], d.get("iface") or d.get("ip") or d.get("mac") or "")
        now = time.time()
        self._record_alert(e["sev"], e["text"], "Live monitor")  # every time: repeats are counted (auto-fix at 5)
        if now - self.alert_cool.get(key, 0) < 900:  # same kind of event on the same port/device: once per 15 min
            return
        self.alert_cool[key] = now
        self._health_log("Live monitor", e["sev"], f"{e['src']}: {e['text']}")
        if self.var_alerts.get() and now >= self.alert_mute_until:
            self._popup(e["sev"], e["text"])

    def _raise_alert(self, sev, title, items, source):
        text = title + (" - " + "; ".join(items) if items else "")
        self._log_event(sev, text, source)
        self._record_alert(sev, text, source)
        if self.var_alerts.get() and time.time() >= self.alert_mute_until:
            self._popup(sev, text)

    def _record_alert(self, sev, text, source):
        """Keeps the alert (time, priority, fix) for the Alerts tab, the export and the phone."""
        try:
            e = self.alert_log.add(sev, text, source, self.lip, self.gw)
            self.alert_log.save()
            self._refresh_alerts()
            self._auto_fix(e)
        except Exception:
            pass

    AUTO_FIX_AFTER = 5

    def _auto_fix(self, e):
        """The same problem 5 times: apply its safe router fix by itself (setting in Alerts; on by default)."""
        if e.get("count", 1) < self.AUTO_FIX_AFTER or e.get("autofix") or e.get("status") == "fixed" or \
                not self._settings().get("auto_fix", True):
            return
        r = AL.explain(e["text"], e["sev"], self.lip, self.gw)
        fix = next((a for a in r["auto"] if a["where"] == "router"), None) if r["kind"] in AL.AUTO_SAFE else None
        if not fix:
            return
        c = self.router_client(ask=False)
        if not c:
            return
        e["autofix"] = "trying"

        def work():
            try:
                with c:
                    err = c.run_script(fix["cmd"])
            except Exception as ex:
                err = str(ex)
            self.q.put(("call", lambda: done(err)))

        def done(err):
            e["autofix"] = "failed: " + err[:120] if err else "done"
            if not err:
                self.alert_log.set_status({e["id"]}, "fixed", f"auto-fixed after {e['count']} repeats: {fix['label']}")
            self.alert_log.save()
            self._refresh_alerts()
            self._log_event("info" if not err else "warning",
                            f"Auto-fix ({e['count']} repeats) - {fix['label']}: " + ("done" if not err else err[:120]),
                            "Auto-fix")
        threading.Thread(target=work, daemon=True).start()

    def _refresh_alerts(self):
        if threading.current_thread() is not threading.main_thread():
            self.q.put(("call", self._refresh_alerts))
            return
        tab = getattr(self, "alerts_tab", None)
        if tab:
            tab.refresh()
        try:
            n = len(self.alert_log.recent(3000, only_open=True))
            self.nb.tab(self.tabs["alerts"], text=f"  Alerts ({n})  " if n else "  Alerts  ")
        except Exception:
            pass

    def _log_event(self, sev, text, source):
        if self.mon:
            self.mon.event(sev, "Auto check", text, "auto")
        self._health_log(source, sev, text)

    def _health_log(self, source, level, text):
        """One line per check / problem in Documents/NetworkDoctor Reports/health-log-YYYY-MM.csv (opens in Excel)."""
        try:
            os.makedirs(core.REPORT_DIR, exist_ok=True)
            p = os.path.join(core.REPORT_DIR, time.strftime("health-log-%Y-%m.csv"))
            new = not os.path.exists(p)
            with open(p, "a", newline="", encoding="utf-8-sig" if new else "utf-8") as f:
                w = csv.writer(f)
                if new:
                    w.writerow(["Time", "Check", "Level", "Result"])
                w.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), source, level, text])
        except Exception:
            pass

    def open_health_log(self):
        p = os.path.join(core.REPORT_DIR, time.strftime("health-log-%Y-%m.csv"))
        if not os.path.exists(p):
            messagebox.showinfo(APP, "No health log yet - it starts with the first automatic check.")
            return
        try:
            if core.IS_WIN:
                os.startfile(p)
            else:
                subprocess.Popen(["open" if core.IS_MAC else "xdg-open", p])
        except Exception as e:
            messagebox.showerror(APP, str(e))

    def _popup(self, sev, text):
        self.alert_lines.append((time.strftime("%H:%M:%S"), sev, text))
        self.alert_lines = self.alert_lines[-40:]
        w = self.alert_win
        if w is None or not w.winfo_exists():
            w = self.alert_win = tk.Toplevel(self)
            w.title("Network Doctor - alert")
            w.geometry("760x400")
            try:
                w.attributes("-topmost", True)
            except Exception:
                pass
            bar = ttk.Frame(w, padding=6)
            bar.pack(fill="x", side="bottom")

            def show(tab):
                self.deiconify()
                self.lift()
                self.show_tab(tab)
                if tab == "rca":
                    self.run_rca()
                w.destroy()

            def mute():
                self.alert_mute_until = time.time() + 3600
                self.var_status.set("Alerts muted for 1 hour (they are still written to the health log).")
                w.destroy()
            def trouble():
                show("alerts")
                self.alerts_tab.open_latest()
            ttk.Button(bar, text="Troubleshoot", style="Big.TButton", command=trouble).pack(side="left")
            ttk.Button(bar, text="All alerts / export", command=lambda: show("alerts")).pack(side="left", padx=6)
            ttk.Button(bar, text="Root cause", command=lambda: show("rca")).pack(side="left")
            if "torrent" in text.lower():
                def torrent():
                    w.destroy()
                    self.show_tab("tools")
                    self.tools.show("guard")
                    for k, v in self.tools.g.items():
                        v.set(k == "torrent")
                    self.tools._guard_make()
                ttk.Button(bar, text="Block torrents...", style="Big.TButton", command=torrent).pack(side="left",
                                                                                                    padx=6)
            ttk.Button(bar, text="Mute 1 hour", command=mute).pack(side="right")
            ttk.Button(bar, text="Close", command=w.destroy).pack(side="right", padx=6)
            self.alert_txt = text_box(w)
        t = self.alert_txt
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", "New network problems\n", "h1")
        for ts, sv, tx in reversed(self.alert_lines):
            r = AL.explain(tx, sv, self.lip, self.gw)
            t.insert("end", f"{ts}  ", "mute")
            t.insert("end", r["prio_text"].upper() + "  ", "crit" if r["prio"] <= 2 else "warn")
            t.insert("end", tx + "\n")
            fx = r["fix"].replace("(the button below)", "(Troubleshoot)").replace("(button below)", "(Troubleshoot)")
            t.insert("end", "      Fix: " + fx + "\n", "mute")
        t.configure(state="disabled")
        try:
            w.deiconify()
            w.lift()
            if core.IS_WIN:
                import winsound
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            else:
                self.bell()
        except Exception:
            pass

    # ---- start with Windows / at Mac login (keeps the 24/7 checks running after a restart)
    def _launch_cmd(self):
        if getattr(sys, "frozen", False):
            return [sys.executable, "--minimized"]
        exe = sys.executable
        if core.IS_WIN and exe.lower().endswith("python.exe"):
            exe = exe[:-10] + "pythonw.exe"
        return [exe, os.path.abspath(__file__), "--minimized"]

    def _plist_path(self):
        return os.path.join(os.path.expanduser("~"), "Library", "LaunchAgents", self.PLIST_ID + ".plist")

    def _autostart_enabled(self):
        try:
            if core.IS_WIN:
                r = subprocess.run(["schtasks", "/Query", "/TN", self.TASK_NAME], capture_output=True,
                                   stdin=subprocess.DEVNULL, creationflags=0x08000000)
                return r.returncode == 0
            if core.IS_MAC:
                return os.path.exists(self._plist_path())
        except Exception:
            pass
        return False

    def toggle_autostart(self):
        on = self.var_autostart.get()
        ok, err = True, ""
        try:
            if core.IS_WIN:
                if on:  # Task Scheduler, highest privileges: starts at login without a UAC prompt
                    tr = subprocess.list2cmdline(self._launch_cmd())
                    cmd = ["schtasks", "/Create", "/TN", self.TASK_NAME, "/SC", "ONLOGON", "/RL", "HIGHEST",
                           "/DELAY", "0000:30", "/TR", tr, "/F"]
                else:
                    cmd = ["schtasks", "/Delete", "/TN", self.TASK_NAME, "/F"]
                r = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                                   creationflags=0x08000000, errors="replace")
                ok, err = r.returncode == 0, (r.stderr or r.stdout).strip()
            elif core.IS_MAC:
                p = self._plist_path()
                if on:
                    os.makedirs(os.path.dirname(p), exist_ok=True)
                    args = "".join(f"<string>{html.escape(a)}</string>" for a in self._launch_cmd())
                    with open(p, "w", encoding="utf-8") as f:
                        f.write('<?xml version="1.0" encoding="UTF-8"?>\n'
                                '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                                '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>'
                                f"<key>Label</key><string>{self.PLIST_ID}</string>"
                                f"<key>ProgramArguments</key><array>{args}</array>"
                                "<key>RunAtLoad</key><true/></dict></plist>\n")
                elif os.path.exists(p):
                    os.remove(p)
            else:
                ok, err = False, "only available on Windows and Mac"
        except Exception as e:
            ok, err = False, str(e)
        if not ok:
            self.var_autostart.set(not on)
            hint = "\n\nRestart Network Doctor as Administrator and try again." if core.IS_WIN and not core.is_admin() else ""
            messagebox.showerror(APP, f"Could not change the start-up setting: {err}{hint}")
        elif on:
            self.var_status.set("Network Doctor will start automatically (minimised) when you log in.")

    def _on_close_button(self):
        if (self._interval(self.var_quick_min) or self._interval(self.var_full_min)) and not messagebox.askyesno(
                APP, "Closing Network Doctor stops the automatic loop / conflict checks and the live monitor.\n\n"
                     "Close anyway?\n\n(No = keep it running minimised)"):
            self.iconify()
            return
        self._close()

    # ---------------------------------------------------------------- critical-device watch
    WATCH_EVERY = 30   # seconds between pings
    WATCH_FAILS = 3    # missed rounds before "down" (about 1.5 minutes)

    def watch_now(self):
        self.watch_wake.set()

    def _watch_targets(self):
        by_mac = {d["mac"]: d for d in list(self.devices) if d.get("mac")}
        hist = self.db.get("devices") or {}
        out = {}
        for mac, t in T.watched(self.db).items():
            d = by_mac.get(mac) or {}
            ip = d.get("ip") or (hist.get(mac) or {}).get("ip")
            if ip:
                out[mac] = (t.get("name") or d.get("name") or ip, ip, t.get("parent", ""))
        return out

    @staticmethod
    def _watch_ping(ip):
        for _ in range(2):
            t = NT.ping_times(core.run(core.ping_cmd(ip, 1000), 5))
            if t:
                return t[0]
        return None

    def _watch_loop(self):
        """Background thread: pings the watched devices and hands the results to the window."""
        time.sleep(5)
        while self.alive:
            try:
                targets = self._watch_targets()
                if targets:
                    items = list(targets.items())
                    pool = threading.BoundedSemaphore(16)
                    res = {}

                    def one(mac, ip):
                        with pool:
                            res[mac] = self._watch_ping(ip)
                    ths = [threading.Thread(target=one, args=(m, v[1]), daemon=True) for m, v in items]
                    for th in ths:
                        th.start()
                    for th in ths:
                        th.join(10)
                    self.q.put(("watch", targets, dict(res)))
            except Exception:
                pass
            self.watch_wake.wait(self.WATCH_EVERY)
            self.watch_wake.clear()

    def _on_watch(self, targets, res):
        now = time.time()
        for mac in list(self.watch_state):
            if mac not in targets:
                self.watch_state.pop(mac, None)
                self.alerts_active.pop(f"watch:{mac}", None)
        tags = T.tags_of(self.db)
        names = {d.get("mac"): d.get("name") or d.get("ip") for d in self.devices if d.get("mac")}
        for mac, (name, ip, parent) in targets.items():
            st = self.watch_state.setdefault(mac, {"fails": 0, "down_since": None, "downs": 0, "rtt": None,
                                                   "hist": deque(maxlen=24 * 3600 // self.WATCH_EVERY)})
            st["name"], st["ip"] = name, ip
            rtt = res.get(mac)
            st["hist"].append((now, rtt is not None))
            if rtt is not None:
                st["rtt"] = rtt
                if st["down_since"]:
                    mins = (now - st["down_since"]) / 60
                    self.alerts_active.pop(f"watch:{mac}", None)
                    self._log_event("info", f"Back up: {name} ({ip}) answers again after {mins:.0f} min", "Device watch")
                    st["last_down"] = st["down_since"]
                    st["down_since"] = None
                st["fails"] = 0
            else:
                st["fails"] += 1
                if st["fails"] >= self.WATCH_FAILS and not st["down_since"]:
                    st["down_since"] = now - (self.WATCH_FAILS - 1) * self.WATCH_EVERY
                    st["downs"] += 1
                    title = f"Critical device not answering: {name} ({ip})"
                    pname = (tags.get(parent, {}).get("name") or names.get(parent)) if parent else ""
                    same = [v["name"] for m, v in self.watch_state.items() if m != mac and v.get("down_since")
                            and parent and (tags.get(m, {}).get("parent") == parent)]
                    hint = (f"also down behind {pname}: {', '.join(same)} - check {pname} and its uplink" if same else
                            f"connected to {pname} - check its power, cable and that switch port" if pname else
                            "check its power and cable; tag where it is connected so the map shows the path")
                    self.alerts_active[f"watch:{mac}"] = {"title": title, "sev": "critical", "first": now,
                                                          "last": now, "source": "Device watch"}
                    self._raise_alert("critical", title, [hint], "Device watch")
        self._auto_label()
        try:
            if self.nb.select() == self.tabs.get("tools"):
                self.tools.refresh_watch()
            if self.nb.select() == self.tabs.get("map") and any(v.get("down_since") for v in self.watch_state.values()):
                self.map.redraw()
        except Exception:
            pass

    def _new_devices(self, macs):
        """New MAC addresses since the earlier scans (listed in Problems by the scan engine): a note and a pop-up."""
        if not macs:
            return
        news = [d for d in self.devices if d.get("mac") in set(macs)]
        items = [f"{d.get('name') or '-'}  {d.get('ip')}  {d.get('mac')}  {d.get('vendor') or ''}  ({d.get('category')})"
                 + ("  random MAC" if d.get("random") else "") for d in news]
        for d in news:
            d.setdefault("notes", []).append("NEW on the network")
        txt = "New device(s) on the network: " + "; ".join(i.split("  (")[0] for i in items[:4]) + (
            f" and {len(items) - 4} more" if len(items) > 4 else "")
        self._health_log("Full scan", "info", txt)
        self._record_alert("warning", txt, "Full scan")
        if self.mon:
            self.mon.event("info", "Auto check", txt, "auto")
        if self._settings().get("alert_new", True) and self.var_alerts.get() and time.time() >= self.alert_mute_until:
            self._popup("warning", txt)

    # ---------------------------------------------------------------- phone link
    def toggle_share(self):
        on = self.var_share.get()
        self._settings()["share_enabled"] = on
        self._save_settings()
        self._ensure_share()

    def enable_reports(self):
        """Lets PC fix scripts report back (also when the phone link is off). Returns the report key."""
        self._settings()["reports_enabled"] = True
        self._save_settings()
        self._ensure_share()
        return self._settings().setdefault("share", {}).get("report_key", "")

    def _ensure_share(self):
        on = self.var_share.get()
        need = on or self._settings().get("reports_enabled", False)
        if need and not (self.share and self.share.running):
            store = self._settings().setdefault("share", {})
            self.share = SH.ShareServer(APP, VERSION, self._snapshot, self._remote_cmd, store, self._save_settings,
                                        report_fn=lambda client, data: self.q.put(("pc_report", client, data)))
            self._save_settings()
            if not self.share.start():
                if on:
                    self.var_share.set(False)
                messagebox.showerror(APP, "Phone link / PC reports could not start: " + (self.share.error or "?"))
                self.share = None
            elif core.IS_WIN and core.is_admin():
                name = "Network Doctor phone link"
                if name not in core.run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"], 10):
                    core.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in",
                              "action=allow", "protocol=TCP", f"localport={SH.HTTP_PORT}", "remoteip=localsubnet"], 10)
                    core.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name} discovery", "dir=in",
                              "action=allow", "protocol=UDP", f"localport={SH.DISCOVERY_PORT}", "remoteip=localsubnet"], 10)
        elif not need and self.share:
            self.share.stop()
            self.share = None
        if self.share:
            self.share.pairing_enabled = on
        self._share_label()

    def _apply_report(self, client, data, quiet=False):
        """A PC fix script reported: tag every adapter MAC of that PC with its computer name."""
        host = str(data.get("hostname") or "")[:40]
        user = str(data.get("user") or "")[:60]
        tags = T.tags_of(self.db)
        macs = []
        for a in data.get("adapters") or []:
            if not isinstance(a, dict):
                continue
            for key in ("mac", "permanent"):
                mac = core.norm_mac(str(a.get(key) or ""))
                if mac and not core.is_bad_mac(mac) and mac not in macs:
                    macs.append(mac)
        for mac in macs:
            t = tags.get(mac, {})
            T.set_tag(self.db, mac, name=None if t.get("name") else host,
                      notes=None if t.get("notes") else f"user {user}" if user else None)
        links = []
        for a in data.get("adapters") or []:
            if isinstance(a, dict) and str(a.get("status", "")).lower() == "up" and not a.get("wifi"):
                try:
                    links.append({"name": str(a.get("name") or "")[:40], "speed": str(a.get("speed") or "")[:20],
                                  "bps": int(a.get("bps") or 0), "duplex": a.get("duplex") if isinstance(
                                      a.get("duplex"), bool) else None, "errors": int(a.get("errors") or 0)})
                except (TypeError, ValueError):
                    pass
        with core.DB_LOCK:
            self.db.setdefault("pc_reports", {})[host or client] = {
                "time": core.now_s(), "ip": client, "user": user, "os": str(data.get("os") or "")[:60], "macs": macs,
                "links": links[:6], "actions": [str(x)[:120] for x in (data.get("actions") or [])][:10],
                "hw": T.clean_hw(data.get("hw"))}
        core.save_db(self.db)
        acts = "; ".join(str(x) for x in (data.get("actions") or [])[:4])
        if not quiet and acts != "daily inventory report":
            self._log_event("info", f"PC fix script ran on {host} ({client}) - {acts}", "PC fix script")
        rx = T.REPORT_TITLES
        self.issues = [i for i in self.issues if not rx.search(i["title"])] + T.report_issues(self.db)
        self.fill_problems()
        self.after_tags_changed()

    def _share_label(self):
        sh = self.share
        if not sh or not sh.running:
            self.var_share_info.set("off")
            return
        if not sh.pairing_enabled:
            self.var_share_info.set(f"phone link off - accepting PC fix script reports on {self.lip}")
            return
        n = len(sh.phones())
        last = ""
        if sh.last_client and time.time() - sh.last_client[1] < 30:
            last = f"   |   phone {sh.last_client[0]} connected"
        warn = f"   ({sh.error})" if sh.error else ""
        self.var_share_info.set(f"Pairing code: {sh.code}    PC address: {self.lip}    Paired phones: {n}{last}{warn}")

    def new_share_code(self):
        if self.share:
            self.share.code = SH.ShareServer.new_code()
            self._share_label()

    def forget_phones(self):
        if not self.share:
            store = self._settings().get("share", {})
            store["phones"] = {}
            self._save_settings()
            return
        phones = self.share.phones()
        if phones and messagebox.askyesno(APP, f"Remove {len(phones)} paired phone(s)? They will need a new code."):
            for tok, _ in phones:
                self.share.forget(tok)
        self._share_label()

    # ---------------------------------------------------------------- phone app actions (phone-link thread)
    def _job(self, title, fn):
        """Runs fn() -> text in the background; the phone polls with action 'job'."""
        jobs = self.__dict__.setdefault("phone_jobs", {})
        jid = f"{int(time.time() * 1000)}"
        jobs[jid] = {"id": jid, "title": title, "done": False, "ok": None, "text": "", "t": time.time()}

        def work():
            try:
                text = fn()
                jobs[jid].update(done=True, ok=True, text=str(text or "done")[:20000])
            except Exception as e:
                jobs[jid].update(done=True, ok=False, text=f"{type(e).__name__}: {e}"[:2000])
        threading.Thread(target=work, daemon=True).start()
        for k in [k for k, v in jobs.items() if time.time() - v["t"] > 3600]:
            jobs.pop(k, None)
        return {"ok": True, "job": jid, "message": title + " started"}

    def _router_job(self, title, script):
        c = self.router_client(ask=False)
        if not c:
            return {"ok": False, "message": "No router login is saved on the PC (Setup > Router login)."}

        def run():
            with c:
                err = c.run_script(script)
            self._health_log("Router", "warning" if err else "info", f"{title} (from the phone): {err or 'applied'}")
            if err:
                raise RuntimeError("the router refused it: " + err)
            return f"{title}: applied on the router."
        return self._job(title, run)

    def _dev_by(self, args):
        mac = core.norm_mac(str(args.get("mac") or "")) if args.get("mac") else ""
        ip = str(args.get("ip") or "")
        for d in list(self.devices):
            if mac and d.get("mac") == mac or not mac and ip and d.get("ip") == ip:
                return d
        return None

    def _remote_cmd(self, name, args=None):
        """Actions the paired phone app may run. Always answers a dict {ok, message[, job]}."""
        a = args if isinstance(args, dict) else {}
        try:
            return self._remote(name, a)
        except Exception as e:
            return {"ok": False, "message": f"{type(e).__name__}: {e}"}

    def _remote(self, name, a):
        ipre = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        if name == "scan":
            if getattr(self, "scanning", False):
                return "a scan is already running"
            self.q.put(("remote_scan",))
            return "scan started"
        if name == "job":
            j = (self.__dict__.get("phone_jobs") or {}).get(str(a.get("id")))
            return dict(j, ok=True) if j else {"ok": False, "message": "unknown job"}
        if name == "quick":
            self.q.put(("call", lambda: self.start_quick(manual=True)))
            return {"ok": True, "message": "Quick check started on the PC"}
        if name in ("ping", "trace"):
            ip = str(a.get("ip", ""))
            if not ipre.match(ip):
                return {"ok": False, "message": "not an IP address"}
            if name == "ping":
                cmd = ["ping", "-n", "8", ip] if core.IS_WIN else ["ping", "-c", "8", ip]
            else:
                cmd = ["tracert", "-d", "-w", "700", "-h", "15", ip] if core.IS_WIN else ["traceroute", "-n", ip]
            return self._job(f"{'Ping' if name == 'ping' else 'Traceroute'} {ip} from the PC", lambda: core.run(cmd, 90))
        if name == "wol":
            mac = core.norm_mac(str(a.get("mac", "")))
            pre = int(self.net.split("/")[1]) if "/" in (self.net or "") else 24
            m, sent = NT.wake_on_lan(mac, self.lip, pre, a.get("ip"))
            return {"ok": True, "message": f"Magic packet for {m} sent to {', '.join(sent)}"}
        if name == "tag":
            mac = core.norm_mac(str(a.get("mac", "")))
            if not mac:
                return {"ok": False, "message": "this device has no MAC address"}
            vals = {k: str(a[k])[:60] for k in ("name", "dept", "location", "notes") if k in a}

            def do():
                T.set_tag(self.db, mac, **vals)
                self.after_tags_changed()
            self.q.put(("call", do))
            return {"ok": True, "message": "Saved on the PC"}
        if name == "alert_status":
            self.alert_log.set_status({str(a.get("id"))}, "fixed" if a.get("status") == "fixed" else "open",
                                      "marked on the phone")
            self.alert_log.save()
            self._refresh_alerts()
            return {"ok": True, "message": "Alert updated"}
        if name == "alert_fix":
            x = self.alert_log.get(str(a.get("id")))
            if not x:
                return {"ok": False, "message": "alert not found"}
            r = AL.explain(x["text"], x["sev"], self.lip, self.gw)
            fixes = [f for f in r["auto"] if f["where"] in ("router", "router_read")]
            n = int(a.get("n", 0))
            if not 0 <= n < len(fixes):
                return {"ok": False, "message": "no automatic fix for this alert"}
            f = fixes[n]
            cmd = f["cmd"]
            if cmd in ("@torrent_guard", "@dhcp_guard"):
                cmd = T.guard_commands({"torrent" if "torrent" in cmd else "dhcp": True}, [], self.lip, "bridge")[0]
            if f["where"] == "router_read":
                c = self.router_client(ask=False)
                if not c:
                    return {"ok": False, "message": "No router login is saved on the PC."}

                def read():
                    with c:
                        return c.run_cli(cmd)
                return self._job(f["label"], read)
            res = self._router_job(f["label"], cmd)
            if res.get("ok"):
                self.alert_log.set_status({x["id"]}, "fixed", "fixed from the phone: " + f["label"])
                self.alert_log.save()
                self._refresh_alerts()
            return res
        if name == "block":
            d = self._dev_by(a)
            mac = (d or {}).get("mac") or core.norm_mac(str(a.get("mac", "")))
            if not mac:
                return {"ok": False, "message": "device not found"}
            if a.get("on", True):
                rule = f'chain=forward src-mac-address={mac} action=drop comment="ND phone block {mac}"'
                script = (f':do {{ /ip firewall filter add {rule} place-before=([/ip firewall filter find]->0) }} '
                          f'on-error={{ /ip firewall filter add {rule} }}')
                return self._router_job(f"Block internet of {(d or {}).get('name') or mac}", script)
            return self._router_job(f"Unblock {(d or {}).get('name') or mac}",
                                    f'/ip firewall filter remove [find where comment="ND phone block {mac}"]')
        if name == "bind":
            devs = [self._dev_by({"mac": m}) for m in (a.get("macs") or [])]
            devs = [d for d in devs if d and d.get("mac") and d.get("ip")]
            if not devs:
                return {"ok": False, "message": "no device to bind"}
            apply, _undo = T.binding_commands(devs, T.tags_of(self.db), False, False, "bridge")
            res = self._router_job(f"IP-MAC binding ({len(devs)} device(s))", apply)
            if res.get("ok"):
                with core.DB_LOCK:
                    b = self.db.setdefault("bindings", {})
                    for d in devs:
                        b[d["mac"]] = {"ip": d["ip"], "time": core.now_s()}
                core.save_db(self.db)
            return res
        if name == "guard":
            opt = str(a.get("opt", ""))
            if opt not in ("torrent", "dns", "dhcp", "random"):
                return {"ok": False, "message": "unknown guard option"}
            script = T.guard_commands({opt: True}, [], self.lip, "bridge")[0]
            return self._router_job({"torrent": "Block torrents", "dns": "All DNS through the router",
                                     "dhcp": "Block rogue DHCP", "random": "Block randomized MACs"}[opt], script)
        if name == "router_cmd":
            i = int(a.get("i", -1))
            if not 0 <= i < len(T.COMMANDS) or T.COMMANDS[i][1] != "Router":
                return {"ok": False, "message": "not a router command"}
            d = self._dev_by(a)
            gwd = next((x for x in self.devices if x.get("ip") == self.gw and x.get("mac")), None)
            vals = T.command_values(d, self.gw, gwd["mac"] if gwd else "", self.lip)
            vals.update({k: str(v) for k, v in (a.get("values") or {}).items() if re.fullmatch(r"\w+", k)})
            text, missing = T.fill(T.COMMANDS[i][3], vals)
            if missing:
                return {"ok": False, "message": "fill in: " + ", ".join(missing), "missing": missing}
            c = self.router_client(ask=False)
            if not c:
                return {"ok": False, "message": "No router login is saved on the PC."}

            def run():
                with c:
                    if re.search(r"\b(add|set|remove|disable|enable)\b", text):
                        err = c.run_script(text)
                        if err:
                            raise RuntimeError(err)
                        return "applied:\n" + text
                    return c.run_cli(text) or "(no output)"
            return self._job(T.COMMANDS[i][2], run)
        if name == "slow":
            import nd_slow as S
            url = S.norm_url(str(a.get("url", "")))
            if not url:
                return {"ok": False, "message": "type a website"}
            dev = self._dev_by(a)
            mbps = float(a.get("mbps") or self._settings().get("line_mbps") or 100)
            ctx = {"gw": self.gw, "lip": self.lip, "mon": self.mon, "usage": self.usage, "db": self.db,
                   "raw": self.raw, "issues": list(self.issues), "devices": list(self.devices),
                   "router": self.router_client(ask=False), "line_mbps": mbps}

            def run():
                m = S.measure(url, dev, ctx)
                m["gw"] = self.gw
                out = []
                for f in S.judge(m):
                    out.append(f"■ {f['title']}  ({f['conf']})")
                    out += ["   · " + e for e in f.get("evidence", [])[:6]]
                    out += ["   → " + x for x in f.get("fixes", [])[:6]]
                    out.append("")
                return "\n".join(out) or "No problem found."
            return self._job(f"Slow website check: {url}", run)
        if name == "set_category":
            if not self.usage:
                return {"ok": False, "message": "usage history is off"}
            self.usage.set_category(str(a.get("kind", "app")), str(a.get("value", "")), a.get("cat") or None,
                                    str(a.get("dept", "")) or "")
            self._usage_snap_cache = None
            return {"ok": True, "message": "Category saved"}
        return {"ok": False, "message": f"unknown action '{name}'"}

    def _snapshot(self):
        """Everything the phone app shows. Runs on the phone-link thread: reads data only, never Tk."""
        mon = self.mon
        rates = mon.traffic.rates(120) if mon and mon.last_flow else {}
        devs = []
        for d in list(self.devices):
            typ, why = M.ip_type(d, mon, self.db, self.raw) if d.get("online") else ("", "")
            r = rates.get(d.get("ip")) or {}
            devs.append({"name": d.get("name", ""), "ip": d.get("ip", ""),
                         "ips": sorted(d.get("ips", []), key=core.ip_key), "mac": d.get("mac") or "",
                         "vendor": d.get("vendor", ""), "category": d.get("category", ""),
                         "reason": d.get("reason", ""), "status": d.get("status", ""), "online": bool(d.get("online")),
                         "ip_type": typ, "ip_type_why": why, "ports": d.get("ports", []), "dept": d.get("dept", ""),
                         "services": [core.PORTS.get(x, str(x)) for x in d.get("ports", [])],
                         "web_port": (d.get("http") or {}).get("port"), "notes": d.get("notes", []),
                         "random_mac": bool(d.get("random")), "down_bps": r.get("down_bps"), "up_bps": r.get("up_bps")})
        finds, missing = M.rca_network(mon, list(self.devices), list(self.issues), self.db)
        now = time.time()
        snap = {"pc": socket.gethostname(), "version": VERSION, "time": now, "network": self.net,
                "gateway": self.gw, "pc_ip": self.lip, "devices": devs, "issues": list(self.issues),
                "checks": [{"name": n, "result": r, "detail": x} for n, r, x in self.checks],
                "rca": {"findings": finds, "missing": missing},
                "scan": dict((self.raw or {}).get("meta", {}), tests=None) if self.raw else None,
                "scanning": bool(getattr(self, "scanning", False)), "monitor": None,
                "auto": {"summary": self.quick_summary, "last_check": self.last_quick_t or None,
                         "active_alerts": [dict(v) for v in list(self.alerts_active.values())]},
                "watch": [{"name": v.get("name"), "ip": v.get("ip"), "down": bool(v.get("down_since")),
                           "rtt": v.get("rtt"), "downs": v.get("downs", 0)} for v in list(self.watch_state.values())]}
        snap["checklist"] = list(getattr(self, "_checklist_cache", []))
        alerts = []
        for x in self.alert_log.recent(80):
            r = AL.explain(x["text"], x["sev"], self.lip, self.gw)
            alerts.append({"id": x["id"], "t": x["t"], "last": x["last"], "prio": x["prio"],
                           "prio_text": AL.PRIO[x["prio"]], "text": x["text"], "title": r["title"], "why": r["why"],
                           "fix": x["fix"], "status": x.get("status", ""), "count": x.get("count", 1),
                           "steps": r["steps"], "ip": x.get("ip", ""),
                           "fixes": [f["label"] for f in r["auto"] if f["where"] in ("router", "router_read")],
                           "pc_fixes": [f["label"] + ": " + f["cmd"] for f in r["auto"] if f["where"] == "pc"]})
        snap["alerts"] = alerts
        snap["router_login"] = bool(RO.from_settings(self._settings(), self.gw))
        snap["phone_api"] = 2
        try:
            bad, ports = self.map.problems()
            root = T.build_map(list(self.devices), self.db, self.gw, bad, ports)

            def node(n, depth=0):
                d = n.get("dev") or {}
                return {"label": n.get("label", ""), "sub": n.get("sub", ""), "kind": n.get("kind", ""),
                        "bad": n.get("bad") or n.get("child_bad") or "", "ip": d.get("ip", ""), "mac": d.get("mac", ""),
                        "children": [node(c, depth + 1) for c in n.get("children", [])] if depth < 8 else []}
            snap["map"] = node(root)
        except Exception:
            snap["map"] = None
        if not getattr(self, "_cmd_lib", None):
            self._cmd_lib = [{"i": i, "group": c[0], "where": c[1], "name": c[2], "cmd": c[3], "use": c[4]}
                             for i, c in enumerate(T.COMMANDS)]
        snap["commands"] = self._cmd_lib
        try:
            import nd_slow
            snap["slow_sites"] = [{"label": a, "url": b} for a, b in nd_slow.COMMON_SITES]
        except Exception:
            snap["slow_sites"] = []
        snap["line_mbps"] = self._settings().get("line_mbps") or 100
        snap["usage"] = self._usage_snapshot()
        try:
            leases = [{"mac-address": m, "address": v.get("ip", ""), "host-name": v.get("host", "")}
                      for m, v in ((self.raw or {}).get("leases") or {}).items()]
            keep = ("name", "ip", "mac", "vendor", "category", "host", "dept", "location", "status", "first_seen",
                    "os", "model", "serial", "cpu", "ram_gb", "disk_gb", "disk_free_gb", "user", "online",
                    "maker", "ram_detail", "disks", "gpu", "monitors", "keyboards", "mice", "printers", "antivirus",
                    "firewall", "driver_problems", "last_update", "bios", "software_count", "flag_text")
            snap["inventory"] = [{k: r.get(k, "") for k in keep}
                                 for r in T.inventory_rows(list(self.devices), self.db, leases)][:600]
        except Exception:
            snap["inventory"] = []
        if mon:
            names = {d["ip"]: d.get("name", "") for d in devs}
            talk = sorted(rates.items(), key=lambda x: -(x[1]["down_bps"] + x[1]["up_bps"]))[:15]
            cache = dict(getattr(self, "_app_cache", {}))  # main app / website per device (Live monitor)
            snap["monitor"] = {
                "status": mon.feed_status(), "running": mon.running,
                "samples": [[round(t), b, m] for t, b, m in mon.samples_copy(now - 600)][::2],
                "events": [{"t": e["t"], "sev": e["sev"], "src": e["src"], "text": e["text"]}
                           for e in mon.events_copy()[-150:] if e["sev"] != "debug"][::-1],
                "links_down": {k: [t for t, st in v if st == "down" and t > now - 3600]
                               for k, v in mon.links_copy().items()},
                "talkers": [{"ip": ip, "name": names.get(ip, ""), "down_bps": r["down_bps"], "up_bps": r["up_bps"],
                             "last10": sum(mon.traffic.window_total(ip, 600)),
                             "app": (cache.get(ip) or ("", ""))[1], "site": (cache.get(ip) or ("",) * 6)[5],
                             "risk": (cache.get(ip) or ("",) * 3)[2]} for ip, r in talk]}
        return snap

    def _usage_snapshot(self):
        """Usage for the phone app (today and 7 days, advisor), refreshed at most once a minute."""
        c = getattr(self, "_usage_snap_cache", None)
        if c and time.time() - c[0] < 60:
            return c[1]
        out = None
        if self.usage:
            try:
                def cut(sm):
                    return {"start": sm["start"], "end": sm["end"], "cats": sm["cats"], "apps": sm["apps"][:25],
                            "sites": [dict(x, site=US.pretty_site(x["site"])) for x in sm["sites"][:25]],
                            "devices": sm["devices"][:60]}
                out = {"today": cut(self.usage.summary(1)), "week": cut(self.usage.summary(7)),
                       "insights": self.usage.insights(), "labels": US.CAT_LABEL}
            except Exception:
                out = None
        self._usage_snap_cache = (time.time(), out)
        return out

    # ---------------------------------------------------------------- online updates (GitHub Releases)
    def _settings(self):
        if not hasattr(self, "_set"):
            try:
                with open(os.path.join(core.DATA_DIR, "settings.json"), encoding="utf-8") as f:
                    self._set = json.load(f)
            except Exception:
                self._set = {}
        return self._set

    def _save_settings(self):
        try:
            os.makedirs(core.DATA_DIR, exist_ok=True)
            with open(os.path.join(core.DATA_DIR, "settings.json"), "w", encoding="utf-8") as f:
                json.dump(self._settings(), f, indent=1)
        except Exception:
            pass

    UPDATE_MODES = {"Install automatically (recommended)": "auto", "Ask me first": "ask", "Never check": "off"}
    UPDATE_EVERY = 6 * 3600  # (old) seconds between automatic checks - now once a day at 15:00, see _daily_update

    def _daily_update(self):
        """Automatic update check every day at 15:00 (and at start-up when the PC was off at 15:00)."""
        if self._update_mode(True) != "off" and U.daily_due(self._settings().get("last_check", 0)) \
                and not getattr(self, "_checking", False) and time.time() - getattr(self, "_upd_fail_t", 0) > 1800:
            self.check_updates(True)

    def _update_mode(self, code=False):
        st = self._settings()
        m = st.get("update_mode")
        if m not in ("auto", "ask", "off"):
            m = "auto" if st.get("auto_update", True) else "off"  # setting from older versions
        return m if code else next(k for k, v in self.UPDATE_MODES.items() if v == m)

    def check_updates(self, auto=False, force=False):  # noqa: ARG002 (force kept for callers)
        """auto=True: the scheduled check (daily at 15:00). auto=False: the user pressed a button."""
        if auto and self._update_mode(True) == "off":
            return
        if getattr(self, "_checking", False):
            return
        self._checking = True
        self.var_upd.set("Checking GitHub for a new version...")
        threading.Thread(target=self._check_worker, args=(auto,), daemon=True).start()

    def _check_worker(self, auto):
        try:
            info, err = U.check(VERSION), None
        except U.UpdateError as e:
            info, err = None, str(e)
        self.q.put(("upd", info, err, auto))

    def _on_update_info(self, info, err, auto):
        self._checking = False
        st = self._settings()
        if err and auto:
            self._upd_fail_t = time.time()  # try again in 30 minutes (no internet at 15:00)
        else:
            st["last_check"] = time.time()
            self._save_settings()
        if err:
            self.var_upd.set(f"Update check failed: {err}")
            if not auto:
                messagebox.showwarning(APP, err)
            return
        if not info:
            self.var_upd.set(f"Version {VERSION} - up to date (checked {time.strftime('%d-%b %H:%M')})")
            self.btn_update.configure(text=f"Updates (v{VERSION})")
            if not auto:
                messagebox.showinfo(APP, f"You have the latest version ({VERSION}).")
            return
        self.update_info = info
        self.var_upd.set(f"Version {info['version']} is available (you have {VERSION})")
        self.btn_update.configure(text=f"Update to {info['version']}", style="Big.TButton")
        if not auto:
            self._ask_update(info)
            return
        mode = self._update_mode(True)
        if mode == "auto":
            self._auto_update(info)
        elif mode == "ask" and st.get("skip") != info["version"]:
            self._ask_update(info)

    def _scheduled_check(self):
        self._upd_next = None
        self.check_updates(True)

    def _ask_update(self, info):
        notes = info["notes"][:900] or "(no release notes)"
        r = messagebox.askyesnocancel(
            APP, f"Network Doctor {info['version']} is available - you have {VERSION}.\n\n{notes}\n\n"
                 "Update now?\n\nYes = update and restart   No = later   Cancel = skip this version")
        if r is True:
            self.update_now()
        elif r is None:
            self._settings()["skip"] = info["version"]
            self._save_settings()

    def _auto_update(self, info):
        """Installs without asking - waits for a running scan / check to finish first."""
        if getattr(self, "_updating", False):
            return
        if getattr(self, "scanning", False) or self.quick_running:
            self.after(60 * 1000, lambda: self._auto_update(info))
            return
        if time.time() < self._settings().get("upd_postpone_until", 0):
            return
        self.update_now(silent=True)

    def _restart_args(self):
        args = ["--updated-from", VERSION]
        if self.state() == "iconic" or "--minimized" in sys.argv:
            args.append("--minimized")
        return args

    def update_now(self, silent=False):
        if getattr(self, "_ready_path", None) and not silent:
            path, self._ready_path = self._ready_path, None
            self._updating = True
            self._upd_silent = False
            self._install(path)
            return
        info = getattr(self, "update_info", None)
        if not info:
            self.check_updates(False)
            return
        if getattr(self, "_updating", False):
            return
        self._updating = True
        self._upd_silent = silent
        self.upd_lbl = tk.StringVar(value="")
        self.upd_pb = None
        self.upd_win = None
        if silent:
            self.btn_update.configure(text=f"Downloading {info['version']}...")
            self.var_upd.set(f"Downloading version {info['version']} in the background...")
        else:
            self._update_window(info)

        def work():
            try:
                if U.is_frozen():
                    path = U.download_exe(info, lambda d, t: self.q.put(("upd_prog", d, t)))
                    self.q.put(("upd_ready", path))
                else:
                    U.update_sources(info, core.HERE)
                    self.q.put(("upd_ready", None))
            except U.UpdateError as e:
                self.q.put(("upd_err", str(e)))
            except Exception as e:
                self.q.put(("upd_err", f"{type(e).__name__}: {e}"))
        threading.Thread(target=work, daemon=True).start()

    def _update_window(self, info):
        win = tk.Toplevel(self)
        win.title("Updating Network Doctor")
        win.geometry("460x130")
        win.transient(self)
        ttk.Label(win, text=f"Downloading version {info['version']} from GitHub...", padding=10).pack(anchor="w")
        self.upd_pb = ttk.Progressbar(win, maximum=100, length=420)
        self.upd_pb.pack(padx=14)
        ttk.Label(win, textvariable=self.upd_lbl, padding=10).pack(anchor="w")
        self.upd_win = win

    def _on_update_msg(self, msg):
        k = msg[0]
        if k == "upd_prog":
            d, t = msg[1], msg[2]
            if t and self.upd_pb is not None:
                self.upd_pb["value"] = 100 * d / t
            txt = f"{d / 1048576:.1f} MB" + (f" of {t / 1048576:.1f} MB" if t else "")
            self.upd_lbl.set(txt)
            if self._upd_silent:
                self.var_upd.set(f"Downloading the new version: {txt}")
        elif k == "upd_err":
            self._updating = False
            try:
                if self.upd_win:
                    self.upd_win.destroy()
            except Exception:
                pass
            self.btn_update.configure(text="Update now" if getattr(self, "update_info", None) else
                                      f"Updates (v{VERSION})")
            self.var_upd.set("Update failed: " + msg[1][:120])
            self._health_log("Update", "warning", "update failed: " + msg[1][:200])
            if not self._upd_silent:
                messagebox.showerror(APP, "Update failed: " + msg[1] +
                                     f"\n\nYou can also download it from:\n{U.RELEASES_PAGE}")
        elif k == "upd_ready":
            if self._upd_silent:
                self._countdown(msg[1])
            else:
                self.upd_lbl.set("Verified. Restarting...")
                self.update_idletasks()
                self._install(msg[1])

    def _countdown(self, path, secs=60):
        """Downloaded and verified: restart in 60 s unless the user says Later."""
        info = self.update_info
        self.btn_update.configure(text=f"Install {info['version']}")
        win = tk.Toplevel(self)
        win.title("Network Doctor update")
        win.attributes("-topmost", True)
        win.resizable(False, False)
        ttk.Label(win, text=f"Network Doctor {info['version']} is ready (you have {VERSION}).",
                  font=("Segoe UI", 11, "bold"), padding=(14, 12, 14, 2)).pack(anchor="w")
        var = tk.StringVar()
        ttk.Label(win, textvariable=var, padding=(14, 2)).pack(anchor="w")
        ttk.Label(win, text="Monitoring and automatic checks continue after the restart.", foreground="#667085",
                  padding=(14, 0, 14, 8)).pack(anchor="w")
        bar = ttk.Frame(win, padding=(14, 0, 14, 12))
        bar.pack(fill="x")
        state = {"left": secs, "done": False}

        def now():
            if state["done"]:
                return
            state["done"] = True
            var.set("Restarting...")
            win.update_idletasks()
            self._install(path)

        def later():
            state["done"] = True
            self._updating = False
            self._settings()["upd_postpone_until"] = time.time() + 20 * 3600
            self._save_settings()
            self.var_upd.set(f"Version {info['version']} downloaded - press 'Update' at the top to install it")
            self.btn_update.configure(text=f"Update to {info['version']}")
            self._ready_path = path
            win.destroy()
        ttk.Button(bar, text="Restart now", style="Big.TButton", command=now).pack(side="left")
        ttk.Button(bar, text="Later (tomorrow)", command=later).pack(side="left", padx=8)
        win.protocol("WM_DELETE_WINDOW", later)
        try:  # top-right corner of the main window, away from the alert pop-up (top-left)
            win.update_idletasks()
            x = self.winfo_rootx() + self.winfo_width() - win.winfo_reqwidth() - 30
            win.geometry(f"+{max(0, x)}+{self.winfo_rooty() + 60}")
        except Exception:
            pass

        def tick():
            if state["done"]:
                return
            if state["left"] <= 0:
                now()
                return
            var.set(f"Restarting in {state['left']} seconds to install it.")
            state["left"] -= 1
            self.after(1000, tick)
        tick()

    def _install(self, path):
        self._health_log("Update", "info", f"updating {VERSION} -> {self.update_info['version']}")
        try:
            if path:
                U.apply_update(path, self._restart_args())
            else:
                U.restart_sources(core.HERE, self._restart_args())
        except Exception as e:
            self._updating = False
            messagebox.showerror(APP, f"Update failed: {e}\n\nYou can also download it from:\n{U.RELEASES_PAGE}")
            return
        self._close()

    def _after_update_note(self):
        """Started by the updater: say so, once."""
        if "--updated-from" not in sys.argv:
            return
        try:
            old = sys.argv[sys.argv.index("--updated-from") + 1]
        except IndexError:
            old = "?"
        self.var_status.set(f"Updated from {old} to {VERSION}. What's new: Setup > Release page.")
        self.var_upd.set(f"Version {VERSION} - updated from {old} just now")
        self._health_log("Update", "info", f"updated from {old} to {VERSION}")
        st = self._settings()
        st.pop("upd_postpone_until", None)
        st.pop("skip", None)
        self._save_settings()

    def _close(self):
        self.alive = False
        self.watch_wake.set()
        try:
            if self.mon:
                self.mon.stop()
            self.orgs.close()
            if self.share:
                self.share.stop()
        except Exception:
            pass
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
    os._exit(0)  # do not wait for background lookups / pings still running
