#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Doctor 3.2 - standalone network scanner, live monitor and root-cause tool for Windows.

Files: NetworkDoctor.py (this window), nd_core.py (scan engine), nd_monitor.py (monitor / traffic / RCA).
Build a single exe with Build_NetworkDoctor_EXE.bat.
"""

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
from collections import Counter

import nd_core as core
import nd_monitor as M
import nd_update as U
import nd_share as SH

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, messagebox, simpledialog, filedialog

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
VERSION = "3.3.0"
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


def make_tree(parent, cols, heads, widths, first, height=None):
    fr = ttk.Frame(parent)
    fr.pack(fill="both", expand=True)
    kw = {"height": height} if height else {}
    tv = ttk.Treeview(fr, columns=cols, show="tree headings" if first else "headings", selectmode="browse", **kw)
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
            cmd = ["ping", "-n", "1", "-w", "1000", self.ip] if core.IS_WIN else ["ping", "-c", "1", "-W", "1", self.ip]
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
        for th in (("vista", "winnative", "clam") if core.IS_WIN else ("clam",)):
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
        self.devices, self.issues, self.checks = [], [], []
        self.gw, self.lip = core.detect_network()
        self.net = str(ipaddress.ip_network(f"{self.lip}/24", strict=False))
        self.threat = M.ThreatIntel()
        self.orgs = M.OrgLookup()
        self.mon = None
        self.ev_seen = 0
        self.rca_cache = None
        self._build()
        self.after(100, self._poll)
        self.after(2000, self._tick)
        threading.Thread(target=self._bg_load, daemon=True).start()
        self.last_scan_t = 0
        self.after(800, self.start_monitor)
        self.after(2500, self.start_scan)
        U.cleanup_leftovers()
        self.share = None
        if self.var_share.get():
            self.after(1200, self.toggle_share)
        self.after(15000, lambda: self.check_updates(True))
        self.protocol("WM_DELETE_WINDOW", self._close)

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
        self.var_net = tk.StringVar(value=self.net)
        ttk.Entry(top, textvariable=self.var_net, width=18).pack(side="left", padx=(4, 8))
        self.btn_scan = ttk.Button(top, text="Scan", style="Big.TButton", command=self.start_scan)
        self.btn_scan.pack(side="left")
        self.btn_stop = ttk.Button(top, text="Stop", command=self.stop_scan, state="disabled")
        self.btn_stop.pack(side="left", padx=6)
        self.var_deep = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Deep packet tests", variable=self.var_deep).pack(side="left", padx=6)
        self.var_fast = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Fast", variable=self.var_fast).pack(side="left")
        self.var_auto = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Re-scan every 30 min", variable=self.var_auto).pack(side="left", padx=6)
        if core.IS_WIN and not core.is_admin():
            ttk.Button(top, text="Restart as Administrator (full tests)", command=self.elevate).pack(side="right")
        else:
            ttk.Label(top, text="Administrator: full tests on", foreground="#1f7a3d").pack(side="right")
        self.btn_update = ttk.Button(top, text="Update", style="Big.TButton", command=self.update_now)
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
        self._tab_devices()
        self._tab_monitor()
        self._tab_rca()
        self._tab_problems()
        self._tab_checks()
        self._tab_setup()

    def _tab_devices(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="  Devices  ")
        sf = ttk.Frame(f, padding=(0, 6))
        sf.pack(fill="x")
        ttk.Label(sf, text="Search:").pack(side="left")
        self.var_q = tk.StringVar()
        self.var_q.trace_add("write", lambda *a: self.fill_devices())
        ttk.Entry(sf, textvariable=self.var_q, width=34).pack(side="left", padx=6)
        self.var_sort_bw = tk.BooleanVar(value=False)
        ttk.Checkbutton(sf, text="Sort by bandwidth", variable=self.var_sort_bw,
                        command=self.fill_devices).pack(side="left", padx=8)
        act = ttk.Frame(f, padding=(0, 6, 0, 0))
        act.pack(fill="x", side="bottom")
        self.var_sel = tk.StringVar(value="Select a device:")
        ttk.Label(act, textvariable=self.var_sel, width=42, font=("Segoe UI", 10, "bold")).pack(side="left")
        for txt, cmd in (("Analyse (root cause)", lambda: self.act("analyse")), ("Ping", lambda: self.act("ping")),
                         ("Open in browser", lambda: self.act("web")), ("Traceroute", lambda: self.act("trace")),
                         ("Set label", lambda: self.act("label")), ("Copy IP", lambda: self.act("cip"))):
            ttk.Button(act, text=txt, command=cmd).pack(side="left", padx=3)
        cols = ("status", "ip", "iptype", "mac", "vendor", "bw", "services", "why", "notes")
        heads = ("Status", "IP", "IP type", "MAC address", "Vendor", "Bandwidth now", "Services", "Why this category", "Notes")
        widths = (100, 115, 105, 140, 170, 150, 200, 240, 220)
        self.tv = make_tree(f, cols, heads, widths, first=("Name", 210))
        self.tv.bind("<Button-3>", self._menu)
        self.tv.bind("<Double-1>", lambda e: self.act("analyse"))
        self.tv.bind("<<TreeviewSelect>>", self._sel)
        self.row_dev = {}

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
        self.tt = make_tree(a, ("ip", "down", "up", "ten", "app", "risk"),
                            ("IP", "Download", "Upload", "Last 10 min", "Main app", "Risk"),
                            (105, 85, 85, 90, 170, 160), first=("Device", 150))
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
        self.var_autoupd = tk.BooleanVar(value=self._settings().get("auto_update", True))

        def _toggle():
            self._settings()["auto_update"] = self.var_autoupd.get()
            self._save_settings()
        ttk.Checkbutton(up, text="Check automatically every day", variable=self.var_autoupd,
                        command=_toggle).pack(side="left", padx=8)
        self.var_upd = tk.StringVar(value=f"Version {VERSION}")
        ttk.Label(up, textvariable=self.var_upd).pack(side="left", padx=10)
        ttk.Button(up, text="Release page", command=lambda: webbrowser.open(U.RELEASES_PAGE)).pack(side="right")
        ph = ttk.LabelFrame(f, text="Phone app link (office LAN only)", padding=(8, 4))
        ph.pack(fill="x", pady=(0, 6))
        self.var_share = tk.BooleanVar(value=self._settings().get("share_enabled", False))
        ttk.Checkbutton(ph, text="Allow the Network Doctor phone app to connect", variable=self.var_share,
                        command=self.toggle_share).pack(side="left")
        self.var_share_info = tk.StringVar(value="off")
        ttk.Label(ph, textvariable=self.var_share_info, font=("Segoe UI", 10, "bold")).pack(side="left", padx=12)
        ttk.Button(ph, text="Remove paired phones", command=self.forget_phones).pack(side="right")
        ttk.Button(ph, text="New pairing code", command=self.new_share_code).pack(side="right", padx=6)
        self.tsetup = text_box(f)
        self._fill_setup()

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
                        "stays a separate app: it never logs in to the router and changes nothing there.\n")
        t.insert("end", "  - Traffic data (NetFlow, UDP 2055): bandwidth per device, apps / sites, dangerous destinations\n")
        t.insert("end", "  - Router log (syslog, UDP 514): ether2 up/down, loops, DHCP vs static, IP conflicts\n\n")
        t.insert("end", f"Use a PC that stays on, with a fixed IP. This PC: {self.lip}\n", "warn")
        t.insert("end", "\nMikroTik commands (WinBox > New Terminal, paste once):\n", "h")
        t.insert("end", M.router_setup_commands(self.lip), "mono")
        t.insert("end", "\nOther brands: enable 'NetFlow v5/v9' or 'IPFIX' export to this PC port 2055, and "
                        "'remote syslog' to this PC port 514.\n")
        t.insert("end", "\nOptional - packet sniffer (loop echo test, who sends the broadcasts, ARP-spoofing / NetCut "
                        "detection, DHCP requests): install Npcap from https://npcap.com and build the exe with Scapy.\n")
        t.configure(state="disabled")

    # ---------------------------------------------------------------- monitor
    def start_monitor(self):
        if self.mon and self.mon.running:
            return
        if core.IS_WIN and core.is_admin():
            self.firewall(quiet=True)
        try:
            lan = str(ipaddress.ip_network(self.var_net.get().strip(), strict=False))
        except ValueError:
            lan = self.net
        self.mon = M.Monitor(lan, self.gw, self.lip, self.threat, self.orgs)
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
            self._share_label()
        except Exception:
            pass
        if self.var_auto.get() and self.last_scan_t and time.time() - self.last_scan_t > 1800 \
                and str(self.btn_scan["state"]) == "normal":
            self.start_scan()
        self.after(2000, self._tick)

    def _tick_once(self):
        mon = self.mon
        if not mon:
            return
        fs = mon.feed_status()
        self.mon_labels["flows"].set(fs["flows"])
        self.mon_labels["syslog"].set(fs["syslog"])
        self.mon_labels["sniffer"].set(fs["sniffer"])
        b = f"{fs['bcast']:.0f}" if fs["bcast"] is not None else "?"
        g = (f"{fs['gw_avg']:.0f} ms avg, {fs['gw_max']:.0f} max" if fs["gw_avg"] is not None else
             "not answering" if fs["gw"] else "no router found")
        self.mon_labels["health"].set(f"broadcasts {b}/s  |  router {g}, loss {fs['gw_loss']:.0f}%")
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
                app_c = Counter()
                for n, ((remote, svc, proto, inbound), v) in enumerate(rem[:300]):
                    info = self.orgs.get(remote) if n < 5 else self.orgs.cache_peek(remote)
                    app_c[M.classify(remote, svc, proto, info, inbound)[0]] += v[0] + v[1]
                main = app_c.most_common(1)[0][0] if app_c else ""
                bad = [k for k, v in threats.items() if v[1] != "tor" and not v[2]]
                risk = ("MALWARE: " + bad[0]) if bad else (sorted(risks)[0] if risks else "")
                c = cache[ip] = (now, main, risk, bool(bad), bool(risks))
            _, main, risk, bad, risky = c
            u10, d10 = mon.traffic.window_total(ip, 600)
            d = names.get(ip)
            tag = ("critical",) if bad else ("warning",) if risky else ("hot",) if r["down_bps"] + r["up_bps"] > 1.25e6 else ()
            iid = "t" + ip
            keep.add(iid)
            vals = (ip, M.fmt_rate(r["down_bps"]), M.fmt_rate(r["up_bps"]), M.fmt_bytes(u10 + d10), main, risk)
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
    def start_scan(self):
        if getattr(self, "scanning", False):
            return
        try:
            net = ipaddress.ip_network(self.var_net.get().strip(), strict=False)
        except ValueError:
            messagebox.showerror(APP, "Enter a network like 192.168.0.0/24")
            return
        if net.num_addresses > 1024:
            messagebox.showerror(APP, "Network too large (maximum /22 = 1024 addresses).")
            return
        self.stop_ev.clear()
        self.scanning = True
        self.btn_scan.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        opts = {"deep": self.var_deep.get(), "fast": self.var_fast.get()}
        threading.Thread(target=self._worker, args=(str(net), opts), daemon=True).start()

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
                if k == "prog":
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
                    messagebox.showerror(APP, msg[1])
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
            ds = [d for d in self.devices if d["category"] == c]
            if qy:
                ds = [d for d in ds if qy in " ".join([d["name"], " ".join(d["ips"]), d["mac"] or "", d["vendor"],
                                                       d["reason"], " ".join(d["notes"])]).lower()]
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
                                values=(d["status"], ", ".join(sorted(d["ips"], key=core.ip_key)), typ, d["mac"] or "-",
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
        sel = self.tv.selection()
        d = self.row_dev.get(sel[0]) if sel else None
        self.var_sel.set(f"{d['name'] or '-'}  {d['ip']}" if d else "Select a device:")

    def _menu(self, ev):
        iid = self.tv.identify_row(ev.y)
        if iid not in self.row_dev:
            return
        self.tv.selection_set(iid)
        m = tk.Menu(self, tearoff=0)
        for lab, k in (("Analyse (root cause)", "analyse"), ("Ping (live graph)", "ping"), ("Open in browser", "web"),
                       ("Traceroute", "trace"), (None, None), ("Set label / name...", "label"),
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
                if not mac:
                    messagebox.showinfo(APP, "This device has no MAC address to remember it by.")
                    return
                v = simpledialog.askstring(APP, f"Label for {mac} ({ip}):", initialvalue=self.db["labels"].get(mac, d["name"]))
                if v is not None:
                    if v.strip():
                        self.db["labels"][mac] = v.strip()
                    else:
                        self.db["labels"].pop(mac, None)
                    core.save_db(self.db)
                    d["names"]["label"] = v.strip()
                    d["name"] = v.strip() or d["names"].get("netbios", "")
                    self.fill_devices()
            elif what == "share" and core.IS_WIN:
                subprocess.Popen(["explorer", f"\\\\{ip}"])
            elif what == "rdp" and core.IS_WIN:
                subprocess.Popen(["mstsc", f"/v:{ip}"])
            elif what == "wol" and mac:
                pkt = b"\xff" * 6 + bytes.fromhex(mac.replace(":", "")) * 16
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.sendto(pkt, ("255.255.255.255", 9))
                s.close()
                self.var_status.set(f"Wake-on-LAN sent to {mac}")
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
        name = "Network Doctor receivers"
        if name not in core.run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"], 10):
            core.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in", "action=allow",
                      "protocol=UDP", f"localport={M.FLOW_PORT},{M.SYSLOG_PORT}"], 10)
        if not quiet:
            messagebox.showinfo(APP, f"Windows Firewall now allows UDP {M.FLOW_PORT} and {M.SYSLOG_PORT}.")

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
            if ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, core.HERE, 1) > 32:
                self._close()
        except Exception as e:
            messagebox.showerror(APP, str(e))

    # ---------------------------------------------------------------- phone link
    def toggle_share(self):
        on = self.var_share.get()
        self._settings()["share_enabled"] = on
        self._save_settings()
        if on and not (self.share and self.share.running):
            store = self._settings().setdefault("share", {})
            self.share = SH.ShareServer(APP, VERSION, self._snapshot, self._remote_cmd, store, self._save_settings)
            if not self.share.start():
                self.var_share.set(False)
                messagebox.showerror(APP, "Phone link could not start: " + (self.share.error or "?"))
                self.share = None
            elif core.IS_WIN and core.is_admin():
                name = "Network Doctor phone link"
                if name not in core.run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"], 10):
                    core.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in",
                              "action=allow", "protocol=TCP", f"localport={SH.HTTP_PORT}", "remoteip=localsubnet"], 10)
                    core.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name} discovery", "dir=in",
                              "action=allow", "protocol=UDP", f"localport={SH.DISCOVERY_PORT}", "remoteip=localsubnet"], 10)
        elif not on and self.share:
            self.share.stop()
            self.share = None
        self._share_label()

    def _share_label(self):
        sh = self.share
        if not sh or not sh.running:
            self.var_share_info.set("off")
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

    def _remote_cmd(self, name):
        if name == "scan":
            if getattr(self, "scanning", False):
                return "a scan is already running"
            self.q.put(("remote_scan",))
            return "scan started"
        return "unknown command"

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
                         "ip_type": typ, "ip_type_why": why, "ports": d.get("ports", []),
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
                "scanning": bool(getattr(self, "scanning", False)), "monitor": None}
        if mon:
            names = {d["ip"]: d.get("name", "") for d in devs}
            talk = sorted(rates.items(), key=lambda x: -(x[1]["down_bps"] + x[1]["up_bps"]))[:15]
            snap["monitor"] = {
                "status": mon.feed_status(), "running": mon.running,
                "samples": [[round(t), b, m] for t, b, m in mon.samples_copy(now - 600)][::2],
                "events": [{"t": e["t"], "sev": e["sev"], "src": e["src"], "text": e["text"]}
                           for e in mon.events_copy()[-150:] if e["sev"] != "debug"][::-1],
                "links_down": {k: [t for t, st in v if st == "down" and t > now - 3600]
                               for k, v in mon.links_copy().items()},
                "talkers": [{"ip": ip, "name": names.get(ip, ""), "down_bps": r["down_bps"], "up_bps": r["up_bps"],
                             "last10": sum(mon.traffic.window_total(ip, 600))} for ip, r in talk]}
        return snap

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

    def check_updates(self, auto=False):
        st = self._settings()
        if auto:
            if not self.var_autoupd.get():
                return
            if time.time() - st.get("last_check", 0) < 20 * 3600:
                self.after(3600 * 1000, lambda: self.check_updates(True))
                return
        self.var_upd.set("Checking GitHub for a new version...")
        threading.Thread(target=self._check_worker, args=(auto,), daemon=True).start()

    def _check_worker(self, auto):
        try:
            info, err = U.check(VERSION), None
        except U.UpdateError as e:
            info, err = None, str(e)
        self.q.put(("upd", info, err, auto))

    def _on_update_info(self, info, err, auto):
        st = self._settings()
        st["last_check"] = time.time()
        self._save_settings()
        if auto:
            self.after(24 * 3600 * 1000, lambda: self.check_updates(True))
        if err:
            self.var_upd.set(f"Update check: {err}")
            if not auto:
                messagebox.showwarning(APP, err)
            return
        if not info:
            self.var_upd.set(f"Version {VERSION} - up to date (checked {time.strftime('%d-%b %H:%M')})")
            if not auto:
                messagebox.showinfo(APP, f"You have the latest version ({VERSION}).")
            return
        self.update_info = info
        self.var_upd.set(f"Version {info['version']} is available (you have {VERSION})")
        self.btn_update.configure(text=f"Update to {info['version']}")
        self.btn_update.pack(side="right", padx=6)
        if auto and st.get("skip") == info["version"]:
            return
        notes = info["notes"][:900] or "(no release notes)"
        r = messagebox.askyesnocancel(
            APP, f"Network Doctor {info['version']} is available - you have {VERSION}.\n\n{notes}\n\n"
                 "Update now?\n\nYes = update and restart   No = later   Cancel = skip this version")
        if r is True:
            self.update_now()
        elif r is None:
            st["skip"] = info["version"]
            self._save_settings()

    def update_now(self):
        info = getattr(self, "update_info", None)
        if not info:
            self.check_updates(False)
            return
        if getattr(self, "_updating", False):
            return
        self._updating = True
        win = tk.Toplevel(self)
        win.title("Updating Network Doctor")
        win.geometry("460x130")
        win.transient(self)
        ttk.Label(win, text=f"Downloading version {info['version']} from GitHub...", padding=10).pack(anchor="w")
        self.upd_pb = ttk.Progressbar(win, maximum=100, length=420)
        self.upd_pb.pack(padx=14)
        self.upd_lbl = tk.StringVar(value="")
        ttk.Label(win, textvariable=self.upd_lbl, padding=10).pack(anchor="w")
        self.upd_win = win

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

    def _on_update_msg(self, msg):
        k = msg[0]
        if k == "upd_prog":
            d, t = msg[1], msg[2]
            if t:
                self.upd_pb["value"] = 100 * d / t
            self.upd_lbl.set(f"{d / 1048576:.1f} MB" + (f" of {t / 1048576:.1f} MB" if t else ""))
        elif k == "upd_err":
            self._updating = False
            try:
                self.upd_win.destroy()
            except Exception:
                pass
            messagebox.showerror(APP, "Update failed: " + msg[1] + f"\n\nYou can also download it from:\n{U.RELEASES_PAGE}")
        elif k == "upd_ready":
            self.upd_lbl.set("Verified. Restarting...")
            self.update_idletasks()
            if msg[1]:
                U.apply_exe(msg[1])
            else:
                U.restart_sources(core.HERE)
            self._close()

    def _close(self):
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
