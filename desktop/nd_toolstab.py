# -*- coding: utf-8 -*-
"""Network Doctor - the Tools tab: everyday network-engineer tools in one place."""

import concurrent.futures as cf
import ipaddress
import queue
import statistics
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import ttk, messagebox, simpledialog

import nd_core as core
import nd_monitor as M
import nd_net as NT
import nd_plugins
import nd_snmp
import nd_tabs
import nd_tools as T

APP = "Network Doctor"

TOOLS = [
    ("watch", "Critical devices (alert if down)",
     "Ping the devices the office cannot work without (router, server, ERP PC, DVR, switches) every 30 seconds. "
     "If one stops answering for about 1.5 minutes you get a pop-up, a sound and a line in the health log."),
    ("speed", "Internet speed and quality",
     "Public IP and ISP, ping / jitter / loss to the router and the internet, download and upload speed, and latency "
     "while the line is busy (bufferbloat). Uses the Cloudflare speed-test servers."),
    ("switch", "Switch / router details (SNMP, any brand)",
     "Reads a managed switch or router of any brand over SNMP (read-only): model, uptime, every port with its "
     "speed, traffic and errors, LLDP neighbours, and which device is plugged into which port."),
    ("ports", "Port scanner",
     "Which services a device offers (open TCP ports), with what each one is and the risky ones marked."),
    ("dns", "DNS lookup / DNS server test",
     "Look up any record (A, MX, TXT, PTR...) on any DNS server, or compare the router's, the ISP's and public DNS "
     "servers for speed, failures and hijacking."),
    ("web", "Website / server check",
     "Is a web server, ERP, router page or camera web page up? DNS, connect, TLS and answer times, and when its "
     "certificate expires."),
    ("lan", "LAN speed test (PC to PC)",
     "Real speed through the cables and switches between this PC and another PC running Network Doctor. Finds "
     "100 Mbps cables and slow switches."),
    ("wifi", "Wi-Fi analyzer",
     "Nearby Wi-Fi networks, channels, signal and security, the least crowded channel, and the signal of this PC."),
    ("nic", "This PC's network adapters",
     "Link speed (1 Gbps / 100 Mbps), duplex, packet errors, DHCP / IP and MTU of every network card in this PC."),
    ("mtu", "MTU finder",
     "Largest packet that passes without being split - finds PPPoE / VPN problems where some websites hang."),
    ("subnet", "Subnet calculator",
     "Network, mask, wildcard, broadcast and host range for any address, and how to split it."),
    ("wol", "Wake-on-LAN",
     "Switch on a PC that is off, from here (Wake-on-LAN must be on in that PC's BIOS / network card)."),
    ("mac", "MAC address lookup",
     "Manufacturer of a MAC address, whether it is randomized, and where that MAC was last seen on this network."),
    ("ready", "Setup check - what is missing",
     "Checks everything Network Doctor needs to see the whole network and tells you what to switch on."),
]


class ToolsTab:
    def __init__(self, app, parent):
        self.app = app
        self.q = queue.Queue()
        self.frames, self.texts, self.status, self.stops, self.btns = {}, {}, {}, {}, {}
        self.lan_server = None
        pw = ttk.PanedWindow(parent, orient="horizontal")
        pw.pack(fill="both", expand=True, pady=(6, 0))
        left = ttk.Frame(pw)
        self.body = ttk.Frame(pw)
        pw.add(left, weight=0)
        pw.add(self.body, weight=1)
        self.lb = tk.Listbox(left, width=34, activestyle="none", font=("Segoe UI", 10), exportselection=False,
                             relief="flat", highlightthickness=1, highlightbackground="#d0d5dd",
                             selectbackground="#1d4ed8", selectforeground="white")
        self.lb.pack(fill="both", expand=True)
        for _, name, _ in TOOLS:
            self.lb.insert("end", "  " + name)
        self.lb.bind("<<ListboxSelect>>", lambda e: self.show())
        self.current = None
        self.lb.selection_set(0)
        self.show()
        app.after(150, self._poll)

    # ------------------------------------------------------------------ plumbing
    def show(self, key=None):
        if key is None:
            sel = self.lb.curselection()
            key = TOOLS[sel[0]][0] if sel else "watch"
        else:
            idx = [t[0] for t in TOOLS].index(key)
            self.lb.selection_clear(0, "end")
            self.lb.selection_set(idx)
        if self.current == key:
            return
        if self.current:
            self.frames[self.current].pack_forget()
        if key not in self.frames:
            f = ttk.Frame(self.body, padding=(10, 0, 0, 0))
            self.frames[key] = f
            name, desc = next((n, d) for k, n, d in TOOLS if k == key)
            ttk.Label(f, text=name, font=("Segoe UI", 13, "bold")).pack(anchor="w")
            ttk.Label(f, text=desc, foreground="#667085", wraplength=900, justify="left").pack(anchor="w", pady=(0, 6))
            getattr(self, "_build_" + key)(f)
        self.frames[key].pack(fill="both", expand=True)
        self.current = key
        if key == "watch":
            self.refresh_watch()

    def _out_box(self, f, key):
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=(4, 2))
        v = tk.StringVar(value="")
        ttk.Label(bar, textvariable=v, foreground="#5b21b6").pack(side="left")
        ttk.Button(bar, text="Copy result", command=lambda: self._copy(key)).pack(side="right")
        self.status[key] = v
        t = nd_tabs.UI["text_box"](f)
        t.configure(state="disabled", font=("Consolas", 10))
        self.texts[key] = t
        return t

    def _copy(self, key):
        self.app.clipboard_clear()
        self.app.clipboard_append(self.texts[key].get("1.0", "end").strip())

    def _run_btn(self, row, key, text, fn, side="left"):
        b = ttk.Button(row, text=text, style="Big.TButton", command=lambda: self.start(key, fn))
        b.pack(side=side, padx=4)
        self.btns.setdefault(key, []).append(b)
        return b

    def _stop_btn(self, row, key):
        ttk.Button(row, text="Stop", command=lambda: self.stops.get(key) and self.stops[key].set()).pack(side="left")

    def start(self, key, fn):
        if self.stops.get(key) and not self.stops[key].is_set():
            return  # already running
        stop = threading.Event()
        self.stops[key] = stop
        t = self.texts[key]
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.configure(state="disabled")
        for b in self.btns.get(key, []):
            b.configure(state="disabled")
        self.status[key].set("working...")

        def out(text, tag=""):
            self.q.put((key, text, tag))

        def work():
            try:
                fn(out, stop)
            except Exception as e:
                out(f"\nFailed: {type(e).__name__}: {e}", "crit")
            finally:
                self.q.put((key, None, "done"))
        threading.Thread(target=work, daemon=True).start()

    def _poll(self):
        try:
            while True:
                key, text, tag = self.q.get_nowait()
                if tag == "done":
                    if self.stops.get(key):
                        self.stops[key].set()
                    for b in self.btns.get(key, []):
                        b.configure(state="normal")
                    if self.status[key].get() == "working...":
                        self.status[key].set("finished " + time.strftime("%H:%M:%S"))
                elif tag == "status":
                    self.status[key].set(text)
                elif tag == "call":
                    text()
                elif tag == "clear":
                    t = self.texts[key]
                    t.configure(state="normal")
                    t.delete("1.0", "end")
                    t.configure(state="disabled")
                elif tag == "log":
                    self.app._health_log(*text)
                else:
                    t = self.texts[key]
                    t.configure(state="normal")
                    t.insert("end", text + ("\n" if not text.endswith("\n") else ""), tag or ())
                    t.see("end")
                    t.configure(state="disabled")
        except queue.Empty:
            pass
        self.app.after(150, self._poll)

    def _targets(self, extra=()):
        app = self.app
        vals = list(extra)
        for d in sorted([d for d in app.devices if d.get("online")], key=lambda d: core.ip_key(d.get("ip", ""))):
            vals.append(f"{d['ip']}   {d.get('name') or ''}".rstrip())
        return vals

    @staticmethod
    def _ip_of(text):
        return (text or "").strip().split()[0] if (text or "").strip() else ""

    def _combo(self, row, label, values, width=28, default=""):
        ttk.Label(row, text=label).pack(side="left")
        v = tk.StringVar(value=default)
        cb = ttk.Combobox(row, textvariable=v, values=values, width=width)
        cb.pack(side="left", padx=(4, 10))
        extras = list(values)
        cb.bind("<Button-1>", lambda e: cb.configure(values=self._targets(extras)))
        return v, cb

    # ------------------------------------------------------------------ critical devices
    def _build_watch(self, f):
        row = ttk.Frame(f)
        row.pack(fill="x", pady=4)
        ttk.Label(row, text="Device:").pack(side="left")
        self.var_wdev = tk.StringVar()
        self.wcb = ttk.Combobox(row, textvariable=self.var_wdev, width=52, state="readonly")
        self.wcb.pack(side="left", padx=4)
        ttk.Button(row, text="Watch this device", style="Big.TButton", command=lambda: self._set_watch(True)).pack(
            side="left", padx=4)
        ttk.Button(row, text="Stop watching", command=lambda: self._set_watch(False)).pack(side="left")
        ttk.Button(row, text="Watch router + all network equipment", command=self._watch_gear).pack(side="left", padx=8)
        self.wt = nd_tabs.UI["make_tree"](f, ("ip", "status", "up", "rtt", "downs", "since", "where"),
                                          ("IP", "Status", "Up (24 h)", "Last ping", "Times down", "Down since / last down",
                                           "Connected to"), (115, 120, 85, 80, 95, 170, 220), first=("Device", 220))
        ttk.Label(f, text="You can also tick 'Watch' in Tag... for any device. Watching works while Network Doctor runs "
                          "(turn on Setup > Start with Windows on the monitoring PC).", foreground="#667085").pack(
            anchor="w", pady=4)

    def _wdevs(self):
        app = self.app
        out = {}
        for d in sorted([d for d in app.devices if d.get("mac")], key=lambda d: core.ip_key(d.get("ip", ""))):
            out[f"{d.get('name') or '-'}   {d.get('ip', '')}   {d['mac']}"] = d
        return out

    def _set_watch(self, on):
        d = self._wdevs().get(self.var_wdev.get())
        if not d:
            messagebox.showinfo(APP, "Choose a device first (run a scan if the list is empty).")
            return
        T.set_tag(self.app.db, d["mac"], watch="1" if on else "")
        core.save_db(self.app.db)
        self.app.watch_now()
        self.refresh_watch()

    def _watch_gear(self):
        tags = T.tags_of(self.app.db)
        n = 0
        for d in self.app.devices:
            if d.get("mac") and d.get("online") and (d.get("ip") == self.app.gw or T.is_gear(d, tags)):
                T.set_tag(self.app.db, d["mac"], watch="1")
                n += 1
        core.save_db(self.app.db)
        self.app.watch_now()
        self.refresh_watch()
        messagebox.showinfo(APP, f"{n} device(s) are now watched.")

    def refresh_watch(self):
        if "watch" not in self.frames:
            return
        self.wcb.configure(values=list(self._wdevs()))
        tv = self.wt
        tv.delete(*tv.get_children())
        tags = T.tags_of(self.app.db)
        names = {d.get("mac"): (d.get("name") or d.get("ip")) for d in self.app.devices if d.get("mac")}
        st_all = self.app.watch_state
        rows = T.watched(self.app.db)
        if not rows:
            tv.insert("", "end", text="No device is watched yet - choose one above and press 'Watch this device'.")
            return
        for mac, t in sorted(rows.items(), key=lambda kv: (kv[1].get("name") or "").lower()):
            st = st_all.get(mac) or {}
            hist = st.get("hist") or []
            up = f"{100.0 * sum(1 for _, ok in hist if ok) / len(hist):.1f}%" if hist else "-"
            if not st:
                status, tag = "starting...", ()
            elif st.get("down_since"):
                status, tag = "DOWN", ("critical",)
            elif st.get("fails"):
                status, tag = f"missed {st['fails']} ping(s)", ("warning",)
            else:
                status, tag = "OK", ("pass",)
            since = time.strftime("%d-%b %H:%M", time.localtime(st["down_since"])) if st.get("down_since") else (
                "last: " + time.strftime("%d-%b %H:%M", time.localtime(st["last_down"])) if st.get("last_down") else "")
            par = tags.get(t.get("parent") or "", {})
            where = (par.get("name") or names.get(t.get("parent")) or "") + (
                f" port {t['switch_port']}" if t.get("switch_port") else "")
            if not where and t.get("router_port"):
                where = "router " + t["router_port"]
            tv.insert("", "end", text=t.get("name") or names.get(mac) or mac, tags=tag,
                      values=(st.get("ip", "not seen yet"), status, up,
                              f"{st['rtt']:.0f} ms" if st.get("rtt") is not None else "-", st.get("downs", 0), since,
                              where))

    # ------------------------------------------------------------------ internet speed
    def _build_speed(self, f):
        row = ttk.Frame(f)
        row.pack(fill="x")
        self._run_btn(row, "speed", "Run speed test (about 30 s)", self._speed)
        self._stop_btn(row, "speed")
        ttk.Label(row, text="  Other people's downloads during the test lower the result - see Live monitor > Top "
                            "bandwidth users.", foreground="#667085").pack(side="left")
        self._out_box(f, "speed")

    def _speed(self, out, stop):
        app = self.app
        out("Public address", "h")
        info = NT.public_ip_info()
        if not info:
            out("The internet is not reachable from this PC (or speed.cloudflare.com is blocked by a firewall).", "crit")
        else:
            out(f"  Public IP  {info['ip']}")
            if info.get("isp"):
                out(f"  ISP        {info['isp']}" + (f"  (AS{info['asn']})" if info.get("asn") else ""))
            out(f"  Location   {info.get('city', '')} {info.get('country', '')} - speed-test server {info.get('colo', '')}")
        out("\nPing quality (10 pings each)", "h")
        targets = []
        if app.gw:
            targets.append(("Router (your LAN)", app.gw))
        dns = NT.system_dns_servers()
        if dns and dns[0] != app.gw:
            targets.append(("DNS server", dns[0]))
        targets += [("Internet - Cloudflare", "1.1.1.1"), ("Internet - Google", "8.8.8.8")]
        with cf.ThreadPoolExecutor(len(targets)) as ex:
            res = list(ex.map(lambda t: NT.ping_stats(t[1], 10), targets))
        for (lab, ip), r in zip(targets, res):
            if r["recv"]:
                out(f"  {lab:<24}{ip:<16}{r['avg']:6.1f} ms   jitter {r['jitter']:5.1f} ms   loss {r['loss']:3.0f}%",
                    "warn" if r["loss"] > 0 or r["jitter"] > 30 else "")
            else:
                out(f"  {lab:<24}{ip:<16}  no answer", "crit")
        gwr = res[0] if app.gw else None
        inet = [r for (lab, _), r in zip(targets, res) if lab.startswith("Internet")]
        if gwr and gwr["loss"] > 0:
            out("  ! Pings to the ROUTER are lost: the problem is inside the office (loop, bad cable, weak Wi-Fi or an "
                "overloaded router) - not the ISP.", "crit")
        elif inet and all(r["loss"] > 0 for r in inet):
            out("  ! The router is fine but the internet loses packets: the ISP line / modem. Show this to the ISP.", "warn")
        idle = inet[0]["avg"] if inet and inet[0]["recv"] else None
        if stop.is_set() or not info:
            return
        out("\nDownload", "h")
        down = up = loaded = None
        try:
            with NT.LoadedPinger("1.1.1.1") as lp:
                down = NT.throughput("down", 8, 4, stop, lambda m: out(f"download {m:.0f} Mbit/s ...", "status"))
            loaded = statistics.median(lp.times) if lp.times else None
            out(f"  {down:.1f} Mbit/s", "ok")
        except Exception as e:
            out(f"  failed: {e}", "crit")
        if stop.is_set():
            return
        out("\nUpload", "h")
        try:
            up = NT.throughput("up", 8, 3, stop, lambda m: out(f"upload {m:.0f} Mbit/s ...", "status"))
            out(f"  {up:.1f} Mbit/s", "ok")
        except Exception as e:
            out(f"  failed: {e}", "crit")
        out("\nLatency", "h")
        if idle is not None:
            out(f"  idle {idle:.0f} ms" + (f",  while downloading {loaded:.0f} ms" if loaded is not None else ""))
        tips = NT.grade_line(down, up, idle, loaded)
        for tline in tips:
            out("  ! " + tline, "warn")
        if not tips and down:
            out("  Line looks healthy.", "ok")
        out("Speed test", "status")
        out(("Speed test", "info", f"down {down or 0:.1f} Mbit/s, up {up or 0:.1f} Mbit/s, ping {idle or 0:.0f} ms, "
                                   f"loaded {loaded or 0:.0f} ms, ISP {info.get('isp', '')}"), "log")
        out("\n(The result is saved in the health log, so you can compare days and times.)", "mute")

    # ------------------------------------------------------------------ port scanner
    def _build_ports(self, f):
        row = ttk.Frame(f)
        row.pack(fill="x")
        self.var_ptarget, _ = self._combo(row, "Device:", [], 30)
        ttk.Label(row, text="Ports:").pack(side="left")
        self.var_pset = tk.StringVar(value=list(NT.PRESETS)[0])
        cb = ttk.Combobox(row, textvariable=self.var_pset, values=list(NT.PRESETS), width=26, state="readonly")
        cb.pack(side="left", padx=4)
        self.var_plist = tk.StringVar(value="common")
        cb.bind("<<ComboboxSelected>>", lambda e: self.var_plist.set(NT.PRESETS[self.var_pset.get()]))
        ttk.Entry(row, textvariable=self.var_plist, width=22).pack(side="left", padx=4)
        self._run_btn(row, "ports", "Scan", self._ports)
        self._stop_btn(row, "ports")
        if self.app.selected_device:
            self.var_ptarget.set(self.app.selected_device.get("ip", ""))
        self._out_box(f, "ports")

    def _ports(self, out, stop):
        host = self._ip_of(self.var_ptarget.get())
        if not host:
            out("Choose a device or type an IP / name.", "warn")
            return
        ports = NT.parse_ports(self.var_plist.get())
        out(f"Scanning {len(ports):,} TCP ports on {host} ...", "h")
        t0 = time.time()
        ip, found = NT.port_scan(host, ports, stop=stop,
                                 progress=lambda d, n, k: out(f"{d:,} / {n:,} ports checked, {k} open", "status"))
        out(f"{len(found)} open port(s) on {ip}   ({time.time() - t0:.1f} s)\n", "h")
        if not found:
            out("No open ports: the device is off, blocks everything (firewall), or offers no services on these ports.")
        for r in found:
            out(f"  {r['port']:>5}  {r['service'][:34]:<34} {r['banner'][:70]}")
            if r["risk"]:
                out(f"         ! {r['risk']}", "warn")
        if stop.is_set():
            out("\n(stopped)", "mute")

    # ------------------------------------------------------------------ switch / router (SNMP)
    def _build_switch(self, f):
        row = ttk.Frame(f)
        row.pack(fill="x")
        self.var_sw, _ = self._combo(row, "Switch / router:", [], 30)
        ttk.Label(row, text="Community:").pack(side="left")
        self.var_sw_comm = tk.StringVar(value="public")
        ttk.Entry(row, textvariable=self.var_sw_comm, width=14).pack(side="left", padx=4)
        ttk.Label(row, text="Version:").pack(side="left")
        self.var_sw_ver = tk.StringVar(value="2c")
        ttk.Combobox(row, textvariable=self.var_sw_ver, values=["2c", "1"], width=4,
                     state="readonly").pack(side="left", padx=4)
        self._run_btn(row, "switch", "Read", self._switch)
        row2 = ttk.Frame(f)
        row2.pack(fill="x", pady=(4, 0))
        self._run_btn(row2, "switch", "Live traffic + loop check", self._switch_live)
        self._stop_btn(row2, "switch")
        row3 = ttk.Frame(f)
        row3.pack(fill="x", pady=(4, 0))
        ttk.Label(row3, text="Port:").pack(side="left")
        self.var_sw_port = tk.StringVar()
        self.cb_sw_port = ttk.Combobox(row3, textvariable=self.var_sw_port, values=[], width=24, state="readonly")
        self.cb_sw_port.pack(side="left", padx=4)
        ttk.Label(row3, text="Write community:").pack(side="left")
        self.var_sw_wcomm = tk.StringVar()
        ttk.Entry(row3, textvariable=self.var_sw_wcomm, width=14, show="*").pack(side="left", padx=4)
        row4 = ttk.Frame(f)
        row4.pack(fill="x", pady=(4, 0))
        for label, action in (("Turn off", "off"), ("Turn on", "on"), ("Restart port", "restart"),
                              ("Rename...", "rename"), ("Undo last change", "undo")):
            b = ttk.Button(row4, text=label, command=lambda a=action: self._switch_change(a))
            b.pack(side="left", padx=2)
            self.btns.setdefault("switch", []).append(b)
        ttk.Label(f, text="Turn on SNMP (v2c) on the switch first, with a community name. Reading never changes "
                          "anything. Live traffic refreshes every 5 seconds until you press Stop. To turn ports off / on "
                          "or rename them, press Read first, then use the switch's read-write community; every change "
                          "asks first and can be undone.", foreground="#667085", wraplength=900, justify="left").pack(
            anchor="w")
        self.sw_ports, self.sw_macs, self.sw_undo, self.sw_host = {}, {}, [], ""
        if self.app.selected_device:
            self.var_sw.set(self.app.selected_device.get("ip", ""))
        self._out_box(f, "switch")

    def _switch(self, out, stop):
        host = self._ip_of(self.var_sw.get())
        if not host:
            out("Choose a switch or router, or type its IP.", "warn")
            return
        creds = {"community": self.var_sw_comm.get().strip() or "public", "version": self.var_sw_ver.get()}
        out(f"Reading {host} over SNMP v{creds['version']} ...", "h")
        plugin = nd_plugins.find(host, creds)
        if not plugin:
            out("No SNMP answer. Check that SNMP is on, the community name is right, and this PC's IP is "
                "allowed to read it.", "crit")
            return
        d = plugin.read(host, creds)
        si = d["system"]
        out(f"\n{si['name'] or host}" + (f"  -  {si['vendor']}" if si["vendor"] else ""), "h")
        if si["descr"]:
            out("  " + si["descr"][:160])
        out(f"  Up for {nd_snmp.uptime_text(si['uptime'])}" + (f"   Location: {si['location']}" if si["location"] else "")
            + (f"   Contact: {si['contact']}" if si["contact"] else ""))

        ports = [i for i in d["interfaces"] if i["type"] != 24]  # 24 = loopback
        up = [i for i in ports if i["status"] == "up"]

        def keep(ports=ports, macs=d["macs"]):
            self.sw_host, self.sw_macs = host, macs
            self.sw_ports = {f"{i['name']}" + (f"  ({i['alias']})" if i["alias"] else ""): i for i in ports}
            self.cb_sw_port.configure(values=list(self.sw_ports))
        out(keep, "call")
        out(f"\nPorts ({len(ports)}, {len(up)} up)", "h")
        for i in ports:
            if i["status"] != "up":
                out(f"  {i['name'][:24]:<24} {i['status']}" + (f"   {i['alias']}" if i["alias"] else ""), "mute")
                continue
            out(f"  {i['name'][:24]:<24} up     {nd_snmp.speed_text(i['speed_mbps']):<9} in {M.fmt_bytes(i['in_octets']):>9}"
                f"  out {M.fmt_bytes(i['out_octets']):>9}" + (f"   {i['alias']}" if i["alias"] else ""))
            if i["speed_mbps"] in (10, 100) and i["type"] == 6:
                out(f"      ! runs at {i['speed_mbps']} Mbps - check the cable or the device's network card", "warn")
            if i["in_errors"] or i["out_errors"]:
                out(f"      ! errors in/out {i['in_errors']:,} / {i['out_errors']:,} - bad cable, connector or duplex "
                    "mismatch", "warn")

        if d["neighbors"]:
            out("\nNeighbours (LLDP)", "h")
            for n in d["neighbors"]:
                out(f"  {n['local_port'][:24]:<24} {n['name'] or n['chassis']}" + (f"  port {n['port']}" if n["port"] else ""))

        by_port = nd_snmp.ports_with_devices(d["macs"])
        out(f"\nDevices per port ({len(d['macs'])} MAC addresses)", "h")
        if not by_port:
            out("  The switch did not share its MAC address table.", "mute")
        known = {x.get("mac"): x for x in self.app.devices if x.get("mac")}
        for port, macs in by_port.items():
            if len(macs) > 4:
                out(f"  {port[:24]:<24} {len(macs)} devices - probably a link to another switch, AP or the router")
                continue
            for k, mac in enumerate(macs):
                x = known.get(mac)
                who = f"{x.get('name') or ''}  {x.get('ip', '')}".strip() if x else ""
                out(f"  {(port if k == 0 else '')[:24]:<24} {mac}  {who}")

    def _switch_live(self, out, stop):
        """Traffic per port every 5 s, plus loop signs: broadcast storms and MACs bouncing between ports."""
        host = self._ip_of(self.var_sw.get())
        if not host:
            out("Choose a switch or router, or type its IP.", "warn")
            return
        c = nd_snmp.Snmp(host, self.var_sw_comm.get().strip() or "public", self.var_sw_ver.get())
        out(f"Reading {host} ...", "h")
        try:
            si = nd_snmp.system_info(c)
            ifs = {i["index"]: i for i in nd_snmp.interfaces(c) if i["type"] != 24}
        except nd_snmp.SnmpError as e:
            out(f"No SNMP answer ({e}). Check that SNMP is on, the community name is right, and this PC's IP is "
                "allowed to read it.", "crit")
            return
        name = si["name"] or host
        known = {x.get("mac"): x for x in self.app.devices if x.get("mac")}
        prev, macs, rounds, logged = nd_snmp.counters(c), None, 0, set()
        moves_seen = {}  # (port_a, port_b) -> set of MACs that bounced between them this session
        while not stop.wait(5):
            try:
                cur = nd_snmp.counters(c)
                if rounds % 6 == 0:  # MAC table every 30 s: it is big on large switches
                    m = nd_snmp.mac_table(c, list(ifs.values()))
                    if macs is not None:
                        for pair, ms in nd_snmp.mac_moves(macs, m).items():
                            moves_seen.setdefault(pair, set()).update(ms)
                    macs = m
            except nd_snmp.SnmpError as e:
                out(f"{name} stopped answering ({e}) - retrying", "status")
                continue
            rates, prev, rounds = nd_snmp.rates(prev, cur), cur, rounds + 1
            rows = []
            for idx, r in rates.items():
                i = ifs.get(idx)
                if i:
                    rows.append((r.get("in", 0) + r.get("out", 0), i, r))
            rows.sort(key=lambda x: -x[0])
            alerts = [(i, lv, t) for _, i, r in rows for lv, t in nd_snmp.port_warnings(r, i["speed_mbps"])]
            loops = {p: ms for p, ms in moves_seen.items() if len(ms) >= 3}

            out("", "clear")
            out(f"{name}  -  live traffic   {time.strftime('%H:%M:%S')}   (every 5 s, press Stop to end)", "h")
            if loops or any(lv == "crit" for _, lv, _ in alerts):
                out("\nLOOP WARNING", "crit")
                for (a, b), ms in loops.items():
                    out(f"  {len(ms)} devices keep jumping between {a} and {b}: these two ports are connected to each "
                        "other through a loop. Unplug the cable on one of them.", "crit")
                for i, lv, t in alerts:
                    if lv == "crit":
                        out(f"  {i['name']}: {t}", "crit")
                for key in [f"{a}|{b}" for a, b in loops] + [i["name"] for i, lv, _ in alerts if lv == "crit"]:
                    if key not in logged:
                        logged.add(key)
                        out(("Loop check", "crit", f"{name}: possible loop at {key.replace('|', ' <-> ')}"), "log")
            out(f"\n  {'Port':<22} {'Speed':<9} {'In':>11} {'Out':>11} {'Busy':>5} {'Bcast/s':>8}  Device")
            for total, i, r in rows[:40]:
                u = nd_snmp.utilisation(r, i["speed_mbps"])
                who = ""
                if macs:
                    on = [mac for mac, port in macs.items() if port == i["name"]]
                    if len(on) == 1 and on[0] in known:
                        who = known[on[0]].get("name") or known[on[0]].get("ip", "")
                    elif len(on) > 4:
                        who = f"{len(on)} devices (switch / AP)"
                    elif on:
                        who = on[0] if len(on) == 1 else f"{len(on)} devices"
                lvs = [lv for lv, _ in nd_snmp.port_warnings(r, i["speed_mbps"])]
                mark = "!!" if "crit" in lvs else ("! " if lvs else "  ")
                out(f"{mark}{i['name'][:22]:<22} {nd_snmp.speed_text(i['speed_mbps']):<9} {M.fmt_rate(r.get('in', 0)):>11} "
                    f"{M.fmt_rate(r.get('out', 0)):>11} {'' if u is None else f'{u:.0f}%':>5} "
                    f"{r.get('bcast', 0):>8,.0f}  {who[:30]}", "mute" if total < 1000 and not lvs else "")
            warns = [(i, t) for i, lv, t in alerts if lv == "warn"]
            if warns:
                out("\nOther problems", "h")
                for i, t in warns:
                    out(f"  {i['name']}: {t}", "warn")
            if not loops and not alerts:
                out("\nNo loop signs and no busy or faulty ports right now.", "ok")
            out(f"{name}: {len(rows)} ports, updated {time.strftime('%H:%M:%S')}", "status")

    def _switch_change(self, action):
        """Port off / on / restart / rename / undo. Asks first (in the window), then runs in the background."""
        host = self.sw_host
        if action == "undo":
            if not self.sw_undo:
                messagebox.showinfo("Undo", "No change to undo.", parent=self.app)
                return
            desc, index, kind, value = self.sw_undo[-1]
            if not messagebox.askyesno("Undo", f"Undo: {desc}?", parent=self.app):
                return
            self.sw_undo.pop()
            port = {"index": index, "name": desc.split(":")[0]}
        else:
            port = self.sw_ports.get(self.var_sw_port.get())
            if not host or not port:
                messagebox.showinfo("Switch", "Press Read first, then choose a port.", parent=self.app)
                return
        wcomm = self.var_sw_wcomm.get().strip()
        if not wcomm:
            messagebox.showinfo("Switch", "Type the switch's read-WRITE community. Reading uses the normal one; "
                                          "changes need the write one.", parent=self.app)
            return
        name, index = port["name"], port["index"]
        if action in ("off", "restart"):
            risk = nd_snmp.port_risk(name, self.sw_macs, [core.local_mac(self.app.lip or "")])
            what = "Turn off" if action == "off" else "Restart (off for 5 seconds, then on)"
            msg = f"{what} port {name} on {host}?" + (f"\n\nWARNING: {risk}." if risk else "")
            if not messagebox.askyesno("Switch port", msg, icon="warning" if risk else "question", parent=self.app):
                return
        elif action == "on":
            if not messagebox.askyesno("Switch port", f"Turn on port {name} on {host}?", parent=self.app):
                return
        elif action == "rename":
            new = simpledialog.askstring("Rename port", f"New description for {name}:", parent=self.app,
                                         initialvalue=port.get("alias", ""))
            if new is None:
                return
        c = nd_snmp.Snmp(host, wcomm, self.var_sw_ver.get())

        def work(out, stop):
            if action == "undo":
                out(f"Undo: {desc} ...", "h")
                if kind == "admin":
                    out(f"  port is now {nd_snmp.set_port(c, index, value == 'up')}", "ok")
                else:
                    nd_snmp.set_alias(c, index, value)
                    out(f"  description is back to '{value}'", "ok")
                return
            if action in ("off", "on"):
                before = nd_snmp.port_admin(c, index)
                now = nd_snmp.set_port(c, index, action == "on")
                out(f"Port {name} on {host} is now {now}.", "ok" if now == ("up" if action == "on" else "down") else "warn")
                self.sw_undo.append((f"{name}: turned {'on' if action == 'on' else 'off'}", index, "admin", before))
            elif action == "restart":
                out(f"Restarting port {name} on {host} ...", "h")
                nd_snmp.set_port(c, index, False)
                out("  off - waiting 5 seconds")
                time.sleep(5)
                now = nd_snmp.set_port(c, index, True)
                out(f"  on again ({now}). The device on it reconnects in a few seconds.", "ok" if now == "up" else "warn")
            elif action == "rename":
                old = nd_snmp.set_alias(c, index, new)
                out(f"Port {name} description: '{old}' -> '{new}'", "ok")
                self.sw_undo.append((f"{name}: renamed to '{new}'", index, "alias", old))
            out(("Switch change", "info", f"{host} {name}: {action}" + (f" '{new}'" if action == "rename" else "")), "log")
        self.start("switch", work)

    # ------------------------------------------------------------------ DNS
    def _build_dns(self, f):
        row = ttk.Frame(f)
        row.pack(fill="x")
        ttk.Label(row, text="Name or IP:").pack(side="left")
        self.var_dname = tk.StringVar(value="google.com")
        ttk.Entry(row, textvariable=self.var_dname, width=30).pack(side="left", padx=4)
        ttk.Label(row, text="Type:").pack(side="left")
        self.var_dtype = tk.StringVar(value="A")
        ttk.Combobox(row, textvariable=self.var_dtype, values=list(NT.QTYPES), width=6, state="readonly").pack(
            side="left", padx=4)
        ttk.Label(row, text="Server:").pack(side="left")
        self.var_dsrv = tk.StringVar(value="This PC's DNS")
        ttk.Combobox(row, textvariable=self.var_dsrv, width=22,
                     values=["This PC's DNS", f"Router {self.app.gw or ''}".strip(), "1.1.1.1 Cloudflare",
                             "8.8.8.8 Google", "9.9.9.9 Quad9"]).pack(side="left", padx=4)
        self._run_btn(row, "dns", "Look up", self._dns)
        self._run_btn(row, "dns", "Test DNS servers", self._dns_bench)
        self._out_box(f, "dns")

    def _dns_server(self):
        v = self.var_dsrv.get().strip()
        if v.startswith("This PC"):
            s = NT.system_dns_servers()
            return s[0] if s else (self.app.gw or "8.8.8.8")
        for tok in v.split():
            try:
                ipaddress.ip_address(tok)
                return tok
            except ValueError:
                continue
        return v

    def _dns(self, out, stop):
        name, typ, srv = self.var_dname.get().strip(), self.var_dtype.get(), self._dns_server()
        if not name:
            return
        if typ == "A":
            try:
                ipaddress.ip_address(name)
                typ = "PTR"
            except ValueError:
                pass
        r = NT.dns_query(name, typ, srv)
        out(f"{typ} {r.get('query', name)}  @ {srv}", "h")
        if "error" in r:
            out(f"  {r['error']} - the server does not answer DNS (wrong address, blocked, or down).", "crit")
            return
        out(f"  answer: {NT.RCODES.get(r['rcode'], r['rcode'])} in {r['ms']:.0f} ms"
            + ("   (authoritative)" if r["aa"] else ""), "ok" if r["rcode"] == 0 else "warn")
        for x in r["records"]:
            if x["section"] == "answer":
                out(f"  {x['type']:<6} {x['data']}   (ttl {x['ttl']} s)")
        if not [x for x in r["records"] if x["section"] == "answer"]:
            out("  no records of this type.")
            for x in r["records"]:
                out(f"  [authority] {x['type']} {x['data']}", "mute")

    def _dns_bench(self, out, stop):
        app = self.app
        servers = []
        for s in NT.system_dns_servers():
            servers.append(("This PC's DNS", s))
        if app.gw and app.gw not in [s for _, s in servers]:
            servers.append(("Router", app.gw))
        servers += NT.PUBLIC_DNS
        out("Testing DNS servers (14 look-ups each + a hijack test)...", "h")
        res = NT.dns_benchmark(servers)
        res.sort(key=lambda r: (r["fail_pct"] > 20, r["median"] if r["median"] is not None else 9e9))
        for r in res:
            med = f"{r['median']:6.0f} ms" if r["median"] is not None else "   no answer"
            out(f"  {r['label']:<16}{r['server']:<16}{med}   failures {r['fail_pct']:3.0f}%"
                + ("   ! REDIRECTS non-existent names (DNS hijacking)" if r["hijack"] else ""),
                "crit" if r["median"] is None else "warn" if r["fail_pct"] or r["hijack"] else "")
        good = [r for r in res if r["median"] is not None and not r["fail_pct"]]
        if good:
            b = good[0]
            out(f"\nFastest reliable: {b['label']} {b['server']}.", "ok")
            sysd = [r for r in res if r["label"] == "This PC's DNS" and r["median"] is not None]
            if sysd and b["median"] and sysd[0]["median"] > b["median"] * 2 and sysd[0]["median"] - b["median"] > 30:
                out(f"This PC's DNS is much slower - set the router to use {b['server']} (MikroTik: /ip dns set "
                    f"servers={b['server']},{'8.8.8.8' if b['server'] != '8.8.8.8' else '1.1.1.1'} allow-remote-requests=yes)"
                    " and give PCs the router as DNS.", "warn")

    # ------------------------------------------------------------------ web check
    def _build_web(self, f):
        row = ttk.Frame(f)
        row.pack(fill="x")
        self.var_url, _ = self._combo(row, "Address:", [], 44, "https://www.google.com")
        self._run_btn(row, "web", "Check", self._web)
        ttk.Label(row, text="e.g. http://192.168.0.50  or  erp-server:8080  or  https://yourdomain.com",
                  foreground="#667085").pack(side="left")
        self._out_box(f, "web")

    def _web(self, out, stop):
        tgt = self.var_url.get().strip()
        if tgt and tgt[0].isdigit() and "   " in tgt:
            tgt = tgt.split()[0]
        if not tgt:
            return
        out(tgt, "h")
        for lab, val, sev in NT.web_check(tgt):
            out(f"  {lab:<14}{val}", {"critical": "crit", "warning": "warn"}.get(sev, ""))

    # ------------------------------------------------------------------ LAN speed
    def _build_lan(self, f):
        row = ttk.Frame(f)
        row.pack(fill="x")
        self.var_lanrx = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text=f"Receiver ON on this PC (TCP {NT.LAN_PORT}, 60 min)", variable=self.var_lanrx,
                        command=self._lan_rx).pack(side="left")
        ttk.Separator(row, orient="vertical").pack(side="left", fill="y", padx=10)
        self.var_lantarget, _ = self._combo(row, "Other PC:", [], 28)
        self._run_btn(row, "lan", "Test speed", self._lan)
        ttk.Label(f, text="How: open Network Doctor on the other PC, Tools > LAN speed test, tick 'Receiver ON'. Then "
                          "press Test speed here. Test across the switch you suspect.", foreground="#667085").pack(
            anchor="w", pady=(4, 0))
        self._out_box(f, "lan")

    def _lan_rx(self):
        if self.var_lanrx.get():
            try:
                self.app.firewall(quiet=True)
                self.lan_server = NT.LanSpeedServer()
                self.lan_server.start()
                self.status["lan"].set(f"receiver on: other PCs can test to {self.app.lip}")
            except OSError as e:
                self.var_lanrx.set(False)
                messagebox.showerror(APP, f"Could not start the receiver: {e}")
        elif self.lan_server:
            self.lan_server.stop()
            self.lan_server = None
            self.status["lan"].set("receiver off")

    def _lan(self, out, stop):
        ip = self._ip_of(self.var_lantarget.get())
        if not ip:
            out("Choose the other PC.", "warn")
            return
        out(f"Testing {self.app.lip} <-> {ip} (5 s each way)...", "h")
        try:
            up, down = NT.lan_speed_test(ip, 5, lambda s: out("  " + s))
        except OSError as e:
            out(f"  {ip} does not answer on TCP {NT.LAN_PORT}: tick 'Receiver ON' in Network Doctor on that PC, and "
                f"allow it in its firewall (Setup > Allow in Windows Firewall). ({e})", "crit")
            return
        out(f"  {ip} -> this PC: {down:.0f} Mbit/s")
        worst = min(up, down)
        out("\n" + NT.lan_advice(worst), "ok" if worst >= 600 else "warn")
        out(("LAN speed test", "info", f"{self.app.lip} <-> {ip}: up {up:.0f} / down {down:.0f} Mbit/s"), "log")

    # ------------------------------------------------------------------ Wi-Fi
    def _build_wifi(self, f):
        row = ttk.Frame(f)
        row.pack(fill="x")
        self._run_btn(row, "wifi", "Scan Wi-Fi", self._wifi)
        ttk.Label(row, text="  Run it on a laptop where the Wi-Fi problem is - it sees what that spot sees.",
                  foreground="#667085").pack(side="left")
        self._out_box(f, "wifi")

    def _wifi(self, out, stop):
        cur, nets, note = NT.wifi_scan()
        if note:
            out(note, "warn")
        if not nets and not cur:
            return
        lines, counts = NT.wifi_analyse(nets, cur)
        out("Advice", "h")
        for ln in lines:
            out(ln, "warn" if "!" in ln else "")
        out(f"\n{len(nets)} access point(s) seen", "h")
        out(f"  {'Network (SSID)':<28}{'Band':<9}{'Ch':>4}{'Signal':>8}   {'Security':<22}BSSID")
        for n in sorted(nets, key=lambda n: (n.get("band", ""), n.get("channel") or 0, -(n.get("signal") or 0))):
            out(f"  {n['ssid'][:27]:<28}{n.get('band', ''):<9}{n.get('channel') or '':>4}"
                f"{(str(n['signal']) + '%') if n.get('signal') is not None else '':>8}   "
                f"{(n.get('auth') or '')[:21]:<22}{n.get('bssid', '')}",
                "warn" if (n.get("signal") or 100) < 35 else "")
        out("\nChannel use (2.4 GHz)", "h")
        for ch in range(1, 14):
            if counts.get(ch):
                out(f"  ch {ch:>2} {'#' * counts[ch]}  {counts[ch]}")
        five = sorted(c for c in counts if c > 14)
        if five:
            out("Channel use (5 GHz)", "h")
            for ch in five:
                out(f"  ch {ch:>3} {'#' * counts[ch]}  {counts[ch]}")

    # ------------------------------------------------------------------ adapters
    def _build_nic(self, f):
        row = ttk.Frame(f)
        row.pack(fill="x")
        self._run_btn(row, "nic", "Check adapters", self._nic)
        ttk.Label(row, text="  To check every office PC at once, run the PC fix script - it reports cable speed too "
                            "(Problems tab).", foreground="#667085").pack(side="left")
        self._out_box(f, "nic")

    def _nic(self, out, stop):
        ads = NT.adapters()
        if not ads:
            out("Could not read the network adapters.", "crit")
            return
        out("Findings", "h")
        for sev, text in NT.adapter_findings(ads):
            out(("  ! " if sev != "ok" else "  ") + text, {"critical": "crit", "warning": "warn", "ok": "ok"}.get(sev, ""))
        out("\nAdapters", "h")
        for a in sorted(ads, key=lambda a: (str(a.get("status")).lower() != "up", bool(a.get("virtual")))):
            vir = "  (virtual)" if a.get("virtual") else ""
            out(f"  {a.get('name')}{vir} - {a.get('desc', '')}", "" if str(a.get("status")).lower() == "up" else "mute")
            if str(a.get("status")).lower() != "up":
                out(f"      {a.get('status')}", "mute")
                continue
            dup = "" if a.get("duplex") is None else ("full duplex" if a.get("duplex") else "HALF duplex")
            out(f"      link {a.get('speed') or '?'} {dup}   MAC {a.get('mac', '')}   "
                f"{'Wi-Fi' if a.get('wifi') else 'cable'}")
            if a.get("ip"):
                out(f"      IP {a['ip']}" + (f"/{a['prefix']}" if a.get("prefix") else "") +
                    (f"   DHCP {a['dhcp']}" if a.get("dhcp") else "") + (f"   MTU {a['mtu']}" if a.get("mtu") else ""))
            out(f"      errors in/out {int(a.get('rxerr') or 0):,} / {int(a.get('txerr') or 0):,}   discarded "
                f"{int(a.get('rxdisc') or 0):,} / {int(a.get('txdisc') or 0):,}")

    # ------------------------------------------------------------------ MTU
    def _build_mtu(self, f):
        row = ttk.Frame(f)
        row.pack(fill="x")
        self.var_mtu, _ = self._combo(row, "Target:", ["8.8.8.8", "1.1.1.1"], 28, "8.8.8.8")
        self._run_btn(row, "mtu", "Find MTU", self._mtu)
        self._stop_btn(row, "mtu")
        self._out_box(f, "mtu")

    def _mtu(self, out, stop):
        t = self._ip_of(self.var_mtu.get())
        out(f"Finding the largest packet to {t} ...", "h")
        m = NT.mtu_probe(t, out, stop)
        if m:
            out(f"\nPath MTU: {m}", "h")
            out(NT.mtu_advice(m), "ok" if m >= 1500 else "warn")

    # ------------------------------------------------------------------ subnet
    def _build_subnet(self, f):
        row = ttk.Frame(f)
        row.pack(fill="x")
        ttk.Label(row, text="Address:").pack(side="left")
        pre = self.app.net.split("/")[1] if "/" in self.app.net else "24"
        self.var_sub = tk.StringVar(value=f"{self.app.lip}/{pre}")
        e = ttk.Entry(row, textvariable=self.var_sub, width=30)
        e.pack(side="left", padx=4)
        e.bind("<Return>", lambda ev: self._subnet())
        ttk.Button(row, text="Calculate", style="Big.TButton", command=self._subnet).pack(side="left", padx=4)
        ttk.Label(row, text="   Is this IP in the same network?").pack(side="left")
        self.var_sub2 = tk.StringVar()
        e2 = ttk.Entry(row, textvariable=self.var_sub2, width=16)
        e2.pack(side="left", padx=4)
        e2.bind("<Return>", lambda ev: self._subnet())
        self._out_box(f, "subnet")
        self._subnet()

    def _subnet(self):
        t = self.texts["subnet"]
        t.configure(state="normal")
        t.delete("1.0", "end")
        try:
            rows, net = NT.subnet_info(self.var_sub.get())
            for k, v in rows:
                t.insert("end", f"  {k:<24}{v}\n")
            other = self.var_sub2.get().strip()
            if other:
                inside = ipaddress.ip_address(other) in net
                t.insert("end", f"\n  {other} is {'INSIDE' if inside else 'NOT in'} {net}" +
                         ("" if inside else " - it needs the router (gateway) to reach this network") + "\n",
                         "ok" if inside else "warn")
        except ValueError as e:
            t.insert("end", str(e), "crit")
        t.configure(state="disabled")

    # ------------------------------------------------------------------ Wake-on-LAN
    def _build_wol(self, f):
        row = ttk.Frame(f)
        row.pack(fill="x")
        ttk.Label(row, text="Device:").pack(side="left")
        self.var_wol = tk.StringVar()
        self.wolcb = ttk.Combobox(row, textvariable=self.var_wol, width=56)
        self.wolcb.pack(side="left", padx=4)
        self.wolcb.bind("<Button-1>", lambda e: self.wolcb.configure(values=list(self._wol_devs())))
        ttk.Button(row, text="Wake up", style="Big.TButton", command=self._wol).pack(side="left", padx=4)
        ttk.Label(f, text="Pick a PC (also ones that are off now - they are remembered from earlier scans) or type a MAC.",
                  foreground="#667085").pack(anchor="w", pady=4)
        self._out_box(f, "wol")

    def _wol_devs(self):
        app = self.app
        tags = T.tags_of(app.db)
        out = {}
        for mac, h in (app.db.get("devices") or {}).items():
            name = tags.get(mac, {}).get("name") or (h.get("names") or [""])[-1]
            out[f"{name or '-'}   {h.get('ip', '')}   {mac}"] = (mac, h.get("ip"))
        return dict(sorted(out.items(), key=lambda kv: kv[0].lower()))

    def _wol(self):
        v = self.var_wol.get().strip()
        mac, ip = self._wol_devs().get(v, (None, None))
        if not mac:
            mac = core.norm_mac(v.split()[-1]) if v else None
        t = self.texts["wol"]
        t.configure(state="normal")
        try:
            pre = int(self.app.net.split("/")[1]) if "/" in self.app.net else 24
            m, sent = NT.wake_on_lan(mac or "", self.app.lip, pre, ip)
            t.insert("end", f"{time.strftime('%H:%M:%S')}  magic packet for {m} sent to {', '.join(sent)}\n", "ok")
            t.insert("end", "  A PC needs 'Wake on LAN' / 'Wake on Magic Packet' ON in BIOS and in the network card's "
                            "Power Management, and must be on cable (most Wi-Fi cannot wake). Give it 1-2 minutes.\n",
                     "mute")
        except ValueError as e:
            t.insert("end", str(e) + "\n", "crit")
        t.configure(state="disabled")

    # ------------------------------------------------------------------ MAC lookup
    def _build_mac(self, f):
        row = ttk.Frame(f)
        row.pack(fill="x")
        ttk.Label(row, text="MAC:").pack(side="left")
        self.var_mac = tk.StringVar()
        e = ttk.Entry(row, textvariable=self.var_mac, width=26)
        e.pack(side="left", padx=4)
        e.bind("<Return>", lambda ev: self._mac())
        ttk.Button(row, text="Look up", style="Big.TButton", command=self._mac).pack(side="left", padx=4)
        ttk.Label(row, text="  any format: 00-11-22-33-44-55, 0011.2233.4455, 001122334455 (first 6 digits are enough "
                            "for the vendor)", foreground="#667085").pack(side="left")
        self._out_box(f, "mac")

    def _mac(self):
        t = self.texts["mac"]
        t.configure(state="normal")
        t.delete("1.0", "end")
        raw = self.var_mac.get().strip()
        hexs = "".join(c for c in raw if c in "0123456789abcdefABCDEF")
        if 6 <= len(hexs) < 12:
            hexs = hexs + "0" * (12 - len(hexs))
        try:
            rows = NT.mac_info(hexs if len(hexs) == 12 else raw, self.app.oui)
            for k, v in rows:
                t.insert("end", f"  {k:<20}{v}\n")
            mac = core.norm_mac(hexs)
            d = next((d for d in self.app.devices if d.get("mac") == mac), None)
            h = (self.app.db.get("devices") or {}).get(mac)
            tag = T.tags_of(self.app.db).get(mac, {})
            if d:
                t.insert("end", f"\n  On the network now: {d.get('name') or '-'}  {d.get('ip')}  ({d.get('category')})\n",
                         "ok")
            elif h:
                t.insert("end", f"\n  Seen before: last {h.get('last_seen', '?')} at {h.get('ip', '?')}\n", "warn")
            else:
                t.insert("end", "\n  Never seen on this network by Network Doctor.\n", "mute")
            if tag:
                t.insert("end", "  Tag: " + ", ".join(f"{k} {v}" for k, v in tag.items()) + "\n")
        except ValueError as e:
            t.insert("end", str(e), "crit")
        t.configure(state="disabled")

    # ------------------------------------------------------------------ setup check
    def _build_ready(self, f):
        row = ttk.Frame(f)
        row.pack(fill="x")
        self._run_btn(row, "ready", "Check now", self._ready)
        app = self.app
        for txt, cmd in (("Restart as Administrator", app.elevate if core.IS_WIN else None),
                         ("Allow in Windows Firewall", app.firewall if core.IS_WIN else None),
                         ("Get Npcap (packet sniffer)", lambda: webbrowser.open("https://npcap.com/#download")),
                         ("Copy router commands", app.copy_setup),
                         ("IP-MAC binding", lambda: app.show_tab("binding"))):
            if cmd:
                ttk.Button(row, text=txt, command=cmd).pack(side="left", padx=3)
        self._out_box(f, "ready")

    def _ready(self, out, stop):
        app = self.app
        good, todo = [], []

        def item(ok, text, fix=""):
            (good if ok else todo).append((text, fix))
        if core.IS_WIN:
            item(core.is_admin(), "Running as Administrator (IP-conflict rounds, firewall rule, raw tests)",
                 "Press 'Restart as Administrator' (top right), or turn on Setup > Start with Windows - it starts as "
                 "administrator without asking.")
            rule = "Network Doctor receivers" in core.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=Network Doctor receivers"], 10)
            item(rule, "Windows Firewall lets the router feeds in", "Press 'Allow in Windows Firewall' (as administrator).")
        item(core.scapy_ok(), "Packet sniffer (Npcap) - loop echo test, who floods broadcasts, ARP-spoofing detection",
             "Install Npcap from npcap.com (tick 'WinPcap API-compatible mode'), then restart Network Doctor."
             if core.IS_WIN else "Run Network Doctor with administrator rights (sudo) for the sniffer.")
        mon = app.mon
        item(bool(mon and mon.last_flow and time.time() - mon.last_flow < 600),
             "Router sends traffic data (NetFlow) - bandwidth per device, websites / apps, malware",
             "Paste the router commands once (button 'Copy router commands', then WinBox > New Terminal).")
        item(bool(mon and mon.last_syslog and time.time() - mon.last_syslog < 3600 * 6),
             "Router sends its log (syslog) - ether2 up/down, DHCP, IP conflicts, login attempts",
             "Same router commands as above (they set up both feeds).")
        item("loaded" in str(app.threat.status).lower() or any(c.isdigit() for c in str(app.threat.status)),
             f"Threat lists: {app.threat.status}", "Setup > Update threat lists (needs internet).")
        item(app._autostart_enabled(), "Starts with Windows / at login - keeps watching 24/7",
             "Setup > tick 'Start with Windows' on the PC that stays on.")
        item(app._interval(app.var_quick_min) is not None, "Automatic loop / conflict checks are on",
             "Setup > Automatic checks: choose a check interval.")
        if core.IS_WIN:
            dh = core.local_dhcp_enabled(app.lip)
            bound = app.lip in [b.get("ip") for b in (app.db.get("bindings") or {}).values()] if isinstance(
                app.db.get("bindings"), dict) else False
            item(dh is False or bound, f"This monitoring PC keeps the same IP ({app.lip})",
                 "The router feeds go to this IP - reserve it in the IP-MAC binding tab (this PC is always included).")
        w = T.watched(app.db)
        item(bool(w), f"Critical devices watched: {len(w)}",
             "Tools > Critical devices: watch the router, server, ERP PC, DVR and switches.")
        tags = T.tags_of(app.db)
        on = [d for d in app.devices if d.get("online") and d.get("mac")]
        tagged = [d for d in on if tags.get(d["mac"], {}).get("dept") or tags.get(d["mac"], {}).get("parent")]
        if on:
            pct = 100 * len(tagged) / len(on)
            item(pct >= 60, f"Devices tagged with department / switch: {len(tagged)} of {len(on)} ({pct:.0f}%)",
                 "Devices tab: select devices > Tag... - the map can only trace problems to tagged switches / ports.")
        gear = [d for d in on if T.is_gear(d, tags) and d.get("ip") != app.gw]
        nogear_port = [d for d in gear if not tags.get(d["mac"], {}).get("router_port") and
                       not tags.get(d["mac"], {}).get("parent")]
        if gear:
            item(not nogear_port, f"Switches / access points placed on the map: {len(gear) - len(nogear_port)} of "
                                  f"{len(gear)}", "Tag each switch with the router port (or switch) it is plugged into.")
        rep = app.db.get("pc_reports") or {}
        item(bool(rep), f"PCs that ran the PC fix script: {len(rep)}",
             "IP-MAC binding > PC fix script: stops random MACs and reports each PC's name and cable speed.")
        out(f"Ready: {len(good)}     To do: {len(todo)}", "h")
        for text, fix in todo:
            out(f"\n  [ ] {text}", "warn")
            out(f"      -> {fix}")
        if good:
            out("\nAlready fine", "h")
            for text, _ in good:
                out(f"  [x] {text}", "ok")

