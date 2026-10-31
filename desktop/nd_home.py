# -*- coding: utf-8 -*-
"""Home screen: the network at a glance, what is still to set up (each with a Fix button), and big buttons for
the everyday jobs - so nobody has to know which of the tabs to open."""

import time
import tkinter as tk
from tkinter import ttk

import nd_core as core
import nd_tabs

BG, CARD, INK, MUTE = "#f4f5f7", "#ffffff", "#1c2230", "#667085"
OK, WARN, BAD, ACCENT = "#1f7a3d", "#b54708", "#b42318", "#1d4ed8"
FONT = "Segoe UI"


class HomeTab:
    def __init__(self, app, parent):
        self.app = app
        outer = tk.Frame(parent, bg=BG)
        outer.pack(fill="both", expand=True)
        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0)
        sb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        self.body = tk.Frame(canvas, bg=BG, padx=18, pady=12)
        self.body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        win = canvas.create_window((0, 0), window=self.body, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win, width=e.width))
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        b = self.body
        self.var_head = tk.StringVar(value="")
        tk.Label(b, text="Your network", font=(FONT, 18, "bold"), bg=BG, fg=INK).pack(anchor="w")
        tk.Label(b, textvariable=self.var_head, font=(FONT, 10), bg=BG, fg=MUTE).pack(anchor="w", pady=(0, 10))

        cards = tk.Frame(b, bg=BG)
        cards.pack(fill="x")
        self.cards = {}
        for i, (key, title, tab) in enumerate((("devices", "Devices online", "devices"),
                                               ("problems", "Problems", "problems"),
                                               ("usage", "Internet used today", "usage"),
                                               ("router", "Router connection", "setup"))):
            f = tk.Frame(cards, bg=CARD, highlightbackground="#e3e6eb", highlightthickness=1, padx=14, pady=10,
                         cursor="hand2")
            f.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 10, 0))
            cards.columnconfigure(i, weight=1, uniform="c")
            t = tk.Label(f, text=title, font=(FONT, 10), bg=CARD, fg=MUTE)
            t.pack(anchor="w")
            v = tk.Label(f, text="-", font=(FONT, 22, "bold"), bg=CARD, fg=INK)
            v.pack(anchor="w")
            s = tk.Label(f, text="", font=(FONT, 9), bg=CARD, fg=MUTE, justify="left", wraplength=260)
            s.pack(anchor="w")
            for w in (f, t, v, s):
                w.bind("<Button-1>", lambda e, tab=tab: self.app.show_tab(tab))
            self.cards[key] = (v, s)

        tk.Label(b, text="What do you want to do?", font=(FONT, 13, "bold"), bg=BG, fg=INK).pack(anchor="w",
                                                                                                   pady=(18, 6))
        grid = tk.Frame(b, bg=BG)
        grid.pack(fill="x")
        actions = [
            ("Scan the network now", "find every device, problems and conflicts", self.app.start_scan),
            ("See problems and how to fix them", "each problem with the reason and the fix",
             lambda: self.app.show_tab("problems")),
            ("Who uses the internet?", "apps, websites and productivity per person", lambda: self.app.show_tab("usage")),
            ("A website is slow for someone", "Google Sheets slow? find the cause and fix it",
             lambda: self.app.show_tab("slow")),
            ("All devices", "names, IPs, makers; tag them by department", lambda: self.app.show_tab("devices")),
            ("Inventory", "every PC with model, serial, RAM; export to Excel", lambda: self._tool("inventory")),
            ("Block websites / apps", "YouTube, games, adult sites... for the whole office",
             lambda: self._tool("website")),
            ("Stop a second router / random MACs", "network guard: DHCP, DNS, private MACs",
             lambda: self._tool("guard")),
            ("Give a device a fixed IP", "IP-MAC binding, applied on the router", lambda: self.app.show_tab("binding")),
            ("Watch the network live", "bandwidth now, router log, loops", lambda: self.app.show_tab("monitor")),
            ("Find the cause of a problem", "root cause from everything recorded", lambda: self.app.show_tab("rca")),
            ("Internet speed test", "speed and quality of the internet line", lambda: self._tool("speed")),
            ("Setup and router login", "one-time settings, updates, phone app", lambda: self.app.show_tab("setup")),
        ]
        sec_col = {s[0]: s[2] for s in nd_tabs.SECTIONS}
        page_sec = {p: s[0] for s in nd_tabs.SECTIONS for p, _ in s[4]}
        tile_page = ["devices", "problems", "usage", "slow", "devices", "inventory", "t_website", "t_guard", "binding",
                     "monitor", "rca", "t_speed", "setup"]
        for i, (title, sub, fn) in enumerate(actions):
            colr = sec_col.get(page_sec.get(tile_page[i] if i < len(tile_page) else "", ""), ACCENT)
            f = tk.Frame(grid, bg=CARD, highlightbackground="#e3e6eb", highlightthickness=1, padx=12, pady=9,
                         cursor="hand2")
            f.grid(row=i // 4, column=i % 4, sticky="nsew", padx=(0 if i % 4 == 0 else 10, 0), pady=(0, 10))
            grid.columnconfigure(i % 4, weight=1, uniform="a")
            tk.Frame(f, bg=colr, height=3).pack(fill="x", pady=(0, 4))  # the colour of the section it opens
            t = tk.Label(f, text=title, font=(FONT, 11, "bold"), bg=CARD, fg=colr, anchor="w", justify="left")
            t.pack(anchor="w")
            s = tk.Label(f, text=sub, font=(FONT, 9), bg=CARD, fg=MUTE, anchor="w", justify="left", wraplength=250)
            s.pack(anchor="w")
            t.configure(wraplength=250)
            f.bind("<Configure>", lambda e, t=t, s=s: (t.configure(wraplength=max(120, e.width - 26)),
                                                      s.configure(wraplength=max(120, e.width - 26))), add="+")
            for w in (f, t, s):
                w.bind("<Button-1>", lambda e, fn=fn: fn())
                w.bind("<Enter>", lambda e, f=f, c=colr: f.configure(highlightbackground=c))
                w.bind("<Leave>", lambda e, f=f: f.configure(highlightbackground="#e3e6eb"))

        tk.Label(b, text="Setup checklist", font=(FONT, 13, "bold"), bg=BG, fg=INK).pack(anchor="w", pady=(10, 2))
        tk.Label(b, text="Everything green = Network Doctor sees the whole network. Each line has its own Fix button.",
                 font=(FONT, 9), bg=BG, fg=MUTE).pack(anchor="w", pady=(0, 6))
        self.check = tk.Frame(b, bg=CARD, highlightbackground="#e3e6eb", highlightthickness=1, padx=12, pady=8)
        self.check.pack(fill="x")
        self.rows = []
        self._usage_cache = (0, None)
        self.refresh()

    def _tool(self, key):
        try:
            self.app.tools.show(key)
        except Exception:
            pass

    # ------------------------------------------------------------------ data
    def checklist(self):
        """[(ok: True/False/None, title, detail, fix_text, fix_fn)] - None = not known yet."""
        app = self.app
        st = app._settings()
        mon = app.mon
        fs = mon.feed_status() if mon else {}
        r = st.get("router_api") or {}
        out = []
        ident = r.get("ident", "")
        out.append((bool(r.get("user")) and "connected" in ident, "Router login",
                    ident or "not saved - needed for phone names, website names and applying changes",
                    "Open Setup", lambda: app.show_tab("setup")))
        flows = fs.get("flows", "")
        out.append(("receiving" in flows if mon else False, "Traffic data from the router (NetFlow)",
                    flows or "Live monitor is off", "Apply router settings",
                    lambda: app.router_apply(app.M.router_setup_commands(app.lip),
                                             "Router settings (NetFlow, log, SNMP, loop protection)")))
        logs = fs.get("syslog", "")
        out.append(("receiving" in logs or "stopped" in logs if mon else False, "Router log",
                    logs or "Live monitor is off", "Apply router settings",
                    lambda: app.router_apply(app.M.router_setup_commands(app.lip),
                                             "Router settings (NetFlow, log, SNMP, loop protection)")))
        t = ((app.raw or {}).get("meta") or {}).get("tests") or {}
        if app.raw:
            leases = (app.raw or {}).get("leases") or {}
            named = sum(1 for x in leases.values() if x.get("host"))
            out.append((bool(t.get("router_arp")), "Router's device list and phone names",
                        (f"{t['router_arp']['entries']} devices known to the router, {named} with a name"
                         if t.get("router_arp") else "not read in the last scan - save the router login, then Scan"),
                        "Scan now", app.start_scan))
        else:
            out.append((None, "Router's device list and phone names", "no scan yet", "Scan now", app.start_scan))
        if core.IS_WIN:
            fw = st.get("fw_ok")
            out.append((bool(fw), "Windows Firewall lets the router data in",
                        f"allowed {time.strftime('%d %b %H:%M', time.localtime(fw))}" if fw else
                        "press Fix once (needs Network Doctor as Administrator)", "Allow", lambda: app.firewall()))
        var = getattr(app, "var_autostart", None)
        if var is not None:
            auto = bool(var.get())
        else:  # schtasks is slow: ask once, not every refresh
            if not hasattr(self, "_auto"):
                self._auto = app._autostart_enabled()
            auto = self._auto
        out.append((auto, "Starts with Windows" if core.IS_WIN else "Starts at login",
                    "keeps watching after a restart" if auto else
                    "off - after a restart nothing is watched until someone opens it", "Turn on",
                    lambda: (app.var_autostart.set(True), app.toggle_autostart())))
        dns_ok = getattr(getattr(app, "tools", None), "dnsf", None)
        out.append((None if not dns_ok else True, "Exact app per person (optional)",
                    "website firewall running - every look-up is known" if dns_ok else
                    "optional: run the website firewall and send all DNS through this PC for exact app names",
                    "Open", lambda: self._tool("website")))
        return out

    # ------------------------------------------------------------------ drawing
    def refresh(self):
        app = self.app
        on = [d for d in app.devices if d.get("online")]
        new = len((app.raw or {}).get("meta", {}).get("new_macs") or []) if app.raw else 0
        v, s = self.cards["devices"]
        v.configure(text=str(len(on)) if app.devices else "-")
        cats = {}
        for d in on:
            k = d.get("category", "").split(" (")[0].split(" /")[0]
            cats[k] = cats.get(k, 0) + 1
        s.configure(text=("  ".join(f"{k}: {n}" for k, n in sorted(cats.items(), key=lambda x: -x[1])[:4]) +
                          (f"\n{new} new since last scan" if new else "")) if on else "press Scan the network now")
        crit = sum(1 for i in app.issues if i["sev"] == "critical")
        warn = sum(1 for i in app.issues if i["sev"] == "warning")
        v, s = self.cards["problems"]
        v.configure(text=str(crit + warn) if app.raw else "-", fg=BAD if crit else WARN if warn else OK)
        s.configure(text=(f"{crit} critical, {warn} warnings" if crit + warn else "nothing serious found")
                    if app.raw else "after the first scan")
        v, s = self.cards["usage"]
        t0, summ = self._usage_cache
        if app.usage and time.time() - t0 > 60:
            try:
                summ = app.usage.summary(1)
            except Exception:
                summ = None
            self._usage_cache = (time.time(), summ)
        if summ and sum(summ["cats"].values()):
            from nd_usage import fmt_bytes, productivity
            w = sum(x["work"] for x in summ["devices"])
            p = sum(x["personal"] for x in summ["devices"])
            sc = productivity(w, p)
            top = summ["apps"][0]["app"] if summ["apps"] else ""
            v.configure(text=fmt_bytes(sum(summ["cats"].values())))
            s.configure(text=(f"productivity {sc}%  |  " if sc is not None else "") + f"most used: {top}")
        else:
            v.configure(text="-")
            s.configure(text="needs traffic data from the router (see checklist)")
        v, s = self.cards["router"]
        r = app._settings().get("router_api") or {}
        fs = app.mon.feed_status() if app.mon else {}
        recv = sum(1 for k in ("flows", "syslog") if "receiving" in fs.get(k, ""))
        good = "connected" in r.get("ident", "")
        v.configure(text="OK" if good and recv == 2 else ("Partly" if good or recv else "Not set"),
                    fg=OK if good and recv == 2 else WARN if good or recv else BAD)
        s.configure(text=(r.get("ident", "").replace("connected to ", "") or "no router login") +
                    f"\nrouter data: {recv} of 2 feeds arriving")
        self.var_head.set(f"This PC {app.lip}  |  router {app.gw}  |  " +
                          (f"last scan {app.raw['meta'].get('finished', '')}" if app.raw else "not scanned yet"))
        self._draw_checklist()

    def _draw_checklist(self):
        items = self.checklist()
        sig = [(a, b, c) for a, b, c, _, _ in items]
        if sig == getattr(self, "_sig", None):
            return
        self._sig = sig
        for w in self.check.winfo_children():
            w.destroy()
        for row, (ok, title, detail, fix, fn) in enumerate(items):
            mark, col = ("✔", OK) if ok else ("•", MUTE) if ok is None else ("✖", BAD)
            tk.Label(self.check, text=mark, font=(FONT, 13, "bold"), fg=col, bg=CARD, width=2).grid(
                row=row, column=0, sticky="w", pady=3)
            tk.Label(self.check, text=title, font=(FONT, 10, "bold"), fg=INK, bg=CARD).grid(row=row, column=1,
                                                                                         sticky="w")
            tk.Label(self.check, text=detail, font=(FONT, 9), fg=MUTE, bg=CARD, wraplength=640, justify="left").grid(
                row=row, column=2, sticky="w", padx=12)
            if not ok:
                ttk.Button(self.check, text=fix, command=fn).grid(row=row, column=3, sticky="e", padx=4)
        self.check.columnconfigure(2, weight=1)
