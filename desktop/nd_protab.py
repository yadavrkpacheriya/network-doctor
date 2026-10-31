# -*- coding: utf-8 -*-
"""Network Doctor Pro - the extra pages (only in the private Pro build): Auto-defense, Security check,
Packet capture, Internet exposure, Users & sign-in, Audit log. Built on the same section navigator as the
rest of the app."""
import time
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

import nd_core as core
import nd_defense as DF
import nd_tabs

UI = nd_tabs.UI


def console(app, action, args):
    """Run a Pro action from the PC console (physical access = trusted) and audit it as 'console'."""
    res = app._remote(action, dict(args))
    try:
        if getattr(app, "audit", None) and action not in ("job", "defense", "audit", "hardening", "vuln", "capture",
                                                           "exposure"):
            app.audit.add("console", "admin", action,
                          " ".join(f"{k}={v}" for k, v in args.items() if k in ("ip", "mac", "opt", "on")),
                          "done" if res.get("ok", True) else str(res.get("message", "")))
    except Exception:
        pass
    return res


def run_job(app, textbox, action, args, title):
    """Runs a long Pro action and streams its result into a text box."""
    textbox.configure(state="normal")
    textbox.delete("1.0", "end")
    textbox.insert("1.0", title + " - working...\n")
    textbox.configure(state="disabled")

    def work():
        res = console(app, action, args)
        jid = res.get("job")
        if jid:
            for _ in range(130):
                j = (app.__dict__.get("phone_jobs") or {}).get(jid, {})
                if j.get("done"):
                    res = j
                    break
                time.sleep(1)
        text = res.get("text") or res.get("message") or ("done" if res.get("ok") else "failed")
        app.q.put(("call", lambda: _show(textbox, text)))
    import threading
    threading.Thread(target=work, daemon=True).start()


def _show(t, text):
    t.configure(state="normal")
    t.delete("1.0", "end")
    t.insert("1.0", text)
    t.configure(state="disabled")


# ====================================================================== Auto-defense
class AutoDefensePage:
    def __init__(self, app, f):
        self.app = app
        ttk.Label(f, text="Auto-defense - keep the network safe even at night", font=("Segoe UI", 13, "bold")).pack(
            anchor="w")
        ttk.Label(f, text="When armed, Network Doctor contains an attacker by itself: it can cut the internet of a "
                          "device, fully quarantine it on the router, or (with the PC agent) shut it down. Every "
                          "automatic action is reversible and written to the Audit log.",
                  foreground="#667085", wraplength=1100, justify="left").pack(anchor="w", pady=(0, 8))
        bar = ttk.Frame(f)
        bar.pack(fill="x")
        self.v_arm = tk.BooleanVar()
        self.v_mode = tk.StringVar(value="auto")
        self.v_night = tk.BooleanVar()
        self.v_from = tk.StringVar(value="20")
        self.v_to = tk.StringVar(value="7")
        ttk.Checkbutton(bar, text="ARM auto-defense", variable=self.v_arm,
                        command=self.save).pack(side="left")
        ttk.Label(bar, text="   When armed:").pack(side="left")
        ttk.Radiobutton(bar, text="Act automatically", value="auto", variable=self.v_mode,
                        command=self.save).pack(side="left", padx=4)
        ttk.Radiobutton(bar, text="Only alert me", value="alert", variable=self.v_mode,
                        command=self.save).pack(side="left")
        ttk.Checkbutton(bar, text="   Act only at night, from", variable=self.v_night,
                        command=self.save).pack(side="left", padx=(10, 2))
        ttk.Entry(bar, textvariable=self.v_from, width=3).pack(side="left")
        ttk.Label(bar, text="to").pack(side="left")
        ttk.Entry(bar, textvariable=self.v_to, width=3).pack(side="left")
        ttk.Label(bar, text="h").pack(side="left")
        self.status = tk.StringVar()
        ttk.Label(f, textvariable=self.status, foreground="#b42318", font=("Segoe UI", 10, "bold")).pack(
            anchor="w", pady=4)
        lf = ttk.LabelFrame(f, text="How far may it go for each kind of attack?", padding=8)
        lf.pack(fill="x", pady=4)
        self.levels = {}
        for i, (kind, (title, _d)) in enumerate(DF.THREATS.items()):
            ttk.Label(lf, text=title).grid(row=i, column=0, sticky="w", pady=1)
            v = tk.StringVar()
            cb = ttk.Combobox(lf, textvariable=v, values=["notify", "internet", "isolate", "poweroff"],
                              state="readonly", width=10)
            cb.grid(row=i, column=1, padx=8, pady=1)
            cb.bind("<<ComboboxSelected>>", lambda e: self.save())
            self.levels[kind] = v
        ex = ttk.Frame(f)
        ex.pack(fill="x", pady=4)
        ttk.Label(ex, text="Never auto-act on these (IPs / MACs, comma separated - servers, your own PC):").pack(
            side="left")
        self.v_exc = tk.StringVar()
        e = ttk.Entry(ex, textvariable=self.v_exc, width=50)
        e.pack(side="left", padx=4)
        e.bind("<FocusOut>", lambda ev: self.save())
        ttk.Label(f, text="Quarantined now (released devices get their network back):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(8, 2))
        self.tv = UI["make_tree"](f, ("ip", "mac", "kind", "level", "by"),
                                  ("IP", "MAC", "Why", "Action", "By"), (110, 140, 160, 90, 110),
                                  first=("Device", 170))
        ttk.Button(f, text="Release selected device", command=self.release).pack(anchor="w", pady=4)
        self.load()

    def load(self):
        st = self.app._defense_status()
        self.v_arm.set(st["armed"])
        self.v_mode.set(st["mode"])
        self.v_night.set(st["night_only"])
        self.v_from.set(str(st["night_from"]))
        self.v_to.set(str(st["night_to"]))
        self.v_exc.set(", ".join(st["exclude_ips"] + st["exclude_macs"]))
        for k, v in self.levels.items():
            v.set(st["levels"].get(k, "notify"))
        self.refresh_contained()
        self.status.set(("ARMED - " + ("acting automatically" if st["mode"] == "auto" else "alerting only")
                         + (" at night only" if st["night_only"] else "")) if st["armed"]
                        else "Off - attacks are detected and alerted, but nothing is contained automatically.")

    def refresh_contained(self):
        self.tv.delete(*self.tv.get_children())
        for c in self.app._defense_status()["contained"]:
            self.tv.insert("", "end", iid=c["key"], text=c.get("name", ""),
                           values=(c.get("ip", ""), c.get("mac", ""), DF.THREATS.get(c.get("kind"), ("",))[0],
                                   c.get("level", ""), c.get("by", "")))

    def save(self):
        exc = [x.strip() for x in self.v_exc.get().split(",") if x.strip()]
        ips = [x for x in exc if core.is_private_ip(x)]
        macs = [x for x in exc if x not in ips]
        patch = {"armed": self.v_arm.get(), "mode": self.v_mode.get(), "night_only": self.v_night.get(),
                 "night_from": int(self.v_from.get() or 20), "night_to": int(self.v_to.get() or 7),
                 "exclude_ips": ips, "exclude_macs": macs,
                 "levels": {k: v.get() for k, v in self.levels.items()}}
        console(self.app, "defense_config", patch)
        self.load()

    def release(self):
        sel = self.tv.selection()
        if sel:
            c = self.app._defense_status()
            row = next((x for x in c["contained"] if x["key"] == sel[0]), None)
            if row:
                console(self.app, "defense_release", {"mac": row.get("mac", ""), "ip": row.get("ip", "")})
                self.refresh_contained()


# ====================================================================== simple run-and-show pages
class _RunPage:
    action = ""
    title = ""
    desc = ""
    button = "Run"
    args = {}

    def __init__(self, app, f):
        self.app = app
        ttk.Label(f, text=self.title, font=("Segoe UI", 13, "bold")).pack(anchor="w")
        ttk.Label(f, text=self.desc, foreground="#667085", wraplength=1100, justify="left").pack(anchor="w",
                                                                                                 pady=(0, 6))
        self.bar = ttk.Frame(f)
        self.bar.pack(fill="x")
        self.extra(self.bar)
        ttk.Button(self.bar, text=self.button, style="Big.TButton", command=self.run).pack(side="left", padx=4)
        ttk.Button(self.bar, text="Copy", command=self.copy).pack(side="left")
        self.txt = UI["text_box"](f)
        self.txt.configure(font=("Consolas", 9))

    def extra(self, bar):
        pass

    def get_args(self):
        return dict(self.args)

    def run(self):
        run_job(self.app, self.txt, self.action, self.get_args(), self.title)

    def copy(self):
        self.app.clipboard_clear()
        self.app.clipboard_append(self.txt.get("1.0", "end").strip())
        self.app.var_status.set("Copied.")


class VulnPage(_RunPage):
    action, button = "vuln", "Run security check"
    title = "Security check - find weaknesses before an attacker does"
    desc = ("Like Nessus / Nuclei, but safe: it only reads. Finds devices open to the internet, default "
            "passwords, Telnet/FTP, old SMBv1, weak HTTPS and credential poisoners - each with a plain fix. "
            "It never logs in or attacks anything.")


class CapturePage(_RunPage):
    action, button = "capture", "Start capture"
    title = "Packet capture - see exactly what is on the wire (Wireshark + Zeek, readable)"
    desc = ("Records packets for a few seconds, then explains them: protocols, who talked to whom, the websites "
            "looked up, and anything suspicious (clear-text passwords, a port scan, a flood). Needs Npcap.")

    def extra(self, bar):
        ttk.Label(bar, text="Seconds:").pack(side="left")
        self.secs = tk.StringVar(value="20")
        ttk.Entry(bar, textvariable=self.secs, width=5).pack(side="left", padx=4)
        ttk.Label(bar, text="Filter (optional, e.g. host 192.168.0.9):").pack(side="left")
        self.bpf = tk.StringVar()
        ttk.Entry(bar, textvariable=self.bpf, width=30).pack(side="left", padx=4)

    def get_args(self):
        return {"seconds": int(self.secs.get() or 20), "bpf": self.bpf.get().strip()}


class ExposePage(_RunPage):
    action, button = "exposure", "Check what the internet sees"
    title = "Internet exposure - what Shodan & Censys see of your office"
    desc = ("Looks up your office's public IP on Shodan and Censys (the internet-wide scanners attackers use) "
            "and lists every service the outside world can reach. Paste your free API keys below (saved on "
            "this PC only).")

    def extra(self, bar):
        pro = self.app._settings().setdefault("pro", {})
        ttk.Label(bar, text="Shodan key:").pack(side="left")
        self.sh = tk.StringVar(value=pro.get("shodan_key", ""))
        ttk.Entry(bar, textvariable=self.sh, width=22, show="*").pack(side="left", padx=4)
        ttk.Label(bar, text="Censys ID / secret:").pack(side="left")
        self.cid = tk.StringVar(value=pro.get("censys_id", ""))
        self.csec = tk.StringVar(value=pro.get("censys_secret", ""))
        ttk.Entry(bar, textvariable=self.cid, width=14).pack(side="left", padx=2)
        ttk.Entry(bar, textvariable=self.csec, width=14, show="*").pack(side="left", padx=2)

    def get_args(self):
        pro = self.app._settings().setdefault("pro", {})
        pro["shodan_key"] = self.sh.get().strip()
        pro["censys_id"] = self.cid.get().strip()
        pro["censys_secret"] = self.csec.get().strip()
        self.app._save_settings()
        return {}


# ====================================================================== accounts + audit
class AccountsPage:
    def __init__(self, app, f):
        self.app = app
        ttk.Label(f, text="Users & sign-in", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        ttk.Label(f, text="The phone and remote access require one of these users to sign in. Roles: admin (all, "
                          "incl. power-off and settings), operator (scan, fix, block, isolate), viewer (look only). "
                          "The PC console here is always trusted (physical access) and is logged as 'console'.",
                  foreground="#667085", wraplength=1100, justify="left").pack(anchor="w", pady=(0, 6))
        bar = ttk.Frame(f)
        bar.pack(fill="x")
        ttk.Button(bar, text="Add user...", style="Big.TButton", command=self.add).pack(side="left")
        ttk.Button(bar, text="Set password...", command=self.setpw).pack(side="left", padx=4)
        ttk.Button(bar, text="Change role...", command=self.setrole).pack(side="left")
        ttk.Button(bar, text="Enable / disable", command=self.toggle).pack(side="left", padx=4)
        self.tv = UI["make_tree"](f, ("role", "disabled", "created", "last"),
                                  ("Role", "Disabled", "Created", "Last sign-in"), (90, 80, 140, 140),
                                  first=("User", 160))
        rf = ttk.LabelFrame(f, text="Remote access (reach this PC from outside the office)", padding=8)
        rf.pack(fill="x", pady=(8, 0))
        self.v_remote = tk.BooleanVar(value=app._settings().get("remote_enabled", False))
        ttk.Checkbutton(rf, text="Allow signed-in users to connect from the internet", variable=self.v_remote,
                        command=self.remote).pack(anchor="w")
        ttk.Label(rf, text="Outside connections can do nothing until they sign in with a user above, and every "
                           "action is in the Audit log. To get a safe internet address without opening a port, "
                           "install a free Cloudflare Tunnel or Tailscale on this PC and point it at "
                           "http://localhost:8787, then enter that address in the phone app (PC menu > Reach from "
                           "outside).", foreground="#667085", wraplength=1000, justify="left").pack(anchor="w")
        self.refresh()

    def remote(self):
        self.app._settings()["remote_enabled"] = self.v_remote.get()
        self.app._save_settings()
        if getattr(self.app, "share", None):
            self.app.share.remote_enabled = bool(core.IS_PRO and self.v_remote.get())
        self.app.audit.add("console", "admin", "settings",
                           f"remote access {'ON' if self.v_remote.get() else 'off'}")

    def refresh(self):
        self.tv.delete(*self.tv.get_children())
        for n, u in self.app.accounts.users().items():
            self.tv.insert("", "end", iid=n, text=n,
                           values=(u["role"], "yes" if u["disabled"] else "", u["created"], u["last_login"]))

    def _sel(self):
        s = self.tv.selection()
        return s[0] if s else None

    def add(self):
        name = simpledialog.askstring("Add user", "User name:", parent=self.app)
        if not name:
            return
        pw = simpledialog.askstring("Add user", f"Password for {name} (6+ characters):", show="*", parent=self.app)
        if not pw:
            return
        role = simpledialog.askstring("Add user", "Role: admin / operator / viewer", initialvalue="operator",
                                      parent=self.app)
        try:
            self.app.accounts.add_user(name, pw, (role or "operator").strip())
            self.app.audit.add("console", "admin", "account", f"add {name} ({role})")
            self.refresh()
        except ValueError as e:
            messagebox.showerror("Users", str(e))

    def setpw(self):
        n = self._sel()
        if not n:
            return
        pw = simpledialog.askstring("Set password", f"New password for {n}:", show="*", parent=self.app)
        if pw:
            try:
                self.app.accounts.set_password(n, pw)
                self.app.audit.add("console", "admin", "account", f"password reset {n}")
            except ValueError as e:
                messagebox.showerror("Users", str(e))

    def setrole(self):
        n = self._sel()
        if not n:
            return
        role = simpledialog.askstring("Change role", "admin / operator / viewer", parent=self.app)
        if role:
            try:
                self.app.accounts.set_role(n, role.strip())
                self.app.audit.add("console", "admin", "account", f"role {n}={role}")
                self.refresh()
            except ValueError as e:
                messagebox.showerror("Users", str(e))

    def toggle(self):
        n = self._sel()
        if not n:
            return
        u = self.app.accounts.users()[n]
        try:
            self.app.accounts.disable(n, not u["disabled"])
            self.app.audit.add("console", "admin", "account", f"{'enable' if u['disabled'] else 'disable'} {n}")
            self.refresh()
        except ValueError as e:
            messagebox.showerror("Users", str(e))


class AuditPage:
    def __init__(self, app, f):
        self.app = app
        ttk.Label(f, text="Audit log - who changed what", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        ttk.Label(f, text="Every change (block, isolate, router fix, auto-defense action, account change, setting) "
                          "is recorded here and never erased.", foreground="#667085").pack(anchor="w", pady=(0, 6))
        bar = ttk.Frame(f)
        bar.pack(fill="x")
        ttk.Button(bar, text="Refresh", command=self.refresh).pack(side="left")
        ttk.Button(bar, text="Open log folder", command=lambda: self.app.open_folder(
            core.DATA_DIR + "/pro")).pack(side="left", padx=4)
        self.tv = UI["make_tree"](f, ("user", "role", "action", "detail", "result", "ip"),
                                  ("User", "Role", "Action", "Detail", "Result", "From"),
                                  (110, 80, 110, 300, 140, 110), first=("Time", 150))
        self.refresh()

    def refresh(self):
        self.tv.delete(*self.tv.get_children())
        for e in (self.app.audit.recent(400) if getattr(self.app, "audit", None) else []):
            self.tv.insert("", "end", text=e.get("ts", ""),
                           values=(e.get("user", ""), e.get("role", ""), e.get("action", ""),
                                   e.get("detail", ""), e.get("result", ""), e.get("ip", "")))


class ActivatePage:
    """Always visible (even in the locked app). Shows licence status and lets the owner paste a licence
    to unlock the advanced features. The licence is signed with the owner's private key, so a plain email
    or a copied string from anyone else will not verify."""

    def __init__(self, app, f):
        self.app = app
        import nd_license as L
        self.L = L
        ttk.Label(f, text="Pro / Activate - advanced security features", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        ttk.Label(f, text="The advanced features (24/7 auto-defense, isolate / power-off a breached device, "
                          "remote access from your phone, packet capture, security check, internet-exposure "
                          "check, users & sign-in, audit log) are built in but locked. Paste your licence key "
                          "below to unlock them. A licence is tied to your account and signed by the owner - it "
                          "cannot be shared or faked.", wraplength=820, foreground="#344054",
                  justify="left").pack(anchor="w", pady=(0, 10))
        self.var_status = tk.StringVar(value="")
        self.lbl = ttk.Label(f, textvariable=self.var_status, font=("Segoe UI", 11, "bold"), wraplength=820,
                             justify="left")
        self.lbl.pack(anchor="w", pady=(0, 10))
        box = ttk.LabelFrame(f, text="Licence key", padding=10)
        box.pack(fill="x", pady=(0, 10))
        ttk.Label(box, text="Paste the licence key you were given (one long line):",
                  foreground="#667085").pack(anchor="w")
        self.txt = tk.Text(box, height=4, width=100, font=("Consolas", 9), wrap="char")
        self.txt.pack(fill="x", pady=4)
        bar = ttk.Frame(box)
        bar.pack(fill="x")
        ttk.Button(bar, text="Activate", style="Big.TButton", command=self.activate).pack(side="left")
        ttk.Button(bar, text="Load from file...", command=self.load_file).pack(side="left", padx=6)
        ttk.Button(bar, text="Remove licence", command=self.remove).pack(side="left", padx=6)
        ttk.Label(f, text="Where do I get a licence? Licences are issued by the owner of Network Doctor. During "
                          "testing only the owner's account is enabled. Paid licences will be available in a future "
                          "release.", wraplength=820, foreground="#667085", justify="left").pack(anchor="w")
        self.refresh()

    def refresh(self):
        info = core.pro_info()
        if info:
            exp = info.get("exp", 0)
            when = "no expiry" if not exp else ("expires " + time.strftime("%Y-%m-%d", time.localtime(exp)))
            self.var_status.set("✔ Pro is ACTIVE for %s  (%s, %s)." %
                                (info.get("email", "?"), info.get("plan", "pro"), when))
            self.lbl.configure(foreground="#067647")
        else:
            cur = self.L.read_license(core.DATA_DIR)
            if cur:
                ok, _p, reason = self.L.verify_license(cur)
                self.var_status.set("✖ The installed licence is not valid (%s). Paste a current licence." % reason)
            else:
                self.var_status.set("✖ Pro is locked. No licence installed - the standard features work "
                                    "normally; paste a licence to unlock the advanced ones.")
            self.lbl.configure(foreground="#b42318")

    def load(self):
        self.refresh()

    def activate(self):
        lic = self.txt.get("1.0", "end").strip()
        if not lic:
            messagebox.showinfo("Network Doctor", "Paste your licence key first.")
            return
        ok, info, reason = self.L.save_license(core.DATA_DIR, lic)
        if not ok:
            messagebox.showerror("Network Doctor", "That licence could not be activated: %s.\n\nCheck you copied "
                                 "the whole key (one long line)." % reason)
            self.refresh()
            return
        core.refresh_pro()
        self.txt.delete("1.0", "end")
        self.refresh()
        messagebox.showinfo("Network Doctor", "Pro activated for %s.\n\nPlease restart Network Doctor so the "
                            "advanced tabs appear." % info.get("email", ""))

    def load_file(self):
        from tkinter import filedialog
        p = filedialog.askopenfilename(title="Select your licence file",
                                       filetypes=[("Licence", "*.ndlic *.txt"), ("All files", "*.*")])
        if not p:
            return
        try:
            with open(p, "r", encoding="utf-8") as fh:
                self.txt.delete("1.0", "end")
                self.txt.insert("1.0", fh.read().strip())
        except Exception as e:
            messagebox.showerror("Network Doctor", str(e))
            return
        self.activate()

    def remove(self):
        if not messagebox.askyesno("Network Doctor", "Remove the installed licence and lock the advanced "
                                   "features again?"):
            return
        self.L.clear_license(core.DATA_DIR)
        core.refresh_pro()
        self.refresh()
        messagebox.showinfo("Network Doctor", "Licence removed. Restart Network Doctor to hide the advanced tabs.")


PRO_PAGES = {"defense": AutoDefensePage, "vuln": VulnPage, "capture": CapturePage, "expose": ExposePage,
             "accounts": AccountsPage, "audit": AuditPage}

# Always available, even when Pro is locked (so the owner can paste a licence):
ALWAYS_PAGES = {"activate": ActivatePage}
