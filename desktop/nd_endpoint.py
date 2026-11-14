"""Reads the CSV logs written by the LeakWatch endpoint agent (endpoint/leakwatch-agent.ps1, running on each
office PC) so Network Doctor can show what the office network cannot see on its own: a USB pen drive / phone /
disk plugged in, and a file copied onto it (a file leaving by USB).

The agent writes, per PC per month, a file leak-<PC>-<YYYYMM>.csv with the header
    time,pc,user,event,detail,drive,size_kb
into a shared folder on the IT PC. This module only reads that folder. It never runs the agent and holds no
state of its own - everything comes from the files, so it is safe to call again any time."""
import csv
import glob
import os
import time

EVENTS = {"USB_IN": "USB drive connected", "USB_OUT": "USB drive removed",
          "USB_PRESENT": "USB drive already connected", "COPY_TO_USB": "File copied to USB",
          "AGENT_START": "LeakWatch started"}
COPY = "COPY_TO_USB"


def agent_local_dir():
    """Where the PC agent writes on THIS PC (so the Network Doctor PC reads its own agent with no share set up)."""
    base = os.environ.get("ProgramData") or r"C:\ProgramData"
    import nd_core as core
    return os.path.join(base, "NetworkDoctor", "agent") if core.IS_WIN else os.path.join(core.DATA_DIR, "agent")


def default_dirs(configured=""):
    """Every folder to read agent logs from: the shared folder set in Settings (configured), this PC's own
    agent folder, and the old leakwatch folder. De-duplicated, existing or not (a reader skips a missing one)."""
    import nd_core as core
    out, seen = [], set()
    for d in (configured, agent_local_dir(), os.path.join(core.DATA_DIR, "leakwatch"),
              os.path.join(core.DATA_DIR, "agent")):
        key = os.path.normcase(os.path.abspath(d)) if d else ""
        if d and key not in seen:
            seen.add(key)
            out.append(d)
    return out


def default_dir():
    return agent_local_dir()


def _dirs(folder):
    """A reader's `folder` may be one path or a list of paths."""
    if isinstance(folder, (list, tuple)):
        return [f for f in folder if f]
    return [folder] if folder else []


def read_events(folder, since_days=7, now=None):
    """Every event in the folder's CSV files from the last `since_days`, newest first. Rows that cannot be
    parsed are skipped, so a half-written line (the agent appending at the same moment) never breaks reading."""
    now = now or time.time()
    cut = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - since_days * 86400))
    out = []
    for path in [p for d in _dirs(folder) for p in glob.glob(os.path.join(d, "leak-*.csv"))]:
        try:
            with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
                for r in csv.DictReader(fh):
                    t = (r.get("time") or "").strip()
                    if len(t) != 19 or t < cut:
                        continue
                    try:
                        kb = int(r.get("size_kb") or 0)
                    except ValueError:
                        kb = 0
                    out.append({"time": t, "pc": (r.get("pc") or "").strip(), "user": (r.get("user") or "").strip(),
                                "event": (r.get("event") or "").strip(), "detail": (r.get("detail") or "").strip(),
                                "drive": (r.get("drive") or "").strip(), "kb": kb})
        except OSError:
            continue
    out.sort(key=lambda e: e["time"], reverse=True)
    return out


def summarize(events):
    """A short status per PC for the dashboard / a page: how many USB plug-ins and how much was copied out."""
    by_pc = {}
    for e in events:
        p = by_pc.setdefault(e["pc"] or "?", {"pc": e["pc"] or "?", "users": set(), "usb_in": 0,
                                              "copies": 0, "copy_kb": 0, "last": ""})
        if e["user"]:
            p["users"].add(e["user"])
        if e["event"] == "USB_IN":
            p["usb_in"] += 1
        elif e["event"] == COPY:
            p["copies"] += 1
            p["copy_kb"] += e["kb"]
        p["last"] = max(p["last"], e["time"])
    for p in by_pc.values():
        p["users"] = sorted(p["users"])
    return sorted(by_pc.values(), key=lambda p: -p["copy_kb"])


def leak_alerts(events, min_copy_mb=20, who=lambda pc, user: f"{user} on {pc}"):
    """Alerts for files copied to USB in this window, grouped by PC+user: [(sev, title, text)].
    Everything on a USB copy is reported (the network can see none of it); a large total is 'critical'."""
    groups = {}
    for e in events:
        if e["event"] != COPY:
            continue
        g = groups.setdefault((e["pc"], e["user"]), {"n": 0, "kb": 0, "files": [], "last": ""})
        g["n"] += 1
        g["kb"] += e["kb"]
        g["last"] = max(g["last"], e["time"])
        if len(g["files"]) < 6:
            g["files"].append(os.path.basename(e["detail"]) or e["detail"])
    out = []
    for (pc, user), g in sorted(groups.items(), key=lambda kv: -kv[1]["kb"]):
        mb = g["kb"] / 1024
        sev = "critical" if mb >= min_copy_mb else "warning"
        more = f" and {g['n'] - len(g['files'])} more" if g["n"] > len(g["files"]) else ""
        out.append((sev, f"{who(pc, user)} copied {g['n']} file(s) to USB ({mb:.0f} MB)",
                    "Files: " + ", ".join(g["files"]) + more + f". Last at {g['last']}. "
                    "Seen by the LeakWatch agent on the PC; the network cannot see USB copies."))
    return out


import json as _json

# native apps that OWN their traffic: when such a process is talking to an address, that address is really that
# app, better than any DNS guess. Browsers are left out on purpose - for a browser the website name (from DNS)
# says more than "chrome.exe", so browser traffic keeps its DNS-based name.
PROC_APP = {
    "whatsapp": "WhatsApp", "telegram": "Telegram", "signal": "Signal", "discord": "Discord", "slack": "Slack",
    "outlook": "Outlook / Exchange", "hxoutlook": "Outlook / Exchange", "thunderbird": "Email (other)",
    "onedrive": "OneDrive / SharePoint", "dropbox": "Dropbox", "googledrivefs": "Google Drive / Docs",
    "anydesk": "AnyDesk", "teamviewer": "TeamViewer", "tv_w32": "TeamViewer", "tv_x64": "TeamViewer",
    "ms-teams": "Microsoft Teams", "teams": "Microsoft Teams", "zoom": "Zoom",
    "acronis": "Acronis Cloud Backup", "trueimage": "Acronis Cloud Backup", "acronisagent": "Acronis Cloud Backup", "arsm": "Acronis Cloud Backup",
    "steam": "Steam", "steamwebhelper": "Steam", "epicgameslauncher": "Epic Games / Fortnite",
    "spotify": "Spotify", "tally": "Tally", "winword": "Microsoft 365 (Office)", "excel": "Microsoft 365 (Office)",
    "code": "Dev tools (GitHub...)", "git": "Dev tools (GitHub...)", "github": "Dev tools (GitHub...)",
    "qbittorrent": "BitTorrent", "utorrent": "BitTorrent", "bittorrent": "BitTorrent", "transmission": "BitTorrent",
}


def proc_app(process):
    """Friendly app for a Windows process name, or None for a browser / unknown (keep the DNS name then)."""
    p = (process or "").strip().lower()
    if p.endswith(".exe"):
        p = p[:-4]
    if p in ("chrome", "msedge", "firefox", "iexplore", "opera", "brave", "safari", "vivaldi"):
        return None
    if p in PROC_APP:
        return PROC_APP[p]
    for key, app in PROC_APP.items():
        if key in p:
            return app
    return None


def read_reports(folder):
    """The pc-<NAME>.json files the agent wrote (one per PC): the report dicts Network Doctor's _apply_report
    takes, each with the PC's first LAN IPv4 added as 'ip'. Newest file first."""
    out = []
    for path in sorted([p for d in _dirs(folder) for p in glob.glob(os.path.join(d, "pc-*.json"))],
                       key=lambda p: os.path.getmtime(p), reverse=True):
        try:
            with open(path, encoding="utf-8-sig", errors="replace") as fh:
                data = _json.load(fh)
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        ip = ""
        for a in data.get("adapters") or []:
            for one in str((a or {}).get("ip") or "").split(","):
                one = one.strip()
                if one.startswith(("192.168.", "10.", "172.")):
                    ip = ip or one
        data["ip"] = ip
        out.append(data)
    seen, uniq = set(), []
    for d in out:                  # newest first already; keep one report per PC
        h = (d.get("hostname") or d.get("ip") or "").lower()
        if h and h in seen:
            continue
        seen.add(h)
        uniq.append(d)
    return uniq


def read_conns(folder, since_days=1, now=None):
    """The conn-*.csv rows (process <-> remote address) from the last `since_days`. Newest first."""
    now = now or time.time()
    cut = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - since_days * 86400))
    out = []
    for path in [p for d in _dirs(folder) for p in glob.glob(os.path.join(d, "conn-*.csv"))]:
        try:
            with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
                for r in csv.DictReader(fh):
                    t = (r.get("time") or "").strip()
                    if len(t) != 19 or t < cut:
                        continue
                    out.append({"time": t, "pc": (r.get("pc") or "").strip(),
                                "local_ip": (r.get("local_ip") or "").strip(),
                                "remote_ip": (r.get("remote_ip") or "").strip(),
                                "process": (r.get("process") or "").strip()})
        except OSError:
            continue
    out.sort(key=lambda e: e["time"], reverse=True)
    return out


def proc_name_map(conns):
    """{(local LAN ip, remote ip): app} for native apps only, newest row winning. Network Doctor feeds this to
    the usage history so a connection's own app (WhatsApp, Acronis, AnyDesk...) names its traffic exactly,
    instead of the router's address-owner guess. Browser traffic is left for DNS naming."""
    out = {}
    for c in sorted(conns, key=lambda e: e["time"]):   # oldest first so the newest overwrites
        app = proc_app(c["process"])
        if app and c["local_ip"] and c["remote_ip"]:
            out[(c["local_ip"], c["remote_ip"])] = app
    return out


def read_auth(folder, since_days=1, now=None):
    """Failed Windows logons (Event ID 4625) the agent reported, from the last `since_days`. Newest first.
    Each row: a PC, the account someone tried, where it came from (IP / computer), the logon kind, and how
    many tries in that agent window."""
    now = now or time.time()
    cut = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - since_days * 86400))
    out = []
    for path in [p for d in _dirs(folder) for p in glob.glob(os.path.join(d, "auth-*.csv"))]:
        try:
            with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
                for r in csv.DictReader(fh):
                    t = (r.get("time") or "").strip()
                    if len(t) != 19 or t < cut:
                        continue
                    try:
                        fails = int(r.get("fails") or 0)
                    except ValueError:
                        fails = 0
                    out.append({"time": t, "pc": (r.get("pc") or "").strip(),
                                "account": (r.get("account") or "").strip(),
                                "source": (r.get("source") or "").strip(),
                                "logon": (r.get("logon") or "").strip(), "fails": fails})
        except OSError:
            continue
    out.sort(key=lambda e: e["time"], reverse=True)
    return out


def _is_external(src):
    s = (src or "").strip()
    if not s or s[0].isalpha():          # a computer name, not an IP
        return False
    return not (s.startswith(("192.168.", "10.", "127.", "169.254.")) or s.startswith("172.")
                or s in ("this PC / console", "::1"))


def auth_alerts(events, warn=10, crit=30):
    """Brute-force alerts from failed-logon rows, grouped by PC + account + source over the window:
    [(sev, title, text)]. A login coming from the internet (a real IP, not a LAN address) or RDP is treated
    as worse. Returns most-tries first."""
    groups = {}
    for e in events:
        g = groups.setdefault((e["pc"], e["account"], e["source"]),
                              {"fails": 0, "logon": e["logon"], "last": ""})
        g["fails"] += e["fails"]
        g["last"] = max(g["last"], e["time"])
    out = []
    for (pc, acct, src), g in sorted(groups.items(), key=lambda kv: -kv[1]["fails"]):
        ext = _is_external(src)
        rdp = g["logon"] == "RDP"
        if g["fails"] < warn and not (ext and g["fails"] >= 5):
            continue
        sev = "critical" if (g["fails"] >= crit or ext or rdp) else "warning"
        where = f"from {src}" + (" (from the internet!)" if ext else "") + (" over Remote Desktop" if rdp else "")
        out.append((sev, f"{g['fails']} failed logins on {pc}: account '{acct}' {where}",
                    f"Last at {g['last']}. Someone is trying to guess the '{acct}' password. "
                    + ("This is coming from OUTSIDE your network - close Remote Desktop to the internet and change "
                       "the password now. " if ext or rdp else "It is from inside the network - find that device. ")
                    + "Seen by the agent reading Windows Event ID 4625."))
    return out
