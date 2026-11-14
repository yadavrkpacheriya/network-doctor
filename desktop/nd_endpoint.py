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


def default_dir():
    """Where the agent's logs are collected (set in Settings; this is the fall-back next to the app's data)."""
    import nd_core as core
    return os.path.join(core.DATA_DIR, "leakwatch")


def read_events(folder, since_days=7, now=None):
    """Every event in the folder's CSV files from the last `since_days`, newest first. Rows that cannot be
    parsed are skipped, so a half-written line (the agent appending at the same moment) never breaks reading."""
    now = now or time.time()
    cut = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - since_days * 86400))
    out = []
    for path in glob.glob(os.path.join(folder or "", "leak-*.csv")):
        try:
            with open(path, encoding="utf-8", errors="replace", newline="") as fh:
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
