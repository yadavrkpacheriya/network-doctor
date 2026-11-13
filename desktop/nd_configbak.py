"""Router config backup & diff (Network Doctor) - config versioning for change tracking.

Nothing else in the app recorded what changed in the ROUTER'S OWN SETTINGS over time - alerts and
telemetry cover traffic and devices, not "who changed what on the router and when" (a real gap for a
network engineer: a port-forward or firewall rule someone added by hand in Winbox, with no record).

The snapshot is read section by section through the RouterOS API (print only - nothing is ever written),
NOT with "/export":
  - "/export" starts with a date/time line, so two identical configs never compared equal (every backup
    looked like a change);
  - on RouterOS 6 the text of a command can only be read back through a file, and files over 4 KB cannot
    be read through the API at all - a real export never fits;
  - RouterOS 6 "/export" prints passwords (PPPoE, Wi-Fi keys, PPP secrets) unless told not to.
Reading the sections directly works the same on RouterOS 6 and 7, leaves out counters and other values
that change by themselves, and never stores a password or key.

Rules the app itself added (comment starting "ND") are left out: they are already in the Auto-fixes list
with their own Undo, and this page is for what changed OUTSIDE the app.

The history lives in its own file (not settings.json: 30 router configs would be rewritten on every
settings save).
"""
import difflib
import json
import os
import threading
import time

MAX_SNAPSHOTS = 30     # keep the history small; a daily unchanged config would otherwise grow forever
FORMAT = 2             # 1 = "/export" text (3.28.0 - 3.28.3); those entries cannot be compared with these
_LOCK = threading.Lock()

# (heading, API path) - order kept as the router gives it (it matters for firewall rules)
SECTIONS = [
    ("/system identity", "/system/identity/print"),
    ("/user", "/user/print"),
    ("/ip service", "/ip/service/print"),
    ("/interface bridge", "/interface/bridge/print"),
    ("/interface bridge port", "/interface/bridge/port/print"),
    ("/interface list member", "/interface/list/member/print"),
    ("/ip address", "/ip/address/print"),
    ("/ip pool", "/ip/pool/print"),
    ("/ip dhcp-server", "/ip/dhcp-server/print"),
    ("/ip dhcp-server network", "/ip/dhcp-server/network/print"),
    ("/ip dhcp-server lease", "/ip/dhcp-server/lease/print"),
    ("/ip dns", "/ip/dns/print"),
    ("/ip dns static", "/ip/dns/static/print"),
    ("/ip route", "/ip/route/print"),
    ("/ip firewall filter", "/ip/firewall/filter/print"),
    ("/ip firewall nat", "/ip/firewall/nat/print"),
    ("/ip firewall mangle", "/ip/firewall/mangle/print"),
    ("/ip firewall address-list", "/ip/firewall/address-list/print"),
    ("/ip upnp", "/ip/upnp/print"),
    ("/ip cloud", "/ip/cloud/print"),
    ("/ppp secret", "/ppp/secret/print"),
    ("/queue simple", "/queue/simple/print"),
    ("/system scheduler", "/system/scheduler/print"),
    ("/system script", "/system/script/print"),
]

# never stored
SENSITIVE = {"password", "secret", "key", "wpa-pre-shared-key", "wpa2-pre-shared-key", "passphrase",
             "private-key", "pre-shared-key", "authentication-password", "encryption-password"}
# change by themselves (counters, state, clocks) - a difference here is not a config change
VOLATILE = {".id", ".nextid", "bytes", "packets", "dynamic", "invalid", "inactive", "running", "slave",
            "active", "last-seen", "active-address", "active-mac-address", "active-client-id",
            "active-server", "expires-after", "status", "host-name", "last-logged-in", "run-count",
            "next-run", "last-started", "rate", "packet-rate", "total-bytes", "total-packets",
            "total-rate", "total-packet-rate", "queued-bytes", "queued-packets", "total-queued-bytes",
            "total-queued-packets", "dropped", "total-dropped", "public-address", "public-address-ipv6",
            "cache-used", "dynamic-servers", "actual-mtu", "actual-interface", "gateway-status",
            "immediate-gw", "reachable", "last-caller-id", "last-disconnect-reason", "last-logged-out",
            "radius", "blocked", "creation-time", "connection-bytes", "ddns-update-interval",
            "warning", "back-to-home-vpn", "age", "class-id", "vrf-interface"}


def _line(row):
    keep = {k: v for k, v in row.items() if k not in VOLATILE and k not in SENSITIVE}
    return " ".join(f"{k}={json.dumps(v) if (' ' in str(v) or v == '') else v}" for k, v in sorted(keep.items()))


def snapshot_via_api(c):
    """The router's settings as text, read section by section (print only). `c` is anything with
    .cmd(path) -> list of dicts (nd_routeros.RouterOS, already connected). A section the router does not
    have (package not installed, older version) is skipped. Returns "" when nothing at all could be read."""
    out, got = [], 0
    for head, path in SECTIONS:
        try:
            rows = c.cmd(path)
        except Exception:
            continue
        got += 1
        lines = []
        for r in rows:
            if str(r.get("dynamic", "")).lower() == "true":
                continue                                     # made by the router itself, not a setting
            if str(r.get("comment", "")).startswith("ND"):
                continue                                     # made by this app (has its own Undo list)
            ln = _line(r)
            if ln:
                lines.append("  " + ln)
        out.append(head)
        out.extend(lines)
    return "\n".join(out) + "\n" if got else ""


def load(path):
    """The saved history ([] when there is none or it cannot be read). Old "/export" entries are dropped."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return [e for e in data if isinstance(e, dict) and e.get("fmt") == FORMAT and e.get("text")]
    except Exception:
        return []


def save(path, history):
    """Written to a temp file and renamed, so a crash half-way never leaves a broken history."""
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(history, f)
        os.replace(tmp, path)
        return True
    except Exception:
        return False


def add_snapshot(history, text, now=None, who=""):
    """Add a new config snapshot - skipped (returns None) if identical to the most recent one, so a
    config that never changes doesn't pad the history with duplicates."""
    if not text:
        return None
    if history and history[-1]["text"] == text:
        return None
    entry = {"at": now or time.time(), "text": text, "who": who, "fmt": FORMAT}
    history.append(entry)
    del history[:-MAX_SNAPSHOTS]
    return entry


def record(path, text, now=None):
    """Load + add + save in one locked step (the button, the 6-hourly check and the phone can all get
    here from different threads). Returns (entry_or_None, previous_or_None, count)."""
    with _LOCK:
        hist = load(path)
        prev = latest(hist)
        entry = add_snapshot(hist, text, now)
        if entry is not None:
            save(path, hist)
        return entry, prev, len(hist)


def latest(history):
    return history[-1] if history else None


def previous(history):
    return history[-2] if len(history) >= 2 else None


def diff_snapshots(old_text, new_text):
    """Diff lines between two snapshots ("+" added, "-" removed, " " context). Empty when nothing changed."""
    old_lines = (old_text or "").splitlines(keepends=True)
    new_lines = (new_text or "").splitlines(keepends=True)
    lines = list(difflib.unified_diff(old_lines, new_lines, fromfile="before", tofile="after", lineterm="",
                                      n=1))
    return [ln.rstrip("\n") for ln in lines if not ln.startswith(("---", "+++", "@@"))]


def summarize_diff(diff_lines):
    """One short line: how many settings were added/removed/changed."""
    added = sum(1 for ln in diff_lines if ln.startswith("+"))
    removed = sum(1 for ln in diff_lines if ln.startswith("-"))
    if not added and not removed:
        return "No changes since the previous backup."
    return f"{added} line(s) added, {removed} line(s) removed since the previous backup."


def run_backup(c, path, now=None):
    """Everything one backup does, for all three callers. `c` is a connected RouterOS client.
    Returns {"ok", "changed", "first", "count", "summary", "diff"}; ok False = nothing could be read."""
    text = snapshot_via_api(c)
    if not text.strip():
        return {"ok": False, "changed": False, "first": False, "count": 0, "summary": "", "diff": []}
    entry, prev, count = record(path, text, now)
    if entry is None:
        return {"ok": True, "changed": False, "first": False, "count": count,
                "summary": "No changes since the last backup.", "diff": []}
    diff = diff_snapshots(prev["text"], entry["text"]) if prev else []
    return {"ok": True, "changed": bool(prev and diff), "first": prev is None, "count": count,
            "summary": summarize_diff(diff) if prev else "First backup saved - later ones are compared with it.",
            "diff": diff}
