"""Router config backup & diff (Network Doctor) - config versioning for change tracking.

Nothing else in the app recorded what changed in the ROUTER'S OWN SETTINGS over time - alerts and
telemetry cover traffic and devices, not "who changed what on the router and when" (a real gap for a
network engineer: a port-forward or firewall rule someone added by hand in Winbox, with no record).

Pure logic only (snapshot text + diff); the caller supplies the actual "/export compact" text via the
RouterOS client and decides where the history list is kept (settings dict, same as fix_history).
"""
import difflib
import time

MAX_SNAPSHOTS = 30     # keep the history small; a daily unchanged config would otherwise grow forever


def add_snapshot(history, text, now=None, who=""):
    """Add a new config snapshot - skipped (returns None) if identical to the most recent one, so a
    config that never changes doesn't pad the history with duplicates."""
    if not text:
        return None
    if history and history[-1]["text"] == text:
        return None
    entry = {"at": now or time.time(), "text": text, "who": who}
    history.append(entry)
    del history[:-MAX_SNAPSHOTS]
    return entry


def latest(history):
    return history[-1] if history else None


def previous(history):
    return history[-2] if len(history) >= 2 else None


def diff_snapshots(old_text, new_text):
    """Unified diff lines between two snapshots. Empty list when nothing changed."""
    old_lines = (old_text or "").splitlines(keepends=True)
    new_lines = (new_text or "").splitlines(keepends=True)
    lines = list(difflib.unified_diff(old_lines, new_lines, fromfile="before", tofile="after", lineterm=""))
    return [ln for ln in lines if not ln.startswith(("---", "+++", "@@"))]


def summarize_diff(diff_lines):
    """One short line: how many settings were added/removed/changed."""
    added = sum(1 for ln in diff_lines if ln.startswith("+"))
    removed = sum(1 for ln in diff_lines if ln.startswith("-"))
    if not added and not removed:
        return "No changes since the previous backup."
    return f"{added} line(s) added, {removed} line(s) removed since the previous backup."
