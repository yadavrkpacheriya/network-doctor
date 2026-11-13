# -*- coding: utf-8 -*-
"""
Network Doctor - the "learning brain" behind auto-fixes: a record of every fix the app applied by
itself, an Undo for each one, and a confidence score per fix-kind so a kind that keeps needing to be
undone is applied more cautiously (and, as it proves itself safe, more readily).

Pure logic only (no window code, no router I/O) so it can be tested without a router or a UI - the
caller (NetworkDoctor.py) does the actual router/PC command and passes the result in here.
"""

import time
import uuid

STATUS_APPLIED = "applied"      # ran, no problem seen yet (still inside its regression-check window)
STATUS_OK = "ok"                # ran, regression window passed clean - counts as a success
STATUS_UNDONE = "undone"        # the user pressed Undo
STATUS_AUTO_UNDONE = "auto_undone"  # the app undid it itself: a new issue appeared right after
STATUS_FAILED = "failed"        # the command itself failed (router unreachable, script error...)

REGRESSION_WINDOW = 15 * 60     # seconds to watch for a new problem on the same device/IP after a fix


def new_fix(history, kind, title, mac=None, ip=None, cmd="", undo_cmd="", alert_id=None, now=None):
    """Record a fix about to be applied. Returns the new entry (append it to `history` yourself so the
    caller can decide where it is kept, e.g. inside the settings dict that is already saved to disk)."""
    e = {"id": uuid.uuid4().hex[:12], "kind": kind, "title": title, "mac": mac, "ip": ip, "cmd": cmd,
         "undo_cmd": undo_cmd, "alert_id": alert_id, "status": STATUS_APPLIED, "at": now or time.time(),
         "note": ""}
    history.append(e)
    return e


def mark_result(history, fix_id, ok, note=""):
    """The router command itself succeeded/failed to run (not the same as a regression check)."""
    e = find(history, fix_id)
    if e:
        e["status"] = STATUS_APPLIED if ok else STATUS_FAILED
        e["note"] = note


def find(history, fix_id):
    return next((e for e in history if e["id"] == fix_id), None)


def mark_undone(history, stats, fix_id, auto=False, note=""):
    """Undo was applied (by the user, or by the app itself after a regression). Feeds the learning
    store so this fix-kind's track record gets worse - future fixes of this kind need more repeats
    before Network Doctor tries again."""
    e = find(history, fix_id)
    if not e or e["status"] in (STATUS_UNDONE, STATUS_AUTO_UNDONE):
        return
    e["status"] = STATUS_AUTO_UNDONE if auto else STATUS_UNDONE
    e["note"] = note
    s = stats.setdefault(e["kind"], {"tries": 0, "ok": 0, "undone": 0})
    s["undone"] += 1


def mark_ok(history, stats, fix_id):
    """The regression window passed with nothing new - count it as a success for this fix-kind."""
    e = find(history, fix_id)
    if not e or e["status"] != STATUS_APPLIED:
        return
    e["status"] = STATUS_OK
    s = stats.setdefault(e["kind"], {"tries": 0, "ok": 0, "undone": 0})
    s["tries"] += 1
    s["ok"] += 1


def record_try(stats, kind):
    """Call once when a fix of this kind is applied, regardless of outcome - 'tries' is the denominator
    mark_ok()/mark_undone() work against."""
    s = stats.setdefault(kind, {"tries": 0, "ok": 0, "undone": 0})
    s["tries"] += 1


def confidence(stats, kind):
    """0..1: share of this kind's past tries that did NOT need an undo. 1.0 (fully trusted) if it has
    never been tried, so a brand-new fix-kind is not punished for having no history yet."""
    s = stats.get(kind)
    if not s or not s["tries"]:
        return 1.0
    return max(0.0, 1 - s["undone"] / s["tries"])


def repeat_threshold(stats, kind, base):
    """How many times the same problem must repeat before Network Doctor auto-fixes it. Starts at
    `base` (the cautious default); a fix-kind with a clean track record needs fewer repeats (as low as
    1), one that keeps getting undone needs more (so it is applied more rarely, not never - the user
    can always turn auto-fix off for good)."""
    s = stats.get(kind)
    if not s or not s["tries"]:
        return base
    if s["undone"]:
        return base + s["undone"]  # at least one undo on record: be more cautious, not less
    # clean record: ease the threshold down as tries accumulate, floor of 1
    return max(1, base - s["ok"] // 3)


def check_regressions(history, active_alerts, before_ids, now=None):
    """Call shortly after a fix (REGRESSION_WINDOW later): for every still-"applied" fix whose window
    has passed, decide success/failure. `active_alerts` is the current alert list (dicts with at least
    "id", "mac", "ip"); `before_ids` is the set of alert ids that already existed right when the fix
    was applied (snapshot taken by the caller at fix time) - a NEW alert touching the same device/IP is
    the signal that the fix made things worse, not better.
    Returns (to_mark_ok, to_auto_undo): lists of fix ids."""
    now = now or time.time()
    ok, bad = [], []
    for e in history:
        if e["status"] != STATUS_APPLIED or now - e["at"] < REGRESSION_WINDOW:
            continue
        new_touching = [a for a in active_alerts if a.get("id") not in before_ids.get(e["id"], set())
                         and (a.get("mac") and a.get("mac") == e.get("mac")
                              or a.get("ip") and a.get("ip") == e.get("ip"))]
        if new_touching:
            bad.append(e["id"])
        else:
            ok.append(e["id"])
    return ok, bad


def stats_summary(stats):
    """One row per fix-kind for a settings/learning panel: tries, undone, confidence (0-100%)."""
    return [{"kind": k, "tries": v["tries"], "ok": v["ok"], "undone": v["undone"],
             "confidence": round(100 * confidence(stats, k))}
            for k, v in sorted(stats.items())]
