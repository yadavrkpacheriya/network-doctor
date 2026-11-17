# -*- coding: utf-8 -*-
"""Camera firmware registry - remembers every camera's details and firmware across sessions.

Stored in settings['camera_registry'], keyed by MAC (or IP when no MAC). Each time you run the Camera health
report (online), every camera's brand / model / firmware / serial is recorded, and a new firmware version is
added to its history - so you always know what each camera is, what firmware it runs, and whether it changed.

This is the SAFE half of firmware management: it tracks and flags. It never flashes firmware itself - the
registry feeds the assisted-update flow (back up config, verify model, you apply the vendor file, verify
after) documented in docs/CAMERA_FIRMWARE.md.
"""
import time


def _key(rec):
    return (rec.get("mac") or "").upper() or rec.get("ip") or ""


def record(reg, rec, now=None):
    """Add/update one camera from a health or discovery record. Appends to firmware history when the version
    changes. `rec`: {name, ip, mac, brand, model, firmware, serial}. Returns the stored entry."""
    now = now or time.time()
    day = time.strftime("%Y-%m-%d", time.localtime(now))
    key = _key(rec)
    if not key:
        return None
    e = reg.get(key)
    if not e:
        e = {"name": "", "ip": "", "mac": "", "brand": "", "model": "", "firmware": "", "serial": "",
             "first_seen": day, "last_seen": day, "history": []}
        reg[key] = e
    for f in ("name", "ip", "mac", "brand", "model", "serial"):
        if rec.get(f):
            e[f] = rec[f]
    e["last_seen"] = day
    fw = rec.get("firmware") or ""
    if fw and (not e["history"] or e["history"][-1].get("ver") != fw):
        e["history"].append({"ver": fw, "date": day})
    if fw:
        e["firmware"] = fw
    return e


def record_all(reg, recs, now=None):
    for r in recs:
        record(reg, r, now)
    return reg


def cameras(reg):
    """All stored cameras, newest-seen first."""
    return sorted((e for e in reg.values() if isinstance(e, dict) and "history" in e),
                  key=lambda e: e.get("last_seen", ""), reverse=True)


def outdated(reg, targets):
    """Cameras whose firmware is not the target set for their model. `targets`: {model: wanted_version}.
    Only models you have set a target for are judged - nothing is called outdated on a guess."""
    out = []
    for e in cameras(reg):
        want = targets.get(e.get("model", ""))
        if want and e.get("firmware") and e["firmware"] != want:
            out.append({"name": e.get("name"), "ip": e.get("ip"), "model": e.get("model"),
                        "firmware": e.get("firmware"), "target": want})
    return out


def summary(reg):
    cams = cameras(reg)
    models = {}
    for e in cams:
        m = e.get("model") or "unknown"
        models.setdefault(m, set()).add(e.get("firmware") or "?")
    return {"cameras": len(cams), "models": {m: sorted(v) for m, v in models.items()}}
