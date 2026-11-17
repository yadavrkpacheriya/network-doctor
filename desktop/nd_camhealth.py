# -*- coding: utf-8 -*-
"""Camera health check - find faults on the cameras and point to the SAFE fix.

What it checks per camera: is it reachable (powered + connected), does a saved login still work, is it still on
a weak/default password, and (for XMeye/local cameras) its model + firmware version. It does NOT auto-flash
firmware - wrong firmware bricks a no-name camera, so firmware is reported for you to update per-camera, and
the only automatic fixes offered are the safe ones already in the app (reboot, reset-to-DHCP, re-bind IP).

Pure logic here (assess / report) with the network reads injected, so it is unit-tested without hardware.
"""

# Common factory logins to detect a camera still on its default password (a real security fault).
COMMON_DEFAULTS = [("admin", ""), ("admin", "admin"), ("admin", "12345"), ("admin", "123456"),
                   ("admin", "888888"), ("admin", "admin12345"), ("admin", "9999"), ("root", "root"),
                   ("admin", "1111"), ("admin", "54321")]

_RANK = {"OFFLINE": 0, "CHECK": 1, "OK": 2}


def is_default(user, pw):
    return (user or "", pw or "") in COMMON_DEFAULTS


def assess(cam, reachable_ports, info, login):
    """Build one camera's health record.
    cam: {name, ip, mac}. reachable_ports: list of open camera ports ([] = offline).
    info: {model, firmware, ...} or None. login: {'user','default'} if a login worked, None if none worked,
    or False if a login was not attempted (e.g. not an XMeye camera)."""
    rec = {"name": cam.get("name") or cam.get("ip") or "?", "ip": cam.get("ip", ""),
           "mac": cam.get("mac", ""), "model": (info or {}).get("model", ""),
           "firmware": (info or {}).get("firmware", ""), "issues": [], "status": "OK", "fix": ""}
    if not reachable_ports:
        rec["status"] = "OFFLINE"
        rec["issues"].append("not responding - check PoE power / network cable (or it is on another subnet)")
        rec["fix"] = "Power-cycle its PoE port, then run Direct camera check to confirm it is connected"
        return rec
    if login is None:
        rec["status"] = "CHECK"
        rec["issues"].append("no saved login works - the password may have been changed")
        rec["fix"] = "Add the camera's login in Setup > Camera/NVR/DVR logins, then run the Login sweep"
    elif isinstance(login, dict) and login.get("default"):
        rec["status"] = "CHECK"
        rec["issues"].append("weak / default password (%s) - anyone can open this camera" % (login.get("user") or "admin"))
        rec["fix"] = "Set a strong password on the camera (its app / web page)"
    return rec


def report(cams, ports_of, probe_login):
    """Health for every camera. `ports_of(cam) -> [open ports]`; `probe_login(cam) -> (info, login)` where
    login is a dict / None / False (see assess). Worst (OFFLINE, then CHECK) first. Never raises per camera."""
    out = []
    for c in cams:
        try:
            ports = ports_of(c) or []
        except Exception:  # noqa: BLE001
            ports = []
        info, login = None, False
        if ports:
            try:
                info, login = probe_login(c)
            except Exception:  # noqa: BLE001
                info, login = None, False
        out.append(assess(c, ports, info, login))
    out.sort(key=lambda r: (_RANK.get(r["status"], 3), r["name"].lower()))
    return out


def summary(records):
    """One-line counts for the top of the report."""
    off = sum(1 for r in records if r["status"] == "OFFLINE")
    chk = sum(1 for r in records if r["status"] == "CHECK")
    ok = sum(1 for r in records if r["status"] == "OK")
    return {"total": len(records), "offline": off, "check": chk, "ok": ok}
