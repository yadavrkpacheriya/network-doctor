# -*- coding: utf-8 -*-
"""Security check for ALL device types - pure helpers, no I/O.

Two kinds of finding:
  * exposure - a genuinely risky service left open (Telnet, FTP, VNC). Flagged for every device, PCs and
    phones included. Passive: just reading which ports answered, nothing is tried.
  * default password - a factory/common login that ACTUALLY works. Only ever tested on devices that do not
    lock accounts out: cameras, recorders, routers, printers. NEVER on PCs/servers/phones, because trying
    passwords against them can lock out the real user's Windows/AD account and disrupt the office - for those
    the password posture comes from the PC agent (checked safely from inside), not from guessing.
"""

import nd_core as core

# port -> (severity, short reason). Open = a real, actionable problem, not a blanket reminder.
RISKY_PORTS = {
    23: ("critical", "Telnet is open - old and unencrypted, a common malware target. Turn it off."),
    21: ("warning", "FTP is open - passwords and files travel unencrypted."),
    5900: ("warning", "VNC remote control is open - make sure it needs a strong password."),
    512: ("warning", "rexec/rlogin is open - unencrypted remote login, turn it off."),
}

# categories where actively testing a default login is SAFE (no account lockout). PCs/phones are excluded.
_SAFE_DEFAULT_CATS = (core.CAT_CAM, core.CAT_ROUTER, core.CAT_NET, core.CAT_PRN, core.CAT_BIO)


def may_test_default(category):
    """True only for device kinds that don't lock accounts out when a login is tried."""
    return str(category or "") in _SAFE_DEFAULT_CATS


def exposure_findings(ports):
    """Risky open services on any device. ports: iterable of open port numbers. Returns [(sev, text)]."""
    have = set(ports or [])
    return [RISKY_PORTS[p] for p in sorted(have) if p in RISKY_PORTS]


def device_findings(category, ports, default_hit=None):
    """All security findings for one device.
    default_hit: (user, pw) if a common default login was confirmed to work, else None. Only pass it for a
    category where may_test_default() is True. Returns [(sev, text)] most-severe-first."""
    out = list(exposure_findings(ports))
    if default_hit:
        u = default_hit[0] or "admin"
        out.insert(0, ("critical", "Default / weak password works (login '%s') - anyone can open this device. "
                                   "Change it now." % u))
    rank = {"critical": 0, "warning": 1, "note": 2}
    out.sort(key=lambda f: rank.get(f[0], 3))
    return out


def summary(results):
    """results: list of (device_name, category, [(sev,text)]). Returns (n_devices_with_findings, n_critical)."""
    dev = sum(1 for _n, _c, f in results if f)
    crit = sum(1 for _n, _c, f in results for s, _t in f if s == "critical")
    return dev, crit
