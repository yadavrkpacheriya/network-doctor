# -*- coding: utf-8 -*-
"""Network Doctor Pro - the auto-defense engine.

Watches the alerts and traffic the rest of the app already produces, decides which ones are a live attack,
and (when you arm it) contains the attacker by itself - even at 3 a.m. with nobody at the desk. Every
automatic action is reversible, written to the audit log, and sent to your phone.

Response ladder (you choose how far it may go, per threat):
  notify     - only raise an alert and notify (never touches the network)
  internet   - cut the device's internet on the router (it keeps the LAN)
  isolate    - drop ALL the device's traffic on the router (full quarantine)
  poweroff   - also tell that PC's agent to shut down / disable its own network card (needs the PC agent)

Safety:
  * Devices on the "never auto-act" list (router, servers, the admin PC) are only ever alerted on.
  * Optional "night only" window, so daytime stays hands-on and nights are automatic.
  * Everything an auto-action does can be released again from Security > Auto-defense, or the phone.
"""
import time

# threat kind -> (title, default furthest response allowed). Kinds line up with nd_alerts / the monitor.
THREATS = {
    "exposed": ("A device is open to the internet", "internet"),
    "malware": ("A device talks to a malware address", "isolate"),
    "arp_spoof": ("Someone is impersonating the router (ARP spoofing)", "isolate"),
    "rogue_dhcp": ("A second router is handing out addresses", "internet"),
    "loop": ("Network loop / broadcast storm", "notify"),
    "login_fail": ("Password-guessing on the router", "notify"),
    "torrent": ("Torrent download", "internet"),
    "port_scan": ("A device is scanning the network (possible intruder)", "isolate"),
    "lateral": ("A device suddenly talks to many PCs (possible spread)", "isolate"),
}
LADDER = ["notify", "internet", "isolate", "poweroff"]
DEFAULT = {
    "armed": False,
    "mode": "auto",          # "auto" acts; "alert" only alerts even when armed
    "night_only": False,
    "night_from": 20, "night_to": 7,
    "exclude_ips": [],       # never auto-acted on (the router is added automatically)
    "exclude_macs": [],
    "levels": {k: v for k, (_t, v) in THREATS.items()},
    "cooldown_min": 30,
}


def cfg(settings):
    d = dict(DEFAULT)
    d.update((settings or {}).get("defense") or {})
    base = dict(DEFAULT["levels"])
    base.update(d.get("levels") or {})
    d["levels"] = base
    return d


def is_night(c, now=None):
    h = time.localtime(now or time.time()).tm_hour
    a, b = c.get("night_from", 20), c.get("night_to", 7)
    return (a <= h or h < b) if a > b else (a <= h < b)


def level_at_most(allowed, wanted):
    """The response to actually use = the smaller of what the threat wants and what you allow."""
    return LADDER[min(LADDER.index(allowed), LADDER.index(wanted))] if allowed in LADDER and wanted in LADDER else "notify"


class Defense:
    """Holds the state of auto-actions. The app calls consider() for each live threat and the engine decides."""

    def __init__(self, settings, gw_ip=""):
        self.settings = settings
        self.gw_ip = gw_ip
        self.last = {}        # (kind, key) -> time, for the cooldown
        self.active = {}      # key(ip/mac) -> {"kind","level","ip","mac","name","t","by"} currently contained

    def config(self):
        return cfg(self.settings)

    def save(self, patch):
        d = self.settings.setdefault("defense", {})
        d.update(patch)
        return cfg(self.settings)

    def excluded(self, ip, mac):
        c = self.config()
        if ip and (ip == self.gw_ip or ip in c["exclude_ips"]):
            return True
        return bool(mac and mac.upper() in {m.upper() for m in c["exclude_macs"]})

    def planned(self, kind, ip="", mac=""):
        """What the engine WOULD do for this threat right now (without doing it): a response level or 'notify'."""
        c = self.config()
        if not c["armed"]:
            return "notify"
        if c["mode"] != "auto":
            return "notify"
        if c["night_only"] and not is_night(c):
            return "notify"
        if self.excluded(ip, mac):
            return "notify"
        want = c["levels"].get(kind, "notify")
        return level_at_most(want, want)

    def cool(self, kind, key):
        c = self.config()
        now = time.time()
        if now - self.last.get((kind, key), 0) < c["cooldown_min"] * 60:
            return True
        self.last[(kind, key)] = now
        return False

    def note_contained(self, key, info):
        self.active[key] = dict(info, t=time.time())

    def release(self, key):
        return self.active.pop(key, None)

    def contained(self):
        return dict(self.active)
