# -*- coding: utf-8 -*-
"""Router-agnostic per-device internet block ("LAN block"): the fallback for every router that is not a
logged-in MikroTik (nd_routeros.py gets a real router-side firewall block instead - see NetworkDoctor.py's
_remote("block"/"isolate")). Needs no router API or login at all, so it works on any router or access
point - home, office, hotel, anything.

How it works: this PC keeps answering the TARGET device's ARP requests for the gateway's IP with this PC's
own MAC address, so the target sends its internet-bound traffic here instead of to the real router - and
this PC simply never forwards it on. Traffic to OTHER devices on the LAN is untouched (the target still
resolves their MACs directly, never through the gateway), so unlike a MikroTik firewall rule, "cut internet,
keep the LAN" needs no extra logic here - it is just how ARP addressing already works.

A true two-way "isolate" (also cutting LAN access, not just internet) would need spoofing the whole LAN's
idea of the target too - a materially bigger blast radius, for a feature whose entire point is to never be
the thing that takes the network down. So this only ever blocks internet, never LAN access; NetworkDoctor.py
falls back to this same "internet" level for an "isolate" request with no MikroTik login, and says so.

Safety:
  * Every target is checked by plan() below using the SAME category/exclusion rules nd_defense.Defense
    already enforces for a router-side block - the gateway, this PC, and anything on the "never auto-act"
    list (phones/tablets, the network backbone) can never be a target.
  * A block exists only while this PC keeps refreshing it (every REFRESH_SEC) from a background thread; if
    Network Doctor is closed or crashes, the spoofed ARP entry simply ages out of the target's own ARP cache
    on its own within its normal timeout (routers and OSes expire stale ARP entries by themselves, usually
    within a couple of minutes) - unlike a router firewall rule, there is no persistent change left behind
    to clean up.
  * stop()/stop_all() send corrected ("healing") ARP replies with the REAL gateway MAC immediately, so
    recovery does not have to wait for that natural timeout.
  * Needs Scapy + Npcap (raw sockets, bundled with the app) and administrator rights, exactly like the
    app's other raw tests (available() below mirrors nd_core.scapy_ok()).
"""
import threading
import time

import nd_defense as DF

REFRESH_SEC = 2     # how often an active block's spoofed ARP reply is re-sent
HEAL_PACKETS = 3    # extra real-MAC "healing" replies sent on release, in case one is lost on the wire


def plan(category, ip, mac, defense):
    """Whether `ip`/`mac` (device `category`) may be LAN-blocked right now. '' when allowed, else why not -
    the same backbone/phone/exclude-list rules nd_defense.Defense already uses for a router-side block, but
    checked directly (not through Defense.guard(), whose ROUTER_SIDE table is about alert KINDS like a
    port-forward, not about which devices a plain "block this device" button may ever target)."""
    if category in DF.NEVER_ACT_CATEGORIES:
        if "Network equipment" in category:
            return "the network backbone (router / switch / AP) is never blocked this way - it would take " \
                   "the whole network down"
        return "phones and tablets are never blocked this way (their IP / MAC changes)"
    if defense.excluded(ip, mac):
        return "this device is on the never-act / excluded list (Security > Auto-defense)"
    if not mac:
        return "no MAC address known for this device yet - wait for the next scan"
    return ""


class ArpBlocker:
    """One instance per running app (NetworkDoctor.py creates self.arpblock). Call start()/stop() from any
    thread; a background thread keeps every active block refreshed until it is stopped or its time runs
    out. All the scapy/raw-socket calls are wrapped so a missing Npcap or a transient send error degrades
    to "nothing sent this round", never a crash - the next refresh (or the explicit heal on stop) retries."""

    def __init__(self, self_mac, gw_ip):
        self.self_mac = self_mac
        self.gw_ip = gw_ip
        self.active = {}   # ip -> {"mac", "gw_mac", "name", "t", "until"}
        self.lock = threading.Lock()
        self._stop_evt = threading.Event()
        self._thread = None

    def available(self):
        import nd_core as core
        return core.scapy_ok() and bool(self.self_mac) and bool(self.gw_ip)

    def is_blocked(self, ip):
        with self.lock:
            return ip in self.active

    def start(self, ip, mac, name="", minutes=60):
        """Starts (or renews) blocking `ip`. Returns (ok, message)."""
        gw_mac = self._resolve(self.gw_ip)
        if not gw_mac:
            return False, "could not learn the router's real MAC address yet - try again in a moment"
        with self.lock:
            self.active[ip] = {"mac": mac, "gw_mac": gw_mac, "name": name or ip,
                               "t": time.time(), "until": time.time() + minutes * 60 if minutes else 0}
        self._ensure_thread()
        return True, ""

    def stop(self, ip):
        with self.lock:
            e = self.active.pop(ip, None)
        if e:
            self._heal(ip, e["mac"], e["gw_mac"])
        return bool(e)

    def stop_all(self):
        with self.lock:
            items = list(self.active.items())
            self.active.clear()
        for ip, e in items:
            self._heal(ip, e["mac"], e["gw_mac"])

    def expired(self, now=None):
        """IPs whose time limit has passed and should be released."""
        now = now if now is not None else time.time()
        with self.lock:
            return [ip for ip, e in self.active.items() if e["until"] and now >= e["until"]]

    def shutdown(self):
        """Called as the app closes: stop the refresh thread and heal every active target."""
        self._stop_evt.set()
        self.stop_all()

    # ------------------------------------------------------------------ scapy (optional, Windows/Npcap)
    def _resolve(self, ip):
        try:
            from scapy.all import ARP, Ether, srp, conf
            conf.verb = 0
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, retry=1)
            for _, r in ans:
                return r.hwsrc
        except Exception:
            pass
        return ""

    def _spoof_once(self, ip, mac, claim_mac):
        try:
            from scapy.all import ARP, Ether, sendp, conf
            conf.verb = 0
            pkt = Ether(dst=mac) / ARP(op=2, psrc=self.gw_ip, hwsrc=claim_mac, pdst=ip, hwdst=mac)
            sendp(pkt, count=1, verbose=0)
        except Exception:
            pass

    def _heal(self, ip, mac, gw_mac):
        for _ in range(HEAL_PACKETS):
            self._spoof_once(ip, mac, gw_mac)  # tell the target the TRUE gateway MAC again
            time.sleep(0.1)

    def _ensure_thread(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop_evt.is_set():
            with self.lock:
                items = [(ip, e["mac"]) for ip, e in self.active.items()]
            for ip, mac in items:
                self._spoof_once(ip, mac, self.self_mac)  # claim to BE the gateway
            self._stop_evt.wait(REFRESH_SEC)
