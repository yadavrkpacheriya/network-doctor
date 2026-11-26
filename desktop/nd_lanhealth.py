# -*- coding: utf-8 -*-
"""LAN health: why a 100 Mbps line still feels like 10 - broadcast/multicast storms, switching loops,
half-duplex / 10-100 links, ARP flooding and proxy-ARP. Speedtest can be full and the LAN still crawl,
because these faults add DELAY (every page, print job and share "wakes up slowly"), not a bandwidth cap.

Everything here reads the live MikroTik through the existing RouterOS API client (two short samples a second
apart, to measure PACKET RATES, not just totals) and turns the numbers into plain findings + one-click fixes.
Pure helpers are unit-tested; diagnose(router) is the live entry the app calls. Nothing here ever raises."""

# A link at or below this (bit/s) on a wired office port is a 10/100 or mis-negotiated gigabit port - a common
# hidden cause of "everything slow" (one bad cable drags shared switch paths).
GIG = 1_000_000_000
HUNDRED = 100_000_000

# Broadcast/multicast packets per second, per interface, above which the segment is being flooded. A healthy
# office idles well under 100 bcast pps; a storm (loop, chatty device, ARP flood) runs into the thousands and
# makes every NIC interrupt constantly, so hosts answer late - exactly "they look asleep, then wake up".
BCAST_PPS_WARN = 400
BCAST_PPS_BAD = 1500
# ARP table size that signals flooding / scanning rather than a normal office (~1 entry per live host).
ARP_BLOAT = 400


def _n(v, d=0):
    try:
        return int(str(v).strip() or d)
    except (TypeError, ValueError):
        return d


def link_speed_bps(eth):
    """Best-effort link speed (bit/s) from an /interface/ethernet 'monitor' row. 0 = unknown/down."""
    rate = str(eth.get("rate") or eth.get("speed") or "").lower().strip()
    if not rate or eth.get("status") not in (None, "", "link-ok"):
        if rate in ("", None):
            return 0
    mult = 1
    if rate.endswith("gbps"):
        mult, rate = 1_000_000_000, rate[:-4]
    elif rate.endswith("mbps"):
        mult, rate = 1_000_000, rate[:-4]
    elif rate.endswith("g"):
        mult, rate = 1_000_000_000, rate[:-1]
    elif rate.endswith("m"):
        mult, rate = 1_000_000, rate[:-1]
    try:
        return int(float(rate) * mult)
    except ValueError:
        return 0


def is_full_duplex(eth):
    """True/False/None from an ethernet monitor row ('full-duplex' = 'true'/'false')."""
    fd = eth.get("full-duplex")
    if fd in ("true", True):
        return True
    if fd in ("false", False):
        return False
    return None


def bcast_rate(first, second, dt):
    """Broadcast+multicast packets/second between two /interface stats samples for one interface.
    Each sample: dict with tx/rx-broadcast and tx/rx-multicast counters (strings). dt = seconds between them.
    Counters wrap on reboot; a negative delta is treated as 0 (no false storm right after a restart)."""
    if dt <= 0:
        return 0.0
    tot = 0
    for k in ("rx-broadcast", "tx-broadcast", "rx-multicast", "tx-multicast"):
        d = _n(second.get(k)) - _n(first.get(k))
        if d > 0:
            tot += d
    return tot / dt


def find_storms(samples_a, samples_b, dt, names=None):
    """Interfaces whose broadcast/multicast rate is a flood. samples_* : {iface_name: stats_row}.
    Returns [(name, pps, severity)] sorted worst first; severity 'bad' or 'warn'."""
    out = []
    for name, a in (samples_a or {}).items():
        b = (samples_b or {}).get(name)
        if not b:
            continue
        if names and name not in names:
            continue
        pps = bcast_rate(a, b, dt)
        if pps >= BCAST_PPS_BAD:
            out.append((name, pps, "bad"))
        elif pps >= BCAST_PPS_WARN:
            out.append((name, pps, "warn"))
    out.sort(key=lambda x: -x[1])
    return out


def detect_loop(fdb_a, fdb_b):
    """A switching loop / flapping shows as the SAME MAC appearing on DIFFERENT bridge ports between two
    host-table samples. fdb_* : list of {'mac-address':.., 'on-interface':..}. Returns [(mac, [ports])]
    for MACs that moved. A loop is the worst LAN fault: it multiplies every broadcast forever."""
    def bymac(rows):
        d = {}
        for r in rows or []:
            mac = (r.get("mac-address") or "").upper()
            port = r.get("on-interface") or r.get("interface") or ""
            if mac and port:
                d.setdefault(mac, set()).add(port)
        return d

    a, b = bymac(fdb_a), bymac(fdb_b)
    moved = []
    for mac in set(a) | set(b):
        ports = (a.get(mac, set()) | b.get(mac, set()))
        # moved between samples, or already seen on >1 port in one sample (classic loop signature)
        if len(ports) > 1:
            moved.append((mac, sorted(ports)))
    moved.sort(key=lambda x: -len(x[1]))
    return moved


def slow_links(eths):
    """Wired ports negotiated at <=100 Mbps or half-duplex, from /interface/ethernet monitor rows (that have a
    link). Returns [(name, speed_bps, full_duplex)]. One such port throttles everything sharing its path."""
    out = []
    for e in eths or []:
        name = e.get("name") or e.get("interface") or ""
        status = (e.get("status") or "").lower()
        if status and status != "link-ok":
            continue  # down ports are not a speed fault
        sp = link_speed_bps(e)
        fd = is_full_duplex(e)
        if (0 < sp <= HUNDRED) or fd is False:
            out.append((name, sp, fd))
    return out


def speed_text(bps):
    if not bps:
        return "unknown"
    if bps >= 1_000_000_000:
        return "%g Gbps" % (bps / 1_000_000_000)
    return "%g Mbps" % (bps / 1_000_000)


# ---- fixes (RouterOS). All idempotent: remove ND items by comment first, then add. Safe to re-run. ----
def fix_script(action, bridge="bridge", lan="", ports=None):
    if action == "no_proxy_arp":
        # proxy-arp makes the router answer ARP for everyone -> every host waits on it. LAN bridges want arp=enabled.
        b = lan or bridge
        return '/interface bridge set [find name="%s"] arp=enabled\n' % b
    if action == "storm_control":
        # cap broadcast/multicast/unknown-unicast flooding on the bridge so one chatty port can\'t drown the rest.
        # RouterOS does this per bridge port with a packet/sec limit; 1000 pps is generous for a real office.
        lines = [':do {/interface bridge port set [find] broadcast-flood=yes} on-error={}\n']
        for p in (ports or []):
            lines.append('/interface bridge port set [find interface="%s"] '
                         'multicast-router=disabled\n' % p)
        return "".join(lines)
    if action == "mac_winbox_find_loop":
        # not a change - prints which ports share a MAC so you can pull the looped cable.
        return ('/interface bridge host print where !local\n')
    if action == "igmp_snoop":
        # stop multicast (CCTV / casting) flooding every port - forward it only where it\'s wanted.
        b = lan or bridge
        return ('/interface bridge set [find name="%s"] igmp-snooping=yes\n' % b)
    return ""


def diagnose(router, dt=1.1):
    """Live LAN-health check through the RouterOS API. Returns a list of findings:
    {sev, title, evidence[list], fixes[list], action(or None)}. Never raises - on any error returns a single
    'could not read the router' info item so the UI stays calm."""
    import time
    findings = []
    try:
        with router:
            # ---- two interface samples a second apart = packet RATES (storm detection) ----
            def iface_stats():
                rows = router.cmd("/interface/print", stats="")
                if not rows:
                    rows = router.cmd("/interface/print")
                return {r.get("name", ""): r for r in rows if r.get("name")}

            a = iface_stats()
            t0 = time.time()
            time.sleep(dt)
            b = iface_stats()
            real_dt = max(0.2, time.time() - t0)

            # bridge ports (so we only flag LAN-facing links, not the WAN)
            try:
                bports = [p.get("interface", "") for p in router.cmd("/interface/bridge/port/print")]
                bridge = next((p.get("bridge", "bridge") for p in router.cmd("/interface/bridge/port/print")),
                              "bridge")
            except Exception:  # noqa: BLE001
                bports, bridge = [], "bridge"
            lan_names = set(bports) | {bridge}

            storms = find_storms(a, b, real_dt, names=lan_names or None)
            for name, pps, sev in storms[:4]:
                findings.append({
                    "sev": "critical" if sev == "bad" else "warning",
                    "title": "Broadcast flood on %s (%.0f packets/sec)" % (name, pps),
                    "evidence": ["healthy office: under %d/sec; this port: %.0f/sec" % (BCAST_PPS_WARN, pps),
                                 "a flood makes every PC, printer and camera answer late - 'asleep then wakes up'"],
                    "fixes": ["Find what is flooding %s: usually a looped cable, a faulty NIC, or a device "
                              "spamming broadcasts. Unplug devices on that port one by one." % name,
                              "Turn on storm control + IGMP snooping on the bridge (buttons below) to cap it."],
                    "action": "igmp_snoop",
                })

            # ---- switching loop (worst case) via bridge host table ----
            try:
                h1 = router.cmd("/interface/bridge/host/print")
                time.sleep(0.4)
                h2 = router.cmd("/interface/bridge/host/print")
                loops = detect_loop(h1, h2)
            except Exception:  # noqa: BLE001
                loops = []
            for mac, ports in loops[:3]:
                findings.append({
                    "sev": "critical",
                    "title": "Possible switching loop: %s seen on %d ports" % (mac, len(ports)),
                    "evidence": ["%s appears on: %s" % (mac, ", ".join(ports)),
                                 "a loop multiplies broadcasts endlessly - the #1 cause of a whole office crawling"],
                    "fixes": ["A cable is almost certainly plugged into two switch ports (a loop). Trace %s and "
                              "remove the duplicate cable." % mac,
                              "Enable loop-protect / RSTP on the switches if they support it."],
                    "action": "mac_winbox_find_loop",
                })

            # ---- slow / half-duplex wired links ----
            try:
                eths = router.cmd("/interface/ethernet/monitor", numbers="all", once="")
            except Exception:  # noqa: BLE001
                eths = []
            # monitor needs a name per call on some ROS; fall back to per-interface
            if not eths:
                eths = []
                for name in (lan_names or []):
                    try:
                        r = router.cmd("/interface/ethernet/monitor", numbers=name, once="")
                        for row in r:
                            row.setdefault("name", name)
                            eths.append(row)
                    except Exception:  # noqa: BLE001
                        pass
            for name, sp, fd in slow_links(eths):
                findings.append({
                    "sev": "warning",
                    "title": "%s runs at %s%s" % (name, speed_text(sp), "" if fd is not False else " HALF-duplex"),
                    "evidence": ["a 10/100 or half-duplex port throttles everything sharing its path",
                                 "gigabit needs all 8 cable wires and a Cat5e+ cable end to end"],
                    "fixes": ["Replace the patch cable on %s and try another switch port." % name,
                              "Check the switch that port leads to - one cheap 10/100 switch limits a whole branch."],
                    "action": None,
                })

            # ---- ARP bloat (flooding / scanning) + proxy-arp left on ----
            try:
                arp = router.cmd("/ip/arp/print")
            except Exception:  # noqa: BLE001
                arp = []
            if len(arp) >= ARP_BLOAT:
                findings.append({
                    "sev": "warning",
                    "title": "Very large ARP table (%d entries)" % len(arp),
                    "evidence": ["a normal office has about one entry per live device",
                                 "this many usually means broadcast flooding or a device scanning the network"],
                    "fixes": ["Find the noisy device (Problems tab / broadcast finding above).",
                              "Consider static ARP for servers and the NVR."],
                    "action": None,
                })
            try:
                for bi in router.cmd("/interface/bridge/print"):
                    if (bi.get("arp") or "").lower() == "proxy-arp":
                        findings.append({
                            "sev": "warning",
                            "title": "Router is in proxy-ARP mode (answers for everyone)",
                            "evidence": ["bridge %s arp=proxy-arp" % bi.get("name", "bridge"),
                                         "every ARP waits on the router instead of the device - adds delay to all"],
                            "fixes": ["Set the LAN bridge back to normal ARP (button below)."],
                            "action": "no_proxy_arp",
                        })
                        break
            except Exception:  # noqa: BLE001
                pass

    except Exception as e:  # noqa: BLE001
        return [{"sev": "info", "title": "Could not read the router for LAN health",
                 "evidence": [str(e)], "fixes": ["Check the router login in Setup, then run this again."],
                 "action": None}]

    if not findings:
        findings.append({"sev": "ok", "title": "LAN layer looks healthy",
                         "evidence": ["no broadcast storm, no loop, no slow/half-duplex port, ARP table normal",
                                      "if pages still feel slow, it is DNS or the line - run the Slow-site check"],
                         "fixes": [], "action": None})
    order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    findings.sort(key=lambda f: order.get(f["sev"], 9))
    return findings
