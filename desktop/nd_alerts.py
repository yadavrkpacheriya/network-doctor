"""Alert history with priority, cause, fix and step-by-step troubleshooting (Network Doctor).

Every warning / problem the app raises is kept in alerts.json (last 3000), so nothing has to be
screenshotted: the Alerts tab lists them with time, priority and the fix, exports them to Excel / HTML,
and its Troubleshoot button fixes what can be fixed by commands (router or this PC) and gives numbered
steps for what needs hands on a cable, a switch or a device.
"""
import csv
import html
import json
import os
import re
import threading
import time

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_RE = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b")
PRIO = {1: "P1 - fix now", 2: "P2 - fix today", 3: "P3 - this week", 4: "P4 - for information"}
SEV_PRIO = {"critical": 1, "warning": 3, "info": 4}

# fixes Network Doctor may apply by itself when the same alert repeats 5 times (they only add a reservation or turn
# on a protection - nothing that can cut off a user or a camera)
AUTO_SAFE = {"dhcp_conflict", "multicast", "loop"}

# placed at the top of the forward chain (above FastTrack) - works on RouterOS 6 and 7
TOP = 'place-before=([/ip firewall filter find]->0)'


def _top_rule(rule):
    """A firewall rule at the top, or at the end when the list is empty (on-error)."""
    return f':do {{ /ip firewall filter add {rule} {TOP} }} on-error={{ /ip firewall filter add {rule} }}'


def _ip_of(text, skip=("255.255.255.255", "0.0.0.0")):
    for ip in IP_RE.findall(text or ""):
        if ip not in skip and not ip.startswith(("224.", "239.")):
            return ip
    return ""


def _fix(prio, kind, title, why, fix, steps, auto=(), app=None):
    """auto: (label, where, command) - where is "router" (RouterOS script) or "pc" (runs on this PC).
    app: (label, action) - opens the right place in Network Doctor."""
    return {"prio": prio, "kind": kind, "title": title, "why": why, "fix": fix, "steps": list(steps),
            "auto": [{"label": a[0], "where": a[1], "cmd": a[2]} for a in auto if a], "app": app}


def recipe(text, sev="warning", lip="", gw=""):
    """What an alert means, how urgent it is and how to fix it."""
    t = text or ""
    low = t.lower()
    ip = _ip_of(t)
    macs = MAC_RE.findall(t)
    mac = macs[0].upper() if macs else ""

    m = re.search(r"conflict by arp response for ((?:\d{1,3}\.){3}\d{1,3}) from ([0-9a-f:]{17})", low)
    if m:
        cip, cmac = m.group(1), m.group(2).upper()
        own = cip == lip
        return _fix(2, "dhcp_conflict", f"IP {cip} is typed by hand on {cmac} inside the router's DHCP range",
                    f"The router wanted to give {cip} to a device, but {cmac} already uses it with a manually typed "
                    "(static) IP. The router skips it now, but when that device is off the router can hand the same "
                    "IP to a phone - then both lose the network." + (" This is the Network Doctor PC itself." if own
                                                                      else ""),
                    f"Reserve {cip} for {cmac} on the router (the button below) - or switch the device to "
                    "automatic IP.",
                    [f"Press 'Reserve {cip} for this device' below: the router keeps {cip} only for {cmac}.",
                     "Or, if the device does not need a fixed IP: on that device set the IP to automatic "
                     "(Windows: Settings > Network > Ethernet > IP assignment > Automatic (DHCP)).",
                     "Run 'Re-check' after a few minutes: the conflict message should not come back."],
                    auto=[(f"Reserve {cip} for this device", "router",
                           f':local l [/ip dhcp-server lease find where mac-address={cmac}]\n'
                           f':if ([:len $l] > 0) do={{ :do {{ /ip dhcp-server lease make-static $l }} on-error={{}}; '
                           f'/ip dhcp-server lease set $l address={cip} comment="ND: fixed IP (typed by hand)" }} '
                           f'else={{ /ip dhcp-server lease add address={cip} mac-address={cmac} '
                           f'comment="ND: fixed IP (typed by hand)" }}')])

    if "ip conflict" in low or "conflict on" in low or "used by another device" in low:
        return _fix(1, "ip_conflict", f"Two devices use the same IP {ip}",
                    "Two devices answer for one IP. Both get cut off at random; printers and ERP sessions drop.",
                    "Give each device its own IP: switch the one with the hand-typed IP to automatic, or bind each "
                    "MAC to its IP (IP-MAC binding).",
                    [f"Note the two MAC addresses in the alert ({', '.join(macs[:2]) or 'see the alert'}).",
                     "Open IP-MAC binding (button below): it shows which device the IP belongs to.",
                     "On the other device set the IP to automatic, or change it to a free IP outside the DHCP range.",
                     "Restart that device's network (unplug the cable 10 seconds, or ipconfig /renew).",
                     "Re-check: the conflict line disappears."],
                    auto=[("Clear this PC's ARP / DNS cache", "pc", "arp -d * & ipconfig /flushdns")],
                    app=("Open IP-MAC binding", "binding"))

    if "torrent" in low or "peer-to-peer" in low:
        return _fix(2, "torrent", f"Torrent download on {ip or 'a device'}",
                    "A torrent program (uTorrent, BitTorrent, qBittorrent, Transmission...) downloads and uploads "
                    "to hundreds of strangers. It fills the internet line for everyone, brings malware and pirated "
                    "files, and port 51413 / 6881 traffic is what ISPs and copyright notices look for.",
                    "Block torrents on the router (button below) and remove the torrent program from that PC.",
                    ["Press 'Block torrents on the router': torrent traffic and torrent websites are blocked for "
                     "every device (Undo is in Security > Network guard).",
                     f"Go to the PC at {ip or 'the IP in the alert'} (Inventory shows its name and user).",
                     "Control Panel > Programs > uninstall uTorrent / BitTorrent / qBittorrent / Transmission / "
                     "BitComet; also close it in the taskbar tray.",
                     "Run a Windows Defender quick scan on that PC (torrent downloads often carry malware).",
                     "Tell the user it is not allowed on the office network."],
                    auto=[("Block torrents on the router", "router", "@torrent_guard"),
                          ("Block only this device's internet", "router",
                           _top_rule(f'chain=forward src-address={ip} action=drop comment="ND: blocked {ip}"'))
                          if ip else None])

    if "from the internet" in low or "exposed" in low or "port forward" in low:
        return _fix(1, "exposed", f"{ip or 'A device'} can be opened from the internet",
                    "A port forward or UPnP on the router lets anyone on the internet reach this device. DVRs, "
                    "cameras and remote desktop get hacked within days (password guessing, known firmware bugs).",
                    "Close the port forward / UPnP (button below); watch the cameras through the maker's app or a "
                    "VPN instead.",
                    ["Press 'Close internet access to this device': the router's port forwards to it are disabled "
                     "and UPnP is turned off.",
                     "Log in to the DVR / device and change the admin password (long, not the default).",
                     "Update the DVR / camera firmware from the maker's website.",
                     "For viewing from outside use the maker's mobile app (cloud / P2P ID) or a VPN - not a port "
                     "forward.",
                     "Re-check: the alert should not return."],
                    auto=[("Close internet access to this device", "router",
                           f"/ip upnp set enabled=no\n/ip firewall nat disable [find where action=dst-nat and "
                           f"to-addresses={ip}]") if ip else ("Turn off UPnP", "router", "/ip upnp set enabled=no")])

    if "rogue" in low or "second dhcp" in low or "another dhcp" in low or "extra router" in low or \
            "not the router" in low:
        return _fix(1, "rogue_dhcp", "A second router gives out IP addresses",
                    "A home Wi-Fi router or a wrong cable makes a second DHCP server. PCs get its IP and lose the "
                    "office network / internet at random.",
                    "Find and unplug it (or set it up as an access point); block it on the router.",
                    [f"The device in the alert ({mac or ip or 'see the alert'}) is the second router.",
                     "Find it: Devices tab > its switch port, or look for a small Wi-Fi router under a desk.",
                     "Unplug it, or log in to it and turn its DHCP server OFF and plug the office cable in a LAN "
                     "port (not WAN/Internet) - then it is a plain access point.",
                     "Press 'Block rogue DHCP on the router' so it cannot happen again.",
                     "On affected PCs: ipconfig /release then ipconfig /renew."],
                    auto=[("Block rogue DHCP on the router", "router", "@dhcp_guard")])

    if "storm" in low or "loop" in low or "mac flap" in low or "mac_flap" in low or "duplicate replies" in low or \
            "spanning-tree" in low:
        return _fix(1, "loop", "Network loop / broadcast storm",
                    "A cable connects two ports of the same switch (or two switches twice). Packets go round in "
                    "circles: the whole network slows down or stops.",
                    "Find the cable that makes the loop and remove it; turn on loop protection.",
                    ["Press 'Turn on loop protection' (router ports shut down a looping port by themselves).",
                     "Look at each switch: a short cable with both ends in the same switch is the usual cause.",
                     "Still there? Unplug the switch uplinks one by one; when the storm stops the last cable "
                     "unplugged leads to the loop.",
                     "Check under desks for an extra small switch with two cables back to the wall.",
                     "Plug back in one cable at a time; managed switches: enable loop detection / BPDU guard "
                     "(Commands tab > your switch brand)."],
                    auto=[("Turn on loop protection", "router", "/interface ethernet set [find] loop-protect=on")])

    if "multicast" in low or "broadcast" in low:
        return _fix(3, "multicast", "A lot of multicast / broadcast traffic",
                    "Cameras, IPTV or discovery traffic sent to every port. Not an outage, but slows Wi-Fi.",
                    "Turn on IGMP snooping so multicast only goes where it is wanted.",
                    ["Press 'Turn on IGMP snooping'.",
                     "If it goes on: Live monitor > the device sending most broadcasts; check that camera / NVR.",
                     "Managed switches: enable IGMP snooping and storm control too."],
                    auto=[("Turn on IGMP snooping", "router", "/interface bridge set [find] igmp-snooping=yes")])

    if "arp spoof" in low or "arp_spoof" in low or "netcut" in low or "gateway mac changed" in low:
        return _fix(1, "arp_spoof", "Someone pretends to be the router (ARP spoofing)",
                    "A program like NetCut / a hacked PC answers for the router's IP. It can cut people off or read "
                    "their traffic.",
                    "Unplug the device with that MAC; lock the router's MAC on the PCs.",
                    [f"The MAC in the alert ({mac or 'see the alert'}) is the attacker. Inventory / Devices shows "
                     "its name and port.",
                     "Unplug it or block it (button below), then check that PC for NetCut / malware.",
                     "Commands tab > PC fix script > 'Lock the router's MAC' on all PCs.",
                     "Enable ARP 'reply-only' on the router LAN only if every device has a static lease."],
                    auto=[("Block this MAC on the router", "router",
                           _top_rule(f'chain=forward src-mac-address={mac} action=drop comment="ND: blocked {mac}"'))
                          if mac else None])

    if "malware" in low or "threat" in low or "botnet" in low or "c&c" in low:
        return _fix(1, "malware", f"Possible malware on {ip or 'a device'}",
                    "The device talks to an address on a malware / botnet list.",
                    "Cut its internet now, then clean the PC.",
                    ["Press 'Block this device's internet' (Undo: remove the ND rule in IP > Firewall).",
                     "On the PC: Windows Security > Virus scan > Microsoft Defender Offline scan.",
                     "Uninstall unknown programs and browser extensions; update Windows.",
                     "Change the passwords used on that PC (email, banking, ERP) from another PC.",
                     "Unblock and watch the Live monitor for a day."],
                    auto=[("Block this device's internet", "router",
                           _top_rule(f'chain=forward src-address={ip} action=drop comment="ND: blocked {ip}"'))
                          if ip else None,
                          ("Defender quick scan on this PC", "pc",
                           'powershell -NoProfile -Command "Update-MpSignature; Start-MpScan -ScanType QuickScan"')])

    if "login fail" in low or "login failure" in low or "password" in low and "router" in low:
        return _fix(2, "login_fail", "Wrong-password logins on the router",
                    "Someone (or a bot on the internet) is guessing the router's password.",
                    "Allow router logins only from the office LAN and use a strong password.",
                    ["WinBox > IP > Services: for winbox, ssh, www, api, telnet and ftp set 'Available From' to the "
                     "office LAN only (e.g. 192.168.0.0/24); disable telnet and ftp.",
                     "WinBox > System > Users: change the admin password; remove unused users.",
                     "If the attempts come from outside: make sure no port forward points to the router itself."])

    if ("gateway" in low or "router" in low) and "not answer" in low or "internet is down" in low or \
            "no internet" in low or "wan down" in low or "gateway" in low and " down" in low:
        return _fix(1, "internet_down", "Router or internet not answering",
                    "The router or the internet line stopped answering.",
                    "Check power and cables first, then the internet provider.",
                    ["Look at the router: power light on? If not, check the adapter / UPS and restart it.",
                     "Check the internet cable (from the ISP box / ONT) is in the router's WAN port (ether1) and "
                     "its light blinks.",
                     "Look at the ISP's fibre box (ONT): a red LOS light = fibre problem, call the ISP.",
                     "Press 'Test from this PC' below to see where it stops.",
                     "Still down after 5 minutes: restart the ONT, wait 2 minutes, then the router."],
                    auto=[("Test from this PC", "pc", f"ping -n 4 {gw or '192.168.0.1'} & ping -n 4 8.8.8.8 & "
                                                      "nslookup google.com & tracert -d -h 8 8.8.8.8")])

    if "link down" in low or "port down" in low or "link_down" in low or "flapping" in low:
        return _fix(2, "link_down", "A cable / port went down",
                    "A port lost its link: unplugged, a bad cable, a switch losing power, or a PC going to sleep.",
                    "Check the cable and the device on that port.",
                    ["Find the port in the alert (e.g. ether3) and follow its cable.",
                     "Check both ends are clicked in; try another patch cable.",
                     "Check the switch / device at the other end has power (UPS?).",
                     "Port going up and down many times = replace the cable or try another port.",
                     "If it is a PC going to sleep at night, it is normal."])

    if "unstable" in low:
        return _fix(2, "unstable", "The connection to the router drops now and then",
                    "Pings to the router get lost: a loose or damaged cable, a weak Wi-Fi signal, an overloaded "
                    "switch or a loop starting.",
                    "Check the cable / Wi-Fi of this PC and the switch between it and the router.",
                    ["On cable: re-seat both ends of the PC cable, then try another patch cable and switch port.",
                     "On Wi-Fi: move closer to the access point or use a cable; check the 5 GHz signal.",
                     "Feel the switches: a very hot or old switch drops packets - restart it, replace if it repeats.",
                     "Press 'Ping the router for 1 minute' and watch for 'Request timed out'.",
                     "Look at the Live monitor for a loop / broadcast alert at the same time."],
                    auto=[("Ping the router for 1 minute", "pc", f"ping -n 60 {gw or '192.168.0.1'}")])

    if "instead of" in low and "bound" in low:
        return _fix(3, "binding", "A bound device came back with another IP",
                    "The device has an IP-MAC binding but now uses a different IP (typed by hand, or DHCP gave a new "
                    "one).",
                    "Set the binding again or switch the device to automatic IP.",
                    ["Open IP-MAC binding (button below) and press 'Apply on router' for this device.",
                     "On the device set the IP to automatic, then ipconfig /release and /renew."],
                    app=("Open IP-MAC binding", "binding"))

    if "voltage" in low or "power" in low and "router" in low:
        return _fix(2, "power", "Power problem at the router",
                    "The router reported a low / unstable supply voltage or restarted after a power cut.",
                    "Put the router, switches and ONT on a UPS; check the adapter.",
                    ["Check the router's power adapter and its plug; replace a hot or loose adapter.",
                     "Put the router, main switch and the ISP box on a UPS.",
                     "WinBox > System > Health shows the voltage; it should be steady."])

    if "half duplex" in low or "half-duplex" in low or "100 mbps" in low or "cable errors" in low or "crc" in low:
        return _fix(3, "cable", "Bad cable or port (slow / errors)",
                    "Gigabit needs all 8 wires. Half duplex, 100 Mbps or errors mean a damaged cable, a bad crimp "
                    "or an old switch.",
                    "Replace the patch cable; try another switch port.",
                    ["Replace the patch cable between the PC and the wall / switch.",
                     "Try another switch port.",
                     "Set the PC network card and the switch port both to Auto-negotiation.",
                     "Still 100 Mbps: the wall cable or its jack needs re-crimping / testing with a cable tester."])

    if "cpu" in low and ("router" in low or "high" in low):
        return _fix(2, "router_cpu", "The router's CPU is very busy",
                    "A busy router slows everyone down: often one device with heavy traffic, many firewall rules, "
                    "or an attack.",
                    "Find who loads it and turn on FastTrack.",
                    ["Live monitor: who uses the most bandwidth right now?",
                     "WinBox > Tools > Profile shows what uses the CPU.",
                     "Make sure FastTrack is on (IP > Firewall: 'fasttrack connection' rule)."],
                    auto=[("Show the router's CPU and load", "router_read", "/system resource print")])

    if "dns" in low and ("slow" in low or "fail" in low or "not answer" in low):
        return _fix(2, "dns", "Website names are slow / failing (DNS)",
                    "Every website starts with a DNS question; a slow or failing DNS server makes everything feel "
                    "slow.",
                    "Use a fast public DNS on the router.",
                    ["Press 'Use fast public DNS on the router'.",
                     "On this PC: ipconfig /flushdns."],
                    auto=[("Use fast public DNS on the router", "router",
                           "/ip dns set servers=1.1.1.1,8.8.8.8 allow-remote-requests=yes"),
                          ("Clear this PC's DNS cache", "pc", "ipconfig /flushdns")])

    if "new device" in low or "randomized" in low or "random mac" in low:
        return _fix(3, "new_device", "New device(s) joined the network",
                    "Phones with a 'private / randomized' MAC show as new devices every time, so their history and "
                    "names get lost.",
                    "Tag the device; ask phone users to turn off 'private address' for the office Wi-Fi.",
                    ["Open Inventory / Devices and tag the new device (name, department).",
                     "Unknown device? Block it (Devices > right-click > Commands > Block a device).",
                     "Phones: Wi-Fi > office network > Privacy / MAC address type > 'Phone MAC' (Android) or turn "
                     "off 'Private Wi-Fi Address' (iPhone).",
                     "To force it: Security > Network guard > block randomized MACs."],
                    app=("Open Inventory", "inventory"))

    prio = SEV_PRIO.get(sev, 3)
    return _fix(prio, "other", t[:80], "See the root-cause analysis for the details.",
                "Open Root cause for the most likely cause and its fix.",
                ["Press 'Open Root cause' below - Network Doctor checks everything and lists the most likely cause "
                 "first.",
                 "Follow the fix shown there; then press Re-check here."],
                app=("Open Root cause", "rca"))


def explain(text, sev="warning", lip="", gw=""):
    r = recipe(text, sev, lip, gw)
    r["prio_text"] = PRIO[r["prio"]]
    return r


class AlertLog:
    """alerts.json: time, level, priority, device, alert, fix, status (open / fixed)."""

    def __init__(self, path, keep=3000):
        self.path, self.keep = path, keep
        self.lock = threading.Lock()
        self.items = []
        try:
            with open(path, encoding="utf-8") as f:
                self.items = [x for x in json.load(f) if isinstance(x, dict)][-keep:]
        except Exception:
            self.items = []

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            tmp = self.path + ".tmp"
            with self.lock:
                data = list(self.items)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=0)
            os.replace(tmp, self.path)
        except Exception:
            pass

    def add(self, sev, text, source="", lip="", gw="", now=None):
        """Adds an alert (the same text within an hour only counts up). Returns the entry."""
        now = time.time() if now is None else now
        r = explain(text, sev, lip, gw)
        with self.lock:
            for x in reversed(self.items[-60:]):
                if x["text"] == text and now - x["last"] < 3600:
                    x["last"], x["count"] = now, x.get("count", 1) + 1
                    if x.get("status") == "fixed":
                        x["status"] = "open"
                    return x
            e = {"id": f"{int(now * 1000)}", "t": now, "last": now, "sev": sev, "text": text[:600],
                 "source": source, "prio": r["prio"], "kind": r["kind"], "title": r["title"][:160],
                 "fix": r["fix"][:300], "ip": _ip_of(text), "count": 1, "status": "open"}
            self.items.append(e)
            self.items = self.items[-self.keep:]
        return e

    def resolve(self, text_part, now=None):
        """A check found the problem gone: mark matching open alerts fixed."""
        now = time.time() if now is None else now
        n = 0
        with self.lock:
            for x in self.items:
                if x.get("status") == "open" and text_part and text_part in x["text"]:
                    x["status"], x["fixed_t"], x["fixed_by"] = "fixed", now, "found fixed by a check"
                    n += 1
        return n

    def set_status(self, ids, status, by="you"):
        with self.lock:
            for x in self.items:
                if x["id"] in ids:
                    x["status"] = status
                    x["fixed_t"] = time.time() if status == "fixed" else None
                    x["fixed_by"] = by if status == "fixed" else ""

    def get(self, aid):
        return next((x for x in self.items if x["id"] == aid), None)

    def recent(self, n=200, only_open=False):
        with self.lock:
            xs = [x for x in self.items if not only_open or x.get("status") == "open"]
        return xs[-n:][::-1]


def _ts(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if t else ""


def export_csv(path, items, names=None):
    names = names or {}
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["First seen", "Last seen", "Times", "Priority", "Level", "Device", "Alert", "What it means",
                    "Fix", "Steps", "Status", "Fixed at"])
        for x in items:
            r = explain(x["text"], x["sev"])
            w.writerow([_ts(x["t"]), _ts(x["last"]), x.get("count", 1), PRIO[x["prio"]], x["sev"],
                        names.get(x.get("ip"), "") + (f" ({x['ip']})" if x.get("ip") else ""), x["text"], r["why"],
                        r["fix"], " | ".join(f"{i}. {s}" for i, s in enumerate(r["steps"], 1)), x.get("status", ""),
                        _ts(x.get("fixed_t"))])


def export_html(path, items, names=None, title="Network Doctor - alerts"):
    names = names or {}
    colors = {1: "#b42318", 2: "#c4320a", 3: "#2a78d6", 4: "#667085"}
    rows = []
    for x in items:
        r = explain(x["text"], x["sev"])
        dev = names.get(x.get("ip"), "") + (f" ({x['ip']})" if x.get("ip") else "")
        steps = "".join(f"<li>{html.escape(s)}</li>" for s in r["steps"])
        rows.append(
            f"<tr><td>{_ts(x['t'])}<br><small>last {_ts(x['last'])} · {x.get('count', 1)}×</small></td>"
            f"<td><b style='color:{colors[x['prio']]}'>{PRIO[x['prio']]}</b></td><td>{html.escape(dev)}</td>"
            f"<td><b>{html.escape(r['title'])}</b><br><small>{html.escape(x['text'])}</small>"
            f"<p>{html.escape(r['why'])}</p></td><td><b>{html.escape(r['fix'])}</b><ol>{steps}</ol></td>"
            f"<td>{html.escape(x.get('status', ''))}<br><small>{_ts(x.get('fixed_t'))}</small></td></tr>")
    open_n = sum(1 for x in items if x.get("status") == "open")
    doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#101828}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #d0d5dd;padding:6px 8px;vertical-align:top;font-size:13px}}th{{background:#f2f4f7;text-align:left}}
ol{{margin:4px 0 0 18px;padding:0}}p{{margin:4px 0;color:#475467}}</style></head><body>
<h1>{html.escape(title)}</h1><p>{len(items)} alerts, {open_n} still open. Made {_ts(time.time())}.</p>
<table><tr><th>Time</th><th>Priority</th><th>Device</th><th>Alert</th><th>Fix and steps</th><th>Status</th></tr>
{''.join(rows)}</table></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
