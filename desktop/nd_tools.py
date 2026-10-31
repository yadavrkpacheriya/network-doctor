# -*- coding: utf-8 -*-
"""
Network Doctor - tools: device tags, network map, MikroTik discovery, IP-MAC binding,
PC fix script and the command library. Pure logic only (no window code) so it can be tested.
"""

import csv
import io
import os
import re
import socket
import struct
import time
import urllib.parse

import nd_core as core

# ==========================================================================
# tags (name, department, type, where it is connected)
# ==========================================================================
KINDS = ["", "Router", "Switch", "Access point", "PC", "Laptop", "Server", "Printer", "Camera", "DVR / NVR",
         "Phone", "Biometric", "IoT / TV", "Other"]
KIND_CAT = {"Router": core.CAT_NET, "Switch": core.CAT_NET, "Access point": core.CAT_NET, "PC": core.CAT_PC,
            "Laptop": core.CAT_PC, "Server": core.CAT_PC, "Printer": core.CAT_PRN, "Camera": core.CAT_CAM,
            "DVR / NVR": core.CAT_CAM, "Phone": core.CAT_PHONE, "Biometric": core.CAT_BIO, "IoT / TV": core.CAT_IOT,
            "Other": core.CAT_UNK}
GEAR_KINDS = {"Router", "Switch", "Access point"}
TAG_FIELDS = ["name", "dept", "location", "kind", "parent", "router_port", "switch_port", "notes", "watch"]
CSV_HEAD = ["MAC", "Name", "Department", "Location", "Type", "Connected to (MAC)", "Router port", "Switch port",
            "Notes", "Watch (alert if down)", "Current IP", "Vendor"]


def watch_value(v):
    """'yes' / '1' / 'true' -> '1' (watched), anything else -> '' (not watched). None stays None (unchanged)."""
    if v is None:
        return None
    return "1" if str(v).strip().lower() in ("1", "yes", "y", "true", "x", "watch", "critical") else ""


def watched(db):
    """{mac: tag} of the devices that must alert when they stop answering."""
    return {m: t for m, t in tags_of(db).items() if t.get("watch") == "1"}


def tags_of(db):
    with core.DB_LOCK:
        t = db.setdefault("tags", {})
        # one-time move of the old "labels" into tags
        for mac, name in list(db.get("labels", {}).items()):
            if name and not t.get(mac, {}).get("name"):
                t.setdefault(mac, {})["name"] = name
    return t


def set_tag(db, mac, **fields):
    """Updates the tag of one device. Empty strings clear a field; None leaves it unchanged."""
    if not mac:
        return
    with core.DB_LOCK:
        t = tags_of(db).setdefault(mac, {})
        for k, v in fields.items():
            if k in TAG_FIELDS and v is not None:
                v = str(v).strip()
                if v:
                    t[k] = v
                else:
                    t.pop(k, None)
        # the scan engine names devices from "labels": keep it in step with the tag name
        if t.get("name"):
            db.setdefault("labels", {})[mac] = t["name"]
        else:
            db.setdefault("labels", {}).pop(mac, None)
        if not t:
            tags_of(db).pop(mac, None)


# search words like "dept:accounts" look only in that field
FILTER_FIELDS = {"name": "name", "dept": "dept", "department": "dept", "loc": "location", "location": "location",
                 "type": "kind", "kind": "kind", "port": "port", "switch": "parent", "vendor": "vendor",
                 "ip": "ip", "mac": "mac", "notes": "notes"}
SHOW = ["All devices", "Online only", "Not tagged yet", "Watched (alert if down)"]


def _field_text(d, field):
    t = d.get("tag") or {}
    if field == "port":
        return f"{t.get('router_port', '')} {t.get('switch_port', '')}"
    if field == "ip":
        return " ".join(d.get("ips") or [d.get("ip", "")])
    if field in ("location", "parent", "notes"):
        return t.get(field, "") + (" " + " ".join(d.get("notes") or []) if field == "notes" else "")
    if field == "kind":
        return d.get("kind") or t.get("kind", "")
    return str(d.get(field) or "")


def tag_values(devices, field):
    """Sorted distinct values of one tag field (for the filter lists)."""
    vals = {(d.get("tag") or {}).get(field, "").strip() for d in devices}
    return sorted((v for v in vals if v), key=str.lower)


def filter_devices(devices, query="", dept="", location="", show=SHOW[0]):
    """Devices that match every search word (or field:value word), the department, location and show choice."""
    words = re.findall(r'(\w+):"([^"]*)"|(\w+):(\S+)|"([^"]*)"|(\S+)', (query or "").lower())
    out = []
    for d in devices:
        t = d.get("tag") or {}
        if dept and t.get("dept", "") != dept:
            continue
        if location and t.get("location", "") != location:
            continue
        if show == SHOW[1] and not d.get("online"):
            continue
        if show == SHOW[2] and any(t.get(k) for k in ("name", "dept", "location", "kind")):
            continue
        if show == SHOW[3] and not watch_value(t.get("watch")):
            continue
        everything = None
        ok = True
        for f1, v1, f2, v2, quoted, plain in words:
            field, value = (f1, v1) if f1 else (f2, v2) if f2 else ("", quoted or plain)
            if field and field in FILTER_FIELDS:
                hay = _field_text(d, FILTER_FIELDS[field]).lower()
            else:
                if field:  # an unknown "x:y" is searched as plain text
                    value = f"{field}:{value}"
                if everything is None:
                    everything = " ".join([d.get("name") or "", " ".join(d.get("ips") or []), d.get("mac") or "",
                                           d.get("vendor") or "", d.get("reason") or "", " ".join(d.get("notes") or []),
                                           d.get("dept") or "", " ".join(str(v) for v in t.values())]).lower()
                hay = everything
            if value not in hay:
                ok = False
                break
        if ok:
            out.append(d)
    return out


def is_gear(d, tags):
    t = tags.get(d.get("mac") or "", {})
    if t.get("kind"):
        return t["kind"] in GEAR_KINDS
    return d.get("category") in (core.CAT_NET, core.CAT_ROUTER)


def apply_tags(devices, db, neighbors=None):
    """Adds tag info to each device: name, department, type (category override)."""
    tags = tags_of(db)
    neighbors = neighbors or {}
    for d in devices:
        mac = d.get("mac") or ""
        t = tags.get(mac, {})
        nb = neighbors.get(mac)
        d["tag"] = dict(t)
        if nb and not t.get("name") and nb.get("identity") and (not d.get("name") or d.get("auto_name")):
            d["name"], d["auto_name"] = nb["identity"], False
        if t.get("name"):
            d["name"] = t["name"]
        d["dept"] = t.get("dept", "")
        kind = t.get("kind") or (guess_kind(nb) if nb else "")
        d["kind"] = kind
        if t.get("kind") and t["kind"] in KIND_CAT and d.get("category") not in (core.CAT_ROUTER, core.CAT_OFF):
            d["category"] = KIND_CAT[t["kind"]]
            d["reason"] = f"tagged as {t['kind']}"
        elif nb and d.get("category") in (core.CAT_UNK, core.CAT_NET, core.CAT_PC):
            if d.get("category") != core.CAT_ROUTER:
                d["category"] = core.CAT_NET
                d["reason"] = f"MikroTik {nb.get('board') or nb.get('platform') or ''} '{nb.get('identity', '')}' (neighbor discovery)"
    return devices


def tags_to_csv(devices, db):
    tags = tags_of(db)
    by_mac = {d.get("mac"): d for d in devices if d.get("mac")}
    macs = sorted(set(by_mac) | set(tags), key=lambda m: core.ip_key((by_mac.get(m) or {}).get("ip", "")))
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(CSV_HEAD)
    for mac in macs:
        t, d = tags.get(mac, {}), by_mac.get(mac, {})
        w.writerow([mac, t.get("name", ""), t.get("dept", ""), t.get("location", ""), t.get("kind", ""),
                    t.get("parent", ""), t.get("router_port", ""), t.get("switch_port", ""), t.get("notes", ""),
                    "yes" if t.get("watch") == "1" else "", d.get("ip", ""), d.get("vendor", "")])
    return out.getvalue()


def tags_from_csv(text, db):
    """Imports a tag sheet (as exported, edited in Excel). Returns (updated, skipped)."""
    rows = list(csv.reader(io.StringIO(text.lstrip("﻿"))))
    if not rows:
        return 0, 0
    head = [h.strip().lower() for h in rows[0]]

    def col(name):
        for i, h in enumerate(head):
            if h.startswith(name):
                return i
        return None
    idx = {"mac": col("mac"), "name": col("name"), "dept": col("department"), "location": col("location"),
           "kind": col("type"), "parent": col("connected"), "router_port": col("router port"),
           "switch_port": col("switch port"), "notes": col("notes"), "watch": col("watch")}
    if idx["mac"] is None:
        raise ValueError("the sheet needs a MAC column")
    done = skipped = 0
    for r in rows[1:]:
        if not any(x.strip() for x in r):
            continue
        mac = core.norm_mac(r[idx["mac"]] if idx["mac"] < len(r) else "")
        if not mac:
            skipped += 1
            continue
        f = {k: (r[i] if i is not None and i < len(r) else None) for k, i in idx.items() if k != "mac"}
        if f.get("kind") and f["kind"] not in KINDS:
            f["kind"] = next((k for k in KINDS if k and k.lower() == f["kind"].strip().lower()), "Other")
        if f.get("parent"):
            f["parent"] = core.norm_mac(f["parent"]) or ""
        if "watch" in f:
            f["watch"] = watch_value(f["watch"])
        set_tag(db, mac, **f)
        done += 1
    return done, skipped


# ==========================================================================
# MikroTik neighbor discovery (MNDP, UDP 5678) - switches / APs announce themselves
# ==========================================================================
MNDP_PORT = 5678
MNDP_TLV = {1: "mac", 5: "identity", 7: "version", 8: "platform", 10: "uptime", 11: "software_id", 12: "board",
            14: "unpack", 15: "ipv6", 16: "iface", 17: "ip"}


def parse_mndp(data):
    """Returns dict of the announcement or None."""
    if len(data) < 4:
        return None
    out, off = {}, 4
    while off + 4 <= len(data):
        t, ln = struct.unpack("!HH", data[off:off + 4])
        v = data[off + 4: off + 4 + ln]
        off += 4 + ln
        name = MNDP_TLV.get(t)
        if not name:
            continue
        if name == "mac" and len(v) == 6:
            out["mac"] = core.norm_mac(v)
        elif name == "ip" and len(v) == 4:
            out["ip"] = socket.inet_ntoa(v)
        elif name == "uptime" and len(v) == 4:
            out["uptime"] = struct.unpack("<I", v)[0]
        elif name in ("unpack", "ipv6"):
            continue
        else:
            out[name] = v.decode("utf-8", "replace").strip("\x00 ")
    return out if out.get("mac") else None


def guess_kind(nb):
    b = ((nb or {}).get("board") or "").lower()
    if not b:
        return ""
    if b.startswith(("crs", "css", "netpower", "netfiber")):
        return "Switch"
    if b.startswith(("cap", "wap", "audience", "ltap")):
        return "Access point"
    return "Router"


# ==========================================================================
# network map (Router -> router port -> switch / AP -> devices, grouped by department)
# ==========================================================================
def build_map(devices, db, gw_ip, problems=None, port_events=None):
    """Returns a tree of nodes: {"id","label","sub","kind","dev","children","bad","count"}.
    problems: {ip_or_mac: "critical"/"warning"}; port_events: {iface: n_downs}."""
    tags = tags_of(db)
    problems = problems or {}
    port_events = port_events or {}
    online = [d for d in devices if d.get("mac") or d.get("ip")]
    by_mac = {d["mac"]: d for d in online if d.get("mac")}
    router = next((d for d in online if d.get("ip") == gw_ip and d.get("online", True)), None)

    def sev_of(d):
        s = problems.get(d.get("ip") or "") or problems.get(d.get("mac") or "")
        return s

    def node(d):
        t = tags.get(d.get("mac") or "", {})
        sub = " | ".join(x for x in (d.get("ip", ""), t.get("dept", ""),
                                     f"port {t['switch_port']}" if t.get("switch_port") else "") if x)
        return {"id": d.get("mac") or d.get("ip"), "label": d.get("name") or d.get("ip") or "?", "sub": sub,
                "kind": "gear" if is_gear(d, tags) else ("off" if not d.get("online", True) else "dev"),
                "dev": d, "children": [], "bad": sev_of(d), "random": bool(d.get("random"))}

    root = {"id": "internet", "label": "Internet", "sub": "", "kind": "cloud", "dev": None, "children": [], "bad": None}
    rnode = node(router) if router else {"id": "router", "label": "Router", "sub": gw_ip or "", "kind": "gear",
                                         "dev": None, "children": [], "bad": None}
    rnode["kind"] = "router"
    if router and not router.get("name"):
        rnode["label"], rnode["sub"] = "Router", router.get("ip", "")
    root["children"].append(rnode)
    nodes = {d.get("mac") or d.get("ip"): node(d) for d in online if d is not router}
    ports = {}

    def port_node(name):
        if name not in ports:
            n = port_events.get(name, 0)
            ports[name] = {"id": "port:" + name, "label": name, "sub": f"went down {n}x" if n else "router port",
                           "kind": "port", "dev": None, "children": [], "bad": "warning" if n else None}
        return ports[name]
    unplaced = {"id": "unplaced", "label": "Not placed yet", "sub": "tag where they are connected", "kind": "group",
                "dev": None, "children": [], "bad": None}
    offline = {"id": "offline", "label": "Not online now", "sub": "seen before, not tagged", "kind": "group",
               "dev": None, "children": [], "bad": None}
    for key, n in nodes.items():
        d = n["dev"]
        t = tags.get(d.get("mac") or "", {})
        parent = t.get("parent")
        if parent and parent in nodes and parent != key:
            nodes[parent]["children"].append(n)
        elif parent and router and parent == router.get("mac"):
            (port_node(t["router_port"])["children"] if t.get("router_port") else rnode["children"]).append(n)
        elif t.get("router_port"):
            port_node(t["router_port"])["children"].append(n)
        elif not d.get("online", True):
            offline["children"].append(n)
        else:
            unplaced["children"].append(n)
    for name in port_events:
        port_node(name)
    rnode["children"] = sorted(ports.values(), key=lambda p: _natural(p["label"])) + rnode["children"]
    if unplaced["children"]:
        root["children"].append(unplaced)
    if offline["children"]:
        root["children"].append(offline)

    def finish(n):
        n["children"].sort(key=lambda c: (0 if c["kind"] in ("port", "gear") else 1, c.get("sub", "").split(" | ")[1:2],
                                          core.ip_key((c.get("dev") or {}).get("ip", ""))))
        worst = n.get("bad")
        cnt = 0
        for c in n["children"]:
            w, k = finish(c)
            cnt += k + (1 if c["kind"] in ("dev", "gear", "off") else 0)
            if w == "critical" or (w == "warning" and worst != "critical"):
                worst = worst if worst == "critical" else w
        n["child_bad"] = worst
        n["count"] = cnt
        return worst, cnt
    finish(root)
    return root


def _natural(s):
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", s)]


def map_path(root, target_id):
    """Ids from the root to the node (for highlighting the path a problem takes to the router)."""
    def walk(n, path):
        if n["id"] == target_id:
            return path + [n["id"]]
        for c in n["children"]:
            r = walk(c, path + [n["id"]])
            if r:
                return r
        return None
    return walk(root, []) or []


# ==========================================================================
# IP-MAC binding (MikroTik commands generated from the scan; the app never logs in to the router)
# ==========================================================================
def binding_candidates(devices, issues, gw_ip):
    """Devices that can be bound, with a reason when they should not be."""
    conflict_ips = {m.group(1) for i in issues or [] for m in [re.match(r"IP conflict on (\S+)", i["title"])] if m}
    out = []
    for d in devices:
        if not d.get("online") or not d.get("mac") or not d.get("ip") or d.get("ip") == gw_ip:
            continue
        why = ""
        if d.get("random"):
            why = "randomized MAC - turn off random addresses on this device first"
        elif d["ip"] in conflict_ips or d.get("conflict"):
            why = "IP conflict - fix the conflict first"
        elif len(d.get("ips") or []) > 1:
            why = "answers on several IPs"
        out.append({"dev": d, "ok": not why, "why": why})
    return out


def _q(s):
    return '"' + str(s).replace("\\", "").replace('"', "'")[:60] + '"'


def binding_commands(rows, tags, strict_arp=False, block_random=False, bridge="bridge", wan="ether1"):
    """rows: list of device dicts to bind. Returns (apply_text, undo_text)."""
    ts = time.strftime("%Y-%m-%d %H:%M")
    a = [f"# Network Doctor - IP / MAC binding ({len(rows)} devices) - generated {ts}",
         "# Paste in WinBox > New Terminal. Each device keeps 'automatic (DHCP)' and always gets the same IP.",
         "# A line that prints 'NOT BOUND' means the router already reserves that IP for another device.",
         "/ip dhcp-server lease"]
    u = [f"# Network Doctor - UNDO IP / MAC binding generated {ts}", "/ip dhcp-server lease"]
    for d in rows:
        t = tags.get(d["mac"], {})
        comment = _q("ND: " + " | ".join(x for x in (t.get("name") or d.get("name") or "", t.get("dept", "")) if x) or "ND")
        mac, ip = d["mac"], d["ip"]
        a.append(f':do {{remove [find where mac-address="{mac}"]}} on-error={{}}; '
                 f':do {{add address={ip} mac-address="{mac}" comment={comment}}} '
                 f'on-error={{:put "NOT BOUND (IP already reserved for another device): {ip} {mac}"}}')
        u.append(f':do {{remove [find where mac-address="{mac}" and comment~"^ND"]}} on-error={{}}')
    if strict_arp:
        a += ["", "# Strict mode: only devices with an IP from the router (or listed below) can talk to it.",
              "# Somebody typing an IP by hand can no longer steal / clash with another device's IP.",
              "/ip dhcp-server set [find] add-arp=yes", "/ip arp"]
        u += ["", f"/interface bridge set [find name={bridge}] arp=enabled", "/ip dhcp-server set [find] add-arp=no",
              "/ip arp"]
        for d in rows:
            a.append(f':do {{remove [find where address={d["ip"]} and dynamic]}} on-error={{}}; '
                     f':do {{add address={d["ip"]} mac-address="{d["mac"]}" interface={bridge} comment="ND binding"}} '
                     f'on-error={{}}')
        u.append(':do {remove [find where comment="ND binding"]} on-error={}')
        a += [f"/interface bridge set [find name={bridge}] arp=reply-only"]
    if block_random:
        a += ["", "# Block devices that use a randomized (private) MAC. Phones must use 'device MAC' for this Wi-Fi.",
              "/interface bridge filter",
              ':do {remove [find where comment="ND: block random MAC"]} on-error={}',
              "add chain=input src-mac-address=02:00:00:00:00:00/02:00:00:00:00:00 action=drop "
              'comment="ND: block random MAC"',
              "add chain=forward src-mac-address=02:00:00:00:00:00/02:00:00:00:00:00 action=drop "
              'comment="ND: block random MAC"']
        u += ["", "/interface bridge filter", ':do {remove [find where comment="ND: block random MAC"]} on-error={}']
    return "\n".join(a) + "\n", "\n".join(u) + "\n"


# ==========================================================================
# Network guard: rogue DHCP / DNS routers, DNS forced through the router, randomized MACs (MikroTik)
# ==========================================================================
def rogue_candidates(devices, raw, gw_ip):
    """Devices that act like a second router: answer DHCP, run DNS (port 53) or announce an internet gateway."""
    t = ((raw or {}).get("meta") or {}).get("tests") or {}
    dhcp_ips = {s for s in (t.get("dhcp") or {}) if s != gw_ip}
    out = []
    for d in devices:
        if not d.get("online") or d.get("ip") == gw_ip or d.get("self") or not d.get("mac"):
            continue
        why = []
        if d.get("ip") in dhcp_ips:
            why.append("gives out IP addresses (DHCP server)")
        if 53 in (d.get("ports") or []):
            why.append("answers DNS (port 53)")
        if "internetgatewaydevice" in " ".join((d.get("upnp") or {}).get("st", [])).lower():
            why.append("announces itself as an internet router (UPnP)")
        if why:
            out.append({"dev": d, "why": ", ".join(why)})
    return out


TORRENT_SITES = ["thepiratebay", "1337x", "1377x", "yts", "yify", "rarbg", "torrentz2", "limetorrents", "torlock",
                 "torrentgalaxy", "eztv", "nyaa", "kickass", "kickasstorrents", "zooqle", "magnetdl", "torrentdownloads",
                 "tamilrockers", "tamilblasters", "movierulz", "filmyzilla", "filmywap", "9xmovies", "bolly4u",
                 "khatrimaza", "worldfree4u", "skymovieshd", "vegamovies", "katmoviehd", "mkvcinemas", "ibomma",
                 "isaimini", "moviesda", "tamilyogi", "fitgirl-repacks", "skidrowreloaded", "igg-games",
                 "utorrent", "bittorrent", "qbittorrent", "tixati", "vuze", "bitcomet", "frostwire"]


DOH_SERVERS = ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222",
               "208.67.220.220", "94.140.14.14", "94.140.15.15", "185.228.168.9", "76.76.2.0")


def guard_commands(opts, rogue_macs=(), lip="", bridge="bridge"):
    """opts: dhcp, dns, dns_target ("router" / "pc"), rogue, random. Returns (apply_text, undo_text)."""
    ts = time.strftime("%Y-%m-%d %H:%M")
    a = [f"# Network Doctor - network guard - generated {ts}",
         "# Paste in WinBox > New Terminal, or Apply on router. Safe to run again: old ND rules are replaced."]
    u = [f"# Network Doctor - UNDO network guard - generated {ts}"]
    clean_bf = ':do {/interface bridge filter remove [find where comment~"^ND guard"]} on-error={}'
    a.append(clean_bf)
    u.append(clean_bf)
    if opts.get("dhcp"):
        a += ["# 1) Only the router may give out IP addresses: DHCP answers from any other device (a second Wi-Fi",
              "#    router plugged in by its LAN port) are dropped when they pass the router's bridge.",
              f'/interface bridge filter add chain=forward mac-protocol=ip ip-protocol=udp src-port=67 dst-port=68 '
              f'action=drop comment="ND guard: rogue DHCP"',
              "#    Bridge filters need the traffic to go through the router CPU: with hardware offload on a switch",
              "#    chip, set the second router to access-point mode or unplug it (the scan shows where it is)."]
    for mac in rogue_macs:
        a.append(f'/interface bridge filter add chain=forward src-mac-address={mac}/FF:FF:FF:FF:FF:FF mac-protocol=ip '
                 f'ip-protocol=udp src-port=67 action=drop comment="ND guard: rogue router {mac} DHCP"')
        a.append(f'/interface bridge filter add chain=forward dst-mac-address={mac}/FF:FF:FF:FF:FF:FF mac-protocol=ip '
                 f'ip-protocol=udp dst-port=53 action=drop comment="ND guard: rogue router {mac} DNS"')
        a.append(f'/interface bridge filter add chain=forward dst-mac-address={mac}/FF:FF:FF:FF:FF:FF mac-protocol=ip '
                 f'ip-protocol=tcp dst-port=53 action=drop comment="ND guard: rogue router {mac} DNS"')
    clean_nat = ':do {/ip firewall nat remove [find where comment~"^ND guard"]} on-error={}'
    a.append(clean_nat)
    u.append(clean_nat)
    if opts.get("dns"):
        to_pc = opts.get("dns_target") == "pc" and lip
        a += ["# 2) Every DNS question from the office goes to " + ("Network Doctor's website firewall on " + lip
              if to_pc else "the router") + ", whatever DNS a device or a",
              "#    second router set - so nobody bypasses the office DNS and wrong DNS servers stop breaking internet."]
        if not to_pc:
            a.append("/ip dns set allow-remote-requests=yes")
        for proto in ("udp", "tcp"):
            if to_pc:
                a.append(f'/ip firewall nat add chain=dstnat in-interface={bridge} src-address=!{lip} protocol={proto} '
                         f'dst-port=53 action=dst-nat to-addresses={lip} to-ports=53 comment="ND guard: DNS to PC"')
            else:
                a.append(f'/ip firewall nat add chain=dstnat in-interface={bridge} protocol={proto} dst-port=53 '
                         f'action=redirect to-ports=53 comment="ND guard: DNS to router"')
        a.append(':do {/ip firewall filter remove [find where comment~"^ND guard"]} on-error={}')
        a.append('/ip firewall filter add chain=input in-interface=!' + bridge + ' protocol=udp dst-port=53 '
                 'action=drop comment="ND guard: no DNS from internet"')
        # browsers' "secure DNS" (DNS over HTTPS / TLS) to Google / Cloudflare / Quad9 / OpenDNS skips the office
        # DNS, so nobody can see which website was opened. Blocking it makes them fall back to normal DNS by themselves.
        a.append('/ip firewall address-list remove [find where list="ND-doh"]')
        for ip in DOH_SERVERS:
            a.append(f'/ip firewall address-list add list=ND-doh address={ip} comment="ND guard: secure DNS server"')
        for proto in ("tcp", "udp"):
            rule = (f'chain=forward protocol={proto} dst-port=443,853 dst-address-list=ND-doh action=reject '
                    f'comment="ND guard: no secure DNS bypass"')
            a.append(f':do {{ /ip firewall filter add {rule} place-before=([/ip firewall filter find]->0) }} '
                     f'on-error={{ /ip firewall filter add {rule} }}')
        u.append(':do {/ip firewall filter remove [find where comment~"^ND guard"]} on-error={}')
        u.append('/ip firewall address-list remove [find where list="ND-doh"]')
    if opts.get("torrent"):
        a += ["# 4) Block torrents (BitTorrent): torrent ports, the torrent handshake / DHT / tracker signatures and",
              "#    torrent websites. Put at the TOP of the forward chain, before FastTrack, or they never see the traffic.",
              ':do {/ip firewall filter remove [find where comment~"^ND guard: torrent"]} on-error={}']
        rules = [
            "protocol=tcp dst-port=6881-6999,51413 action=drop",
            "protocol=udp dst-port=6881-6999,51413 action=drop",
            'protocol=tcp content="BitTorrent protocol" action=drop',
            'protocol=udp content="d1:ad2:id20:" action=drop',
            'protocol=tcp content="info_hash=" action=drop',
            'protocol=udp content="BitTorrent protocol" action=drop',
        ]
        for r in reversed(rules):  # each one goes to the very top, so add them in reverse order
            a.append(f':do {{/ip firewall filter add chain=forward {r} comment="ND guard: torrent" '
                     f'place-before=([/ip firewall filter find]->0)}} '
                     f'on-error={{/ip firewall filter add chain=forward {r} comment="ND guard: torrent"}}')
        sites = "|".join(re.escape(x) for x in TORRENT_SITES)
        a += [':do {/ip dns static remove [find where comment~"^ND guard: torrent"]} on-error={}',
              f'/ip dns static add regexp="(^|\\\\.)({sites})\\\\.[a-z.]+\\$" address=127.0.0.1 '
              'comment="ND guard: torrent sites"',
              "#    Torrent websites are blocked for devices that use the router's DNS - tick 'All DNS through the "
              "router' too."]
        u += [':do {/ip dns static remove [find where comment~"^ND guard: torrent"]} on-error={}']
    if opts.get("random"):
        a += ["# 3) Devices with a randomized (private) MAC get no network: every phone / laptop must use its real",
              "#    MAC on the office Wi-Fi, so its history and reservations stay with one device.",
              "/interface bridge filter add chain=input src-mac-address=02:00:00:00:00:00/02:00:00:00:00:00 "
              'action=drop comment="ND guard: random MAC"',
              "/interface bridge filter add chain=forward src-mac-address=02:00:00:00:00:00/02:00:00:00:00:00 "
              'action=drop comment="ND guard: random MAC"']
    fclean = ':do {/ip firewall filter remove [find where comment~"^ND guard"]} on-error={}'
    if fclean not in u:
        u.append(fclean)
    return "\n".join(a) + "\n", "\n".join(u) + "\n"


RSC_HOWTO = ("Saved {file} (and {undo}).\n\nA .rsc file does nothing when double-clicked on the PC - the ROUTER "
             "runs it:\n1. WinBox > Files: drag {file} into the list.\n2. WinBox > New Terminal, type:\n"
             "   /import file-name={file} verbose=yes\n   (verbose shows each line, and the line that fails).\n\n"
             "Easier: save a router login in Setup and press 'Apply on router'.")


def write_rsc(path, apply_text, undo_text):
    """Writes a RouterOS script the router can /import: plain ASCII, short name, progress messages, and the undo in a
    separate file. Returns the file name."""
    folder, name = os.path.split(path)
    base = re.sub(r"[^A-Za-z0-9_.-]", "-", os.path.splitext(name)[0]) or "netdoctor"
    name = base + ".rsc"

    def body(text, what):
        lines = [":put \"Network Doctor: " + what + " - start\""]
        lines += [ln for ln in text.splitlines() if ln.strip()]
        lines.append(":put \"Network Doctor: " + what + " - done\"")
        return "\n".join(lines) + "\n"
    for fname, text, what in ((name, apply_text, "apply"), (base + "-undo.rsc", undo_text, "undo")):
        with open(os.path.join(folder, fname), "w", encoding="ascii", errors="replace", newline="\n") as f:
            f.write(body(text, what))
    return name


HW_FIELDS = (("maker", "Maker"), ("model", "Model"), ("serial", "Serial no."), ("cpu", "CPU"), ("ram_gb", "RAM GB"),
             ("ram_detail", "RAM sticks"), ("disks", "Disks (SSD / HDD)"), ("disk_gb", "Disk C: GB"),
             ("disk_free_gb", "Free GB"), ("gpu", "Graphics"), ("monitors", "Monitors"), ("keyboards", "Keyboard"),
             ("mice", "Mouse"), ("printers", "Printers"), ("antivirus", "Antivirus"), ("firewall", "Windows Firewall"),
             ("driver_problems", "Driver problems"), ("os_name", "Windows"), ("os_build", "Windows build"),
             ("last_update", "Last Windows update"), ("bios", "BIOS"), ("domain", "Domain / workgroup"),
             ("logged_on", "Logged-on user"), ("last_boot", "Last start"), ("software_count", "Programs installed"),
             ("software", "Programs"))
HW_LONG = {"software": 14000, "driver_problems": 1500, "printers": 800, "disks": 600, "monitors": 400}


def clean_hw(hw):
    """Hardware details reported by the PC script, as short strings (WMI dates made readable)."""
    if not isinstance(hw, dict):
        return {}
    out = {}
    for k, _ in HW_FIELDS + (("installed", ""), ("os_version", "")):
        v = hw.get(k)
        if v is None or v == "":
            continue
        v = str(v).strip()[:HW_LONG.get(k, 200)]
        m = re.match(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})", v) if k in ("installed", "last_boot") else None
        if m:
            v = f"{m.group(1)}-{m.group(2)}-{m.group(3)} {m.group(4)}:{m.group(5)}"
        m = re.match(r"^/Date\((\d+)\)/$", v)
        if m:
            v = time.strftime("%Y-%m-%d %H:%M", time.localtime(int(m.group(1)) / 1000))
        out[k] = v
    return out


INV_COLS = (("name", "Name", 150), ("ip", "IP", 110), ("mac", "MAC", 135), ("vendor", "Maker", 130),
            ("category", "Type", 120), ("host", "Host name", 130), ("dept", "Department", 110),
            ("location", "Location", 110), ("status", "Status", 120), ("first_seen", "First seen", 115),
            ("os", "Windows", 150), ("model", "Model", 140), ("serial", "Serial no.", 110), ("cpu", "CPU", 180),
            ("ram_gb", "RAM GB", 60), ("disk_gb", "Disk GB", 60), ("disk_free_gb", "Free GB", 60),
            ("user", "User", 130), ("disks", "Disks", 170), ("antivirus", "Antivirus", 160),
            ("printers", "Printers", 160), ("flag_text", "Needs attention", 200), ("router_port", "Router port", 80),
            ("notes", "Notes", 200))


def inventory_rows(devices, db, leases=None):
    """One row per device ever seen (by MAC), merging the scan, history, tags, the router's DHCP leases
    (host names) and the hardware the PC script reported."""
    tags = tags_of(db)
    with core.DB_LOCK:
        hist = dict(db.get("devices") or {})
        reports = dict(db.get("pc_reports") or {})
    by_mac_report = {}
    for host, r in reports.items():
        for mac in r.get("macs") or []:
            by_mac_report[mac] = (host, r)
    lease_by_mac = {core.norm_mac(x.get("mac-address", "")): x for x in (leases or []) if x.get("mac-address")}
    rows, seen = [], set()
    for d in devices:
        mac = d.get("mac") or ""
        key = mac or ("IP-" + d.get("ip", ""))
        if key in seen:
            continue
        seen.add(key)
        rows.append(_inv_row(mac, d, hist.get(mac), tags.get(mac, {}), by_mac_report.get(mac), lease_by_mac.get(mac)))
    for mac, h in hist.items():
        if mac not in seen:
            seen.add(mac)
            rows.append(_inv_row(mac, None, h, tags.get(mac, {}), by_mac_report.get(mac), lease_by_mac.get(mac)))
    for mac, ls in lease_by_mac.items():  # known to the router only (never answered a scan)
        if mac and mac not in seen:
            seen.add(mac)
            rows.append(_inv_row(mac, None, None, tags.get(mac, {}), by_mac_report.get(mac), ls))
    rows.sort(key=lambda r: (r["status"] != "online", core.ip_key(r["ip"] or "255.255.255.255")))
    return rows


def _inv_row(mac, d, h, t, rep, lease):
    d, h, t = d or {}, h or {}, t or {}
    host, r = rep or ("", {})
    hw = (r or {}).get("hw") or {}
    online = bool(d.get("online"))
    status = "online" if online else (f"last seen {h['last_seen']}" if h.get("last_seen") else
                                      "router lease" if lease else "")
    row = {"mac": mac, "name": t.get("name") or d.get("name") or host or (lease or {}).get("host-name", "") or
           ((h.get("names") or [""])[-1]),
           "ip": d.get("ip") or (lease or {}).get("address") or h.get("ip", ""),
           "vendor": d.get("vendor") or h.get("vendor", ""), "category": d.get("category") or h.get("category", ""),
           "host": (lease or {}).get("host-name") or host or (d.get("names") or {}).get("netbios", ""),
           "dept": t.get("dept", ""), "location": t.get("location", ""), "status": status,
           "first_seen": d.get("first_seen") or h.get("first_seen", ""), "os": (r or {}).get("os", "") or d.get("os", ""),
           "user": hw.get("logged_on") or (r or {}).get("user", ""), "router_port": t.get("router_port", ""),
           "notes": t.get("notes", ""), "online": online, "random": core.is_random_mac(mac) if mac else False,
           "report_time": (r or {}).get("time", "")}
    for k, _ in HW_FIELDS:
        if not row.get(k):
            row[k] = hw.get(k, "")
    for k in ("model", "serial", "cpu", "ram_gb", "disk_gb", "disk_free_gb"):
        row[k] = hw.get(k, "")
    if not row.get("vendor") and hw.get("maker"):
        row["vendor"] = hw.get("maker")
    row["flags"] = inv_flags(row)
    row["flag_text"] = ", ".join(row["flags"])
    return row


def _num(v):
    try:
        return float(str(v).split()[0])
    except (ValueError, IndexError):
        return None


def inv_flags(r):
    """Things an IT engineer should look at on this PC (only from what the PC reported)."""
    out = []
    if r.get("driver_problems"):
        out.append("driver problem")
    ram = _num(r.get("ram_gb"))
    if ram is not None and 0 < ram <= 4.5:
        out.append("low RAM")
    disks = str(r.get("disks") or "")
    if disks and "HDD" in disks and "SSD" not in disks:
        out.append("HDD (no SSD)")
    free, size = _num(r.get("disk_free_gb")), _num(r.get("disk_gb"))
    if free is not None and size and (free < 15 or free / size < 0.1):
        out.append("disk almost full")
    av = str(r.get("antivirus") or "")
    if r.get("model") and (not av or "OFF" in av or "OUT OF DATE" in av):
        out.append("antivirus off / old" if av else "no antivirus")
    fw = str(r.get("firewall") or "")
    if "off" in fw.lower():
        out.append("firewall off")
    lu = str(r.get("last_update") or "")[:10]
    try:
        if lu and time.time() - time.mktime(time.strptime(lu, "%Y-%m-%d")) > 60 * 86400:
            out.append("no Windows update for 60+ days")
    except ValueError:
        pass
    return out


INV_FILTERS = {"Needs attention (any)": lambda r: bool(r.get("flags")),
               "Driver problems": lambda r: "driver problem" in r.get("flags", []),
               "Low RAM (4 GB or less)": lambda r: "low RAM" in r.get("flags", []),
               "HDD, no SSD": lambda r: "HDD (no SSD)" in r.get("flags", []),
               "Disk almost full": lambda r: "disk almost full" in r.get("flags", []),
               "Antivirus off / out of date": lambda r: any(f.startswith(("antivirus", "no antivirus"))
                                                             for f in r.get("flags", [])),
               "Windows not updated 60+ days": lambda r: any("Windows update" in f for f in r.get("flags", [])),
               "Printers": lambda r: "rinter" in str(r.get("category", ""))}


def driver_page(maker, serial, model=""):
    """The maker's driver download page for this PC (Dell / Lenovo / HP use the serial number)."""
    m = (maker or "").lower()
    s = urllib.parse.quote((serial or "").strip())
    if "dell" in m:
        return (f"https://www.dell.com/support/home/en-in/product-support/servicetag/{s}/drivers" if s else
                "https://www.dell.com/support/home/en-in?app=drivers")
    if "lenovo" in m:
        return f"https://pcsupport.lenovo.com/in/en/search?query={s}" if s else "https://pcsupport.lenovo.com/in/en/"
    if "hp" in m or "hewlett" in m:
        return "https://support.hp.com/in-en/drivers"
    if "asus" in m:
        return "https://www.asus.com/in/support/download-center/"
    if "acer" in m:
        return f"https://www.acer.com/in-en/support/drivers-and-manuals?search={s}"
    if "msi" in m or "micro-star" in m:
        return "https://www.msi.com/support/download"
    if "gigabyte" in m:
        return "https://www.gigabyte.com/Support"
    q = urllib.parse.quote(f"{maker} {model} drivers".strip())
    return f"https://www.bing.com/search?q={q}"


def export_inventory_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow([c[1] for c in INV_COLS] + ["PC report time"])
        for r in rows:
            w.writerow([r.get(c[0], "") for c in INV_COLS] + [r.get("report_time", "")])


REPORT_TITLES = re.compile(r"^(Half-duplex cable link|PC cable runs at 100 Mbps|Cable errors on) ")


def report_issues(db):
    """Problems the PC fix script found on office PCs: cables at 100 Mbps, half duplex, cable errors."""
    slow, half, errs = [], [], []
    for host, r in sorted((db.get("pc_reports") or {}).items()):
        for a in r.get("links") or []:
            nm = f"{host} ({r.get('ip', '')}) {a.get('name', '')}"
            if a.get("duplex") is False:
                half.append(f"{nm}: half duplex at {a.get('speed', '?')}")
            elif 0 < int(a.get("bps") or 0) <= 100_000_000:
                slow.append(f"{nm}: {a.get('speed', '?')}")
            if int(a.get("errors") or 0) > 50:
                errs.append(f"{nm}: {int(a['errors']):,} receive errors")
    out = []
    if half:
        out.append({"sev": "critical", "title": f"Half-duplex cable link on {len(half)} PC(s)", "items": half,
                    "detail": "The PC and the switch port disagree on speed / duplex. That gives collisions, slow file "
                              "copies and dropped ERP sessions.",
                    "fix": "Set the PC adapter and the switch port both to Auto-negotiation; replace the patch cable."})
    if slow:
        out.append({"sev": "warning", "title": f"PC cable runs at 100 Mbps instead of 1 Gbps on {len(slow)} PC(s)",
                    "items": slow,
                    "detail": "Gigabit needs all 8 wires. 100 Mbps usually means a damaged / badly crimped cable, a "
                              "dirty port or an old 100 Mbps switch on the way.",
                    "fix": "Replace the patch cable, try another switch port, or replace the old switch."})
    if errs:
        out.append({"sev": "warning", "title": f"Cable errors on {len(errs)} PC(s)", "items": errs,
                    "detail": "The network card receives damaged packets: a bad cable, connector or switch port, or "
                              "electrical noise from motors / VFD panels near the cable.",
                    "fix": "Replace the cable / connector, keep data cables away from power cables."})
    return out


def binding_issues(devices, db):
    """Problems with devices that were bound: on another IP, or their reserved IP used by somebody else."""
    with core.DB_LOCK:
        binds = dict(db.get("bindings", {}))
    tags = tags_of(db)
    out = []
    by_ip = {}
    for d in devices:
        if d.get("online"):
            for ip in d.get("ips") or [d.get("ip")]:
                by_ip.setdefault(ip, []).append(d)
    for mac, b in binds.items():
        me = next((d for d in devices if d.get("mac") == mac and d.get("online")), None)
        name = tags.get(mac, {}).get("name") or (me or {}).get("name") or mac
        if me and me.get("ip") != b["ip"] and b["ip"] not in (me.get("ips") or []):
            out.append({"sev": "warning", "title": f"Bound device {name} is on {me['ip']} instead of {b['ip']}",
                        "detail": "Its IP was reserved on the router, but the device uses another address. Either the "
                                  "binding commands were not pasted (or were pasted on another router), or the device "
                                  "has a hand-typed IP, or it has not renewed its IP since.",
                        "fix": f"Keep {b['ip']}: IP-MAC binding tab > tick it > Make router commands (they keep "
                               f"{b['ip']}) > paste in WinBox, then set the device to automatic (DHCP) and renew its "
                               f"IP ('ipconfig /renew', or unplug / re-plug it). Want {me['ip']} instead: tick "
                               "'Moved devices: bind their NEW IP' before Make router commands. Not needed any more: "
                               "select it and 'Forget binding of selected'.",
                        "items": [f"{name} / {mac}: reserved {b['ip']}, now {me['ip']}"]})
        for other in by_ip.get(b["ip"], []):
            if other.get("mac") and other["mac"] != mac:
                out.append({"sev": "critical", "title": f"Reserved IP {b['ip']} is used by another device (IP conflict risk)",
                            "detail": f"{b['ip']} is reserved for {name}, but {other.get('name') or other['mac']} is "
                                      "using it - usually a hand-typed IP.",
                            "fix": "Set that device to automatic (DHCP) or give it a free IP. Strict mode in the "
                                   "IP-MAC binding tab stops this from happening again.",
                            "items": [f"{b['ip']} reserved for {name} ({mac}), used by "
                                      f"{other.get('name') or '?'} ({other['mac']})"]})
    return out


# ==========================================================================
# PC fix script (run once on every office PC: double-click or from a shared folder / login script)
# ==========================================================================
PS_HEADER_LINES = 7  # lines of the .cmd launcher before the PowerShell part


def _cmd_launcher(title):
    lines = ["@echo off",
             f"title {title}",
             'set "NDFILE=%~f0"',
             "powershell -NoProfile -ExecutionPolicy Bypass -Command \"(Get-Content -LiteralPath $env:NDFILE | "
             f"Select-Object -Skip {PS_HEADER_LINES}) -join [Environment]::NewLine | Invoke-Expression\"",
             "echo.",
             "pause",
             "exit /b"]
    assert len(lines) == PS_HEADER_LINES
    return "\r\n".join(lines) + "\r\n"


PS_ELEVATE = r"""
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Asking for administrator rights - click Yes..." -ForegroundColor Yellow
    Start-Process -FilePath $env:ComSpec -ArgumentList '/c', ('"' + $env:NDFILE + '"') -Verb RunAs
    exit
}
"""



# ---- PC details for the Network Doctor inventory (read only, changes nothing)
HW_PS = r"""
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $osi = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
    $mem = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue)
    $ramDetail = ($mem | ForEach-Object { "$([math]::Round($_.Capacity / 1GB)) GB $($_.Speed) MHz" }) -join ', '
    $disks = (@(Get-PhysicalDisk -ErrorAction SilentlyContinue) | ForEach-Object { "$($_.FriendlyName) ($($_.MediaType), $([math]::Round($_.Size / 1GB)) GB)" }) -join '; '
    $gpu = (@(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue) | ForEach-Object { $_.Name }) -join '; '
    $mons = (@(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue) | ForEach-Object { ((($_.ManufacturerName | Where-Object { $_ -ne 0 }) | ForEach-Object { [char]$_ }) -join '') + ' ' + ((($_.UserFriendlyName | Where-Object { $_ -ne 0 }) | ForEach-Object { [char]$_ }) -join '') }) -join '; '
    $kbd = (@(Get-CimInstance Win32_Keyboard -ErrorAction SilentlyContinue) | ForEach-Object { $_.Description } | Select-Object -Unique) -join '; '
    $mouse = (@(Get-CimInstance Win32_PointingDevice -ErrorAction SilentlyContinue) | ForEach-Object { $_.Name } | Select-Object -Unique) -join '; '
    $prn = (@(Get-CimInstance Win32_Printer -ErrorAction SilentlyContinue) | Where-Object { $_.Name -notmatch 'PDF|XPS|OneNote|Fax' } | ForEach-Object { $_.Name + $(if ($_.Default) { ' (default)' } else { '' }) }) -join '; '
    $av = (@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue) | ForEach-Object { $st = '{0:X6}' -f $_.productState; $_.displayName + ' (' + $(if ($st.Substring(2,2) -in '10','11') { 'on' } else { 'OFF' }) + ', ' + $(if ($st.Substring(4,2) -eq '00') { 'up to date' } else { 'OUT OF DATE' }) + ')' }) -join '; '
    $fw = (@(Get-NetFirewallProfile -ErrorAction SilentlyContinue) | ForEach-Object { $_.Name + ' ' + $(if ($_.Enabled) { 'on' } else { 'OFF' }) }) -join ', '
    $drv = (@(Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.ConfigManagerErrorCode -ne 0 }) | Select-Object -First 15 | ForEach-Object { "$($_.Name) (code $($_.ConfigManagerErrorCode))" }) -join '; '
    $hot = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Select-Object -First 1
    $sw = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and -not $_.SystemComponent } | ForEach-Object { [string]$_.DisplayName } | Sort-Object -Unique)
    $hw = @{ maker = [string]$cs.Manufacturer; model = [string]$cs.Model; serial = [string]$bios.SerialNumber;
             cpu = [string]$cpu.Name; ram_gb = [math]::Round(([double]$cs.TotalPhysicalMemory) / 1GB, 1);
             disk_gb = [math]::Round(([double]$disk.Size) / 1GB); disk_free_gb = [math]::Round(([double]$disk.FreeSpace) / 1GB);
             os_build = [string]$osi.BuildNumber; os_version = [string]$osi.Version; os_name = [string]$osi.Caption;
             installed = [string]$osi.InstallDate; last_boot = [string]$osi.LastBootUpTime;
             domain = [string]$cs.Domain; logged_on = [string]$cs.UserName;
             ram_detail = $ramDetail; disks = $disks; gpu = $gpu; monitors = $mons; keyboards = $kbd; mice = $mouse;
             printers = $prn; antivirus = $av; firewall = $fw; driver_problems = $drv;
             bios = [string]$bios.SMBIOSBIOSVersion; last_update = $(if ($hot) { [string]$hot.InstalledOn } else { '' });
             software_count = $sw.Count; software = (($sw | Select-Object -First 400) -join '|') }
"""


def local_inventory_cmd():
    """PowerShell that prints this PC's details as JSON (the Network Doctor PC lists itself without a script)."""
    return ["powershell", "-NoProfile", "-NonInteractive", "-Command",
            HW_PS + "\n$hw | ConvertTo-Json -Compress"]


# ---- the PC's network adapters (for the PC report)
ADS_PS = r"""$ads = foreach ($a in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue)) {
    [pscustomobject]@{ name = $a.Name; desc = $a.InterfaceDescription; mac = $a.MacAddress; permanent = $a.PermanentAddress;
        status = [string]$a.Status; wifi = [bool]($a.MediaType -match '802\\.11');
        speed = [string]$a.LinkSpeed; bps = [int64]$a.ReceiveLinkSpeed; duplex = $a.FullDuplex;
        errors = [int64]((Get-NetAdapterStatistics -Name $a.Name -ErrorAction SilentlyContinue).ReceivedPacketErrors);
        ip = ((Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress -join ',');
        dhcp = [string](Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp }
}
"""


def reporter_ps(url, key):
    """The small daily report a PC sends after the script installed it (inventory only, changes nothing)."""
    return ("$ErrorActionPreference = 'SilentlyContinue'\n" + f"$URL = '{url}'; $KEY = '{key}'\n" + ADS_PS + HW_PS +
            "\n$body = @{ hostname = $env:COMPUTERNAME; user = [string]$cs.UserName; os = $osi.Caption; hw = $hw;"
            " adapters = @($ads); actions = @('daily inventory report') } | ConvertTo-Json -Depth 4\n"
            "Invoke-RestMethod -Uri $URL -Method Post -Body $body -ContentType 'application/json' "
            "-Headers @{ 'X-ND-Report' = $KEY } -TimeoutSec 15 | Out-Null\n")


def pc_fix_script(opts, gw, gw_mac, report_url, report_key):
    """opts: random_off, renew, lock_gw, report (booleans); to_dhcp: "ask" / "yes" / "no".
    Use to_dhcp "yes" or "no" when the script runs unattended (login script), "ask" when a person runs it.
    Returns (fix_cmd, undo_cmd)."""
    b = lambda k: "$true" if opts.get(k) else "$false"
    to_dhcp = opts.get("to_dhcp") if opts.get("to_dhcp") in ("ask", "yes", "no") else ("ask" if opts.get("to_dhcp") else "no")
    gw_dash = (gw_mac or "").replace(":", "-").lower()
    ps = f"""
$ErrorActionPreference = 'Continue'
$opt = @{{ RandomOff = {b('random_off')}; ToDhcp = '{to_dhcp}'; Renew = {b('renew')}; LockGw = {b('lock_gw')}; Report = {b('report')}; Daily = {b('daily')} }}
$GW = '{gw or ''}'; $GWMAC = '{gw_dash}'
$URL = '{report_url}'; $KEY = '{report_key}'
$REPORTER = @'
{reporter_ps(report_url, report_key)}
'@
{PS_ELEVATE}
Write-Host "Network Doctor - PC network fix on $env:COMPUTERNAME" -ForegroundColor Cyan
$done = New-Object System.Collections.ArrayList
$cls = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}'

if ($opt.RandomOff) {{
    Write-Host "1. Turning off random (private) MAC addresses for Wi-Fi..."
    foreach ($a in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object {{ $_.MediaType -match '802\\.11' -or $_.PhysicalMediaType -match '802\\.11' }})) {{
        $mac = ($a.PermanentAddress -replace '[:\\-]', '')
        if (-not $mac -or $mac -match '^0+$') {{ $mac = ($a.MacAddress -replace '[:\\-]', '') }}
        $key = Get-ChildItem $cls -ErrorAction SilentlyContinue | Where-Object {{ (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).NetCfgInstanceId -eq $a.InterfaceGuid }} | Select-Object -First 1
        if ($key) {{
            New-ItemProperty -Path $key.PSPath -Name 'NetworkAddress' -Value $mac -PropertyType String -Force | Out-Null
            Restart-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction SilentlyContinue
            [void]$done.Add("Wi-Fi '$($a.Name)' now always uses its real MAC $mac (random addresses off)")
        }}
    }}
}}

if ($opt.ToDhcp -ne 'no') {{
    Write-Host "2. Checking for manually typed IP addresses..."
    foreach ($a in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up')) {{
        $ipif = Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($ipif -and $ipif.Dhcp -eq 'Disabled') {{
            $cur = (Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
            $ans = 'y'
            if ($opt.ToDhcp -eq 'ask') {{ $ans = Read-Host "   '$($a.Name)' has a manually typed IP $cur. Switch to automatic (DHCP)? The router reservation keeps a fixed IP. (Y/N)" }}
            if ($ans -match '^[Yy]') {{
                netsh interface ipv4 set address name="$($a.Name)" source=dhcp | Out-Null
                netsh interface ipv4 set dnsservers name="$($a.Name)" source=dhcp | Out-Null
                [void]$done.Add("'$($a.Name)' switched from manual IP $cur to automatic (DHCP)")
            }}
        }}
    }}
}}

if ($opt.Renew) {{
    Write-Host "3. Renewing the IP address and clearing old address caches..."
    arp -d * 2>$null | Out-Null
    ipconfig /flushdns | Out-Null
    ipconfig /release | Out-Null
    ipconfig /renew | Out-Null
    Start-Sleep -Seconds 4
    [void]$done.Add("IP renewed, ARP and DNS caches cleared")
}}

if ($opt.LockGw -and $GW -and $GWMAC) {{
    Write-Host "4. Locking the router's MAC address (protection against NetCut / ARP spoofing)..."
    foreach ($r in @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object NextHop -eq $GW)) {{
        $name = (Get-NetAdapter -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue).Name
        if ($name) {{
            netsh interface ipv4 delete neighbors interface="$name" address=$GW 2>$null | Out-Null
            netsh interface ipv4 add neighbors interface="$name" address=$GW neighbor=$GWMAC store=persistent | Out-Null
            [void]$done.Add("router $GW locked to MAC $GWMAC on '$name' (undo with the Undo script if the router is replaced)")
        }}
    }}
}}

{ADS_PS}
if ($opt.Report -and $URL) {{
{HW_PS}
    if ($opt.Daily) {{  # keeps the inventory up to date by itself: a small daily report, nothing else
        $dir = Join-Path $env:ProgramData 'NetworkDoctor'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $rep = Join-Path $dir 'nd-report.ps1'
        Set-Content -Path $rep -Encoding UTF8 -Value $REPORTER
        $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$rep`""
        $trg = @((New-ScheduledTaskTrigger -Daily -At 11:30am), (New-ScheduledTaskTrigger -AtStartup))
        $trg[1].Delay = 'PT5M'
        $set = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
        Register-ScheduledTask -TaskName 'Network Doctor report' -Action $act -Trigger $trg -Settings $set -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
        [void]$done.Add("this PC now sends its details to Network Doctor every day (task 'Network Doctor report')")
    }}
    $body = @{{ hostname = $env:COMPUTERNAME; user = "$env:USERDOMAIN\\$env:USERNAME";
               os = $osi.Caption; hw = $hw;
               adapters = @($ads); actions = @($done) }} | ConvertTo-Json -Depth 4
    try {{
        Invoke-RestMethod -Uri $URL -Method Post -Body $body -ContentType 'application/json' -Headers @{{ 'X-ND-Report' = $KEY }} -TimeoutSec 8 | Out-Null
        [void]$done.Add("reported to Network Doctor (this PC is now tagged with its name)")
    }} catch {{ [void]$done.Add("Network Doctor PC not reachable - report skipped") }}
}}

Write-Host ""
Write-Host "Done on $env:COMPUTERNAME :" -ForegroundColor Green
foreach ($x in $done) {{ Write-Host "  - $x" }}
$ads | Where-Object status -eq 'Up' | Format-Table name, mac, ip, dhcp -AutoSize
"""
    undo = f"""
$ErrorActionPreference = 'Continue'
$GW = '{gw or ''}'
{PS_ELEVATE}
$cls = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}'
foreach ($a in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object {{ $_.MediaType -match '802\\.11' }})) {{
    $key = Get-ChildItem $cls -ErrorAction SilentlyContinue | Where-Object {{ (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).NetCfgInstanceId -eq $a.InterfaceGuid }} | Select-Object -First 1
    if ($key) {{ Remove-ItemProperty -Path $key.PSPath -Name 'NetworkAddress' -ErrorAction SilentlyContinue; Restart-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction SilentlyContinue }}
}}
if ($GW) {{ foreach ($a in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue)) {{ netsh interface ipv4 delete neighbors interface="$($a.Name)" address=$GW 2>$null | Out-Null }} }}
Unregister-ScheduledTask -TaskName 'Network Doctor report' -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "Undo finished: Wi-Fi MAC back to Windows settings, router MAC lock removed, daily report task removed." -ForegroundColor Green
"""
    return (_cmd_launcher("Network Doctor - PC network fix") + _crlf(ps),
            _cmd_launcher("Network Doctor - undo PC network fix") + _crlf(undo))


def _crlf(s):
    return s.strip("\n").replace("\r\n", "\n").replace("\n", "\r\n") + "\r\n"


# ==========================================================================
# command library
# ==========================================================================
# where: "This PC" (can be run from the app), "Router" (paste in WinBox > New Terminal), "Each PC" (run on that PC)
# placeholders: {ip} {mac} {mac_dash} {name} {gw} {gw_mac} {gw_mac_dash} {port} {adapter}
COMMANDS = [
    # ---- this PC (Windows)
    ("Windows", "This PC", "My IP, MAC, gateway and DHCP details", "ipconfig /all",
     "First thing to check: shows this PC's IP, MAC (Physical Address), DHCP on/off and lease times."),
    ("Windows", "This PC", "Get a new IP from the router", "ipconfig /release && ipconfig /renew",
     "After a reservation was made, an IP conflict, or 'no internet'."),
    ("Windows", "This PC", "Clear DNS cache", "ipconfig /flushdns", "Websites open the wrong place or not at all."),
    ("Windows", "This PC", "Show ARP table (IP -> MAC this PC knows)", "arp -a",
     "Two IPs with the same MAC, or the router IP with a strange MAC, means a conflict or ARP spoofing."),
    ("Windows", "This PC", "Clear ARP table", "arp -d *", "After fixing a conflict or a spoofing attack (admin)."),
    ("Windows", "This PC", "Ping a device non-stop", "ping -t {ip}",
     "Watch for 'Request timed out' - drops every few minutes point to cable, Wi-Fi or a loop."),
    ("Windows", "This PC", "Ping the router non-stop", "ping -t {gw}", "Is the LAN itself stable? Should be 1-2 ms on cable."),
    ("Windows", "This PC", "Trace the route", "tracert -d {ip}", "Where on the way a connection stops."),
    ("Windows", "This PC", "Packet-loss test per hop", "pathping -n {ip}", "Finds which hop loses packets (takes ~1 min)."),
    ("Windows", "This PC", "Computer name and MAC of a Windows PC", "nbtstat -A {ip}",
     "Identify an unknown Windows device by its IP."),
    ("Windows", "This PC", "MAC addresses of this PC's adapters", "getmac /v /fo list", "For tagging / reservations."),
    ("Windows", "This PC", "Programs with network connections", "netstat -ano | findstr ESTABLISHED",
     "Shows remote addresses and the PID of the program (match PID in Task Manager)."),
    ("Windows", "This PC", "Wi-Fi details (signal, band, BSSID)", "netsh wlan show interfaces",
     "Weak signal (<60%) causes drops that look like network faults."),
    ("Windows", "This PC", "Switch adapter to automatic IP (DHCP)",
     'netsh interface ipv4 set address name="{adapter}" source=dhcp',
     "Removes a manually typed IP (the usual cause of IP conflicts). Adapter name from 'ipconfig'."),
    ("Windows", "This PC", "Lock the router's MAC (anti-NetCut)",
     'netsh interface ipv4 add neighbors interface="{adapter}" address={gw} neighbor={gw_mac_dash} store=persistent',
     "Stops ARP spoofing against this PC. Undo when the router is replaced."),
    ("Windows", "This PC", "Remove the router MAC lock", 'netsh interface ipv4 delete neighbors interface="{adapter}" address={gw}',
     "Undo of the line above."),
    ("Windows", "This PC", "Reset the network stack", "netsh winsock reset && netsh int ip reset",
     "Last resort when networking is broken on one PC (restart afterwards)."),
    ("Windows", "This PC", "Open Wi-Fi settings (random addresses)", "start ms-settings:network-wifi",
     "Turn 'Random hardware addresses' off by hand."),
    # ---- MikroTik router
    ("Windows", "This PC", "Is a service reachable? (test a TCP port)",
     'powershell -NoProfile -Command "Test-NetConnection {ip} -Port {tcpport} | Format-List"',
     "TcpTestSucceeded True = the port is open from this PC (e.g. 80 web, 445 file sharing, 3389 Remote Desktop, "
     "1433 SQL / ERP database)."),
    ("Windows", "This PC", "Cable speed and duplex of this PC",
     'powershell -NoProfile -Command "Get-NetAdapter | Format-Table Name,Status,LinkSpeed,FullDuplex,MacAddress -Auto"',
     "100 Mbps on a cable = damaged cable / old switch; FullDuplex False = speed set by hand somewhere."),
    ("Windows", "This PC", "Network card error counters",
     'powershell -NoProfile -Command "Get-NetAdapterStatistics | Format-Table Name,ReceivedPacketErrors,'
     'OutboundPacketErrors,ReceivedDiscardedPackets -Auto"', "Errors that keep growing = bad cable, connector or port."),
    ("Windows", "This PC", "Routing table", "route print -4",
     "Two 0.0.0.0 routes (cable + Wi-Fi, or a VPN) = traffic may go out the wrong way."),
    ("Windows", "This PC", "MTU of each adapter", "netsh interface ipv4 show subinterfaces",
     "Normal 1500. Use Fix & Commands > MTU finder to test the whole path."),
    ("Windows", "This PC", "Look up a name (DNS)", "nslookup {host}",
     "Which DNS server answers and which IP it gives. 'Non-existent domain' / timeout = DNS problem."),
    ("Windows", "This PC", "Shared folders of a PC / NAS", "net view \\\\{ip}", "Lists what a PC or NAS shares."),
    ("Windows", "This PC", "Firewall on or off (all profiles)", "netsh advfirewall show allprofiles state",
     "If the PC is on 'Public' profile in the office, sharing and remote tools are blocked."),
    ("Windows", "This PC", "Network category (Private / Public)",
     'powershell -NoProfile -Command "Get-NetConnectionProfile | Format-Table Name,InterfaceAlias,NetworkCategory -Auto"',
     "Office network should be Private. Change: Set-NetConnectionProfile -InterfaceAlias Ethernet -NetworkCategory Private"),
    ("Windows", "This PC", "Sync the clock with the internet", "w32tm /resync /force",
     "Wrong PC time breaks HTTPS sites, domain logins and ERP licences. Needs administrator."),
    ("Windows", "This PC", "Wi-Fi drop report (last 3 days)", "netsh wlan show wlanreport",
     "Makes an HTML report of every Wi-Fi disconnect and why (opens from C:\\ProgramData\\Microsoft\\Windows\\WlanReport)."),
    ("MikroTik router", "Router", "Which router port is a device on?", "/interface bridge host print where mac-address={mac}",
     "'on-interface' shows the port (e.g. ether2) - tag the device / switch with it for the map."),
    ("MikroTik router", "Router", "DHCP lease of a device", "/ip dhcp-server lease print detail where mac-address={mac}",
     "Shows its IP, host name, status and whether it is reserved (static)."),
    ("MikroTik router", "Router", "Reserve the current IP for a device (bind)",
     ':do {/ip dhcp-server lease remove [find where mac-address={mac}]} on-error={}; '
     '/ip dhcp-server lease add address={ip} mac-address={mac} comment="ND: {name}"',
     "The device keeps DHCP and always gets this IP. Use the Binding tab for many devices at once."),
    ("MikroTik router", "Router", "Remove a device's reservation", "/ip dhcp-server lease remove [find where mac-address={mac}]",
     "Before giving the IP to another device."),
    ("MikroTik router", "Router", "Find the IP of a MAC", "/ip arp print where mac-address={mac}", ""),
    ("MikroTik router", "Router", "Port link status and speed", "/interface ethernet monitor {port} once",
     "Speed 10M / half duplex = bad cable or port."),
    ("MikroTik router", "Router", "Port error counters (bad cable)", "/interface ethernet print stats where name={port}",
     "Growing rx-fcs-error / rx-align-error = cable or connector problem."),
    ("MikroTik router", "Router", "Who uses the bandwidth on a port right now", "/tool torch interface={port}",
     "Live list of addresses and their traffic. Ctrl+C to stop."),
    ("MikroTik router", "Router", "Port up/down history", '/log print where topics~"interface"',
     "When ether2 restarts, the times show here."),
    ("MikroTik router", "Router", "Turn on loop protection for a port", "/interface ethernet set {port} loop-protect=on",
     "Router disables the port briefly and logs 'loop detected' when a loop appears behind it."),
    ("MikroTik router", "Router", "Turn on RSTP (loop-safe bridge)", "/interface bridge set [find] protocol-mode=rstp",
     "Blocks loops between switches automatically (2-3 s LAN pause when applied)."),
    ("MikroTik router", "Router", "Restart a port (reboots PoE device behind it)",
     "/interface ethernet disable {port}; :delay 3s; /interface ethernet enable {port}", "Camera / AP hanging."),
    ("MikroTik router", "Router", "Block a device (no internet, no other networks)",
     ':do {/ip firewall filter add chain=forward src-mac-address={mac} action=drop comment="ND block {mac}" '
     'place-before=([/ip firewall filter find]->0)} on-error={/ip firewall filter add chain=forward src-mac-address={mac} action=drop '
     'comment="ND block {mac}"}',
     "Cuts internet for a device that is attacking or misbehaving."),
    ("MikroTik router", "Router", "Unblock a device", '/ip firewall filter remove [find where comment="ND block {mac}"]', ""),
    ("MikroTik router", "Router", "Neighbours (switches / APs the router sees)", "/ip neighbor print detail",
     "Identity, model and port of MikroTik / CDP / LLDP devices - use to tag switches."),
    # ---- Mac
    ("MikroTik router", "Router", "Router CPU, memory, uptime", "/system resource print",
     "CPU near 100% = the router is the bottleneck (or a flood / attack). Low uptime = it rebooted (power?)."),
    ("MikroTik router", "Router", "Router errors in the log", '/log print where topics~"error|critical|warning"',
     "Recent problems the router itself noticed."),
    ("MikroTik router", "Router", "Cable test of a port (find the break)", "/interface ethernet cable-test {port}",
     "Shows each wire pair and roughly how many metres away a cable is broken (on models that support it)."),
    ("MikroTik router", "Router", "Live traffic of one device", "/tool torch interface=bridge src-address={ip}/32",
     "What this device is talking to right now and how fast. Ctrl+C to stop."),
    ("MikroTik router", "Router", "Ping from the router", "/ping {ip} count=20",
     "If the router can ping it but a PC can't, the problem is between that PC and the switch."),
    ("MikroTik router", "Router", "Limit the speed of one device",
     ':do {/queue simple remove [find name="ND limit {ip}"]} on-error={}; /queue simple add name="ND limit {ip}" '
     'target={ip}/32 max-limit={limit}/{limit} comment="ND {mac}"',
     "E.g. limit 5M. Stops one PC / camera eating the whole internet line. If the limit seems ignored: FastTrack "
     "(on in the default setup) skips speed limits - use 'Turn off FastTrack' below."),
    ("MikroTik router", "Router", "Turn off FastTrack (so speed limits work)",
     "/ip firewall filter disable [find where action=fasttrack-connection]",
     "Speed limits and per-device traffic counting need it off. The router CPU works harder - check "
     "'Router CPU, memory, uptime' afterwards. Undo: the same with 'enable'."),
    ("MikroTik router", "Router", "Remove a speed limit", '/queue simple remove [find name="ND limit {ip}"]', ""),
    ("MikroTik router", "Router", "Fix websites that hang (MSS clamp)",
     '/ip firewall mangle add chain=forward protocol=tcp tcp-flags=syn action=change-mss new-mss=clamp-to-pmtu '
     'passthrough=yes comment="ND: MSS clamp"', "For PPPoE / VPN lines with MTU below 1500 (Fix & Commands > MTU finder)."),
    ("MikroTik router", "Router", "Use fast public DNS on the router",
     "/ip dns set servers=1.1.1.1,8.8.8.8 allow-remote-requests=yes",
     "After Internet & Usage > DNS server test. Make sure the firewall drops DNS (port 53) coming from the internet side."),
    ("MikroTik router", "Router", "DHCP leases (all devices)", "/ip dhcp-server lease print",
     "Every address the router gave out; 'D' = dynamic, no D = reserved (bound)."),
    ("MikroTik router", "Router", "Is the DHCP pool full?", "/ip pool used print count-only",
     "Compare with the pool size (/ip pool print). A full pool = new devices get no IP (169.254.x.x)."),
    ("MikroTik router", "Router", "Services open on the router (security)", "/ip service print",
     "Turn off what you don't use: /ip service disable telnet,ftp,api,api-ssl. Never leave WinBox open to the internet."),
    ("MikroTik router", "Router", "Who logged in to the router", "/log print where topics~\"account\"",
     "Logins and failed logins - unknown IPs = someone is guessing the password."),
    ("MikroTik router", "Router", "Back up the router settings",
     "/export file=nd-backup; /system backup save name=nd-backup dont-encrypt=no",
     "Then download nd-backup.rsc / .backup from WinBox > Files. Do it before big changes."),
    ("Mac", "This PC", "My IP and MAC", "ifconfig en0", ""),
    ("Mac", "This PC", "ARP table", "arp -an", ""),
    ("Mac", "This PC", "Ping a device", "ping {ip}", "Ctrl+C to stop."),
    ("Mac", "This PC", "Trace route", "traceroute -n {ip}", ""),
    ("Mac", "This PC", "Renew DHCP lease", "sudo ipconfig set en0 DHCP", ""),
    ("Mac", "This PC", "Cable speed of the Mac", "ifconfig en0 | grep media",
     "1000baseT = gigabit. 100baseTX on a cable = damaged cable / old switch."),
    ("Mac", "This PC", "Wi-Fi details", "system_profiler SPAirPortDataType", "Signal, channel, speed of the Wi-Fi."),
    ("Mac", "This PC", "Look up a name (DNS)", "nslookup {host}", ""),
    ("Mac", "This PC", "Clear DNS cache", "sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder", ""),
    ("Mac", "This PC", "Routing table", "netstat -rn -f inet", ""),
]


def fill(cmd, values):
    """Fills {placeholders}; returns (text, missing_names)."""
    missing = []

    def rep(m):
        k = m.group(1)
        v = values.get(k)
        if not v:
            missing.append(k)
            return m.group(0)
        return str(v)
    return re.sub(r"\{(\w+)\}", rep, cmd), sorted(set(missing))


def command_values(d, gw, gw_mac, lip=""):
    d = d or {}
    t = d.get("tag") or {}
    mac = d.get("mac") or ""
    hexm = mac.replace(":", "").lower()
    return {"ip": d.get("ip", ""), "mac": mac, "mac_dash": mac.replace(":", "-").lower(),
            "mac_dot": ".".join(hexm[i:i + 4] for i in range(0, 12, 4)) if len(hexm) == 12 else "",
            "lip": lip or "",
            "name": (t.get("name") or d.get("name") or "").replace('"', "'"), "gw": gw or "",
            "gw_mac": gw_mac or "", "gw_mac_dash": (gw_mac or "").replace(":", "-").lower(),
            "port": t.get("router_port", ""), "adapter": ""}


# ---------------------------------------------------------------- other brands, antivirus, firewall, drivers
# where: "This PC" = runs here (Run button); "Each PC" = run on the PC concerned; anything else = paste it in that
# device's console (SSH / Telnet / serial / the web CLI). {vlan} {iface} {user} {pass} {community} ... are asked.
PS = 'powershell -NoProfile -ExecutionPolicy Bypass -Command "{}"'
VENDOR_COMMANDS = [
    # ---- drivers and updates (Windows)
    ("Drivers & updates", "This PC", "Devices with a driver problem (yellow mark)",
     "pnputil /enum-devices /problem",
     "Lists every device Windows has a problem with (missing / failed driver). Same as the yellow marks in Device Manager."),
    ("Drivers & updates", "This PC", "All installed driver packages",
     "pnputil /enum-drivers", "Driver packages in the Windows driver store with version and date."),
    ("Drivers & updates", "This PC", "Search Windows Update for missing drivers (scan)",
     "UsoClient StartScan", "Starts a Windows Update scan, which also finds drivers. Open Settings > Windows Update after a minute."),
    ("Drivers & updates", "This PC", "Open Windows Update",
     "start ms-settings:windowsupdate", "Install pending updates and optional driver updates (Advanced options > Optional updates)."),
    ("Drivers & updates", "This PC", "Programs with a newer version (winget)",
     "winget upgrade", "Lists installed programs that have an update (Windows 10 / 11 with App Installer)."),
    ("Drivers & updates", "This PC", "Update all programs (winget)",
     "winget upgrade --all --silent --accept-package-agreements --accept-source-agreements",
     "Updates Chrome, Zoom, 7-Zip, AnyDesk ... in one go. Run as administrator."),
    ("Drivers & updates", "This PC", "Dell: install Dell Command Update",
     "winget install --id Dell.CommandUpdate -e", "Dell's own driver / BIOS updater. Then use the next command."),
    ("Drivers & updates", "This PC", "Dell: scan and apply all driver updates",
     '"C:\\Program Files\\Dell\\CommandUpdate\\dcu-cli.exe" /applyUpdates -reboot=disable',
     "Installs every Dell driver and BIOS update for this model (needs Dell Command Update)."),
    ("Drivers & updates", "This PC", "Lenovo: install Lenovo System Update",
     "winget install --id Lenovo.SystemUpdate -e", "Lenovo's driver / BIOS updater for ThinkPad, ThinkCentre, IdeaPad."),
    ("Drivers & updates", "This PC", "HP: install HP Support Assistant",
     "winget install --id HP.SupportAssistant -e", "HP's driver updater. Business PCs can use HP Image Assistant instead."),
    ("Drivers & updates", "This PC", "PC maker, model and serial (for the driver page)",
     PS.format("Get-CimInstance Win32_ComputerSystem | Select Manufacturer,Model; (Get-CimInstance Win32_BIOS).SerialNumber"),
     "Dell service tag / Lenovo / HP serial number to type on the maker's driver page."),
    ("Drivers & updates", "This PC", "Last Windows updates installed",
     PS.format("Get-HotFix | Sort InstalledOn -Desc | Select -First 10"),
     "When this PC was last updated. Older than 1-2 months = check Windows Update."),
    ("Drivers & updates", "This PC", "Network card driver version",
     PS.format("Get-NetAdapter | Select Name,InterfaceDescription,DriverVersion,DriverDate,LinkSpeed"),
     "Old network drivers cause drops and slow Wi-Fi; compare with the maker's page."),
    ("Drivers & updates", "This PC", "Reset Windows Update (when it is stuck)",
     "net stop wuauserv && net stop bits && ren %windir%\\SoftwareDistribution SoftwareDistribution.old && net start bits && net start wuauserv",
     "Fixes Windows Update errors / stuck downloads (admin). The old folder can be deleted later."),
    ("Drivers & updates", "This PC", "Repair Windows system files",
     "DISM /Online /Cleanup-Image /RestoreHealth && sfc /scannow",
     "Repairs damaged Windows files (admin, 10-30 minutes). For crashes and updates that fail."),
    # ---- printers
    ("Printers", "This PC", "Printers installed and their ports",
     PS.format("Get-Printer | Select Name,DriverName,PortName,Shared,PrinterStatus"),
     "Which printer uses which IP / port and driver."),
    ("Printers", "This PC", "Clear a stuck print queue",
     "net stop spooler && del /q /f %windir%\\System32\\spool\\PRINTERS\\* && net start spooler",
     "Jobs stuck in the queue, 'printing' forever (admin)."),
    ("Printers", "This PC", "Add a network printer by IP",
     PS.format("Add-PrinterPort -Name 'IP_{ip}' -PrinterHostAddress '{ip}'; Get-PrinterDriver | Select Name"),
     "Creates the port for the printer at {ip}; then Add-Printer -Name 'Office' -DriverName '<name from the list>' -PortName 'IP_{ip}'."),
    ("Printers", "This PC", "Is the printer's print port open? (9100)",
     PS.format("Test-NetConnection {ip} -Port 9100"), "TcpTestSucceeded True = the printer accepts print jobs."),
    # ---- antivirus
    ("Antivirus", "This PC", "Which antivirus is installed and is it on?",
     PS.format("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select displayName,productState,timestamp"),
     "Every antivirus Windows knows (Defender, Quick Heal, K7, ESET, Seqrite ...). The PC details script decodes on / off and up to date."),
    ("Antivirus", "This PC", "Windows Defender status",
     PS.format("Get-MpComputerStatus | Select AMRunningMode,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,QuickScanEndTime"),
     "Real-time protection on? Signatures from today or yesterday?"),
    ("Antivirus", "This PC", "Windows Defender: update signatures now", PS.format("Update-MpSignature"),
     "Downloads the newest virus definitions."),
    ("Antivirus", "This PC", "Windows Defender: quick scan", PS.format("Start-MpScan -ScanType QuickScan"),
     "5-15 minutes. Results: Get-MpThreatDetection."),
    ("Antivirus", "This PC", "Windows Defender: threats found", PS.format("Get-MpThreatDetection | Select -First 20"),
     "What Defender found and removed / quarantined."),
    ("Antivirus", "This PC", "Windows Defender: offline scan (restarts the PC)", PS.format("Start-MpWDOScan"),
     "For malware that hides while Windows runs. The PC restarts and scans for ~15 minutes."),
    ("Antivirus", "This PC", "Quick Heal / Seqrite: is the service running?",
     PS.format("Get-Service | Where {$_.DisplayName -match 'Quick Heal|Seqrite'} | Select DisplayName,Status"),
     "Status Running = protection active. Update from the Quick Heal / Seqrite window (or the Seqrite EPS console)."),
    ("Antivirus", "This PC", "K7 / ESET / Kaspersky / McAfee: service status",
     PS.format("Get-Service | Where {$_.DisplayName -match 'K7|ESET|Kaspersky|McAfee|Sophos|Trend|Bitdefender'} | Select DisplayName,Status"),
     "Shows whether the third-party antivirus services are running."),
    ("Antivirus", "This PC", "ESET: update and scan from the command line",
     '"C:\\Program Files\\ESET\\ESET Security\\ecls.exe" /update && "C:\\Program Files\\ESET\\ESET Security\\ecls.exe" C:\\Users',
     "ESET command-line scanner (path differs on older ESET versions)."),
    # ---- Windows firewall
    ("Windows Firewall", "This PC", "Firewall on / off for each network type",
     "netsh advfirewall show allprofiles state", "Domain, Private, Public should normally all be ON."),
    ("Windows Firewall", "This PC", "Turn the firewall ON (all profiles)", "netsh advfirewall set allprofiles state on",
     "Admin. Someone turned it off 'to make something work' - turn it back on and allow only that program."),
    ("Windows Firewall", "This PC", "Allow a TCP port in", 'netsh advfirewall firewall add rule name="Allow TCP {tcpport}" dir=in action=allow protocol=TCP localport={tcpport}',
     "For a server program (ERP, Tally 9000, SQL 1433, RDP 3389) that other PCs must reach."),
    ("Windows Firewall", "This PC", "Allow ping (ICMP) in",
     'netsh advfirewall firewall add rule name="Allow ping" dir=in action=allow protocol=icmpv4:8,any',
     "So Network Doctor and others can ping this PC."),
    ("Windows Firewall", "This PC", "Turn on file and printer sharing",
     'netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes',
     "Shared folders / printers on this PC not reachable from other PCs."),
    ("Windows Firewall", "This PC", "Firewall rules that block",
     PS.format("Get-NetFirewallRule -Action Block -Enabled True | Select DisplayName,Direction,Profile"),
     "A block rule can stop a program even when the firewall 'allows' it elsewhere."),
    ("Windows Firewall", "This PC", "Reset the firewall to Windows defaults", "netsh advfirewall reset",
     "Removes all custom rules (admin). Last resort when rules are a mess."),
    # ---- Cisco IOS / IOS-XE (Catalyst switches, ISR routers)
    ("Cisco switch / router (IOS)", "Switch", "Which port is a MAC on?", "show mac address-table address {mac_dot}",
     "The MAC in Cisco form xxxx.xxxx.xxxx. The port column tells where the device is plugged in."),
    ("Cisco switch / router (IOS)", "Switch", "Port status, speed, duplex", "show interfaces status",
     "a-full a-1000 = good. a-half or a-100 on a PC port = cable problem."),
    ("Cisco switch / router (IOS)", "Switch", "Port errors (CRC = bad cable)", "show interfaces counters errors",
     "CRC / FCS / Align errors that keep growing = replace the cable or the port."),
    ("Cisco switch / router (IOS)", "Switch", "Neighbours (which switch is on which port)", "show cdp neighbors detail",
     "LLDP instead: show lldp neighbors detail."),
    ("Cisco switch / router (IOS)", "Switch", "Loop / spanning tree check", "show spanning-tree summary",
     "Topology changes going up all the time = a loop or a port flapping. 'show spanning-tree detail | inc ieee|from' shows where."),
    ("Cisco switch / router (IOS)", "Switch", "Shut / restart a port",
     "configure terminal\ninterface {iface}\nshutdown\nno shutdown\nend",
     "Restarts a port (e.g. Gi1/0/5). Leave out 'no shutdown' to keep it off."),
    ("Cisco switch / router (IOS)", "Switch", "Put a port in a VLAN",
     "configure terminal\ninterface {iface}\nswitchport mode access\nswitchport access vlan {vlan}\nend\nwrite memory",
     "Access port for a PC / phone / camera in one VLAN."),
    ("Cisco switch / router (IOS)", "Switch", "Stop loops: BPDU guard + storm control on PC ports",
     "configure terminal\ninterface range {iface}\nspanning-tree portfast\nspanning-tree bpduguard enable\nstorm-control broadcast level 5\nend\nwrite memory",
     "A port with a loop or a home router plugged in shuts itself down instead of taking the network down."),
    ("Cisco switch / router (IOS)", "Switch", "DHCP snooping (stop rogue DHCP)",
     "configure terminal\nip dhcp snooping\nip dhcp snooping vlan {vlan}\ninterface {iface}\nip dhcp snooping trust\nend\nwrite memory",
     "{iface} = the uplink to the real router - only that port may answer DHCP."),
    ("Cisco switch / router (IOS)", "Switch", "Send logs to Network Doctor (syslog)",
     "configure terminal\nlogging host {lip}\nlogging trap warnings\nend\nwrite memory",
     "Port up / down, loops and errors appear in the Live monitor."),
    ("Cisco switch / router (IOS)", "Switch", "SNMP read access for Network Doctor",
     "configure terminal\nsnmp-server community netdoctor RO\nend\nwrite memory",
     "Lets Network Doctor read the MAC table and port traffic (community netdoctor)."),
    ("Cisco switch / router (IOS)", "Router", "NetFlow to Network Doctor (Cisco router)",
     "configure terminal\nflow exporter ND\n destination {lip}\n transport udp 2055\nflow monitor NDM\n exporter ND\n record netflow ipv4 original-input\ninterface {iface}\n ip flow monitor NDM input\nend",
     "Per-device / per-site traffic in the Live monitor. {iface} = the LAN interface."),
    ("Cisco switch / router (IOS)", "Switch", "Save the configuration", "write memory",
     "Changes are lost at the next power cut without this."),
    # ---- TP-Link JetStream / Omada (CLI similar to Cisco)
    ("TP-Link switch (JetStream / Omada)", "Switch", "Which port is a MAC on?", "show mac address-table address {mac}",
     "MAC with colons. Web UI: MAC Address > Address Table."),
    ("TP-Link switch (JetStream / Omada)", "Switch", "Port status and speed", "show interface status",
     "Check speed / duplex. Web UI: Switching > Port > Port Config."),
    ("TP-Link switch (JetStream / Omada)", "Switch", "Port errors", "show interface counters",
     "Growing error / CRC counters = cable or port problem."),
    ("TP-Link switch (JetStream / Omada)", "Switch", "Loop detection on all ports",
     "configure\nloopback-detection\ninterface range gigabitEthernet 1/0/1-24\nloopback-detection\nloopback-detection config process-mode port-based recovery-mode auto\nend\ncopy running-config startup-config",
     "Blocks a port that has a loop and opens it again later. Web UI: Switching > Loopback Detection."),
    ("TP-Link switch (JetStream / Omada)", "Switch", "Put a port in a VLAN",
     "configure\nvlan {vlan}\nexit\ninterface gigabitEthernet {iface}\nswitchport general allowed vlan {vlan} untagged\nswitchport pvid {vlan}\nend\ncopy running-config startup-config",
     "{iface} like 1/0/5."),
    ("TP-Link switch (JetStream / Omada)", "Switch", "DHCP snooping (stop rogue DHCP)",
     "configure\nip dhcp snooping\nip dhcp snooping vlan {vlan}\ninterface gigabitEthernet {iface}\nip dhcp snooping trust\nend\ncopy running-config startup-config",
     "{iface} = the uplink to the real router."),
    ("TP-Link switch (JetStream / Omada)", "Switch", "Syslog to Network Doctor",
     "configure\nlogging host index 1 {lip} 4\nend\ncopy running-config startup-config", "Port and loop events in the Live monitor."),
    ("TP-Link switch (JetStream / Omada)", "Switch", "SNMP read access",
     "configure\nsnmp-server\nsnmp-server community netdoctor read-only\nend\ncopy running-config startup-config",
     "Network Doctor reads the MAC table and traffic. Omada-managed: set it in the Omada controller (Site > Services > SNMP)."),
    ("TP-Link router (ER / Archer / Omada gateway)", "Router web page", "Reserve an IP / bind IP-MAC",
     "Open http://{gw} > Network / Transmission > DHCP > Address Reservation (ER series: Preferences > IP-MAC Binding). Add MAC {mac} -> IP {ip}.",
     "TP-Link routers have no command line for this - use the web page."),
    ("TP-Link router (ER / Archer / Omada gateway)", "Router web page", "Block a website",
     "Open http://{gw} > Firewall / Security > Access Control (ER series: Behavior Control > URL filtering). Add the domain.",
     "Or point the office DNS to this PC's website firewall (Tools)."),
    # ---- D-Link
    ("D-Link switch (DGS / DES)", "Switch", "Which port is a MAC on?", "show fdb mac_address {mac_dash}",
     "Newer DGS-1250/1510 (Cisco-like CLI): show mac-address-table address {mac_dash}."),
    ("D-Link switch (DGS / DES)", "Switch", "Port status, speed, errors", "show ports\nshow error ports {iface}",
     "Half duplex / 100M on a PC port or growing CRC errors = cable."),
    ("D-Link switch (DGS / DES)", "Switch", "Loop detection on",
     "enable loopdetect\nconfig loopdetect ports all state enabled\nconfig loopdetect recover_timer 60\nsave",
     "Shuts a looping port and reopens it after 60 s."),
    ("D-Link switch (DGS / DES)", "Switch", "Put a port in a VLAN",
     "create vlan v{vlan} tag {vlan}\nconfig vlan v{vlan} add untagged {iface}\nsave", "{iface} = port number, e.g. 5."),
    ("D-Link switch (DGS / DES)", "Switch", "Syslog + SNMP for Network Doctor",
     "enable syslog\ncreate syslog host 1 ipaddress {lip} severity warning state enable\ncreate snmp community netdoctor view CommunityView read_only\nsave",
     "Logs and MAC table for Network Doctor."),
    # ---- HP / Aruba
    ("HP / Aruba switch (ProCurve, AOS-S)", "Switch", "Which port is a MAC on?", "show mac-address {mac_dash}",
     "MAC in xxxxxx-xxxxxx form also works."),
    ("HP / Aruba switch (ProCurve, AOS-S)", "Switch", "Port status and errors", "show interfaces brief\nshow interfaces {iface}",
     "Look at 'FCS Rx' and 'Drops'."),
    ("HP / Aruba switch (ProCurve, AOS-S)", "Switch", "Loop protection",
     "configure\nloop-protect 1-24\nloop-protect trap loop-detected\nwrite memory", "Blocks a looping port."),
    ("HP / Aruba switch (ProCurve, AOS-S)", "Switch", "Syslog + SNMP",
     "configure\nlogging {lip}\nsnmp-server community netdoctor operator\nwrite memory", "For Network Doctor."),
    # ---- Ubiquiti
    ("Ubiquiti (UniFi / EdgeRouter)", "Device SSH", "UniFi device: info and controller address", "info",
     "SSH to the UniFi switch / AP. 'set-inform http://<controller>:8080/inform' adopts it."),
    ("Ubiquiti (UniFi / EdgeRouter)", "Device SSH", "UniFi switch: which port is a MAC on?", "swctrl mac show | grep -i {mac}",
     "Or the UniFi controller > Clients."),
    ("Ubiquiti (UniFi / EdgeRouter)", "Router", "EdgeRouter: DHCP leases", "show dhcp leases", "Names and IPs of all devices."),
    ("Ubiquiti (UniFi / EdgeRouter)", "Router", "EdgeRouter: NetFlow to Network Doctor",
     "configure\nset system flow-accounting interface eth1\nset system flow-accounting netflow server {lip} port 2055\nset system flow-accounting netflow version 9\ncommit; save",
     "eth1 = the LAN port. Per-device traffic in the Live monitor."),
    # ---- Netgear
    ("Netgear smart switch (GS / M4250)", "Switch", "Which port is a MAC on?", "show mac-addr-table {mac}",
     "Smart (web-only) models: Switching > Address Table."),
    ("Netgear smart switch (GS / M4250)", "Switch", "Port status", "show port all", "Speed / duplex for every port."),
    ("Netgear smart switch (GS / M4250)", "Switch", "Loop / broadcast storm protection",
     "configure\nstorm-control broadcast level 5\nkeepalive\nexit\nwrite memory", "Web UI: Security > Traffic Control > Storm Control."),
    # ---- Huawei
    ("Huawei switch (S series)", "Switch", "Which port is a MAC on?", "display mac-address {mac_dash}",
     "Huawei MAC form xxxx-xxxx-xxxx."),
    ("Huawei switch (S series)", "Switch", "Port status and errors", "display interface brief\ndisplay interface {iface}",
     "Look at CRC and duplex."),
    ("Huawei switch (S series)", "Switch", "Loop detection",
     "system-view\nloopback-detect enable\ninterface {iface}\nloopback-detect enable\nreturn\nsave", ""),
    ("Huawei switch (S series)", "Switch", "Syslog to Network Doctor",
     "system-view\ninfo-center loghost {lip}\nreturn\nsave", ""),
    # ---- firewalls
    ("FortiGate firewall", "Firewall", "Who is using the internet now (top sessions)",
     "diagnose sys top-summary\nget system performance status", "CPU, memory, sessions. GUI: Dashboard > FortiView Sources."),
    ("FortiGate firewall", "Firewall", "Sessions of one device", "diagnose sys session filter src {ip}\ndiagnose sys session list",
     "What the device {ip} is connected to. Clear the filter: diagnose sys session filter clear."),
    ("FortiGate firewall", "Firewall", "DHCP leases", "execute dhcp lease-list", "Names / IPs / MACs."),
    ("FortiGate firewall", "Firewall", "Test the internet from the firewall",
     "execute ping 8.8.8.8\nexecute traceroute 8.8.8.8", ""),
    ("FortiGate firewall", "Firewall", "Syslog to Network Doctor",
     "config log syslogd setting\nset status enable\nset server {lip}\nend", "Traffic and security logs in the Live monitor."),
    ("FortiGate firewall", "Firewall", "NetFlow to Network Doctor",
     "config system netflow\nset collector-ip {lip}\nset collector-port 2055\nend\nconfig system interface\nedit {iface}\nset netflow-sampler both\nend",
     "Per-device / per-site traffic. {iface} = LAN interface (e.g. internal / port1)."),
    ("FortiGate firewall", "Firewall", "Block a device (address + deny policy)",
     'config firewall address\nedit "ND-block-{ip}"\nset subnet {ip} 255.255.255.255\nnext\nend',
     "Then add a deny policy for it at the top (GUI: Policy & Objects > Firewall Policy)."),
    ("Sophos firewall (XG / XGS)", "Firewall", "Console: ping / traceroute / ARP",
     "ping 8.8.8.8\ntraceroute 8.8.8.8\narp", "Device console (SSH, option 4 Device Console)."),
    ("Sophos firewall (XG / XGS)", "Firewall", "Syslog to Network Doctor",
     "Web admin: System services > Log settings > Add syslog server {lip} UDP 514, then tick the log types.", ""),
    ("pfSense / OPNsense", "Firewall", "States (connections) of a device", "pfctl -ss | grep {ip}",
     "Shell (option 8). What {ip} is connected to now."),
    ("pfSense / OPNsense", "Firewall", "DHCP leases", "cat /var/dhcpd/var/db/dhcpd.leases | grep -A6 {ip}",
     "GUI: Status > DHCP Leases."),
    ("pfSense / OPNsense", "Firewall", "NetFlow / syslog to Network Doctor",
     "GUI: pfSense - install softflowd, host {lip} port 2055; Status > System Logs > Settings > Remote log {lip}:514. OPNsense - Reporting > NetFlow.",
     ""),
    ("Seqrite / Quick Heal UTM", "Firewall", "Syslog to Network Doctor",
     "Web admin: Logs & Reports > Settings > Syslog server {lip} port 514.", ""),
    # ---- generic
    ("Any switch / router", "Each device", "Find a device's switch port without a login",
     "Network Doctor > Devices > Switches (SNMP) (SNMP community netdoctor), or unplug-and-watch with 'ping -t {ip}'.",
     "Works with any SNMP switch (Cisco, TP-Link, D-Link, HP, Netgear, Huawei)."),
]
for _c in VENDOR_COMMANDS:
    COMMANDS.append(_c)


# ---- details of other PCs without running anything on them (Windows admin login, remote WMI over DCOM)
def remote_inventory_ps():
    """PowerShell that reads one PC's details remotely. Reads ND_IP / ND_USER / ND_PW from its environment (the
    password never appears on a command line). Prints the details as JSON, or 'ERROR: ...'."""
    body = HW_PS
    body = body.replace("Get-CimInstance ", "Get-CimInstance -CimSession $s ")
    body = body.replace("Get-PhysicalDisk ", "Get-PhysicalDisk -CimSession $s ")
    body = body.replace("Get-NetFirewallProfile ", "Get-NetFirewallProfile -CimSession $s ")
    body = body.replace("$hot = Get-HotFix ", "$hot = Get-HotFix -ComputerName $ip -Credential $cred ")
    body = re.sub(r"\$sw = @\(Get-ItemProperty[^\n]*\n", "$sw = @(Get-SW)\n", body)
    return r"""
$ErrorActionPreference = 'SilentlyContinue'
$ip = $env:ND_IP
$user = $env:ND_USER
if ($user -notmatch '[\\@]') { $user = "$ip\$user" }
$cred = New-Object System.Management.Automation.PSCredential($user, (ConvertTo-SecureString $env:ND_PW -AsPlainText -Force))
try {
    $o = New-CimSessionOption -Protocol Dcom
    $s = New-CimSession -ComputerName $ip -Credential $cred -SessionOption $o -OperationTimeoutSec 25 -ErrorAction Stop
} catch { Write-Output ("ERROR: " + $_.Exception.Message); exit }
function Get-SW {
    $out = @()
    foreach ($root in 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
        $r = Invoke-CimMethod -CimSession $s -Namespace root\default -ClassName StdRegProv -MethodName EnumKey -Arguments @{ hDefKey = [uint32]2147483650; sSubKeyName = $root }
        foreach ($k in @($r.sNames)) {
            $v = Invoke-CimMethod -CimSession $s -Namespace root\default -ClassName StdRegProv -MethodName GetStringValue -Arguments @{ hDefKey = [uint32]2147483650; sSubKeyName = "$root\$k"; sValueName = 'DisplayName' }
            if ($v.sValue) { $out += [string]$v.sValue }
        }
    }
    $out | Sort-Object -Unique
}
""" + body + r"""
$hw['hostname'] = [string]$cs.Name
Remove-CimSession $s
$hw | ConvertTo-Json -Compress
"""


def parse_remote_inventory(out):
    """(hw dict, error text) from the remote script's output."""
    out = out or ""
    if "{" in out:
        try:
            import json
            return json.loads(out[out.find("{"):out.rfind("}") + 1]), ""
        except ValueError:
            pass
    err = out.strip().splitlines()[-1] if out.strip() else "no answer"
    low = err.lower()
    if "access is denied" in low or "0x80070005" in low:
        err = "wrong user / password, or this user is not an administrator on that PC"
    elif "rpc server" in low or "0x800706ba" in low or "unavailable" in low:
        err = "the PC's firewall blocks remote WMI (run the PC details script on it once instead)"
    return {}, err.replace("ERROR: ", "")[:200]
