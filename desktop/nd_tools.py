# -*- coding: utf-8 -*-
"""
Network Doctor - tools: device tags, network map, MikroTik discovery, IP-MAC binding,
PC fix script and the command library. Pure logic only (no window code) so it can be tested.
"""

import csv
import io
import re
import socket
import struct
import time

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
TAG_FIELDS = ["name", "dept", "location", "kind", "parent", "router_port", "switch_port", "notes"]
CSV_HEAD = ["MAC", "Name", "Department", "Location", "Type", "Connected to (MAC)", "Router port", "Switch port",
            "Notes", "Current IP", "Vendor"]


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
        if nb and not t.get("name") and nb.get("identity") and not d.get("name"):
            d["name"] = nb["identity"]
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
                    d.get("ip", ""), d.get("vendor", "")])
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
           "switch_port": col("switch port"), "notes": col("notes")}
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
        name = tags.get(mac, {}).get("name") or mac
        me = next((d for d in devices if d.get("mac") == mac and d.get("online")), None)
        if me and me.get("ip") != b["ip"] and b["ip"] not in (me.get("ips") or []):
            out.append({"sev": "warning", "title": f"Bound device {name} is on {me['ip']} instead of {b['ip']}",
                        "detail": "Its IP was reserved on the router, but the device uses another address. Either the "
                                  "binding commands were not pasted yet, or the device has a hand-typed IP.",
                        "fix": "Paste the binding commands from the IP-MAC binding tab, then set the device to "
                               "automatic (DHCP) and renew its IP (PC fix script or 'ipconfig /renew').",
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


def pc_fix_script(opts, gw, gw_mac, report_url, report_key):
    """opts: random_off, renew, lock_gw, report (booleans); to_dhcp: "ask" / "yes" / "no".
    Use to_dhcp "yes" or "no" when the script runs unattended (login script), "ask" when a person runs it.
    Returns (fix_cmd, undo_cmd)."""
    b = lambda k: "$true" if opts.get(k) else "$false"
    to_dhcp = opts.get("to_dhcp") if opts.get("to_dhcp") in ("ask", "yes", "no") else ("ask" if opts.get("to_dhcp") else "no")
    gw_dash = (gw_mac or "").replace(":", "-").lower()
    ps = f"""
$ErrorActionPreference = 'Continue'
$opt = @{{ RandomOff = {b('random_off')}; ToDhcp = '{to_dhcp}'; Renew = {b('renew')}; LockGw = {b('lock_gw')}; Report = {b('report')} }}
$GW = '{gw or ''}'; $GWMAC = '{gw_dash}'
$URL = '{report_url}'; $KEY = '{report_key}'
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

$ads = foreach ($a in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue)) {{
    [pscustomobject]@{{ name = $a.Name; desc = $a.InterfaceDescription; mac = $a.MacAddress; permanent = $a.PermanentAddress;
        status = [string]$a.Status; wifi = [bool]($a.MediaType -match '802\\.11');
        ip = ((Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress -join ',');
        dhcp = [string](Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp }}
}}
if ($opt.Report -and $URL) {{
    $body = @{{ hostname = $env:COMPUTERNAME; user = "$env:USERDOMAIN\\$env:USERNAME";
               os = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption;
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
Write-Host "Undo finished: Wi-Fi MAC back to Windows settings, router MAC lock removed." -ForegroundColor Green
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
    ("MikroTik router", "Router", "Which router port is a device on?", "/interface bridge host print where mac-address={mac}",
     "'on-interface' shows the port (e.g. ether2) - tag the device / switch with it for the map."),
    ("MikroTik router", "Router", "DHCP lease of a device", "/ip dhcp-server lease print detail where mac-address={mac}",
     "Shows its IP, host name, status and whether it is reserved (static)."),
    ("MikroTik router", "Router", "Reserve the current IP for a device (bind)",
     '/ip dhcp-server lease add address={ip} mac-address={mac} comment="{name}"',
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
    ("MikroTik router", "Router", "Block a device", '/ip firewall filter add chain=forward src-mac-address={mac} action=drop place-before=0 comment="ND block {name}"',
     "Cuts internet for a device that is attacking or misbehaving."),
    ("MikroTik router", "Router", "Unblock a device", '/ip firewall filter remove [find where comment="ND block {name}"]', ""),
    ("MikroTik router", "Router", "Neighbours (switches / APs the router sees)", "/ip neighbor print detail",
     "Identity, model and port of MikroTik / CDP / LLDP devices - use to tag switches."),
    # ---- Mac
    ("Mac", "This PC", "My IP and MAC", "ifconfig en0", ""),
    ("Mac", "This PC", "ARP table", "arp -an", ""),
    ("Mac", "This PC", "Ping a device", "ping {ip}", "Ctrl+C to stop."),
    ("Mac", "This PC", "Trace route", "traceroute -n {ip}", ""),
    ("Mac", "This PC", "Renew DHCP lease", "sudo ipconfig set en0 DHCP", ""),
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


def command_values(d, gw, gw_mac):
    d = d or {}
    t = d.get("tag") or {}
    mac = d.get("mac") or ""
    return {"ip": d.get("ip", ""), "mac": mac, "mac_dash": mac.replace(":", "-").lower(),
            "name": (t.get("name") or d.get("name") or "").replace('"', "'"), "gw": gw or "",
            "gw_mac": gw_mac or "", "gw_mac_dash": (gw_mac or "").replace(":", "-").lower(),
            "port": t.get("router_port", ""), "adapter": ""}
