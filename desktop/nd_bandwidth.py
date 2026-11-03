# -*- coding: utf-8 -*-
"""
Network Doctor - bandwidth plan, fixed-IP plan and CCTV isolation for a MikroTik router.

Only plain functions here (no window code) so they can be tested without a screen; the page is in nd_bwtab.py.
Every generator returns (apply_text, undo_text): RouterOS commands to paste in WinBox > New Terminal, or that the
app sends to the router itself. Everything the app adds is named / commented "ND..." so the UNDO text can remove
exactly that and nothing else.
"""
import ipaddress
import math
import re
import time
from collections import Counter
from xml.sax.saxutils import escape

import nd_core as core
import nd_tools as T

# --------------------------------------------------------------------------------------------------- groups
GROUPS = ("nvr", "vip", "mobile", "pc", "cam", "infra", "other")
GROUP_TITLE = {"nvr": "NVR / DVR (remote viewing)", "vip": "VIP PCs (directors, backups, boost)",
               "mobile": "Mobiles / tablets", "pc": "Office PCs", "cam": "CCTV cameras (no internet)",
               "infra": "Router / switches / Wi-Fi", "other": "Printers / IoT / unknown"}
RECORDER_RE = re.compile(r"\b(dvr|nvr|xvr|recorder)\b", re.I)


def is_recorder(d, tag=None):
    """A CCTV device that records (NVR / DVR) rather than a camera. Name, tag, web title and service text are used;
    port numbers cannot tell them apart (cameras open 37777 / 8000 too), so the person can override in the page."""
    t = tag or {}
    text = " ".join(str(x) for x in (d.get("name"), t.get("name"), d.get("services"), (d.get("http") or {}).get("title")
                                     if isinstance(d.get("http"), dict) else d.get("http"), d.get("why")) if x)
    return bool(RECORDER_RE.search(text))


def group_of(d, tags=None, over=None):
    """Which plan group a device belongs to. over: {mac: group} chosen by the person (wins over everything)."""
    g = (over or {}).get(d.get("mac"))
    if g in GROUPS:
        return g
    cat = d.get("category")
    if cat == core.CAT_CAM:
        return "nvr" if is_recorder(d, (tags or {}).get(d.get("mac"))) else "cam"
    if cat == core.CAT_PHONE:
        return "mobile"
    if cat == core.CAT_PC:
        return "pc"
    if cat in (core.CAT_ROUTER, core.CAT_NET):
        return "infra"
    return "other"


def effective_over(over, boosts, now=None):
    """Manual groups plus the devices that are boosted right now (they act as VIP until the boost ends)."""
    now = time.time() if now is None else now
    out = dict(over or {})
    for mac, b in (boosts or {}).items():
        until = (b or {}).get("until")
        if until is None or until > now:
            out[mac] = "vip"
    return out


def live_devices(devices, gw_ip=None):
    return [d for d in devices if d.get("online") and d.get("mac") and d.get("ip") and d.get("ip") != gw_ip]


def groups_ips(devices, tags, over, extra_ips=None, gw_ip=None):
    """{group: sorted IPs} for the live devices. extra_ips: {mac: [more IPs]} (a device that is being moved is listed
    on its old and its new IP, so it stays covered while it renews)."""
    out = {g: set() for g in GROUPS}
    clash = set(find_conflicts(devices))  # an IP two devices answer for would put rules on the wrong one
    for d in live_devices(devices, gw_ip):
        if d["ip"] in clash:
            continue
        g = group_of(d, tags, over)
        out[g].add(d["ip"])
        out[g].update((extra_ips or {}).get(d["mac"], []))
    return {g: sorted(v, key=_ipkey) for g, v in out.items()}


def _ipkey(ip):
    try:
        return int(ipaddress.IPv4Address(ip))
    except ValueError:
        return 0


def detect_wan(routes):
    """The internet port from the router's default route(s) (rows of /ip route print where dst-address=0.0.0.0/0):
    'ether1', 'pppoe-out1'... '' when it cannot be read."""
    for r in routes or []:
        if str(r.get("disabled", "false")).lower() == "true" or str(r.get("inactive", "false")).lower() == "true":
            continue
        for key in ("immediate-gw", "gateway"):
            v = str(r.get(key) or "")
            m = re.search(r"%(\S+)$", v)
            if m:
                return m.group(1)
            if v and not re.fullmatch(r"[\d.,]+", v):  # the gateway is an interface (PPPoE...)
                return v.split(",")[0]
        m = re.search(r"via\s+(\S+)", str(r.get("gateway-status") or ""))
        if m:
            return m.group(1)
    return ""


# --------------------------------------------------------------------------------------------------- bandwidth plan
DEFAULT_PLAN = {"down": 100.0, "up": 100.0, "headroom": 5.0, "nvr": 10.0, "mobile": 20.0, "vip": 5.0,
                "mobile_user": 4.0, "pc_user": 5.0, "vip_user": 20.0, "borrow": True}


def rate(mbps):
    """RouterOS rate text: 5 -> '5M', 2.5 -> '2500k'."""
    mbps = float(mbps)
    return f"{int(mbps)}M" if mbps == int(mbps) else f"{int(round(mbps * 1000))}k"


def compute_pools(plan, counts=None):
    """Splits the line into pools. The line is the smaller of download / upload (remote viewing of the cameras uses the
    UPLOAD, so it is the number that matters). Returns the pools plus 'errors' (cannot apply) and 'warnings'."""
    p = dict(DEFAULT_PLAN)
    p.update({k: plan[k] for k in DEFAULT_PLAN if plan and k in plan and plan[k] is not None})
    line = min(float(p["down"]), float(p["up"]))
    usable = round(line * (1 - float(p["headroom"]) / 100.0), 2)
    pc = round(usable - p["nvr"] - p["mobile"] - p["vip"], 2)
    errors, warnings = [], []
    if line <= 0:
        errors.append("The internet speed must be more than 0.")
    if pc <= 0:
        errors.append(f"NVR + mobiles + VIP ({p['nvr'] + p['mobile'] + p['vip']:g} Mbps) is more than the usable "
                      f"line ({usable:g} Mbps). Lower one of them.")
    for k, lab in (("pc_user", "PC"), ("mobile_user", "mobile"), ("vip_user", "VIP")):
        if p[k] <= 0:
            errors.append(f"The {lab} limit per user must be more than 0.")
    if float(p["up"]) < float(p["down"]):
        warnings.append(f"Upload ({p['up']:g}) is lower than download ({p['down']:g}): the plan is built on the "
                        f"smaller number ({line:g} Mbps) in both directions.")
    if p["nvr"] < 5:
        warnings.append("Under 5 Mbps for the NVR / DVR allows only a few cameras at once and slow clip downloads.")
    if p["vip_user"] > usable:
        warnings.append("The VIP limit is more than the usable line.")
    out = dict(p, line=line, usable=usable, pc=pc, errors=errors, warnings=warnings)
    c = counts or {}
    for g, k in (("pc", "pc"), ("mobile", "mobile"), ("vip", "vip")):
        n = c.get(g, 0)
        pool = out[k]
        out[g + "_busy"] = round(pool / n, 2) if n else None  # what each gets when everybody is busy at once
    return out


def _header(title, n=None):
    return f"# Network Doctor - {title}{f' ({n})' if n is not None else ''} - generated {time.strftime('%Y-%m-%d %H:%M')}"


_OFF = "ND-off: "  # FastTrack / port-forwards switched off by the plan
_REL = "ND-rel: "  # auto-defense blocks released by hand


def _ros_off(path, cond, tag=_OFF):
    """Disables the rules matching cond and marks them with tag so the UNDO can enable exactly those again."""
    return (f':foreach r in=[{path} find where {cond}] do={{ {path} set $r comment=("{tag}" . [{path} get $r comment]); '
            f'{path} disable $r }}')


def _ros_on(path, tag=_OFF):
    n = len(tag)
    return (f':foreach r in=[{path} find where comment~"^{tag}"] do={{ :local c [{path} get $r comment]; '
            f'{path} set $r comment=[:pick $c {n} [:len $c]]; {path} enable $r }}')


def queue_commands(plan, groups, lan, wan=""):
    """Per-group pools and a per-user cap inside each pool, as MikroTik simple queues with PCQ.
    groups: {'nvr': [ips], 'vip': [ips], 'mobile': [ips]}; lan: '192.168.0.0/24'. wan is not needed (kept so older
    callers still work). Traffic between devices on the same switch never reaches the router, so only internet
    traffic is limited. Order matters (first match wins): NVR, VIP, mobiles, then everything else = Office PCs.
    FastTrack skips queues, so the router's FastTrack rules are switched off - as the LAST step, so a line the router
    refuses cannot leave it with FastTrack off and no queues - and switched on again by the UNDO."""
    counts = {g: len((groups or {}).get(g) or []) for g in ("nvr", "vip", "mobile")}
    pl = compute_pools(plan, counts)
    if pl["errors"]:
        raise ValueError(" ".join(pl["errors"]))
    usable = pl["usable"]
    given = {g: pl[g] for g in ("nvr", "vip", "mobile") if counts[g]}
    pc_at = round(usable - sum(given.values()), 2)  # pools nobody uses go to the office PCs

    def mx(pool):
        return usable if pl["borrow"] else pool

    a = [_header("bandwidth plan"),
         f"# Line {pl['down']:g} down / {pl['up']:g} up Mbps -> plan on {pl['line']:g}, usable {usable:g} "
         f"({pl['headroom']:g}% kept free).",
         f"# NVR/DVR {pl['nvr']:g} | VIP {pl['vip']:g} (each up to {pl['vip_user']:g}) | mobiles {pl['mobile']:g} "
         f"(each up to {pl['mobile_user']:g}) | office PCs {pc_at:g} (each up to {pl['pc_user']:g}).",
         "# Order matters: the first queue that matches a device wins. NVR, VIP, mobiles, then all other devices.",
         "/queue simple", ':do {remove [find where name~"^ND-"]} on-error={}',
         "/queue type", ':do {remove [find where name~"^ND-"]} on-error={}']
    for key, per in (("vip", pl["vip_user"]), ("mobile", pl["mobile_user"]), ("pc", pl["pc_user"])):
        a.append(f"add name=ND-{key}-up kind=pcq pcq-classifier=src-address pcq-rate={rate(per)}")
        a.append(f"add name=ND-{key}-dn kind=pcq pcq-classifier=dst-address pcq-rate={rate(per)}")
    a += ["/queue simple",
          f'add name=ND-TOTAL target={lan} max-limit={rate(usable)}/{rate(usable)} comment="ND: whole internet line"']

    def child(name, ips, prio, at, top, qtype, note):
        tgt = ",".join(f"{i}/32" for i in ips) if ips else lan
        a.append(f'add name={name} target={tgt} parent=ND-TOTAL priority={prio}/{prio} '
                 f'limit-at={rate(at)}/{rate(at)} max-limit={rate(top)}/{rate(top)} queue={qtype} comment="ND: {note}"')
    if counts["nvr"]:
        child("ND-NVR", groups["nvr"], 1, pl["nvr"], mx(pl["nvr"]), "default-small/default-small",
              "NVR / DVR remote viewing")
    if counts["vip"]:
        child("ND-VIP", groups["vip"], 2, pl["vip"], mx(pl["vip"]), "ND-vip-up/ND-vip-dn", "VIP / boosted PCs")
    if counts["mobile"]:
        child("ND-MOBILE", groups["mobile"], 4, pl["mobile"], mx(pl["mobile"]), "ND-mobile-up/ND-mobile-dn", "mobiles")
    child("ND-PC", None, 3, pc_at, mx(pc_at), "ND-pc-up/ND-pc-dn", "office PCs and everything else")
    a += ["", "# Last step: FastTrack skips queues, so it is switched off (the UNDO switches it on again).",
          "/ip firewall filter", _ros_off("/ip firewall filter", "action=fasttrack-connection and disabled=no")]
    u = [_header("UNDO bandwidth plan"), "/queue simple", ':do {remove [find where name~"^ND-"]} on-error={}',
         "/queue type", ':do {remove [find where name~"^ND-"]} on-error={}', "/ip firewall filter",
         _ros_on("/ip firewall filter")]
    return "\n".join(a) + "\n", "\n".join(u) + "\n"


# --------------------------------------------------------------------------------------------------- CCTV isolation
CCTV_PORTS = (37777, 37778, 34567, 8000, 554)  # Dahua, Dahua, XMeye, Hikvision, RTSP


def camera_block_commands(cams, nvrs, wan):
    """Cameras can reach only the NVR / DVR: they are stopped from going out to the internet on the router (many
    cameras have no setting for that), nothing from the internet may start a connection to a camera or recorder, and
    the router's port-forwards to them are switched off. The NVR / DVR itself keeps its outbound connection to the
    maker's cloud (DMSS, Hik-Connect, XMeye...), which is what the phone app uses - no open port needed."""
    if not wan:
        raise ValueError("The internet port of the router (for example ether1) is needed.")
    cams, nvrs = sorted(set(cams or []), key=_ipkey), sorted(set(nvrs or []), key=_ipkey)
    a = [_header("CCTV isolation", len(cams) + len(nvrs)),
         "# Cameras: no internet. NVR / DVR: outbound only (cloud app), nothing may connect in from the internet.",
         "/ip firewall address-list",
         ':do {remove [find where list="ND-CAM"]} on-error={}', ':do {remove [find where list="ND-CCTV"]} on-error={}']
    for ip in cams:
        a.append(f'add list=ND-CAM address={ip} comment="ND: camera"')
    for ip in cams + nvrs:
        a.append(f'add list=ND-CCTV address={ip} comment="ND: camera / recorder"')
    a += ["/ip firewall filter", ':do {remove [find where comment~"^ND: camera"]} on-error={}']
    if cams:
        a.append(f':do {{add chain=forward action=drop src-address-list=ND-CAM out-interface={wan} place-before=0 '
                 f'comment="ND: camera no internet"}} on-error={{add chain=forward action=drop '
                 f'src-address-list=ND-CAM out-interface={wan} comment="ND: camera no internet"}}')
    if cams or nvrs:
        a.append(f':do {{add chain=forward action=drop in-interface={wan} dst-address-list=ND-CCTV '
                 f'connection-state=new place-before=0 comment="ND: camera / recorder no inbound"}} on-error='
                 f'{{add chain=forward action=drop in-interface={wan} dst-address-list=ND-CCTV connection-state=new '
                 f'comment="ND: camera / recorder no inbound"}}')
    a += ["# Port-forwards: to the cameras / recorders, and ANY forward of a CCTV port (a forward that still points at an",
          "# IP the recorder no longer has would send the internet to whatever device has that IP now).",
          "/ip firewall nat"]
    for ip in cams + nvrs:
        a.append(_ros_off("/ip firewall nat", f"action=dst-nat and to-addresses={ip} and disabled=no"))
    for port in CCTV_PORTS:
        a.append(_ros_off("/ip firewall nat", f"action=dst-nat and dst-port={port} and disabled=no"))
    u = [_header("UNDO CCTV isolation"), "/ip firewall filter",
         ':do {remove [find where comment~"^ND: camera"]} on-error={}', "/ip firewall address-list",
         ':do {remove [find where list="ND-CAM"]} on-error={}', ':do {remove [find where list="ND-CCTV"]} on-error={}',
         "/ip firewall nat", _ros_on("/ip firewall nat")]
    return "\n".join(a) + "\n", "\n".join(u) + "\n"


def release_blocks_commands():
    """Switches off every block Network Doctor's auto-defense / phone app put on the router (rules commented
    'ND phone block ...' and 'ND isolate ...'). They are kept, marked 'ND-rel: ', so the UNDO switches them on again."""
    f = "/ip firewall filter"
    a = [_header("release auto-defense blocks"),
         "# A block by MAC / IP cuts whichever device has that MAC / IP NOW - after an IP change that can be the wrong one.",
         f, _ros_off(f, 'comment~"^ND phone block" and disabled=no', _REL),
         _ros_off(f, 'comment~"^ND isolate" and disabled=no', _REL)]
    u = [_header("UNDO release auto-defense blocks"), f, _ros_on(f, _REL)]
    return "\n".join(a) + "\n", "\n".join(u) + "\n"


def portforward_report(nat_rows, devices, tags=None, over=None):
    """Each enabled port-forward (dst-nat) of the router and who is at the target IP now. status: 'ok' (a recorder or
    camera is there), 'STALE' (another kind of device has that IP: the forward now exposes it), 'nobody' (nobody online)."""
    by_ip = {}
    for d in devices:
        if d.get("online") and d.get("ip"):
            by_ip.setdefault(d["ip"], []).append(d)
    out = []
    for r in nat_rows or []:
        if r.get("action") != "dst-nat" or str(r.get("disabled", "false")).lower() == "true":
            continue
        ip = r.get("to-addresses", "")
        devs = by_ip.get(ip, [])
        groups = [group_of(d, tags, over) for d in devs]
        who = ", ".join((((tags or {}).get(d["mac"], {}).get("name")) or d.get("name") or d["mac"]) +
                        f" ({GROUP_TITLE[g].split(' (')[0]})" for d, g in zip(devs, groups))
        if not devs:
            status = "nobody"
        elif len(devs) > 1 or any(g not in ("nvr", "cam") for g in groups):
            status = "STALE"
        else:
            status = "ok"
        out.append({"rule": r.get("comment") or r.get(".id", ""), "port": r.get("dst-port", ""), "to": ip,
                    "who": who or "nobody online at that IP", "status": status})
    return out


def find_conflicts(devices):
    """{ip: [devices]} for IPs that more than one live device (different MAC) answers for."""
    by_ip = {}
    for d in live_devices(devices):
        by_ip.setdefault(d["ip"], []).append(d)
    return {ip: v for ip, v in by_ip.items() if len({x["mac"] for x in v}) > 1}


# --------------------------------------------------------------------------------------------------- fixed IP plan
def default_ranges(net):
    """Suggested blocks inside a /24 (offsets from the network address). The person can edit them."""
    try:
        n = ipaddress.ip_network(net, strict=False)
    except ValueError:
        return {}
    if n.num_addresses < 256:
        return {}
    base = int(n.network_address)
    offs = {"infra": (2, 19), "nvr": (20, 29), "vip": (30, 49), "pc": (50, 149), "cam": (150, 199), "mobile": (200, 250)}
    return {g: (str(ipaddress.IPv4Address(base + lo)), str(ipaddress.IPv4Address(base + hi)))
            for g, (lo, hi) in offs.items()}


def _in_range(ip, rng):
    try:
        return rng and _ipkey(rng[0]) <= _ipkey(ip) <= _ipkey(rng[1])
    except Exception:
        return False


def ip_plan(devices, gw_ip, ranges, move, tags=None, over=None, ip_type_of=None, net=None, want=None):
    """One row per live device: keep its IP, or move it into its group's block. Every row ends up as a DHCP
    reservation on the router (the router always hands the same IP to the same MAC - also after a power cut).
    move: groups whose devices are moved into their block. Cameras should normally NOT be moved: the NVR / DVR stores
    each camera's IP. A device with a hand-typed IP cannot be changed from the router: it is marked 'manual'.
    want: {mac: IP} chosen by the person for single devices (for example the phone that took the recorder's IP)."""
    live = live_devices(devices, gw_ip)
    want = want or {}
    moving = {d["mac"] for d in live if d["mac"] in want and want[d["mac"]] != d["ip"]}
    cnt = Counter(d["ip"] for d in live if d["mac"] not in moving)  # a device that is moving away no longer clashes
    taken = {d["ip"] for d in live} | ({gw_ip} if gw_ip else set())
    try:
        nw = ipaddress.ip_network(net, strict=False) if net else None
    except ValueError:
        nw = None
    rows = []
    for d in sorted(live, key=lambda x: _ipkey(x["ip"])):
        g = group_of(d, tags, over)
        typ = ip_type_of(d) if ip_type_of else ""
        row = {"dev": d, "group": g, "ip_now": d["ip"], "ip_new": d["ip"], "action": "keep", "why": "",
               "manual": bool(re.search(r"static|fixed", typ or "", re.I)), "type": typ}
        if d.get("random"):
            row.update(action="skip", why="randomized (private) MAC: it changes, so it cannot be reserved")
        elif d["mac"] in moving:
            new, why = want[d["mac"]], ""
            try:
                a = ipaddress.IPv4Address(new)
                if nw and (a not in nw or a in (nw.network_address, nw.broadcast_address)):
                    why = f"{new} is outside this network or is its network / broadcast address"
                elif new == gw_ip:
                    why = f"{new} is the router's own IP"
                elif new in taken:
                    why = f"{new} is already used by another device"
            except ValueError:
                why = f"{new} is not an IP address"
            if why:
                row.update(action="skip", why=why)
            else:
                taken.add(new)
                row.update(ip_new=new, action="move", why="chosen by you; the device takes it when it reconnects "
                           "(switch its Wi-Fi off and on, or 'ipconfig /renew')")
        elif cnt[d["ip"]] > 1 or (d.get("conflict") and not any(x["ip"] == d["ip"] for x in live if x["mac"] in moving)):
            row.update(action="skip", why="IP conflict: fix the conflict first")
        elif len(d.get("ips") or []) > 1:
            row.update(action="skip", why="answers on several IPs")
        elif g in (move or ()) and ranges.get(g) and not _in_range(d["ip"], ranges[g]):
            lo, hi = _ipkey(ranges[g][0]), _ipkey(ranges[g][1])
            new = next((str(ipaddress.IPv4Address(i)) for i in range(lo, hi + 1)
                        if str(ipaddress.IPv4Address(i)) not in taken
                        and (not nw or ipaddress.IPv4Address(i) in nw)), None)
            if new:
                taken.add(new)
                row.update(ip_new=new, action="move",
                           why="hand-typed IP: also change it on the device itself" if row["manual"] else
                           "gets the new IP when it renews (restart it or 'ipconfig /renew')")
            else:
                row.update(action="skip", why=f"no free IP left in {ranges[g][0]} - {ranges[g][1]}")
        elif row["manual"]:
            row["why"] = "hand-typed IP on the device: the reservation keeps others from taking it"
        rows.append(row)
    return rows


def reservation_rows(plan_rows):
    return [dict(r["dev"], ip=r["ip_new"]) for r in plan_rows if r["action"] in ("keep", "move")]


def reservation_commands(plan_rows, tags):
    """DHCP reservations (router keeps the IP for the MAC; the device stays on 'automatic')."""
    return T.binding_commands(reservation_rows(plan_rows), tags or {})


def extra_ips(plan_rows):
    """{mac: [old IP]} for devices that are moving, so the queues / firewall cover both addresses meanwhile."""
    return {r["dev"]["mac"]: [r["ip_now"]] for r in plan_rows if r["action"] == "move"}


def ip_list_csv(plan_rows, tags=None):
    """The 'IP list' to keep: also used to type the same fixed IP into cameras after a power cut / camera swap."""
    import csv
    import io
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["Group", "Name", "IP (use this)", "IP now", "MAC", "IP type", "Action", "Note"])
    for r in plan_rows:
        d = r["dev"]
        t = (tags or {}).get(d["mac"], {})
        w.writerow([GROUP_TITLE.get(r["group"], r["group"]), t.get("name") or d.get("name") or "", r["ip_new"],
                    r["ip_now"], d["mac"], r["type"], r["action"], r["why"]])
    return out.getvalue()


# --------------------------------------------------------------------------------------------------- NVR / DVR sizing
OVERHEAD = 1.2  # network overhead on top of the video bitrate


def nvr_sizing(cams=50, nvrs=2, sub=0.5, main=3.0, viewers=3, cams_per_viewer=9, download=8.0):
    """Internet UPLOAD the recorders need for remote viewing. sub / main: video Mbps of one camera's sub-stream /
    main-stream (typical values - check Camera > Encode on the NVR). download: one clip download or playback."""
    live = viewers * cams_per_viewer * sub * OVERHEAD
    need = live + download * OVERHEAD
    reserve = math.ceil(need / 0.8 / 5.0) * 5  # 80% of the reserve is usable; round up to 5 Mbps
    reserve_live = math.ceil(live / 0.8 / 5.0) * 5
    per_cam = sub * OVERHEAD
    return {"cams": cams, "nvrs": nvrs, "per_cam_sub": round(per_cam, 2), "per_cam_main": round(main * OVERHEAD, 2),
            "live_need": round(live, 1), "with_download": round(need, 1), "reserve": reserve,
            "reserve_live": reserve_live,
            "all_sub": round(cams * per_cam, 1), "all_main": round(cams * main * OVERHEAD, 1),
            "recording": round(cams * main, 1),
            "cams_in_10": int(10 * 0.8 / per_cam), "cams_in_20": int(20 * 0.8 / per_cam),
            "per_nvr": round(reserve / max(nvrs, 1), 1)}


def download_minutes(video_mbps, video_minutes, link_mbps):
    """Minutes to fetch a clip: video_mbps is the camera's bitrate, link_mbps what the NVR may upload (80% usable)."""
    size_mb = video_mbps * video_minutes * 60
    return round(size_mb / max(link_mbps * 0.8, 0.1) / 60.0, 1)


# --------------------------------------------------------------------------------------------------- the camera chart
def diagram_spec(n_cams=0, n_nvr=0, n_pc=0, n_mobile=0, line=100, nvr_mbps=10):
    """Boxes and arrows of the CCTV set-up. Used by the page (canvas) and the .svg export."""
    nodes = [
        ("phone", "Phone / PC anywhere", ["DMSS / Hik-Connect / XMeye app", "live view, playback, download"], 30, 20, 250, 70, "app"),
        ("net", f"Internet - {line:g} Mbps", ["maker's cloud relay (P2P)", "no open port, no port-forward"], 330, 20, 250, 70, "net"),
        ("router", "Router (MikroTik)", [f"NVR / DVR: {nvr_mbps:g} Mbps kept for remote view",
                                         "cameras: internet BLOCKED", "port-forwards to CCTV: closed"], 330, 150, 250, 86, "router"),
        ("core", "Office switch", ["office PCs, mobiles, Wi-Fi", f"{n_pc} PCs, {n_mobile} mobiles online"], 330, 290, 250, 60, "lan"),
        ("nvr", f"NVR / DVR ({n_nvr})" if n_nvr else "NVR / DVR", ["records all cameras", "talks to the cloud (outbound only)",
                                                                   "USB export = emergency copy"], 30, 400, 260, 86, "nvr"),
        ("cctv", "CCTV / PoE switches", ["cameras and recorders", "stay on the local network"], 330, 400, 250, 60, "lan"),
        ("cams", f"{n_cams} CCTV cameras" if n_cams else "CCTV cameras", ["send video only to the NVR / DVR",
                                                                         "fixed IP list, saved on the router"], 640, 400, 230, 70, "cam"),
    ]
    edges = [
        ("phone", "net", "", "ok"),
        ("net", "router", f"{line:g} Mbps line", "ok"),
        ("router", "core", "", "ok"),
        ("core", "nvr", "view on the office network", "ok"),
        ("nvr", "cctv", "", "ok"),
        ("cams", "cctv", "", "ok"),
        ("cctv", "core", "", "ok"),
        ("cams", "router", "NO INTERNET", "blocked"),
    ]
    return {"w": 900, "h": 520, "nodes": nodes, "edges": edges,
            "notes": ["Green = allowed. Red dashed = blocked on the router.",
                      "Check cameras from anywhere in the NVR / DVR app. In an emergency: app > Playback > Download, "
                      "or copy to a USB stick at the NVR."]}


_FILL = {"app": "#ede9fe", "net": "#e0f2fe", "router": "#dbeafe", "lan": "#f1f5f9", "nvr": "#dcfce7", "cam": "#fef3c7"}
_LINE = {"app": "#7c3aed", "net": "#0369a1", "router": "#1d4ed8", "lan": "#64748b", "nvr": "#15803d", "cam": "#b45309"}


def _anchor(node, other):
    """Point on the edge of a box facing the other box."""
    _, _, _, x, y, w, h, _ = node
    _, _, _, ox, oy, ow, oh, _ = other
    cx, cy, ocx, ocy = x + w / 2, y + h / 2, ox + ow / 2, oy + oh / 2
    if abs(ocy - cy) >= abs(ocx - cx) and abs(ocy - cy) > (h + oh) / 2 - 1:
        return (cx if abs(ocx - cx) < 1 else min(max(ocx, x + 12), x + w - 12), y + h if ocy > cy else y)
    return (x + w if ocx > cx else x, cy if abs(ocy - cy) < 1 else min(max(ocy, y + 12), y + h - 12))


def diagram_lines(spec):
    """[(x1, y1, x2, y2, label, kind)] for the arrows."""
    by = {n[0]: n for n in spec["nodes"]}
    out = []
    for a, b, label, kind in spec["edges"]:
        (x1, y1), (x2, y2) = _anchor(by[a], by[b]), _anchor(by[b], by[a])
        out.append((x1, y1, x2, y2, label, kind))
    return out


def label_pos(x1, y1, x2, y2, kind):
    """Where an arrow's label goes: the middle, or nearer the camera end for the blocked arrow (clear of the boxes)."""
    t = 0.3 if kind == "blocked" else 0.5
    return x1 + (x2 - x1) * t, y1 + (y2 - y1) * t


def diagram_svg(spec):
    w, h = spec["w"], spec["h"] + 56
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
         f'font-family="Segoe UI, Arial, sans-serif">',
         f'<rect width="{w}" height="{h}" fill="#ffffff"/>',
         '<defs><marker id="ok" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
         'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#15803d"/></marker>'
         '<marker id="bad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
         'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#b91c1c"/></marker></defs>']
    for x1, y1, x2, y2, label, kind in diagram_lines(spec):
        col = "#b91c1c" if kind == "blocked" else "#15803d"
        dash = ' stroke-dasharray="7 5"' if kind == "blocked" else ""
        mk = "bad" if kind == "blocked" else "ok"
        s.append(f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" stroke="{col}" stroke-width="2.4"'
                 f'{dash} marker-end="url(#{mk})"/>')
    for _id, title, lines, x, y, bw, bh, style in spec["nodes"]:
        s.append(f'<rect x="{x}" y="{y}" width="{bw}" height="{bh}" rx="9" fill="{_FILL[style]}" stroke="{_LINE[style]}" '
                 f'stroke-width="2"/>')
        s.append(f'<text x="{x + 10}" y="{y + 22}" font-size="14" font-weight="bold" fill="{_LINE[style]}">{escape(title)}</text>')
        for i, ln in enumerate(lines):
            s.append(f'<text x="{x + 10}" y="{y + 42 + i * 16}" font-size="12" fill="#344054">{escape(ln)}</text>')
    for x1, y1, x2, y2, label, kind in diagram_lines(spec):  # labels last, so no box can cover them
        if label:
            col = "#b91c1c" if kind == "blocked" else "#15803d"
            mx, my = label_pos(x1, y1, x2, y2, kind)
            lw = 6.6 * len(label) + 12
            s.append(f'<rect x="{mx - lw / 2:.0f}" y="{my - 10:.0f}" width="{lw:.0f}" height="20" rx="4" fill="#ffffff"/>')
            s.append(f'<text x="{mx:.0f}" y="{my + 4:.0f}" font-size="12" font-weight="bold" fill="{col}" '
                     f'text-anchor="middle">{escape(label)}</text>')
    for i, ln in enumerate(spec["notes"]):
        s.append(f'<text x="30" y="{spec["h"] + 14 + i * 18}" font-size="12" fill="#475467">{escape(ln)}</text>')
    s.append("</svg>")
    return "\n".join(s)
