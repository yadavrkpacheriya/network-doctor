# -*- coding: utf-8 -*-
"""
Network Doctor - "Reset everything the app changed on the router".

Safety rules (they are tested in tests/test_reset.py):
  * Only things the app made are touched. Every rule / queue / address list / DHCP reservation the app creates carries
    an "ND" name or comment; the ISP's and the owner's own configuration never does, so it is never matched.
  * Rules the app only SWITCHED OFF (a port-forward, FastTrack) are marked "ND-off: " / "ND-rel: " in their comment.
    The reset puts the original comment back and switches them on again BEFORE it removes anything.
  * Every removal has a 'where' condition. No bare 'remove [find]', no reset-configuration, no /user, /ip service,
    /interface or /system change.
  * A copy of the router's configuration is exported to a file on the router first (nd-before-reset.rsc).
  * Global settings the app can change by name (DNS servers, UPnP, loop protection, IGMP snooping, ARP mode) cannot
    be put back blindly - the router does not remember the old value - so they are only listed, never touched.
"""
import re

OFF = "ND-off: "    # switched off by the bandwidth / camera pages (undo switches on)
REL = "ND-rel: "    # auto-defense blocks released by hand (undo switches on)

# What the app creates: comments start "ND " or "ND:" ; queue names start "ND " or "ND-" ; address lists start "ND-".
COMMENT_RE = r"^ND[ :]"
QUEUE_RE = r"^ND[ -]"
LIST_RE = r"^ND-"

RULE_PATHS = ("/ip firewall filter", "/ip firewall nat", "/ip firewall mangle", "/interface bridge filter",
              "/ip dns static")
SCOPES = ("limits", "ips")
SCOPE_TITLE = {"limits": "blocks, limits and rules", "ips": "fixed-IP reservations"}

# Settings that the app's fixes can change on the router and that this reset CANNOT undo by itself.
GLOBAL_CHANGES = (
    ("/ip dns  (servers, allow-remote-requests)", "Fix 'slow web' / DNS fixes set 1.1.1.1 and 8.8.8.8 as the router's DNS. "
     "Winbox > IP > DNS: put back the DNS your ISP gave you (it is also on the ISP's paper / DHCP client)."),
    ("/ip upnp  (enabled)", "'Close internet access to a device' turns UPnP off. Winbox > IP > UPnP: switch it on again only "
     "if you need it."),
    ("/interface ethernet  loop-protect, /interface bridge  igmp-snooping, protocol-mode", "Loop / IGMP fixes. Winbox > "
     "Interfaces / Bridge: switch off what you do not want."),
    ("/interface bridge  arp, /ip dhcp-server  add-arp", "The 'bind IP to MAC' fix can set ARP to reply-only. Winbox > Bridge: "
     "set ARP back to 'enabled'; IP > DHCP Server: untick Add ARP For Leases."),
)


def _ros_off(path, cond, tag=OFF):
    """Disables the rules matching cond and marks them with tag so an undo can enable exactly those again."""
    return (f':foreach r in=[{path} find where {cond}] do={{ {path} set $r comment=("{tag}" . [{path} get $r comment]); '
            f'{path} disable $r }}')


def _ros_on(path, tag=OFF, extra=""):
    """Switches the rules marked with tag on again (extra: ' and to-addresses=1.2.3.4' narrows it to one device)."""
    n = len(tag)
    return (f':foreach r in=[{path} find where comment~"^{tag}"{extra}] do={{ :local c [{path} get $r comment]; '
            f'{path} set $r comment=[:pick $c {n} [:len $c]]; {path} enable $r }}')


def reset_commands(scopes=SCOPES):
    """(script, notes). The script is the reset; notes lists what it does and what it does NOT touch."""
    scopes = [s for s in SCOPES if s in set(scopes)]
    if not scopes:
        raise ValueError("choose what to reset")
    out = ["# Network Doctor - RESET of everything the app changed on the router",
           "# Only items named / commented 'ND ...' are removed. Everything else stays exactly as it is.",
           ':do { /export file=nd-before-reset } on-error={}']
    if "limits" in scopes:
        # 1) put back what the app only switched off (port-forwards, FastTrack ...) - BEFORE any removal
        for p in ("/ip firewall filter", "/ip firewall nat", "/ip firewall mangle"):
            out.append(_ros_on(p, OFF))
        # 2) released auto-defense blocks are the app's own rules: remove them
        out.append(f':do {{ /ip firewall filter remove [find where comment~"^{REL}"] }} on-error={{}}')
        # 3) what the app added
        for p in RULE_PATHS:
            out.append(f':do {{ {p} remove [find where comment~"{COMMENT_RE}"] }} on-error={{}}')
        out.append(f':do {{ /queue simple remove [find where name~"{QUEUE_RE}" or comment~"{COMMENT_RE}"] }} on-error={{}}')
        out.append(f':do {{ /queue type remove [find where name~"^ND-"] }} on-error={{}}')
        out.append(f':do {{ /ip firewall address-list remove [find where list~"{LIST_RE}" or comment~"{COMMENT_RE}"] }} '
                   "on-error={}")
        out.append(":do { /ip dns cache flush } on-error={}")
    if "ips" in scopes:
        out.append(f':do {{ /ip dhcp-server lease remove [find where comment~"{COMMENT_RE}"] }} on-error={{}}')
    notes = [f"Resets: {', '.join(SCOPE_TITLE[s] for s in scopes)}.",
             "A copy of the router configuration is saved first (file nd-before-reset.rsc on the router).",
             "Rules the app switched off (port-forwards, FastTrack) are switched on again - if a camera / DVR "
             "port-forward comes back, the DVR is open to the internet again." if "limits" in scopes else "",
             "Reservations: devices keep working but may get another IP after the next restart." if "ips" in scopes else "",
             "NOT touched: the ISP / owner configuration, router users and passwords, services, interfaces, "
             "the bridge, the DHCP server and its pools, NAT masquerade, wireless, VPN, routes."]
    return "\n".join(out) + "\n", [n for n in notes if n]


def _name(r):
    return str(r.get("name", ""))


def classify(tables):
    """What a reset would do, from rows read from the router (read-only). tables: {path: [row dict]}.
    Returns {'restore': [...], 'remove': [...]} with (path, what) pairs."""
    restore, remove = [], []
    for p in ("/ip firewall filter", "/ip firewall nat", "/ip firewall mangle"):
        for r in tables.get(p) or []:
            c = str(r.get("comment", ""))
            if c.startswith(OFF):
                restore.append((p, c[len(OFF):] or r.get("chain", "") + " rule"))
            elif c.startswith(REL):
                remove.append((p, c[len(REL):]))
    for p in RULE_PATHS:
        for r in tables.get(p) or []:
            if re.search(COMMENT_RE, str(r.get("comment", ""))):
                remove.append((p, str(r.get("comment"))))
    for r in tables.get("/queue simple") or []:
        if re.search(QUEUE_RE, _name(r)) or re.search(COMMENT_RE, str(r.get("comment", ""))):
            remove.append(("/queue simple", _name(r)))
    for r in tables.get("/queue type") or []:
        if re.search(r"^ND-", _name(r)):
            remove.append(("/queue type", _name(r)))
    seen = set()
    for r in tables.get("/ip firewall address-list") or []:
        k = str(r.get("list", ""))
        if (re.search(LIST_RE, k) or re.search(COMMENT_RE, str(r.get("comment", "")))) and k not in seen:
            seen.add(k)
            remove.append(("/ip firewall address-list", k))
    for r in tables.get("/ip dhcp-server lease") or []:
        if re.search(COMMENT_RE, str(r.get("comment", ""))):
            remove.append(("/ip dhcp-server lease", f"{r.get('address', '')} {r.get('mac-address', '')}".strip()))
    return {"restore": restore, "remove": remove}


READ_PATHS = ("/ip firewall filter", "/ip firewall nat", "/ip firewall mangle", "/interface bridge filter",
              "/ip dns static", "/queue simple", "/queue type", "/ip firewall address-list", "/ip dhcp-server lease")


def report_text(found):
    """Plain-language list of what the app has changed on the router (from classify())."""
    if not found["restore"] and not found["remove"]:
        return "The router has nothing made by Network Doctor. Nothing to reset."
    lines = []
    if found["restore"]:
        lines.append(f"SWITCHED ON AGAIN by a reset ({len(found['restore'])}) - the app had switched these off:")
        lines += [f"  {p}: {w}" for p, w in found["restore"]]
    if found["remove"]:
        lines.append(f"REMOVED by a reset ({len(found['remove'])}) - made by the app:")
        lines += [f"  {p}: {w}" for p, w in found["remove"]]
    return "\n".join(lines)


def global_text():
    return "\n".join(f"- {a}\n    {b}" for a, b in GLOBAL_CHANGES)
