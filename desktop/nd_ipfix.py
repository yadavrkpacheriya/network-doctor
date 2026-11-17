# -*- coding: utf-8 -*-
"""Permanent fix for a recurring fixed-IP conflict.

Why conflicts came back every day: the old auto-fix only acted when exactly one device was tagged
"Default device for its IP". Cameras are rarely tagged, so nothing happened and the same IP clashed again
the next day. And even when the router reserved the IP, a camera with a HARD-TYPED static IP kept claiming
it, so the clash returned.

The permanent fix is two halves, and this module plans both from plain inputs (pure functions, easy to test
against the sandbox):

  1. RESERVE on the router  - make-static the MAC<->IP lease so the DHCP server never hands that IP to anyone
                              else. Safe: touches only the router, no device goes offline.
  2. SWITCH the loser to DHCP - if the OTHER device on that IP is a camera we hold a login for, turn its wired
                              interface to automatic IP so it stops hard-claiming the address and takes a
                              clean one from the router. This is the "static -> DHCP" half that ends the daily
                              recurrence for good.

RouterOS commands use FULL paths ("/ip dhcp-server lease ...") - never the bare-verb WinBox style - because
that is what the app's script runner needs.
"""
import re

_MAC = re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}")


def norm_mac(m):
    return (m or "").upper().replace("-", ":")


def free_ips(used, base, want=12, lo=2, hi=254):
    """Unused addresses in a /24, so a new static IP never clashes. `used` is the IPs already on the network
    (devices + leases + ARP); `base` is the first three octets, e.g. '192.168.1'. Skips .1 (the gateway) by
    default (lo=2). Returns up to `want` free IPs in order."""
    used = {str(u) for u in (used or [])}
    out = []
    for n in range(lo, hi + 1):
        ip = "%s.%d" % (base, n)
        if ip not in used:
            out.append(ip)
            if len(out) >= want:
                break
    return out


def base24(ip):
    """'192.168.1.64' -> '192.168.1' (the /24 prefix), or '' if not an IPv4."""
    p = str(ip).split(".")
    return ".".join(p[:3]) if len(p) == 4 else ""


# --------------------------------------------------------------- reach an off-subnet camera
def reach_ip(cam_ip, used=None):
    """Pick a free address on the CAMERA's /24 for the PC to borrow temporarily, so it can reach a camera on
    another subnet (browser + the direct fix tools then work). Prefers .250 downward, skips the camera's own
    IP, the gateway (.1) and anything already used. '' if cam_ip isn't an IPv4."""
    base = base24(cam_ip)
    if not base:
        return ""
    used = {str(u) for u in (used or [])}
    used.add(cam_ip)
    for n in (250, 251, 252, 249, 248, 240, 200, 199, 100):
        ip = "%s.%d" % (base, n)
        if ip not in used and n != 1:
            return ip
    for n in range(2, 255):                      # fall back to any free host
        ip = "%s.%d" % (base, n)
        if ip not in used and ip != cam_ip:
            return ip
    return ""


def netsh_add_argv(iface, ip, mask="255.255.255.0"):
    """Add a second IP to a Windows adapter (no gateway - routing stays on the main IP). Reversible."""
    return ["netsh", "interface", "ipv4", "add", "address", "name=%s" % iface, ip, mask]


def netsh_del_argv(iface, ip):
    """Remove the temporary second IP added by netsh_add_argv."""
    return ["netsh", "interface", "ipv4", "delete", "address", "name=%s" % iface, "address=%s" % ip]


def reach_guide(cam_ip, temp_ip=""):
    """Plain manual steps to reach an off-subnet camera, shown as the fallback if the one-click temp IP fails."""
    base = base24(cam_ip) or "192.168.1"
    temp_ip = temp_ip or (base + ".250")
    return ("Manual steps to reach %s (it is on a different subnet):\n"
            "  1. Open Windows 'Change adapter options' > your LAN adapter > Properties >\n"
            "     Internet Protocol Version 4 > Properties > Advanced > Add a second IP:\n"
            "         IP: %s    Mask: 255.255.255.0   (leave gateway blank)\n"
            "  2. Open  http://%s  in your browser and log in to the camera.\n"
            "  3. Set the camera's IP to your main range (e.g. 192.168.0.x) and save.\n"
            "  4. Remove the second IP you added in step 1.\n"
            "Your main network keeps working the whole time." % (cam_ip, temp_ip, cam_ip))


# --------------------------------------------------------------- router reserve recipe
def reserve_recipe(ip, mac, name=""):
    """(cmd, undo) that pins `ip` to `mac` permanently on a MikroTik. Idempotent: an existing dynamic lease is
    made static and re-addressed; otherwise a static lease is added. The comment lets Undo find exactly this."""
    mac = norm_mac(mac)
    tag = f'ND: fixed IP{(" - " + name) if name else ""}'
    cmd = (f':local l [/ip dhcp-server lease find where mac-address="{mac}"]\n'
           f':if ([:len $l] > 0) do={{ :do {{ /ip dhcp-server lease make-static $l }} on-error={{}}; '
           f'/ip dhcp-server lease set $l address={ip} comment="{tag}" }} '
           f'else={{ /ip dhcp-server lease add address={ip} mac-address="{mac}" comment="{tag}" }}')
    undo = (f':do {{ /ip dhcp-server lease remove [find where mac-address="{mac}" and '
            f'comment~"^ND: fixed IP"] }} on-error={{}}')
    return cmd, undo


# --------------------------------------------------------------- who keeps the IP
def lease_holder(ip, leases):
    """The MAC the router currently has a lease for at `ip` (the device the network already knows), or ''."""
    for ln in leases or []:
        if str(ln.get("address", "")) == ip:
            return norm_mac(ln.get("mac-address", ""))
    return ""


def choose_keeper(ip, macs, leases, tags=None):
    """Which MAC should KEEP `ip`, and why. Priority tag wins; else the current lease holder; else None
    (truly ambiguous - stays a manual fix, never a guess). Returns (mac_or_None, reason)."""
    macs = [norm_mac(m) for m in macs if m]
    tags = tags or {}
    tagged = [m for m in macs if (tags.get(m) or {}).get("priority")]
    if len(tagged) == 1:
        return tagged[0], "tagged 'Default device for its IP'"
    if len(tagged) > 1:
        return None, "more than one device is tagged default - cannot choose"
    held = lease_holder(ip, leases)
    if held and held in macs:
        return held, "the router already leases this IP to it"
    if held and not macs:
        return held, "the router already leases this IP to it"
    if len(macs) == 1:
        return macs[0], "only one device claims this IP"
    return None, "no device is tagged default and none holds the lease - manual choice needed"


# --------------------------------------------------------------- the losing static camera
def camera_on(ip_or_mac, cameras):
    """A known camera entry {'ip','mac','method','name'} matching an IP or MAC, or None.
    `method` is one of nd_camline.SETTERS ('hik','dahua','xmeye','onvif')."""
    key = norm_mac(ip_or_mac) if _MAC.fullmatch(ip_or_mac or "") else ip_or_mac
    for c in cameras or []:
        if norm_mac(c.get("mac", "")) == key or c.get("ip") == ip_or_mac:
            return c
    return None


def permanent_plan(ip, macs, leases=None, cameras=None, saved=None, tags=None):
    """Full permanent recipe for a fixed-IP conflict on `ip` between `macs`.

    Returns {
      'keeper': mac|None, 'keeper_reason': str,
      'reserve': (cmd, undo)|None,              # router half - safe to auto-apply
      'switch':  {'ip','method','cred','mac'}|None,  # camera static->DHCP half (needs a saved login)
      'why': [human lines], 'auto_router_ok': bool,
    }
    'switch' is filled only when the LOSING device is a known camera we have a saved login for, so the app can
    end the recurrence without anyone typing an IP into a camera by hand."""
    macs = [norm_mac(m) for m in macs if m]
    saved = saved or {}
    keeper, reason = choose_keeper(ip, macs, leases, tags)
    why = []
    out = {"keeper": keeper, "keeper_reason": reason, "reserve": None, "switch": None,
           "why": why, "auto_router_ok": False}
    if not keeper:
        why.append(f"not reserving {ip}: {reason}")
        return out

    name = (tags or {}).get(keeper, {}).get("name", "") if tags else ""
    out["reserve"] = reserve_recipe(ip, keeper, name)
    out["auto_router_ok"] = True
    why.append(f"reserve {ip} for {name or keeper} on the router ({reason})")

    loser = next((m for m in macs if m != keeper), "")
    if loser:
        cam = camera_on(loser, cameras)
        cred = (saved or {}).get(loser)
        if cam and cam.get("method") and cred:
            out["switch"] = {"ip": cam.get("ip") or ip, "method": cam["method"], "cred": cred, "mac": loser}
            why.append(f"switch the other device ({cam.get('name') or loser}) to automatic IP so it stops "
                       f"claiming {ip} - uses its saved login, no typing")
        elif cam:
            why.append(f"the other device ({cam.get('name') or loser}) looks like a camera but has no saved "
                       "login - switch it to automatic IP by hand, or run the Login sweep first")
        else:
            why.append(f"the other device ({loser}) keeps its IP; if it is hard-set, switch it to automatic")
    return out
