"""WiFi / LAN access guard - why a device that should get on the network cannot, and a safe one-click fix.

The classic trap: after you start MAC/IP binding, someone sets the LAN bridge (or the WiFi interface) ARP mode to
'reply-only'. From then on ONLY devices already in the static ARP/lease list can talk - every unbound device
(above all phones, which rotate their WiFi MAC) silently fails to connect, even though the WiFi password is right.
A near-full DHCP pool does the same thing more quietly: there is simply no address left to hand a new device.

This module finds those two blockers and plans a reversible fix (set the interface ARP back to 'enabled', never
touching anything else), so bound devices keep their fixed IPs and unbound devices can join again. It is pure
functions over the rows the RouterOS API returns, plus thin read/apply/undo helpers, so the logic tests without a
router and the actual change is ALWAYS a reviewed one-click with a config backup and an undo - never automatic
(changing how the network admits devices must be a human decision)."""

# interface kinds that carry client devices (where reply-only ARP blocks people). Not WAN/ppp/tunnels.
_LAN_KINDS = ("bridge", "ether", "wlan", "wifi", "vlan")
# a near-full pool is a blocker too
POOL_WARN_FREE = 5


def _is_lan(row):
    name = (row.get("name") or "").lower()
    typ = (row.get("type") or "").lower()
    if name.startswith(("pppoe", "wg", "gre", "eoip", "l2tp", "sstp", "ovpn", "lo")):
        return False
    return typ.startswith(_LAN_KINDS) or name.startswith(_LAN_KINDS)


def find_blockers(interfaces):
    """interfaces: rows from /interface/print. Returns the LAN interfaces set to arp=reply-only (they block every
    unbound device). Each: {name, id, arp}."""
    out = []
    for r in interfaces or []:
        if _is_lan(r) and (r.get("arp") or "").lower() == "reply-only":
            out.append({"name": r.get("name", "?"), "id": r.get(".id", ""), "arp": r.get("arp")})
    return out


def pool_health(leases, pools=None):
    """Rough DHCP headroom from /ip/dhcp-server/lease/print (and optional /ip/pool/print rows). Returns
    {used, static, dynamic, waiting, tight}. 'tight' means new devices may get no address."""
    used = len(leases or [])
    static = sum(1 for l in leases or [] if str(l.get("dynamic", "")).lower() != "true")
    dynamic = used - static
    waiting = sum(1 for l in leases or [] if str(l.get("status", "")).lower() == "waiting")
    total = 0
    for p in pools or []:
        for part in str(p.get("ranges", "")).split(","):
            lo, _, hi = part.partition("-")
            try:
                total += int(hi.strip().split(".")[-1]) - int(lo.strip().split(".")[-1]) + 1
            except (ValueError, IndexError):
                pass
    free = (total - used) if total else None
    tight = bool(waiting) or (free is not None and free <= POOL_WARN_FREE)
    return {"used": used, "static": static, "dynamic": dynamic, "waiting": waiting,
            "free": free, "tight": tight}


def assess(blockers, pool):
    """One alert (or None) describing what is keeping devices off the network."""
    if blockers:
        names = ", ".join(b["name"] for b in blockers)
        return {"kind": "arp_block", "sev": "warning",
                "text": f"{names} is set to ARP 'reply-only', so only bound devices can connect - unbound phones "
                        f"and new devices are being blocked. One click sets it back to 'enabled'."}
    if pool and pool.get("tight"):
        w = pool.get("waiting") or 0
        return {"kind": "dhcp_full", "sev": "warning",
                "text": f"The DHCP pool is almost full ({pool.get('used')} in use"
                        + (f", {w} waiting" if w else "") + ") - new devices may get no address. Widen the range."}
    return None


def read(client):
    """Router I/O. Returns (info, alert_or_None). info has interfaces blockers + pool health. Any router error is
    swallowed into an empty, quiet result so a missing section never raises."""
    try:
        ifaces = client.cmd("/interface/print")
    except Exception:  # noqa: BLE001
        return {"blockers": [], "pool": {}}, None
    blockers = find_blockers(ifaces)
    pool = {}
    try:
        pool = pool_health(client.cmd("/ip/dhcp-server/lease/print"), _try(client, "/ip/pool/print"))
    except Exception:  # noqa: BLE001
        pass
    info = {"blockers": blockers, "pool": pool}
    return info, assess(blockers, pool)


def _try(client, path):
    try:
        return client.cmd(path)
    except Exception:  # noqa: BLE001
        return []


def apply_fix(client, blockers):
    """Set each blocking interface's ARP back to 'enabled' - the ONLY change made. Returns an undo list
    [{id, arp}] of the previous values so it can be put back exactly. Caller takes a config backup first."""
    undo = []
    for b in blockers or []:
        if not b.get("id"):
            continue
        client.talk(["/interface/set", "=.id=" + b["id"], "=arp=enabled"])
        undo.append({"id": b["id"], "arp": b.get("arp", "reply-only")})
    return undo


def undo_fix(client, undo):
    """Restore the interfaces to exactly what they were (used by the standard Undo)."""
    for u in undo or []:
        client.talk(["/interface/set", "=.id=" + u["id"], "=arp=" + u.get("arp", "reply-only")])


# ---- whitelist ------------------------------------------------------------------------------------------------
def norm_mac(mac):
    return (mac or "").strip().lower().replace("-", ":")


def is_whitelisted(whitelist, mac):
    """True when this MAC is on the always-allow list. Whitelisted devices are kept open and are never blocked or
    quarantined by the app's own security features - so they always get internet whether or not their MAC is
    randomised (the network itself stays open for them; we do not rely on binding a MAC that may rotate)."""
    m = norm_mac(mac)
    return any(norm_mac(w.get("mac")) == m for w in whitelist or [] if w.get("mac"))


def add_to_whitelist(whitelist, mac, name=""):
    """Add (idempotent). Returns the list."""
    m = norm_mac(mac)
    if not m:
        return whitelist or []
    wl = list(whitelist or [])
    if not any(norm_mac(w.get("mac")) == m for w in wl):
        wl.append({"mac": m, "name": name or ""})
    return wl


def remove_from_whitelist(whitelist, mac):
    m = norm_mac(mac)
    return [w for w in whitelist or [] if norm_mac(w.get("mac")) != m]
