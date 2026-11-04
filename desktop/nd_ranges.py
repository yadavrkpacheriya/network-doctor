# -*- coding: utf-8 -*-
"""
Network Doctor - find devices on EVERY IP range, not only the one this PC sits in.

A device whose address is from another series (a camera still on 192.168.1.108, a PC with a hand-typed 10.0.0.x, a VLAN)
is invisible to a scan that sweeps only this PC's own network. Three sources fix that, all read-only:
  * this PC's other network adapters (cable + Wi-Fi in different ranges),
  * the router: its own interface addresses, DHCP server networks, ARP table, leases and discovered neighbours,
  * the router's switch table (bridge hosts): every MAC on the cable, even one with no usable IP - listed as
    "connected but no IP in a scanned range" so nothing stays hidden.
No packet is sent by this module; nd_core.scan() does the sweeping with the ranges it returns.
"""
import ipaddress
import re

MAX_ADDRESSES = 4096
# Adapters that are not part of the office network (virtual switches, VPNs, containers) - sweeping them only wastes time.
SKIP_ADAPTER_RE = re.compile(r"vethernet|wsl|virtualbox|vmware|docker|hyper-v|loopback|bluetooth|tailscale|zerotier|"
                             r"wireguard|openvpn|vpn|tap-windows|npcap|isatap|teredo|pseudo|veth|br-|virbr|lo\b", re.I)
_PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_private_net(net):
    """RFC 1918 only: not link-local (169.254), not shared/CGNAT (100.64), not loopback, not public."""
    return any(net.subnet_of(p) for p in _PRIVATE)


def _ip_ok(ip):
    try:
        return any(ipaddress.IPv4Address(ip) in p for p in _PRIVATE)
    except ValueError:
        return False


def _covered(net, nets):
    return any(net.subnet_of(n) for n in nets)


def _count(nets):
    hosts = set()
    for n in nets:
        hosts.update(int(h) for h in n.hosts())
    return len(hosts)


# ------------------------------------------------------------------ this PC's own adapters
def _prefix_of(mask):
    try:
        return ipaddress.IPv4Network("0.0.0.0/" + mask).prefixlen
    except ValueError:
        return None


def parse_ipconfig(text):
    """[(ip, prefix, adapter)] from Windows `ipconfig` (any display language: only the numbers are read)."""
    out, adapter, last_ip = [], "", None
    for line in (text or "").splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            adapter, last_ip = line.strip().rstrip(":"), None
            continue
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        if not m:
            continue
        val = m.group(1)
        if val.startswith("255.") and last_ip:
            p = _prefix_of(val)
            if p:
                out.append((last_ip, p, adapter))
            last_ip = None
        elif not val.startswith("255."):
            last_ip = val
    return out


def parse_ip_addr(text):
    """[(ip, prefix, adapter)] from Linux `ip -o -4 addr show`."""
    out = []
    for m in re.finditer(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", text or "", re.M):
        out.append((m.group(2), int(m.group(3)), m.group(1)))
    return out


def parse_ifconfig(text):
    """[(ip, prefix, adapter)] from macOS `ifconfig`."""
    out = []
    for block in re.split(r"\n(?=\S)", text or ""):
        name = block.split(":", 1)[0].strip()
        for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]{8}|\d+\.\d+\.\d+\.\d+)", block):
            mask = m.group(2)
            if mask.startswith("0x"):
                mask = str(ipaddress.IPv4Address(int(mask, 16)))
            p = _prefix_of(mask)
            if p:
                out.append((m.group(1), p, name))
    return out


def nets_of(entries, max_prefix_len=22):
    """Networks of an adapter list: private only, no virtual / VPN adapters, nothing bigger than a /22."""
    nets = []
    for ip, prefix, adapter in entries:
        if SKIP_ADAPTER_RE.search(adapter or "") or not _ip_ok(ip) or prefix < max_prefix_len or prefix > 30:
            continue
        n = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        if n not in nets:
            nets.append(n)
    return nets


def local_networks(run, is_win, is_mac):
    """Private networks of this PC's real adapters. run(list[str], timeout) -> text (nd_core.run)."""
    try:
        if is_win:
            entries = parse_ipconfig(run(["ipconfig"], 10))
        elif is_mac:
            entries = parse_ifconfig(run(["ifconfig"], 10))
        else:
            entries = parse_ip_addr(run(["ip", "-o", "-4", "addr", "show"], 10))
    except Exception:
        return []
    return nets_of(entries)


# ------------------------------------------------------------------ what the router adds
def router_candidates(addresses=(), dhcp_networks=()):
    """[(network, why)] from the router's interface addresses and DHCP server networks."""
    out = []
    for r in addresses or []:
        if str(r.get("disabled", "false")).lower() == "true" or str(r.get("invalid", "false")).lower() == "true":
            continue
        try:
            n = ipaddress.ip_network(str(r.get("address", "")), strict=False)
        except ValueError:
            continue
        out.append((n, f"router interface {r.get('interface', '') or '?'} ({r.get('address')})"))
    for r in dhcp_networks or []:
        try:
            n = ipaddress.ip_network(str(r.get("address", "")), strict=False)
        except ValueError:
            continue
        out.append((n, f"router DHCP network {r.get('address')}"))
    return out


def plan_extra_nets(current, candidates=(), seen_ips=(), limit=MAX_ADDRESSES):
    """Which ranges to add to `current` (list of IPv4Network).
    candidates: [(network, why)], seen_ips: private IPs the router knows (ARP / leases / neighbours).
    Returns {'added': [(net, why)], 'skipped': [(net, why)]}. Never more than `limit` addresses in all; a range bigger than
    a /22 is not swept whole - only the /24s where the router actually knows a device."""
    have = list(current)
    added, skipped = [], []

    def take(net, why):
        if _covered(net, have):
            return
        if _count(have + [net]) > limit:
            skipped.append((net, why + " - not added: more than %d addresses in all" % limit))
            return
        have.append(net)
        added.append((net, why))

    for net, why in candidates:
        if net.version != 4 or not is_private_net(net) or net.prefixlen > 30:
            continue
        if net.prefixlen < 22:
            continue  # handled through the devices the router knows inside it
        take(net, why)
    groups = {}
    for ip in seen_ips:
        if not _ip_ok(ip):
            continue
        n = ipaddress.ip_network(ip + "/24", strict=False)
        if not _covered(n, have):
            groups[n] = groups.get(n, 0) + 1
    for net, cnt in sorted(groups.items(), key=lambda x: (-x[1], int(x[0].network_address))):
        take(net, f"the router knows {cnt} device(s) in it")
    return {"added": added, "skipped": skipped}


# ------------------------------------------------------------------ MACs with no IP
def norm_mac(m):
    h = re.sub(r"[^0-9A-Fa-f]", "", str(m or "")).upper()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else ""


def _bad(mac):
    return (not mac) or mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF") or bool(int(mac[:2], 16) & 1)


def mac_only_hosts(bridge_hosts, known_macs):
    """Devices the router's switch table sees on a cable / Wi-Fi port that no scan source gave an IP for.
    [{'mac', 'port', 'vlan', 'age'}] sorted by port. Router's own MACs ('local') and multicast are left out."""
    known = {norm_mac(m) for m in known_macs}
    out, seen = [], set()
    for r in bridge_hosts or []:
        mac = norm_mac(r.get("mac-address", ""))
        if _bad(mac) or mac in known or mac in seen:
            continue
        if str(r.get("local", "false")).lower() == "true" or str(r.get("invalid", "false")).lower() == "true":
            continue
        seen.add(mac)
        out.append({"mac": mac, "port": r.get("on-interface", ""), "vlan": r.get("vid", ""), "age": r.get("age", "")})
    return sorted(out, key=lambda x: (x["port"], x["mac"]))


def neighbor_ips(neighbors):
    """{ip: mac} from /ip neighbor (MNDP / CDP / LLDP): the neighbour's own claim of its IP, even from another series."""
    out = {}
    for r in neighbors or []:
        ip = str(r.get("address", "")).split(",")[0].strip()
        mac = norm_mac(r.get("mac-address", ""))
        if _ip_ok(ip) and mac:
            out[ip] = mac
    return out
