# -*- coding: utf-8 -*-
"""
Network Doctor - Linux network facts (nd_linux)
=========================================================
Reads the kernel's own files (/proc and /sys) instead of command-line tools,
because `arp`, `ifconfig` and `netstat` are missing on most modern Linux
systems. Every function returns None / empty when it cannot find the answer,
and takes its root folders as arguments so the tests can use sample files.
"""

import ipaddress
import os
import re
import socket
import struct

PROC = "/proc"
SYS = "/sys/class/net"


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


def _int(path):
    v = _read(path)
    try:
        return int(v)
    except ValueError:
        return None


def default_gateway(proc=PROC):
    """(gateway_ip, interface) of the default route with the lowest metric, or (None, None)."""
    best = None
    for line in _read(os.path.join(proc, "net", "route")).splitlines()[1:]:
        p = line.split()
        if len(p) < 7 or p[1] != "00000000" or not int(p[3], 16) & 2:  # destination 0.0.0.0, RTF_GATEWAY
            continue
        gw = socket.inet_ntoa(struct.pack("<I", int(p[2], 16)))
        metric = int(p[6])
        if best is None or metric < best[2]:
            best = (gw, p[0], metric)
    return (best[0], best[1]) if best else (None, None)


def arp_table(proc=PROC):
    """{ip: mac} of complete entries in the kernel's neighbour table."""
    res = {}
    for line in _read(os.path.join(proc, "net", "arp")).splitlines()[1:]:
        p = line.split()
        # IP address, HW type, Flags, HW address, Mask, Device; flag 0x2 = complete
        if len(p) >= 6 and int(p[2], 16) & 2 and p[3] != "00:00:00:00:00:00":
            res[p[0]] = p[3].upper()
    return res


def _ioctl_addr(name, req):
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        r = fcntl.ioctl(s.fileno(), req, struct.pack("256s", name.encode()[:15]))
        return socket.inet_ntoa(r[20:24])
    except OSError:
        return None
    finally:
        s.close()


def iface_ipv4(name):
    """(ip, prefix) of an interface, or (None, None)."""
    ip = _ioctl_addr(name, 0x8915)  # SIOCGIFADDR
    if not ip:
        return None, None
    mask = _ioctl_addr(name, 0x891B)  # SIOCGIFNETMASK
    try:
        prefix = ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen if mask else None
    except ValueError:
        prefix = None
    return ip, prefix


def iface_of(ip, sysdir=SYS):
    """Name of the interface that has this IPv4 address, or None."""
    for name in sorted(os.listdir(sysdir)) if os.path.isdir(sysdir) else []:
        if iface_ipv4(name)[0] == ip:
            return name
    return None


def mac_of(name, sysdir=SYS):
    return _read(os.path.join(sysdir, name, "address")).upper()


def prefix_of(ip, sysdir=SYS):
    name = iface_of(ip, sysdir)
    return iface_ipv4(name)[1] if name else None


VIRTUAL = re.compile(r"^(lo|docker|veth|br-|virbr|vmnet|vboxnet|tun|tap|wg|zt|tailscale|ifb|dummy)")


def adapters(sysdir=SYS, addr=iface_ipv4):
    """Same dicts as nd_net.adapters() on Windows / Mac."""
    res = []
    for name in sorted(os.listdir(sysdir)) if os.path.isdir(sysdir) else []:
        d = os.path.join(sysdir, name)
        if name == "lo":
            continue
        st = os.path.join(d, "statistics")
        oper = _read(os.path.join(d, "operstate"))
        mbps = _int(os.path.join(d, "speed"))  # -1 or unreadable when the link is down / for Wi-Fi
        bps = mbps * 1_000_000 if mbps and mbps > 0 else 0
        dup = _read(os.path.join(d, "duplex"))
        wifi = os.path.isdir(os.path.join(d, "wireless")) or os.path.isdir(os.path.join(d, "phy80211"))
        ip, prefix = addr(name)
        real = os.path.exists(os.path.join(d, "device"))  # backed by hardware
        res.append({"name": name, "desc": "Wi-Fi" if wifi else ("Ethernet" if real else "virtual"),
                    "status": "Up" if oper in ("up", "unknown") and ip else "Disconnected",
                    "speed": f"{mbps} Mbps" if bps else "", "bps": bps,
                    "duplex": None if dup not in ("full", "half") else dup == "full",
                    "mac": mac_of(name, sysdir), "wifi": wifi,
                    "rxerr": _int(os.path.join(st, "rx_errors")) or 0, "txerr": _int(os.path.join(st, "tx_errors")) or 0,
                    "rxdisc": _int(os.path.join(st, "rx_dropped")) or 0,
                    "txdisc": _int(os.path.join(st, "tx_dropped")) or 0,
                    "ip": ip or "", "prefix": prefix, "mtu": _int(os.path.join(d, "mtu")) or 0,
                    "virtual": not real or bool(VIRTUAL.match(name)), "hw": real})
    return res
