#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Doctor - scan engine (nd_core)
=========================================================
A separate desktop app. It does not need WinBox, router logins or any other tool.

How it stays accurate where ordinary IP scanners get confused:
  * Live ARP sweep (every device must answer ARP, even with ping blocked).
  * Repeated ARP rounds with a cleared cache (run as administrator) so TWO
    devices answering for ONE IP are caught = real IP-conflict detection.
  * Reads each PC's CURRENT name from the PC itself (NetBIOS), plus UPnP
    device descriptions, web-page titles and open services to identify it.
  * Remembers every device by MAC in its own database (first seen, last seen,
    old IPs, your labels) so old records never mix with live ones.
  * Explains repeated names (randomized Wi-Fi MAC, cable + Wi-Fi, cloned PC).
  * Loop / storm checks: broadcast rate, gateway packet loss and latency,
    duplicate ping replies, optional echo test.
  * Rogue DHCP check: asks every DHCP server on the LAN to answer.

Runs on plain Python 3.9+ (Tkinter is included with Python on Windows).
Optional: Scapy + Npcap unlock extra packet-level tests automatically.
"""

import csv
import ctypes
import datetime as dt
import html
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

import nd_linux

APP = "Network Doctor"
VERSION = "3.16.0"
IS_WIN = os.name == "nt"
IS_MAC = sys.platform == "darwin"
if getattr(sys, "frozen", False):
    HERE = os.path.dirname(sys.executable)
else:
    HERE = os.path.dirname(os.path.abspath(__file__))
if IS_WIN:
    DATA_DIR = os.path.join(os.environ.get("APPDATA", HERE), "NetworkDoctor")
elif IS_MAC:  # never inside the .app bundle (read-only / moved by macOS)
    DATA_DIR = os.path.join(os.path.expanduser("~"), "Library", "Application Support", "NetworkDoctor")
else:
    DATA_DIR = os.path.join(os.path.expanduser("~"), ".local", "share", "NetworkDoctor")
DB_PATH = os.path.join(DATA_DIR, "devices_db.json")
OUI_PATH = os.path.join(DATA_DIR, "oui_cache.json")
REPORT_DIR = os.path.join(os.path.expanduser("~"), "Documents", "NetworkDoctor Reports")


# ==========================================================================
# helpers
# ==========================================================================
# --------------------------------------------------------------------------
# Name lookups that still work when this PC's own DNS server does not answer (a wrong DNS from a second router,
# the website firewall stopped while the PC points to itself, ISP DNS down). Only used after a normal lookup fails.
PUBLIC_DNS = ("1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222")
_orig_getaddrinfo = socket.getaddrinfo
_dns_cache = {}
_dns_state = {"fallback_used": 0, "last_host": ""}


def _skip_name(msg, off):
    while True:
        ln = msg[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            return off + 2
        off += ln + 1


def public_resolve(host, timeout=2.0):
    """IPv4 addresses of host asked directly from public DNS servers, or []."""
    host = host.strip(".").lower()
    hit = _dns_cache.get(host)
    if hit and time.time() - hit[0] < 600:
        return hit[1]
    q = b"".join(bytes([len(p)]) + p.encode("idna") for p in host.split(".")) + b"\x00"
    for server in PUBLIC_DNS:
        qid = random.randint(1, 0xFFFF)
        pkt = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(timeout)
            s.sendto(pkt, server if isinstance(server, tuple) else (server, 53))
            data, _ = s.recvfrom(4096)
            if struct.unpack("!H", data[:2])[0] != qid:
                continue
            an = struct.unpack("!H", data[6:8])[0]
            off = _skip_name(data, 12) + 4
            ips = []
            for _ in range(an):
                off = _skip_name(data, off)
                typ, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
                off += 10
                if typ == 1 and rdlen == 4:
                    ips.append(socket.inet_ntoa(data[off:off + 4]))
                off += rdlen
            if ips:
                _dns_cache[host] = (time.time(), ips)
                return ips
        except (OSError, struct.error, IndexError):
            continue
        finally:
            s.close()
    return []


def _getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    try:
        return _orig_getaddrinfo(host, port, family, type, proto, flags)
    except socket.gaierror:
        h = host.decode() if isinstance(host, bytes) else (host or "")
        if ("." not in h or re.fullmatch(r"[\d.]+|[0-9a-fA-F:]+", h) or
                h.lower().endswith((".local", ".lan", ".home", ".internal", ".localdomain"))):
            raise
        ips = public_resolve(h)
        if not ips:
            raise
        _dns_state["fallback_used"] += 1
        _dns_state["last_host"] = h
        out = []
        for ip in ips:
            out += _orig_getaddrinfo(ip, port, socket.AF_INET, type, proto, flags)
        return out


socket.getaddrinfo = _getaddrinfo


def run(cmd, timeout=10):
    kw = {"creationflags": 0x08000000} if IS_WIN else {}
    try:
        r = subprocess.run(cmd, capture_output=True, stdin=subprocess.DEVNULL, text=True, timeout=timeout,
                           errors="replace", **kw)
        return r.stdout or ""
    except Exception:
        return ""


def norm_mac(m):
    if not m:
        return ""
    if isinstance(m, (bytes, bytearray)):
        m = bytes(m).hex()
    parts = re.split(r"[:\-]", str(m).strip())
    if len(parts) == 6 and all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", x) for x in parts):
        m = "".join(x.zfill(2) for x in parts)
    h = re.sub(r"[^0-9A-Fa-f]", "", str(m)).upper()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else ""


def is_random_mac(mac):
    return bool(mac) and (int(mac[1], 16) & 2) != 0


def is_bad_mac(mac):
    return (not mac) or mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF") or bool(int(mac[0:2], 16) & 1)


def ip_key(ip):
    try:
        return int(ipaddress.IPv4Address(ip))
    except Exception:
        return 1 << 40


def is_admin():
    if not IS_WIN:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def now_s():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M")


# ==========================================================================
# network discovery primitives
# ==========================================================================
def detect_network():
    gw = lip = None
    if IS_WIN:
        out = run(["route", "print", "-4", "0.0.0.0"], 10)
        active = out.split("Persistent Routes")[0]
        routes = re.findall(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)",
                            active, re.M)
        if routes:
            gw, lip, _ = min(routes, key=lambda r: int(r[2]))  # lowest metric = the route Windows really uses
    elif IS_MAC:
        m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", run(["route", "-n", "get", "default"], 5))
        if m:
            gw = m.group(1)
    else:
        m = re.search(r"default via (\S+)", run(["ip", "route", "show", "default"], 5))
        gw = m.group(1) if m else nd_linux.default_gateway()[0]
    if not lip:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((gw or "8.8.8.8", 80))
            lip = s.getsockname()[0]
            s.close()
        except Exception:
            lip = "127.0.0.1"
    return gw, lip


def local_mac(lip):
    if IS_WIN:
        out = run(["ipconfig", "/all"], 10)
        for block in re.split(r"\r?\n(?=\S)", out):
            if re.search(r"\b" + re.escape(lip) + r"\b", block):
                m = re.search(r"Physical Address[ .]*:\s*([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})\b", block) or \
                    re.search(r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})(?!-)", block)
                if m:
                    return norm_mac(m.group(1))
    if IS_MAC:
        for block in re.split(r"\n(?=\S)", run(["ifconfig"], 10)):
            if re.search(r"inet " + re.escape(lip) + r"\b", block):
                m = re.search(r"ether\s+([0-9a-fA-F:]{11,17})", block)
                if m:
                    return norm_mac(m.group(1))
    if not IS_WIN and not IS_MAC:
        name = nd_linux.iface_of(lip)
        if name and norm_mac(nd_linux.mac_of(name)):
            return norm_mac(nd_linux.mac_of(name))
    n = uuid.getnode()
    return norm_mac("%012X" % n)


_SENDARP = None


def win_sendarp(ip):
    global _SENDARP
    try:
        if _SENDARP is None:
            fn = ctypes.windll.iphlpapi.SendARP
            fn.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
            fn.restype = ctypes.c_uint32
            _SENDARP = fn
        dest = struct.unpack("<I", socket.inet_aton(ip))[0]
        buf = ctypes.create_string_buffer(8)
        size = ctypes.c_ulong(6)
        if _SENDARP(dest, 0, buf, ctypes.byref(size)) == 0 and size.value == 6:
            mac = norm_mac(buf.raw[:6])
            return None if is_bad_mac(mac) else mac
    except Exception:
        pass
    return None


def flush_arp_cache():
    if IS_WIN:
        run(["netsh", "interface", "ip", "delete", "arpcache"], 10)
    elif IS_MAC:
        run(["arp", "-d", "-a"], 10)
    else:
        run(["ip", "neigh", "flush", "all"], 10)


def ping_cmd(ip, wait_ms=1000):
    if IS_WIN:
        return ["ping", "-n", "1", "-w", str(wait_ms), ip]
    if IS_MAC:  # macOS: -W is in milliseconds, -t is the overall timeout in seconds
        return ["ping", "-c", "1", "-W", str(wait_ms), "-t", "2", ip]
    return ["ping", "-c", "1", "-W", str(max(1, wait_ms // 1000)), ip]


def ping(ip, wait_ms=800):
    cmd = ping_cmd(ip, wait_ms)
    m = re.search(r"ttl[=:]\s*(\d+)", run(cmd, 5), re.I)
    return int(m.group(1)) if m else None


def os_arp_table():
    res = {}
    for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?([0-9a-fA-F]{1,2}(?:[-:][0-9a-fA-F]{1,2}){5})", run(["arp", "-a"], 15)):
        mac = norm_mac(m.group(2))
        if not is_bad_mac(mac):
            res[m.group(1)] = mac
    if not IS_WIN and not IS_MAC:  # `arp` is often not installed on Linux; the kernel table always is
        for ip, mac in nd_linux.arp_table().items():
            if not is_bad_mac(norm_mac(mac)):
                res.setdefault(ip, norm_mac(mac))
    return res


PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "Web", 135: "Windows RPC", 139: "NetBIOS",
    443: "Web (https)", 445: "File sharing", 515: "LPD print", 548: "Apple share", 554: "RTSP video",
    631: "IPP print", 1883: "MQTT IoT", 3389: "Remote Desktop", 4370: "Biometric (ZK/eSSL)",
    5000: "Web/NAS", 5900: "VNC", 7547: "TR-069 router", 8000: "Hikvision/Web", 8080: "Web-alt",
    8291: "MikroTik WinBox", 8443: "Web-alt (https)", 8728: "MikroTik API", 9100: "RAW print",
    34567: "XMeye DVR", 37777: "Dahua DVR", 62078: "iPhone/iPad",
}


def tcp_open(ip, port, timeout=0.6):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def http_info(ip, port):
    try:
        s = socket.create_connection((ip, port), timeout=2)
        if port in (443, 8443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s)
        s.settimeout(2)
        s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetworkDoctor\r\n\r\n".encode())
        data = b""
        while len(data) < 20000:
            try:
                c = s.recv(4096)
            except Exception:
                break
            if not c:
                break
            data += c
        s.close()
    except Exception:
        return None
    t = data.decode("latin-1", "replace")
    out = {"port": port}
    for key, rx in (("server", r"^Server:\s*(.+?)\r?$"), ("title", r"<title[^>]*>(.*?)</title>"),
                    ("realm", r'WWW-Authenticate:.*?realm="([^"]*)"')):
        m = re.search(rx, t, re.I | re.M | re.S)
        if m:
            out[key] = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
    out["blob"] = t[:5000].lower()
    return out


def netbios_query(ip, timeout=1.2):
    tid = random.randint(0, 0xFFFF)
    enc = b"".join(bytes([0x41 + (c >> 4), 0x41 + (c & 0x0F)]) for c in b"*" + b"\x00" * 15)
    pkt = struct.pack(">HHHHHH", tid, 0, 1, 0, 0, 0) + b"\x20" + enc + b"\x00" + struct.pack(">HH", 0x21, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, 137))
        data, _ = s.recvfrom(4096)
    except Exception:
        return None
    finally:
        s.close()
    try:
        off = 12
        if data[off] & 0xC0 == 0xC0:
            off += 2
        else:
            while data[off] != 0:
                off += data[off] + 1
            off += 1
        off += 10
        n = data[off]
        off += 1
        host = group = None
        for i in range(n):
            e = data[off + i * 18: off + i * 18 + 18]
            if len(e) < 18:
                break
            nm = e[:15].decode("ascii", "replace").strip()
            suf, fl = e[15], struct.unpack(">H", e[16:18])[0]
            if suf == 0 and not fl & 0x8000 and not host:
                host = nm
            if suf == 0 and fl & 0x8000 and not group:
                group = nm
        mo = off + n * 18
        mac = norm_mac(data[mo:mo + 6]) if len(data) >= mo + 6 else ""
        if host:
            return {"name": host, "group": group or "", "mac": "" if is_bad_mac(mac) else mac}
    except Exception:
        pass
    return None


def reverse_dns(ip):
    try:
        n = socket.gethostbyaddr(ip)[0]
        return "" if n == ip else n
    except Exception:
        return ""


def ssdp_discover(lip, wait=4):
    """UPnP discovery: routers, cameras, NVRs, printers, TVs describe themselves."""
    found = {}
    msg = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
           'MX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(lip))
        except Exception:
            pass
        s.bind((lip, 0))
        s.settimeout(0.5)
        for _ in range(2):
            s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + wait
        while time.time() < end:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            except Exception:
                break
            t = data.decode("latin-1", "replace")
            d = found.setdefault(addr[0], {"st": set(), "server": "", "location": ""})
            for k, rx in (("server", r"^SERVER:\s*(.+?)\r?$"), ("location", r"^LOCATION:\s*(.+?)\r?$")):
                m = re.search(rx, t, re.I | re.M)
                if m and not d[k]:
                    d[k] = m.group(1).strip()
            m = re.search(r"^ST:\s*(.+?)\r?$", t, re.I | re.M)
            if m:
                d["st"].add(m.group(1).strip())
        s.close()
    except Exception:
        return found

    def describe(ip):
        d = found[ip]
        if not d["location"]:
            return
        try:
            req = urllib.request.Request(d["location"], headers={"User-Agent": "NetworkDoctor"})
            x = urllib.request.urlopen(req, timeout=3).read(60000).decode("utf-8", "replace")
            for tag in ("friendlyName", "manufacturer", "modelName", "modelDescription", "deviceType"):
                m = re.search(rf"<{tag}>(.*?)</{tag}>", x, re.S)
                if m:
                    d[tag] = html.unescape(m.group(1).strip())[:80]
        except Exception:
            pass

    with ThreadPoolExecutor(16) as ex:
        list(ex.map(describe, list(found)))
    for d in found.values():
        d["st"] = sorted(d["st"])
    return found


def nonunicast_rx():
    """Broadcast + multicast packets received (netstat -e 'Non-unicast'). Fallback only: see bcast_mcast_rx."""
    if not IS_WIN:
        return None
    m = re.search(r"Non-unicast packets\s+(\d+)\s+(\d+)", run(["netstat", "-e"], 10))
    return int(m.group(1)) if m else None


# Broadcast and multicast counted separately. netstat's 'Non-unicast' adds them together, but multicast (CCTV / NVR
# streams, mDNS, SSDP, IPv6, IPTV) is not a loop sign: on offices with cameras it alone passes the storm limit, and
# the "unplug cables to find the loop" advice then never makes the warning go away.
NU_PS = ("$b=0;$m=0;foreach($s in (Get-NetAdapterStatistics -ErrorAction SilentlyContinue)){"
         "$b+=[uint64]$s.ReceivedBroadcastPackets;$m+=[uint64]$s.ReceivedMulticastPackets};\"$b $m\"")


def bcast_mcast_rx():
    """(broadcast, multicast) packets received on all adapters, or None when Windows cannot split them."""
    if not IS_WIN:
        return None
    m = re.search(r"(\d+)\s+(\d+)", run(["powershell", "-NoProfile", "-NonInteractive", "-Command", NU_PS], 20))
    if not m or (m.group(1) == "0" and m.group(2) == "0"):  # some drivers do not fill these counters
        return None
    return int(m.group(1)), int(m.group(2))


def nu_snapshot():
    """('split', broadcast, multicast) or ('sum', broadcast+multicast, None) or None."""
    bm = bcast_mcast_rx()
    if bm:
        return ("split",) + bm
    n = nonunicast_rx()
    return ("sum", n, None) if n is not None else None


def nu_rates(tests, s0, s1, secs):
    """Fills tests['bcast_pps'] (+ 'mcast_pps', or 'bcast_mixed' when only the total was available)."""
    if not s0 or not s1 or s0[0] != s1[0] or s1[1] < s0[1]:
        return
    secs = max(secs, 1)
    tests["bcast_pps"] = round((s1[1] - s0[1]) / secs, 1)
    if s0[0] == "split":
        tests["mcast_pps"] = round(max(0, s1[2] - s0[2]) / secs, 1)
    else:
        tests["bcast_mixed"] = True


class NuCounter:
    """One hidden PowerShell that prints the broadcast / multicast counters every second (for the live monitor,
    where starting PowerShell every 2 s would cost too much CPU)."""

    def __init__(self):
        self.val, self.t, self.p = None, 0.0, None

    def start(self):
        if not IS_WIN:
            return
        try:
            self.p = subprocess.Popen(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "while($true){" + NU_PS + ";[Console]::Out.Flush();Start-Sleep -Seconds 1}"],
                stdout=subprocess.PIPE, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True,
                creationflags=0x08000000)
        except Exception:
            self.p = None
            return
        threading.Thread(target=self._read, daemon=True, name="nu-counter").start()

    def _read(self):
        try:
            for line in self.p.stdout:
                m = re.match(r"\s*(\d+)\s+(\d+)", line)
                if m and (m.group(1) != "0" or m.group(2) != "0"):
                    self.val, self.t = (int(m.group(1)), int(m.group(2))), time.time()
        except Exception:
            pass

    def read(self):
        return self.val if self.val and time.time() - self.t < 5 else None

    def stop(self):
        try:
            if self.p:
                self.p.kill()
        except Exception:
            pass


def gateway_monitor(gw, count, result):
    """Pings the gateway once a second during the scan: loss / spikes point to loops or bad cabling."""
    if IS_WIN:
        out = run(["ping", "-n", str(count), "-w", "1000", gw], count * 2 + 10)
        m = re.search(r"\((\d+)%", out)
        t = re.search(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", out)
        result["loss"] = int(m.group(1)) if m else None
        if t:
            result.update(min=int(t.group(1)), max=int(t.group(2)), avg=int(t.group(3)))
    else:
        cmd = ["ping", "-c", str(count), "-i", "1"] + (["-W", "1000"] if IS_MAC else []) + [gw]
        out = run(cmd, count * 2 + 10)
        m = re.search(r"([\d.]+)% packet loss", out)
        t = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)", out)
        result["loss"] = float(m.group(1)) if m else None
        if t:
            result.update(min=float(t.group(1)), avg=float(t.group(2)), max=float(t.group(3)))
    result["count"] = count


def _cksum(b):
    if len(b) % 2:
        b += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def icmp_duplicate_test(target, lip, count=20):
    """Raw ICMP (admin): one request should get exactly one reply. Duplicates = loop or IP conflict."""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.bind((lip, 0))
    s.settimeout(0.1)
    ident = random.randint(1, 0xFFFF)
    replies = Counter()
    payload = b"NetworkDoctorDup" * 2
    for seq in range(count):
        hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
        s.sendto(struct.pack("!BBHHH", 8, 0, _cksum(hdr + payload), ident, seq) + payload, (target, 0))
        end = time.time() + (0.3 if seq < count - 1 else 1.5)
        while time.time() < end:
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                continue
            ihl = (data[0] & 0x0F) * 4
            if len(data) < ihl + 8:
                continue
            t, _, _, i, sq = struct.unpack("!BBHHH", data[ihl:ihl + 8])
            if t == 0 and i == ident:
                replies[sq] += 1
    s.close()
    return {"sent": count, "answered": len(replies), "dups": sum(v - 1 for v in replies.values() if v > 1)}


def dhcp_probe_udp(mac, wait=5):
    """DHCP DISCOVER with this PC's own MAC; lists every server that offers (rogue DHCP check)."""
    xid = random.getrandbits(32)
    pkt = (struct.pack("!BBBBIHHIIII", 1, 1, 6, 0, xid, 0, 0x8000, 0, 0, 0, 0) +
           bytes.fromhex(mac.replace(":", "")) + b"\x00" * 10 + b"\x00" * 192 +
           b"\x63\x82\x53\x63" + b"\x35\x01\x01" + b"\x37\x03\x01\x03\x06" + b"\xff")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(("", 68))
    s.settimeout(0.5)
    s.sendto(pkt, ("255.255.255.255", 67))
    servers = {}
    end = time.time() + wait
    while time.time() < end:
        try:
            data, addr = s.recvfrom(4096)
        except socket.timeout:
            continue
        if len(data) < 240 or data[0] != 2 or struct.unpack("!I", data[4:8])[0] != xid:
            continue
        opts, i = {}, 240
        while i < len(data) and data[i] != 255:
            if data[i] == 0:
                i += 1
                continue
            code, ln = data[i], data[i + 1]
            opts[code] = data[i + 2:i + 2 + ln]
            i += 2 + ln
        sid = socket.inet_ntoa(opts[54][:4]) if 54 in opts else addr[0]
        servers[sid] = {"offered": socket.inet_ntoa(data[16:20]),
                        "gateway": socket.inet_ntoa(opts[3][:4]) if 3 in opts else "",
                        "lease": struct.unpack("!I", opts[51][:4])[0] if 51 in opts and len(opts[51]) >= 4 else None,
                        "mac": ""}
    s.close()
    return servers


# ---- optional Scapy + Npcap tests -----------------------------------------
_SCAPY = None


def scapy_ok():
    """Imports Scapy once (slow) and remembers the answer."""
    global _SCAPY
    if _SCAPY is None:
        try:
            import scapy.all  # noqa
            _SCAPY = True
        except Exception:
            _SCAPY = False
    return _SCAPY


def _scapy_iface(gw):
    from scapy.all import conf
    try:
        conf.iface = conf.route.route(gw)[0]
    except Exception:
        pass
    return conf.iface


def scapy_arp_all_replies(network, gw, rounds=2):
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0
    _scapy_iface(gw)
    rep = defaultdict(set)
    for _ in range(rounds):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)), timeout=3, multi=True, retry=0)
        for _, r in ans:
            mac = norm_mac(r.hwsrc)
            if not is_bad_mac(mac):
                rep[r.psrc].add(mac)
    return rep


def scapy_dhcp_probe(gw, wait=6):
    from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp, get_if_hwaddr, conf
    conf.verb = 0
    conf.checkIPaddr = False
    iface = _scapy_iface(gw)
    mac = get_if_hwaddr(iface)
    xid = random.getrandbits(32)
    pkt = (Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / IP(src="0.0.0.0", dst="255.255.255.255") /
           UDP(sport=68, dport=67) /
           BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")) + b"\x00" * 10, xid=xid, flags=0x8000) /
           DHCP(options=[("message-type", "discover"), "end"]))
    ans, _ = srp(pkt, timeout=wait, multi=True)
    out = {}
    for _, r in ans:
        if r.haslayer(BOOTP) and r[BOOTP].xid == xid:
            sid, rt, lease = r[IP].src, "", None
            for o in r[DHCP].options:
                if isinstance(o, tuple) and o[0] == "lease_time":
                    lease = o[1]
                if isinstance(o, tuple) and o[0] == "server_id":
                    sid = o[1]
                if isinstance(o, tuple) and o[0] == "router":
                    rt = o[1]
            out[sid] = {"mac": norm_mac(r[Ether].src), "offered": r[BOOTP].yiaddr, "gateway": rt, "lease": lease}
    return out


def scapy_loop_echo(gw, listen=4):
    from scapy.all import Ether, Raw, sendp, AsyncSniffer, get_if_hwaddr, conf
    conf.verb = 0
    iface = _scapy_iface(gw)
    token = ("NDLOOP%08x" % random.getrandbits(32)).encode()
    sn = AsyncSniffer(iface=iface, filter="ether proto 0x88b5", store=True)
    sn.start()
    time.sleep(0.5)
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(iface), type=0x88B5) / Raw(load=token * 4),
          iface=iface, count=3, inter=0.2)
    time.sleep(listen)
    pkts = sn.stop() or []
    return {"sent": 3, "seen": sum(1 for p in pkts if token in bytes(p))}


# ==========================================================================
# vendor database
# ==========================================================================
def load_oui(log=lambda m: None):
    if os.path.exists(OUI_PATH):
        try:
            with open(OUI_PATH, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    db = {}
    for url, kind in (("https://standards-oui.ieee.org/oui/oui.csv", "csv"),
                      ("https://www.wireshark.org/download/automated/data/manuf", "manuf")):
        try:
            log("Downloading MAC vendor list (first run only)...")
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 NetworkDoctor"})
            data = urllib.request.urlopen(req, timeout=40).read().decode("utf-8", "replace")
            if kind == "csv":
                for row in csv.reader(data.splitlines()):
                    if len(row) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{6}", row[1]):
                        db[row[1].upper()] = row[2].strip()
            else:
                for line in data.splitlines():
                    p = line.split("\t")
                    if len(p) >= 2 and re.fullmatch(r"[0-9A-Fa-f:]{8}", p[0]):
                        db[p[0].replace(":", "").upper()] = (p[2] if len(p) > 2 else p[1]).strip()
            if len(db) > 1000:
                os.makedirs(DATA_DIR, exist_ok=True)
                with open(OUI_PATH, "w", encoding="utf-8") as f:
                    json.dump(db, f)
                return db
        except Exception:
            continue
    return db


def vendor_of(mac, oui):
    if not mac:
        return ""
    if is_random_mac(mac):
        return "Private / randomized MAC"
    return oui.get(mac.replace(":", "")[:6], "")


# ==========================================================================
# categories
# ==========================================================================
CAT_ROUTER = "Router / Gateway"
CAT_NET = "Network equipment (router / switch / AP)"
CAT_PC = "Computers / laptops"
CAT_CAM = "CCTV cameras / DVR / NVR"
CAT_PRN = "Printers / scanners"
CAT_BIO = "Biometric / attendance"
CAT_PHONE = "Phones / tablets"
CAT_IOT = "Smart TV / IoT"
CAT_UNK = "Unknown devices"
CAT_OFF = "Not online now (seen before)"
CAT_ORDER = [CAT_ROUTER, CAT_NET, CAT_PC, CAT_CAM, CAT_PRN, CAT_BIO, CAT_PHONE, CAT_IOT, CAT_UNK, CAT_OFF]

V_CAM = ["hikvision", "dahua", "uniview", "aditya infotech", "cp plus", "xiongmai", "tvt digital", "axis communications",
         "hanwha", "vivotek", "tiandy", "ezviz", "imou", "prama", "milesight", "godrej security"]
V_PRN = ["canon", "epson", "brother", "kyocera", "ricoh", "xerox", "konica", "lexmark", "toshiba tec", "zebra",
         "tvs electronics", "pantum", "sharp corp"]
V_BIO = ["zkteco", "essl", "suprema", "anviz", "realtime biometrics", "matrix comsec"]
V_NET = ["mikrotik", "routerboard", "tp-link", "tenda", "d-link", "netgear", "ubiquiti", "cisco", "ruckus", "aruba",
         "juniper", "h3c", "ruijie", "cambium", "mercusys", "digisol", "netis", "totolink", "fortinet", "sophos",
         "sonicwall", "zyxel", "linksys", "edimax", "syrotech", "jio", "airtel"]
V_PC = ["dell", "lenovo", "liteon", "lite-on", "intel corp", "realtek", "asustek", "giga-byte", "gigabyte",
        "micro-star", "lcfc", "azurewave", "hon hai", "foxconn", "quanta", "wistron", "compal", "pegatron",
        "hewlett packard", "hp inc", "acer", "chicony", "universal global scien", "microsoft", "rivet networks"]
V_PHONE = ["apple", "samsung", "xiaomi", "oppo", "vivo mobile", "oneplus", "realme", "motorola", "huawei device",
           "honor device", "google", "nokia", "transsion", "infinix", "tecno"]
V_IOT = ["espressif", "tuya", "shelly", "itead", "broadlink", "amazon technologies", "sonos", "roku", "lg electronics",
         "tcl", "hisense", "skyworth"]


def _has(t, words):
    t = (t or "").lower()
    return any(w in t for w in words)


PHONE_NAMES = (r"(android|iphone|ipad|galaxy|redmi|oppo|vivo|realme|oneplus|poco|pixel|moto[ -g]|motorola|nokia|"
               r"infinix|tecno|itel|iqoo|nord|xiaomi|samsung|\bsm-[a-z]\d|huawei|honor|narzo|lava|nothing-phone|"
               r"\bmi-|\bmi \d|apple-watch|watch)")


def categorize(d, gw):
    p = set(d["ports"])
    v = (d["vendor"] or "").lower()
    name = (d["name"] or "").lower()
    up = d.get("upnp") or {}
    uptxt = " ".join([up.get("deviceType", ""), up.get("manufacturer", ""), up.get("modelName", ""),
                      up.get("modelDescription", ""), up.get("friendlyName", ""), up.get("server", ""),
                      " ".join(up.get("st", []))]).lower()
    web = " ".join([d["http"].get("title", ""), d["http"].get("server", ""), d["http"].get("realm", ""),
                    d["http"].get("blob", "")[:3000]]).lower()
    nb = bool(d["names"].get("netbios") or d["names"].get("smb"))
    if d["ip"] == gw:
        return CAT_ROUTER, "default gateway of this network"
    if d.get("self"):
        return CAT_PC, "this computer (running the scan)"
    cam_ports = p & {554, 37777, 34567}
    if cam_ports or _has(v, V_CAM) or _has(uptxt, ["camera", "nvr", "dvr", "hikvision", "dahua"]) \
            or re.search(r"\b(dvr|nvr|ipc|ip ?camera|netsurveillance)\b", web) \
            or _has(web, ["hikvision", "dahua", "doc/page/login"]) or re.search(r"\b(dvr|nvr|cctv|cam)\b", name):
        why = []
        if cam_ports:
            why.append("video ports " + ", ".join(map(str, sorted(cam_ports))))
        if _has(v, V_CAM):
            why.append("camera brand")
        if up.get("modelName") and _has(uptxt, ["camera", "nvr", "dvr"]):
            why.append("UPnP: " + up.get("modelName"))
        return CAT_CAM, "; ".join(why) or "camera web page / name"
    if p & {9100, 515, 631} or _has(uptxt, ["printer"]) or (_has(v, V_PRN) and not p & {445, 3389}) \
            or re.match(r"^(npi|brw|epson|hp[0-9a-f]{6})", name):
        return CAT_PRN, "printing ports" if p & {9100, 515, 631} else "printer brand / UPnP / name"
    if 4370 in p or _has(v, V_BIO):
        return CAT_BIO, "attendance port 4370" if 4370 in p else "biometric brand"
    if p & {135, 139, 445, 3389} or nb or re.match(r"^(desktop|laptop|pc|win)-", name):
        why = []
        if p & {135, 139, 445, 3389}:
            why.append("Windows services (" + ", ".join(PORTS[x] for x in sorted(p & {135, 139, 445, 3389})) + ")")
        if nb:
            why.append("answers with computer name")
        return CAT_PC, "; ".join(why) or "computer-style name"
    if "internetgatewaydevice" in uptxt or "wandevice" in uptxt:
        return CAT_NET, "UPnP router (" + (up.get("modelName") or up.get("manufacturer") or "gateway") + ")"
    if p & {8291, 8728, 7547} or (_has(v, V_NET) and not d["random"]):
        return CAT_NET, "router management port" if p & {8291, 8728, 7547} else "network-equipment brand"
    if 62078 in p or _has(v, V_PHONE) or re.search(PHONE_NAMES, name):
        return CAT_PHONE, "Apple device port" if 62078 in p else "phone brand / name"
    if 1883 in p or _has(v, V_IOT) or _has(uptxt, ["mediarenderer", "tv", "dial"]):
        return CAT_IOT, "smart TV / IoT (" + (up.get("modelName") or up.get("manufacturer") or d["vendor"] or "UPnP") + ")"
    if _has(v, V_PC):
        return CAT_PC, "PC network-card brand"
    if d["random"] and not p:
        return CAT_PHONE, "randomized MAC, no services (typical phone)"
    ttl = d.get("ttl")
    if ttl and ttl > 128:
        return CAT_NET, f"TTL {ttl} (typical of network equipment)"
    if ttl and 64 < ttl <= 128:
        return CAT_PC, f"TTL {ttl} (typical of Windows)"
    return CAT_UNK, "no clues - right-click > Set label to name it"


# ==========================================================================
# device memory (own database, no router needed)
# ==========================================================================
def load_db():
    try:
        with open(DB_PATH, encoding="utf-8") as f:
            db = json.load(f)
    except Exception:
        db = {}
    db.setdefault("labels", {})
    db.setdefault("devices", {})
    db.setdefault("ip_owner", {})
    db.setdefault("scans", 0)
    return db


DB_LOCK = threading.RLock()


def save_db(db):
    try:
        with DB_LOCK:
            text = json.dumps(db, indent=1)
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = DB_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, DB_PATH)
    except Exception:
        pass


# ==========================================================================
# scan engine
# ==========================================================================
class Stopped(Exception):
    pass


def parse_nets(text):
    """'192.168.0.0/24, 192.168.1.0/24' -> [IPv4Network, ...]. Raises ValueError. Up to 4096 addresses in all."""
    nets = []
    for part in re.split(r"[,;\s]+", str(text or "").strip()):
        if part:
            n = ipaddress.ip_network(part, strict=False)
            if n.version != 4:
                raise ValueError("only IPv4 networks")
            if n not in nets:
                nets.append(n)
    if not nets:
        raise ValueError("no network")
    if sum(n.num_addresses for n in nets) > 4096:
        raise ValueError("too many addresses (at most 4096 in all, for example four /24 networks)")
    return nets


def in_net(ip, net):
    try:
        return ipaddress.IPv4Address(ip) in net
    except Exception:
        return False


def is_private_ip(ip):
    try:
        return ipaddress.IPv4Address(ip).is_private
    except Exception:
        return False


ARP_OID = "1.3.6.1.2.1.4.22.1.2"  # ipNetToMediaPhysAddress: index ifIndex.a.b.c.d -> MAC


def router_arp_table(gw, community=None, timeout=1.2, port=161):
    """{ip: mac} from the router's ARP table over SNMP, and the community that worked; ({}, '') if not allowed."""
    import nd_snmp
    for comm in [c for c in (community, "netdoctor", "public") if c]:
        try:
            rows = nd_snmp.Snmp(gw, comm, "2c", port=port, timeout=timeout, retries=0).table(ARP_OID)
        except Exception:
            continue
        out = {}
        for idx, v in rows.items():
            parts = idx.split(".")
            if len(parts) >= 5:
                ip = ".".join(parts[-4:])
                mac = norm_mac(nd_snmp.mac_of(v))
                if mac and not is_bad_mac(mac):
                    out[ip] = mac
        if out:
            return out, comm
    return {}, ""


def scan(subnet, opts, progress, stop):
    """Returns raw results. progress(pct, text). stop = threading.Event."""
    def chk():
        if stop.is_set():
            raise Stopped()

    gw, lip = detect_network()
    nets = parse_nets(subnet)
    net = next((n for n in nets if in_net(lip, n)), nets[0])  # this PC's own network (ARP works only there)
    hosts = sorted({str(h) for n in nets for h in n.hosts()}, key=ip_key)
    admin = is_admin()
    local = in_net(lip, net)

    def is_local(ip):
        return local and in_net(ip, net)
    raw = {"meta": {"started": now_s(), "gateway": gw, "local_ip": lip, "subnet": ", ".join(map(str, nets)),
                    "admin": admin, "scapy": False, "tests": {}, "local_subnet": local,
                    "self_dhcp": local_dhcp_enabled(lip), "self_lease": local_lease_seconds(lip)},
           "arp": defaultdict(set), "ping": {}, "ports": {}, "http": {}, "nbns": {}, "dns": {}, "upnp": {},
           "self_mac": local_mac(lip)}
    tests = raw["meta"]["tests"]
    use_scapy = opts.get("deep") and scapy_ok()
    raw["meta"]["scapy"] = use_scapy

    # 1. quiet-network baseline: broadcast rate + start gateway monitor
    progress(2, "Measuring broadcast traffic (storm / loop check)...")
    mon = {}
    mon_t = None
    if gw:
        mon_t = threading.Thread(target=gateway_monitor, args=(gw, 30, mon), daemon=True)
        mon_t.start()
    b0, t0 = nu_snapshot(), time.time()
    for _ in range(10):
        chk()
        time.sleep(0.5)
    nu_rates(tests, b0, nu_snapshot(), time.time() - t0)

    # 2. live sweep
    progress(8, f"Finding live devices in {raw['meta']['subnet']} (ARP + ping)...")
    done = [0]

    def probe(ip):
        if stop.is_set():
            return ip, None, None
        mac = win_sendarp(ip) if (IS_WIN and is_local(ip) and ip != lip) else None
        ttl = ping(ip)
        if ttl is None and mac:
            ttl = ping(ip)
        done[0] += 1
        if done[0] % 16 == 0:
            progress(8 + 27 * done[0] / len(hosts), f"Sweeping... {done[0]}/{len(hosts)}")
        return ip, mac, ttl

    with ThreadPoolExecutor(96) as ex:
        for ip, mac, ttl in ex.map(probe, hosts):
            if mac:
                raw["arp"][ip].add(mac)
            if ttl is not None:
                raw["ping"][ip] = ttl
    chk()
    # Second chance for phones / cameras in Wi-Fi power-save, which often miss the first ARP request.
    if IS_WIN and local:
        missed = [ip for ip in hosts if is_local(ip) and ip != lip and ip not in raw["arp"]]
        progress(34, f"Second ARP round for {len(missed)} addresses (sleeping phones / cameras)...")
        with ThreadPoolExecutor(96) as ex:
            for ip, mac in zip(missed, ex.map(win_sendarp, missed)):
                if mac:
                    raw["arp"][ip].add(mac)
    chk()
    if local:  # what the operating system learned on its own (all systems, Windows included)
        hostset = set(hosts)
        for ip, mac in os_arp_table().items():
            if ip in hostset and ip != lip and not raw["arp"].get(ip):
                raw["arp"][ip].add(mac)
    # The router knows every device that talked in the last minutes, on every network it routes - including
    # phones that sleep and cameras on another range. Read its ARP table over SNMP when it allows it.
    if gw:
        progress(35, "Asking the router which devices it knows...")
        ra, who = {}, ""
        fetch = opts.get("router_fetch")  # router login (API): ARP table + DHCP leases with device names
        if fetch:
            try:
                got = fetch() or {}
            except Exception as e:
                got = {"error": str(e)}
            if got.get("error"):
                tests["router_api_err"] = str(got["error"])[:200]
            ra, who = got.get("arp") or {}, "router login (API)" if got.get("arp") else ""
            raw["leases"] = got.get("leases") or {}
        if not ra:
            ra, who = router_arp_table(gw, opts.get("router_snmp"))
        if ra:
            hostset = set(hosts)
            tests["router_arp"] = {"community": who, "entries": len(ra)}
            raw["router_arp"] = {}
            for ip, mac in ra.items():
                if ip in hostset and ip != lip:
                    raw["router_arp"][ip] = mac
                    if not raw["arp"].get(ip):
                        raw["arp"][ip].add(mac)
            raw["other_nets"] = sorted({str(ipaddress.ip_network(ip + "/24", strict=False)) for ip in ra
                                        if ip not in hostset and is_private_ip(ip)})
    alive = sorted(set(raw["arp"]) | set(raw["ping"]), key=ip_key)

    # 3. IP-conflict rounds: clear cache, ask again; a 2nd MAC winning a round = conflict
    if IS_WIN and admin and alive and local:
        rounds = 4
        for r in range(rounds):
            chk()
            progress(36 + r * 3, f"IP-conflict check, round {r + 1}/{rounds}...")
            flush_arp_cache()
            with ThreadPoolExecutor(96) as ex:
                for ip, mac in zip(alive, ex.map(lambda x: win_sendarp(x) if is_local(x) else None, alive)):
                    if mac:
                        raw["arp"][ip].add(mac)
            time.sleep(0.7)
        tests["conflict_rounds"] = rounds
    elif not IS_WIN and admin and alive and local:
        rounds = 3
        for r in range(rounds):
            chk()
            progress(36 + r * 4, f"IP-conflict check, round {r + 1}/{rounds}...")
            flush_arp_cache()
            with ThreadPoolExecutor(64) as ex:
                list(ex.map(lambda ip: ping(ip, 600), alive))
            for ip, mac in os_arp_table().items():
                if ip in raw["arp"]:
                    raw["arp"][ip].add(mac)
        tests["conflict_rounds"] = rounds
    if use_scapy and local:
        progress(48, "Packet-level ARP sweep (all replies)...")
        try:
            for ip, macs in scapy_arp_all_replies(net, gw).items():
                raw["arp"][ip] |= macs
            tests["scapy_arp"] = True
        except Exception as e:
            tests["scapy_arp_err"] = str(e)[:150]
    alive = sorted(set(raw["arp"]) | set(raw["ping"]) | {lip}, key=ip_key)
    chk()

    # 4. identify
    progress(52, f"Identifying {len(alive)} devices: services...")
    with ThreadPoolExecutor(200) as ex:
        jobs = {(ip, p): ex.submit(tcp_open, ip, p) for ip in alive for p in PORTS}
        for (ip, p), f in jobs.items():
            if f.result():
                raw["ports"].setdefault(ip, []).append(p)
    chk()
    progress(68, "Reading computer names (NetBIOS)...")
    with ThreadPoolExecutor(64) as ex:
        for ip, r in zip(alive, ex.map(netbios_query, alive)):
            if r:
                raw["nbns"][ip] = r
    chk()
    # Windows PCs that ignore NetBIOS still tell their name in the first step of a file-sharing login (SMB)
    # (asked of every PC with file sharing: also gives the exact Windows version and the domain / workgroup)
    smb_ips = [ip for ip in alive if 445 in raw["ports"].get(ip, []) and ip != lip]
    if smb_ips:
        import nd_smbinfo
        progress(72, f"Reading computer names from file sharing ({len(smb_ips)})...")
        with ThreadPoolExecutor(32) as ex:
            for ip, r in zip(smb_ips, ex.map(nd_smbinfo.smb_info, smb_ips)):
                if r:
                    raw.setdefault("smb", {})[ip] = r
    chk()
    progress(74, "UPnP discovery (routers, cameras, TVs)...")
    raw["upnp"] = ssdp_discover(lip)
    chk()
    progress(80, "Reading device web pages...")
    webj = []
    for ip in alive:
        for p in (80, 8080, 8000, 443, 8443):
            if p in raw["ports"].get(ip, []):
                webj.append((ip, p))
                break
    with ThreadPoolExecutor(32) as ex:
        for (ip, p), r in zip(webj, ex.map(lambda a: http_info(*a), webj)):
            if r:
                raw["http"][ip] = r
    chk()
    if not opts.get("fast"):
        progress(85, "Reverse DNS names...")
        with ThreadPoolExecutor(64) as ex:
            for ip, n in zip(alive, ex.map(reverse_dns, alive)):
                if n:
                    raw["dns"][ip] = n
    chk()

    # 5. health tests
    progress(88, "Checking for rogue DHCP servers...")
    try:
        tests["dhcp"] = scapy_dhcp_probe(gw) if use_scapy else dhcp_probe_udp(raw["self_mac"])
    except Exception as e:
        tests["dhcp_err"] = (str(e) or type(e).__name__)[:150]
    chk()
    if gw and admin:
        progress(92, "Duplicate-reply test on gateway...")
        try:
            tests["icmp_dup"] = icmp_duplicate_test(gw, lip)
        except Exception as e:
            tests["icmp_dup_err"] = str(e)[:150]
    if use_scapy and gw:
        progress(94, "Loop echo test...")
        try:
            tests["echo"] = scapy_loop_echo(gw)
        except Exception as e:
            tests["echo_err"] = str(e)[:150]
    progress(96, "Finishing gateway stability test...")
    if mon_t:
        mon_t.join(timeout=45)
        tests["gw_ping"] = mon
    raw["meta"]["finished"] = now_s()
    raw["arp"] = {k: sorted(v) for k, v in raw["arp"].items()}
    return raw


# ==========================================================================
# analysis
# ==========================================================================
def build_devices(raw, oui, db):
    m = raw["meta"]
    gw, lip = m["gateway"], m["local_ip"]
    devs = {}

    def dev(mac, ip):
        key = mac or f"IP-{ip}"
        d = devs.get(key)
        if d is None:
            d = devs[key] = {"mac": mac, "ips": set(), "names": {}, "ports": [], "http": {}, "upnp": {},
                             "ttl": None, "notes": [], "online": True}
        d["ips"].add(ip)
        return d

    for ip, macs in raw["arp"].items():
        for mac in macs:
            dev(mac, ip)
    me = dev(raw.get("self_mac") or None, lip)
    me["self"] = True
    me["names"]["netbios"] = socket.gethostname().upper()
    me["notes"].append("This PC")
    by_ip = defaultdict(list)
    for d in devs.values():
        for ip in d["ips"]:
            by_ip[ip].append(d)
    for ip, ttl in raw["ping"].items():
        if ip not in by_ip:
            by_ip[ip].append(dev(None, ip))
        for d in by_ip[ip]:
            d["ttl"] = ttl
    for ip, ports in raw["ports"].items():
        for d in by_ip.get(ip, []):
            d["ports"] = sorted(set(d["ports"]) | set(ports))
    for ip, h in raw["http"].items():
        for d in by_ip.get(ip, []):
            d["http"] = h
    for ip, u in raw["upnp"].items():
        for d in by_ip.get(ip, []):
            d["upnp"] = u
    for ip, nb in raw["nbns"].items():
        for d in by_ip.get(ip, []):
            if len(by_ip[ip]) == 1 or not nb.get("mac") or nb["mac"] == d["mac"]:
                d["names"]["netbios"] = nb["name"]
                d["workgroup"] = nb.get("group", "")
                if nb.get("mac") and d["mac"] and nb["mac"] != d["mac"]:
                    d["notes"].append(f"PC reports adapter {nb['mac']}")
    for ip, n in raw["dns"].items():
        for d in by_ip.get(ip, []):
            d["names"]["dns"] = n
    for ip, r in (raw.get("smb") or {}).items():
        for d in by_ip.get(ip, []):
            d["names"]["smb"] = r.get("name", "")
            if r.get("domain") and not d.get("workgroup"):
                d["workgroup"] = r["domain"]
            if r.get("os"):
                d["os"] = r["os"]
                d["notes"].append(r["os"])
    for mac, ls in (raw.get("leases") or {}).items():  # names devices give the router (phones, TVs, laptops)
        d = devs.get(mac)
        if d is None and ls.get("ip") in by_ip and len(by_ip[ls["ip"]]) == 1 and not by_ip[ls["ip"]][0]["mac"]:
            d = by_ip[ls["ip"]][0]
        if d is not None and ls.get("host"):
            d["names"]["dhcp"] = ls["host"]

    out = []
    for d in devs.values():
        mac = d["mac"] or ""
        d["random"] = is_random_mac(mac)
        d["vendor"] = vendor_of(mac, oui)
        d["ip"] = sorted(d["ips"], key=ip_key)[0]
        if mac and db["labels"].get(mac):
            d["names"]["label"] = db["labels"][mac]
        up = d["upnp"] or {}
        nm = d["names"]
        d["name"] = (nm.get("label") or nm.get("netbios") or nm.get("smb") or nm.get("dhcp") or up.get("friendlyName") or
                     nm.get("dns", "").split(".")[0] or "")
        if d["random"]:
            d["notes"].append("Randomized MAC")
        if d["ip"] in (raw.get("router_arp") or {}) and d["ip"] not in raw["ping"]:
            d["notes"].append("seen by the router (does not answer this PC - sleeping phone or firewall)")
        h = db["devices"].get(mac) if mac else None
        d["first_seen"] = h["first_seen"] if h else m["started"]
        if h and h.get("names") and nm.get("netbios") and h["names"][-1] != nm["netbios"]:
            d["notes"].append(f"Renamed (was {h['names'][-1]})")
        d["category"], d["reason"] = categorize(d, gw)
        if not d["name"]:
            d["name"], d["auto_name"] = auto_name(d), True
        d["status"] = "Online"
        out.append(d)

    online_macs = {d["mac"] for d in out if d["mac"]}
    for mac, h in db["devices"].items():
        if mac in online_macs:
            continue
        try:
            age = (dt.datetime.now() - dt.datetime.strptime(h["last_seen"], "%Y-%m-%d %H:%M")).days
        except Exception:
            age = 0
        if age > 60:
            continue
        name = db["labels"].get(mac) or (h.get("names") or [""])[-1]
        out.append({"mac": mac, "ips": {h.get("ip", "")}, "ip": h.get("ip", ""), "names": {"label": name},
                    "name": name, "ports": [], "http": {}, "upnp": {}, "ttl": None, "random": is_random_mac(mac),
                    "vendor": vendor_of(mac, oui), "notes": [f"was: {h.get('category', '')}"], "online": False,
                    "status": f"Last seen {h['last_seen']}", "category": CAT_OFF,
                    "reason": "not answering now (off, asleep or left)", "first_seen": h.get("first_seen", "")})
    out.sort(key=lambda d: (CAT_ORDER.index(d["category"]), ip_key(d["ip"])))
    return out


AUTO_KIND = {CAT_NET: "Switch / AP", CAT_PC: "PC", CAT_CAM: "Camera", CAT_PRN: "Printer", CAT_BIO: "Biometric",
             CAT_PHONE: "Phone", CAT_IOT: "IoT", CAT_UNK: "Device", CAT_ROUTER: "Router"}
CAM_BRANDS = (("hikvision", "Hikvision"), ("dahua", "Dahua"), ("xmeye", "XMeye"), ("netsurveillance", "XMeye"),
              ("cp plus", "CP Plus"), ("uniview", "Uniview"), ("tp-link", "TP-Link"), ("ezviz", "EZVIZ"),
              ("godrej", "Godrej"), ("honeywell", "Honeywell"))


def auto_name(d):
    """A readable name for a device that tells none (e.g. 'Hikvision Camera .105', 'HP PC .57', 'Phone .101').
    Shown until you tag it; never stored as its real name."""
    kind = AUTO_KIND.get(d.get("category"), "Device")
    http = d.get("http") or {}
    txt = " ".join(str(x) for x in (http.get("title", ""), http.get("server", ""), http.get("realm", ""),
                                    str(http.get("blob", ""))[:2000], (d.get("upnp") or {}).get("modelName", ""),
                                    " ".join(d.get("notes") or []))).lower()
    brand = ""
    if d.get("category") == CAT_CAM:
        if 34567 in (d.get("ports") or []):
            brand = "XMeye"
        brand = next((b for k, b in CAM_BRANDS if k in txt), brand)
    if not brand and not d.get("random"):
        v = (d.get("vendor") or "").replace(",", " ").split()
        brand = v[0] if v else ""
        brand = {"hewlett": "HP", "lcfc(hefei)": "Lenovo", "liteon": "LiteON", "routerboard.com": "MikroTik",
                 "shenzhen": "", "private": ""}.get(brand.lower(), brand)[:14]
    last = (d.get("ip") or "").rsplit(".", 1)[-1]
    return " ".join(x for x in (brand, kind, "." + last if last else "") if x)


def label_of(d):
    bits = [d["name"]] if d["name"] else []
    bits += [d["ip"], (d["mac"] or "no MAC") + (" (randomized)" if d["random"] else "")]
    if d["vendor"] and not d["random"]:
        bits.append(d["vendor"])
    return " / ".join(b for b in bits if b)


def analyse(raw, devices, db):
    m = raw["meta"]
    t = m["tests"]
    gw = m["gateway"]
    issues, checks = [], []
    online = [d for d in devices if d["online"]]
    by_mac = {d["mac"]: d for d in online if d["mac"]}
    gw_mac = next((d["mac"] for d in online if d["ip"] == gw), None)

    def add(sev, title, detail, fix, items=()):
        issues.append({"sev": sev, "title": title, "detail": detail, "fix": fix, "items": list(items)})

    # ---- IP conflicts
    conflicts = {ip: macs for ip, macs in raw["arp"].items()
                 if len([x for x in macs if not (x == gw_mac and ip != gw)]) > 1}
    for ip, macs in sorted(conflicts.items(), key=lambda x: ip_key(x[0])):
        add("critical", f"IP conflict on {ip}",
            f"{len(macs)} different devices answered for {ip}. Both will lose network randomly, and scanners will "
            "show this IP with a changing name/MAC.",
            "One of them has a manually typed IP. Change it to automatic (DHCP), or give it an IP outside the "
            "router's DHCP range. Then reserve that IP for it on the router.",
            [f"{ip} claimed by: " + (label_of(by_mac[x]) if x in by_mac else x) for x in macs])
    tested = []
    if t.get("conflict_rounds"):
        tested.append(f"{t['conflict_rounds']} cleared-cache ARP rounds")
    if t.get("scapy_arp"):
        tested.append("packet-level all-reply sweep")
    if tested:
        checks.append(("IP conflicts", "fail" if conflicts else "pass", " + ".join(tested)))
    else:
        checks.append(("IP conflicts", "warn" if conflicts else "skip",
                       "Run as Administrator for the full conflict test (single ARP pass only)"))

    # IP owner changed since last scan (history)
    flips = []
    for d in online:
        if not d["mac"]:
            continue
        prev = db["ip_owner"].get(d["ip"])
        # A phone that changes its private (randomized) MAC is the same phone, not another device taking the IP.
        if prev and prev["mac"] != d["mac"] and not is_random_mac(prev["mac"]):
            prev_now = by_mac.get(prev["mac"])
            if prev_now is None or prev_now["ip"] == d["ip"]:
                flips.append(f"{d['ip']}: was {prev['mac']} ({prev.get('name', '')}) on {prev['time']}, now {label_of(d)}")
    if flips:
        add("info", f"{len(flips)} IP address(es) now used by a different device",
            "Compared with the previous scan. Normal when a device's DHCP lease expires; if the old device is "
            "still on the network with a manual IP, it is a conflict waiting to happen.",
            "If it keeps changing, reserve fixed IPs on the router for important devices.", flips)

    # ---- duplicate names
    groups = defaultdict(list)
    for d in online:
        n = (d["names"].get("netbios") or d["names"].get("smb") or "").strip().lower()
        if n and d["mac"]:
            groups[n].append(d)
    dupn = 0
    for n, ds in sorted(groups.items()):
        if len(ds) < 2:
            continue
        dupn += 1
        if any(d["random"] for d in ds):
            sev, why = "info", ("One entry uses a randomized (private) Wi-Fi MAC - it is the SAME computer, shown "
                                "twice because Windows 'Random hardware addresses' is ON.")
            fix = "On that PC: Settings > Network > Wi-Fi > this network > Random hardware addresses = Off."
        else:
            sev, why = "warning", ("Two real network cards answer with the same computer name: either one PC is "
                                   "connected by cable AND Wi-Fi at the same time, or two PCs have the same name.")
            fix = ("One PC on two connections: switch Wi-Fi off when the cable is in. Two PCs: rename one "
                   "(Settings > System > About > Rename this PC); duplicate names break file sharing.")
        add(sev, f"'{ds[0]['names']['netbios']}' appears {len(ds)} times", why, fix, [label_of(d) for d in ds])
    checks.append(("Duplicate computer names", "warn" if dupn else "pass", f"{dupn} group(s), each explained"))

    # ---- multi-IP devices
    for d in online:
        if len(d["ips"]) > 1 and not any(ip in conflicts for ip in d["ips"]):
            add("info", f"One device answers on {len(d['ips'])} IPs",
                "A PC with several IPs, a virtual-machine host, or a device that recently changed IP.",
                "Usually harmless.", [label_of(d) + " : " + ", ".join(sorted(d["ips"], key=ip_key))])

    # ---- rogue DHCP / extra routers
    dhcp = t.get("dhcp")
    if dhcp:
        rogue = {s: v for s, v in dhcp.items() if s != gw}
        items = [f"DHCP server {s} offered {v['offered']} with gateway {v.get('gateway') or '?'}" for s, v in rogue.items()]
        if rogue and len(dhcp) >= 2:
            add("critical", f"Rogue DHCP server ({len(rogue)}) found",
                f"{len(dhcp)} different DHCP servers answered. Computers take whichever answers first, so some get "
                "the wrong gateway, lose internet, or clash with other devices.",
                "It is usually a Wi-Fi router plugged in through its LAN port with DHCP on. Unplug it, or turn its "
                "DHCP off and use it only as an access point.", items)
        elif rogue:
            add("warning", "DHCP is given by a device that is not the router",
                "Only one DHCP server answered, but it is not the default gateway. That is fine if it is your official "
                "DHCP server (e.g. a Windows server); otherwise it is a rogue DHCP server.",
                "If you do not recognise it, find it and switch its DHCP off.", items)
        checks.append(("Rogue DHCP servers", "fail" if (rogue and len(dhcp) >= 2) else "warn" if rogue else "pass",
                       f"{len(dhcp)} server(s) answered: {', '.join(dhcp)}"))
    elif dhcp is not None:
        checks.append(("Rogue DHCP servers", "skip", "no DHCP reply could be received on this PC (Windows keeps them) "
                       "- install Npcap + Scapy and tick Deep tests for this check"))
    else:
        checks.append(("Rogue DHCP servers", "skip", "could not listen for DHCP offers (" + t.get("dhcp_err", "?") +
                       ") - install Npcap + Scapy and tick Deep tests"))
    extra = [d for d in online if d["ip"] != gw and d["category"] == CAT_NET and
             ("internetgatewaydevice" in " ".join((d.get("upnp") or {}).get("st", [])).lower() or 53 in d["ports"])]
    if extra:
        add("warning", f"{len(extra)} extra router(s) on the LAN",
            "These devices behave like routers (UPnP internet gateway or DNS server). If their DHCP is on, they "
            "cause rogue DHCP and IP clashes.",
            "Set them to Access Point / bridge mode with DHCP OFF.", [label_of(d) for d in extra])

    # ---- loops / storms / stability
    loop = False
    bp = t.get("bcast_pps")
    mixed = bool(t.get("bcast_mixed"))
    if bp is not None and mixed:
        # Only the total of broadcast + multicast was available: a high value may be cameras, not a loop.
        bad = bp > 300
        if bad:
            loop = loop or bp > 3000
            add("critical" if bp > 3000 else "warning", f"Very high broadcast / multicast traffic ({bp}/second)",
                "This PC receives hundreds of broadcast or multicast packets per second (Windows could not tell the two "
                "apart here). Broadcasts point to a network loop; multicast usually comes from CCTV cameras / NVRs "
                "streaming in multicast or from IPTV, copied to every port by switches without IGMP snooping.",
                "1) Turn on IGMP snooping (MikroTik: /interface bridge set [find] igmp-snooping=yes) and set cameras / "
                "NVR to unicast streaming, then re-scan. 2) If the number stays high, unplug switch-to-switch cables "
                "one by one; when it drops, you found the loop.")
        checks.append(("Broadcast level", "fail" if bad else "pass", f"{bp} broadcast + multicast per second"))
    elif bp is not None:
        bad = bp > 300
        if bad:
            loop = loop or bp > 1000
            add("critical" if bp > 1000 else "warning", f"Very high broadcast traffic ({bp}/second)",
                "Normal office LAN: under 50/s. Hundreds or thousands per second means a network loop (a cable "
                "connecting a switch back to itself or two switches linked twice) or a faulty device.",
                "Unplug switch-to-switch cables one by one and re-scan; when the number drops, you found the loop. "
                "Use switches with loop protection / STP.")
        checks.append(("Broadcast level", "fail" if bad else "pass", f"{bp} broadcasts per second received"))
    mp = t.get("mcast_pps")
    if mp is not None:
        bad = mp > 1000
        if bad:
            add("warning", f"Very high multicast traffic ({mp}/second)",
                "Not a loop. Multicast this high usually comes from CCTV cameras / an NVR streaming in multicast, or "
                "IPTV. Switches without IGMP snooping copy it to every port, which slows Wi-Fi, old PCs and printers.",
                "Set the cameras / NVR to unicast streaming (or turn multicast off). Turn on IGMP snooping: MikroTik "
                "/interface bridge set [find] igmp-snooping=yes, and on managed switches. Then re-scan.")
        checks.append(("Multicast level", "warn" if bad else "pass", f"{mp} per second received (cameras, mDNS, IPv6)"))
    g = t.get("gw_ping") or {}
    if g.get("loss") is not None:
        bad = g["loss"] >= 5 or (g.get("avg") or 0) > 30 or (g.get("max") or 0) > 300
        if bad:
            add("warning", "Connection to the router is unstable",
                f"{g['loss']}% packets lost, latency avg {g.get('avg', '?')} ms / max {g.get('max', '?')} ms over "
                f"{g.get('count')} pings (a healthy wired LAN: 0% loss, 1-5 ms).",
                "If this PC is on Wi-Fi, test on cable. On cable: check patch cord, switch port, switch power. "
                "Together with high broadcast traffic this points to a loop.")
        checks.append(("Gateway stability", "warn" if bad else "pass",
                       f"loss {g['loss']}%, avg {g.get('avg', '?')} ms, max {g.get('max', '?')} ms"))
    dup = t.get("icmp_dup")
    if dup:
        if dup["dups"] > 0:
            loop = True
            add("critical", "Duplicate replies from the router",
                f"{dup['dups']} extra replies to {dup['sent']} pings. Each ping must get exactly one answer: "
                "duplicates mean the packets are circling (loop) or two devices share the router's IP.",
                "Look for a loop between switches; check nobody set a device to the router's IP.")
        checks.append(("Duplicate-reply test", "fail" if dup["dups"] else "pass",
                       f"{dup['sent']} sent, {dup['answered']} answered, {dup['dups']} duplicates"))
    elif not m["admin"]:
        checks.append(("Duplicate-reply test", "skip", "needs Run as Administrator"))
    echo = t.get("echo")
    if echo:
        bad = echo["seen"] > echo["sent"] + 1
        loop = loop or bad
        if bad:
            add("critical", "Loop confirmed by echo test",
                f"3 test frames were sent and {echo['seen']} copies came back.",
                "Unplug switch uplinks one at a time; when the echo stops, the last cable removed was the loop.")
        checks.append(("Loop echo test", "fail" if bad else "pass", f"sent {echo['sent']}, came back {echo['seen']}"))
    checks.append(("Loop overall", "fail" if loop else "pass", "based on the tests above"))

    # ---- networks / devices this PC could not reach itself
    other = raw.get("other_nets") or []
    if other:
        add("info", f"The router also knows devices on {len(other)} other network(s)",
            "Its ARP table lists devices outside the networks you scanned - cameras / NVRs often sit on their own "
            "range (Hikvision 192.168.1.x, Dahua 192.168.1.108).",
            "Add them to the network box at the top, separated by commas (for example "
            f"'{raw['meta'].get('subnet', '')}, {other[0]}'), and scan again.", other[:10])
    ra = t.get("router_arp")
    if ra:
        via = ra["community"] if "API" in ra["community"] else f"SNMP community '{ra['community']}'"
        checks.append(("Router device list", "pass", f"{ra['entries']} entries read through {via}"))
    elif not raw["meta"].get("quick"):
        err = t.get("router_api_err")
        checks.append(("Router device list", "skip", (f"router login failed ({err}) - " if err else "") +
                       "the router's device list could not be read - sleeping phones, phone names and other networks "
                       "may be missed. Save the router login in Setup (or Setup > Copy router commands turns on SNMP)"))
    leases = raw.get("leases") or {}
    if leases:
        named = sum(1 for x in leases.values() if x.get("host"))
        checks.append(("Device names from the router", "pass", f"{named} of {len(leases)} DHCP leases carry a "
                       "device name (phones, TVs, laptops)"))

    # ---- info
    rnd = [d for d in online if d["random"]]
    if rnd:
        add("info", f"{len(rnd)} device(s) use randomized MACs",
            "These change MAC per network or over time, so other scanners show them as new devices again and again.",
            "For office laptops switch random MAC off for the office Wi-Fi.", [label_of(d) for d in rnd])
    unk = [d for d in online if d["category"] == CAT_UNK]
    if unk:
        add("info", f"{len(unk)} device(s) could not be identified", "No name, no known brand, no open services.",
            "Select the device > Tag... The tag is remembered by MAC for every future scan.",
            [label_of(d) for d in unk])
    newd = [d for d in online if d["mac"] and d["mac"] not in db["devices"]] if db["scans"] else []
    if newd:
        add("info", f"{len(newd)} new device(s) since the last scan",
            "Never seen before by this app. Usually a new phone, laptop or visitor - but an unknown device can also be "
            "someone plugging a personal router / switch into the office network (loops, rogue DHCP).",
            "Check that you recognise them and tag the ones you know. Unknown ones: find their port (Commands > "
            "'Which router port is a device on?') and the switch on the Network map.", [label_of(d) for d in newd])
    order = {"critical": 0, "warning": 1, "info": 2}
    issues.sort(key=lambda i: order[i["sev"]])
    return issues, checks


def update_db(db, raw, devices):
    with DB_LOCK:
        _update_db(db, raw, devices)
    save_db(db)


def _update_db(db, raw, devices):
    ts = raw["meta"]["started"]
    for d in devices:
        if not d["online"] or not d["mac"]:
            continue
        h = db["devices"].setdefault(d["mac"], {"first_seen": ts, "names": [], "ips": []})
        h["last_seen"] = ts
        h["ip"] = d["ip"]
        h["category"] = d["category"]
        h["vendor"] = d["vendor"]
        n = (d["names"].get("netbios") or d["names"].get("smb") or (d.get("upnp") or {}).get("friendlyName") or
             d["names"].get("dhcp") or "")
        if n and (not h["names"] or h["names"][-1] != n):
            h["names"] = (h["names"] + [n])[-5:]
        if d["ip"] not in h["ips"]:
            h["ips"] = (h["ips"] + [d["ip"]])[-5:]
        db["ip_owner"][d["ip"]] = {"mac": d["mac"], "time": ts, "name": d["name"]}
    db["scans"] += 1


# ==========================================================================
# exports
# ==========================================================================
REPORT_CSS = """:root{--bg:#f5f6f8;--card:#fff;--ink:#1c2230;--mute:#667085;--line:#e3e6eb;--crit:#c4281c;--critbg:#fdecea;
--warn:#a15c00;--warnbg:#fff4e0;--info:#0b6bcb;--infobg:#e8f1fb;--ok:#1f7a3d;--chip:#eef0f3}
@media (prefers-color-scheme:dark){:root{--bg:#11151c;--card:#1a1f29;--ink:#e6e9ef;--mute:#98a2b3;--line:#2b3240;
--crit:#ff7b6e;--critbg:#3a1d1b;--warn:#ffb648;--warnbg:#372a14;--info:#7cb8ff;--infobg:#172a40;--ok:#6fd08f;--chip:#242a36}}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 "Segoe UI",system-ui,sans-serif}
.w{max-width:1250px;margin:0 auto;padding:20px 16px 50px}h1{font-size:22px;margin:0}h2{font-size:17px;margin:26px 0 10px}
.sub{color:var(--mute)}.i{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--info);
border-radius:8px;padding:10px 14px;margin:8px 0}.i.critical{border-left-color:var(--crit)}.i.warning{border-left-color:var(--warn)}
.s{font-size:11px;font-weight:700;text-transform:uppercase;padding:2px 7px;border-radius:4px;margin-right:8px}
.s.critical{background:var(--critbg);color:var(--crit)}.s.warning{background:var(--warnbg);color:var(--warn)}
.s.info{background:var(--infobg);color:var(--info)}.fix{color:var(--ok)}ul{font-family:Consolas,monospace;font-size:12.5px}
.c{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:12px 0;overflow-x:auto}
.c h3{margin:0;padding:10px 14px;font-size:15px}table{border-collapse:collapse;width:100%;min-width:900px}
th,td{text-align:left;padding:6px 10px;border-top:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--mute);background:var(--chip)}td.m{font-family:Consolas,monospace;font-size:12.5px}"""


def export_html(path, raw, devices, issues, checks):
    m = raw["meta"]
    e = lambda x: html.escape(str(x if x is not None else ""))
    h = [f"<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
         f"<title>Network Report</title><style>{REPORT_CSS}</style></head><body><div class=w>",
         f"<h1>Network report - {e(m['subnet'])}</h1><div class=sub>{e(m['started'])} &middot; from {e(m['local_ip'])} "
         f"&middot; gateway {e(m['gateway'])} &middot; {sum(1 for d in devices if d['online'])} devices online</div>",
         "<h2>Problems</h2>"]
    for i in issues:
        h.append(f"<div class='i {i['sev']}'><span class='s {i['sev']}'>{i['sev']}</span><b>{e(i['title'])}</b>"
                 f"<p>{e(i['detail'])}</p><p class=fix><b>Fix:</b> {e(i['fix'])}</p>")
        if i["items"]:
            h.append("<ul>" + "".join(f"<li>{e(x)}</li>" for x in i["items"]) + "</ul>")
        h.append("</div>")
    if not issues:
        h.append("<div class=i>No problems found.</div>")
    h.append("<h2>Health checks</h2><div class=c><table><tr><th>Check</th><th>Result</th><th>Details</th></tr>")
    for n, s, d in checks:
        h.append(f"<tr><td>{e(n)}</td><td><b>{e(s.upper())}</b></td><td>{e(d)}</td></tr>")
    h.append("</table></div><h2>Devices</h2>")
    for c in CAT_ORDER:
        ds = [d for d in devices if d["category"] == c]
        if not ds:
            continue
        h.append(f"<div class=c><h3>{e(c)} ({len(ds)})</h3><table><tr><th>Name</th><th>IP</th><th>MAC</th><th>Vendor</th>"
                 "<th>Services</th><th>Why</th><th>Status / notes</th></tr>")
        for d in ds:
            h.append(f"<tr><td><b>{e(d['name'] or '-')}</b></td><td class=m>{e(', '.join(sorted(d['ips'], key=ip_key)))}</td>"
                     f"<td class=m>{e(d['mac'])}</td><td>{e(d['vendor'])}</td><td>{e(', '.join(PORTS.get(p, str(p)) for p in d['ports']))}</td>"
                     f"<td>{e(d['reason'])}</td><td>{e(d['status'])}{(' - ' + e('; '.join(d['notes']))) if d['notes'] else ''}</td></tr>")
        h.append("</table></div>")
    h.append(f"<p class=sub>{APP} v{VERSION}</p></div></body></html>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("".join(h))


def export_csv(path, devices):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["Category", "Status", "Name", "IP", "All IPs", "MAC", "Randomized", "Vendor", "Services",
                    "Why category", "Computer name", "First seen", "Notes"])
        for d in devices:
            w.writerow([d["category"], d["status"], d["name"], d["ip"], " ".join(sorted(d["ips"], key=ip_key)),
                        d["mac"], "yes" if d["random"] else "", d["vendor"],
                        ", ".join(PORTS.get(p, str(p)) for p in d["ports"]), d["reason"],
                        d["names"].get("netbios", ""), d.get("first_seen", ""), "; ".join(d["notes"])])




def local_dhcp_enabled(lip):
    """True/False for this PC's own adapter (from netsh), None if unknown."""
    if not IS_WIN:
        return None
    out = run(["netsh", "interface", "ip", "show", "config"], 10)
    for block in re.split(r"\r?\n\s*\r?\n(?=Configuration for interface)", out):
        if re.search(r"\b" + re.escape(lip) + r"\b", block):
            m = re.search(r"DHCP enabled:\s*(\w+)", block)
            if m:
                return m.group(1).lower() in ("yes", "ja", "oui", "si", "sí")
    return None


def local_lease_seconds(lip):
    """DHCP lease length of this PC (from ipconfig /all), used to judge DHCP vs static of others."""
    if not IS_WIN:
        return None
    out = run(["ipconfig", "/all"], 10)
    for block in re.split(r"\r?\n(?=\S)", out):
        if not re.search(r"\b" + re.escape(lip) + r"\b", block):
            continue
        a = re.search(r"Lease Obtained[ .]*:\s*(.+)", block)
        b = re.search(r"Lease Expires[ .]*:\s*(.+)", block)
        if a and b:
            for fmt in ("%A, %B %d, %Y %I:%M:%S %p", "%A, %d %B, %Y %I:%M:%S %p", "%d %B %Y %H:%M:%S",
                        "%A, %B %d, %Y %H:%M:%S", "%d-%m-%Y %H:%M:%S"):
                try:
                    t1 = dt.datetime.strptime(a.group(1).strip(), fmt)
                    t2 = dt.datetime.strptime(b.group(1).strip(), fmt)
                    sec = (t2 - t1).total_seconds()
                    return sec if 0 < sec < 400 * 86400 else None
                except ValueError:
                    continue
    return None


# ==========================================================================
# quick health check (runs every few minutes between full scans)
# ==========================================================================
QUICK_TITLES = re.compile(r"conflict|rogue dhcp|dhcp is given|broadcast|multicast|loop|unstable|duplicate replies|extra router",
                          re.I)


def quick_check(subnet, known_ips, opts, stop=None):
    """Fast loop / conflict / rogue-DHCP / stability check on the devices found by the last full scan.
    Returns a raw dict in the same shape as scan(), so analyse() can judge it."""
    def chk():
        if stop is not None and stop.is_set():
            raise Stopped()

    gw, lip = detect_network()
    nets = parse_nets(subnet)
    net = next((n for n in nets if in_net(lip, n)), nets[0])
    admin = is_admin()
    local = in_net(lip, net)
    raw = {"meta": {"started": now_s(), "gateway": gw, "local_ip": lip, "subnet": str(net), "admin": admin,
                    "scapy": False, "tests": {}, "local_subnet": local, "quick": True},
           "arp": defaultdict(set), "ping": {}, "ports": {}, "http": {}, "nbns": {}, "dns": {}, "upnp": {},
           "self_mac": local_mac(lip)}
    tests = raw["meta"]["tests"]
    t_start = time.time()
    mon = {}
    mon_t = None
    if gw:
        mon_t = threading.Thread(target=gateway_monitor, args=(gw, 12, mon), daemon=True)
        mon_t.start()
    # broadcast level over 6 s (loop / storm)
    b0, t0 = nu_snapshot(), time.time()
    for _ in range(12):
        chk()
        time.sleep(0.5)
    nu_rates(tests, b0, nu_snapshot(), time.time() - t0)
    # IP conflicts on the known devices
    ips = [ip for ip in known_ips if ip and ip != lip]
    try:
        ips = [ip for ip in ips if ipaddress.IPv4Address(ip) in net][:1024]
    except Exception:
        pass
    if local and ips:
        rounds = 2 if admin else 1
        for _ in range(rounds):
            chk()
            if admin:
                flush_arp_cache()
            if IS_WIN:
                with ThreadPoolExecutor(96) as ex:
                    for ip, mac in zip(ips, ex.map(win_sendarp, ips)):
                        if mac:
                            raw["arp"][ip].add(mac)
            else:
                with ThreadPoolExecutor(64) as ex:
                    list(ex.map(lambda ip: ping(ip, 600), ips))
                for ip, mac in os_arp_table().items():
                    if ip in ips:
                        raw["arp"][ip].add(mac)
        if admin:
            tests["conflict_rounds"] = rounds
    use_scapy = opts.get("deep") and scapy_ok()
    raw["meta"]["scapy"] = bool(use_scapy)
    if use_scapy and local:
        try:
            for ip, macs in scapy_arp_all_replies(net, gw, rounds=1).items():
                raw["arp"][ip] |= macs
            tests["scapy_arp"] = True
        except Exception as e:
            tests["scapy_arp_err"] = str(e)[:150]
    chk()
    # rogue DHCP (not every time: each probe appears as a line in the router's DHCP log)
    if opts.get("dhcp", True):
        try:
            tests["dhcp"] = scapy_dhcp_probe(gw, wait=4) if use_scapy else dhcp_probe_udp(raw["self_mac"], wait=4)
        except Exception as e:
            tests["dhcp_err"] = (str(e) or type(e).__name__)[:150]
    chk()
    # duplicate replies (loop / router IP clash) and echo test
    if gw and admin:
        try:
            tests["icmp_dup"] = icmp_duplicate_test(gw, lip, count=10)
        except Exception as e:
            tests["icmp_dup_err"] = str(e)[:150]
    if use_scapy and gw:
        try:
            tests["echo"] = scapy_loop_echo(gw, listen=3)
        except Exception as e:
            tests["echo_err"] = str(e)[:150]
    if mon_t:
        mon_t.join(timeout=30)
        tests["gw_ping"] = mon
    raw["meta"]["finished"] = now_s()
    raw["meta"]["duration"] = int(time.time() - t_start)
    raw["arp"] = {k: sorted(v) for k, v in raw["arp"].items()}
    return raw


def analyse_quick(raw, devices, db):
    """Judges a quick check with the normal rules, keeping only loop / conflict / DHCP / stability results."""
    issues, checks = analyse(raw, [d for d in devices if d.get("online")], db)
    keep = [i for i in issues if QUICK_TITLES.search(i["title"])]
    checks = [c for c in checks if QUICK_TITLES.search(c[0]) or c[0] in ("IP conflicts", "Gateway stability",
                                                                          "Loop overall", "Loop echo test")]
    return keep, checks
