"""Network Doctor - engineer tools (no GUI here, so everything can be tested).

Port scan, DNS lookup and DNS-server test, Wake-on-LAN, subnet calculator, MTU finder, internet quality and speed,
Wi-Fi analyzer, this PC's adapters (link speed / duplex / errors), LAN speed test between two PCs, web / server check,
MAC vendor lookup.
"""
import concurrent.futures as cf
import http.client
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import statistics
import struct
import subprocess
import threading
import time
import urllib.parse
import urllib.request

import nd_core as core

# ==========================================================================
# shared helpers
# ==========================================================================
SERVICES = {
    20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 69: "TFTP", 80: "Web (HTTP)",
    88: "Kerberos", 110: "POP3", 111: "RPC", 123: "NTP", 135: "Windows RPC", 137: "NetBIOS", 139: "NetBIOS / file sharing",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "Web (HTTPS)", 445: "Windows file sharing (SMB)", 465: "SMTP (SSL)",
    500: "VPN (IKE)", 515: "Printer (LPD)", 548: "Mac file sharing", 554: "RTSP video", 587: "SMTP (mail submit)",
    631: "Printer (IPP)", 636: "LDAP (SSL)", 873: "rsync", 902: "VMware", 993: "IMAP (SSL)", 995: "POP3 (SSL)",
    1080: "SOCKS proxy", 1194: "OpenVPN", 1433: "SQL Server", 1521: "Oracle DB", 1701: "L2TP VPN", 1723: "PPTP VPN",
    1883: "MQTT (IoT)", 1900: "UPnP", 2000: "MikroTik bandwidth test", 2049: "NFS", 2082: "cPanel", 3000: "Web app",
    3128: "Web proxy", 3306: "MySQL", 3389: "Remote Desktop", 4370: "Biometric (ZKTeco)", 5000: "Web app / Synology",
    5001: "Synology (HTTPS)", 5060: "SIP phone", 5222: "XMPP chat", 5353: "mDNS", 5432: "PostgreSQL", 5555: "Android ADB",
    5900: "VNC remote control", 5985: "WinRM", 6379: "Redis", 6881: "BitTorrent", 7547: "TR-069 (ISP router management)",
    8000: "Web / Hikvision", 8008: "Web", 8080: "Web (alt)", 8081: "Web (alt)", 8088: "Web (alt)", 8291: "MikroTik WinBox",
    8443: "Web (HTTPS alt)", 8728: "MikroTik API", 8729: "MikroTik API (SSL)", 8787: "Network Doctor phone link",
    8789: "Network Doctor LAN speed test", 8888: "Web (alt)", 9000: "Web app", 9090: "Web console", 9100: "Printer (RAW)",
    10000: "Webmin / backup", 27017: "MongoDB", 34567: "DVR (XMEye)", 37777: "DVR (Dahua)", 49152: "UPnP / Windows",
}
for _p, _n in getattr(core, "PORTS", {}).items():
    SERVICES.setdefault(_p, _n)

RISKY = {
    23: "Telnet sends passwords in plain text - turn it off, use SSH",
    21: "FTP sends passwords in plain text",
    445: "SMB file sharing - must never be reachable from the internet",
    3389: "Remote Desktop - must never be reachable from the internet (ransomware entry point)",
    5900: "VNC - often has a weak or no password",
    5555: "Android debugging open - anyone on the network can control this device",
    7547: "ISP remote management port",
    6881: "BitTorrent client running",
    1080: "Open proxy?", 3128: "Web proxy",
    8291: "WinBox open - make sure the router password is strong and WinBox is closed on the internet side",
    8728: "MikroTik API open", 161: "SNMP - change the default 'public' community",
    6379: "Redis - usually no password", 27017: "MongoDB - usually no password",
}

COMMON_PORTS = sorted({20, 21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 515, 548, 554,
                       587, 631, 636, 873, 902, 993, 995, 1080, 1433, 1521, 1723, 1883, 2000, 2049, 3000, 3128, 3306,
                       3389, 4370, 5000, 5001, 5060, 5222, 5432, 5555, 5900, 5985, 6379, 6881, 7547, 8000, 8008, 8080,
                       8081, 8088, 8291, 8443, 8728, 8729, 8787, 8888, 9000, 9090, 9100, 10000, 27017, 34567, 37777,
                       49152} | set(getattr(core, "PORTS", {})))

PRESETS = {
    "Common (about 75 ports)": "common",
    "Well-known 1-1024": "1-1024",
    "Web ports": "80,81,443,3000,5000,8000,8008,8080,8081,8088,8443,8888,9000,9090",
    "Cameras / DVR": "80,443,554,8000,8080,8899,34567,37777,37778",
    "Windows / file sharing": "135,137,139,445,3389,5985",
    "MikroTik / network gear": "21,22,23,53,80,161,443,2000,8080,8291,8728,8729",
    "All ports 1-65535 (slow)": "1-65535",
}


def run(cmd, timeout=15):
    """Runs a command and returns its text output ('' when it fails). Never opens a console window."""
    try:
        kw = {}
        if core.IS_WIN:
            kw["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, **kw)
        raw = p.stdout + p.stderr
        for enc in ("utf-8", "mbcs" if core.IS_WIN else "latin-1", "latin-1"):
            try:
                return raw.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
        return raw.decode("latin-1", "replace")
    except Exception:
        return ""


def powershell(script, timeout=30):
    return run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], timeout)


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_link_local or a.is_loopback
    except ValueError:
        return False


def resolve(host):
    host = host.strip()
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return socket.gethostbyname(host)


# ==========================================================================
# this PC's real subnet (not always /24)
# ==========================================================================
def local_prefix(lip):
    """Prefix length of this PC's address (24 for 255.255.255.0). None when it can't be found."""
    mask = None
    if core.IS_WIN:
        out = run(["ipconfig"], 10)
        for block in re.split(r"\r?\n\s*\r?\n(?=\S)", out) or [out]:
            if re.search(r"\b" + re.escape(lip) + r"\b", block):
                m = re.search(r"Subnet Mask[ .]*:\s*(\d+\.\d+\.\d+\.\d+)", block)
                if m:
                    mask = m.group(1)
        if not mask:  # older layout - the mask line follows the IPv4 line
            m = re.search(re.escape(lip) + r"[^\n]*\n[^\n]*?:\s*(\d+\.\d+\.\d+\.\d+)", out)
            if m and m.group(1).startswith("255"):
                mask = m.group(1)
    else:
        out = run(["ifconfig"], 10)
        m = re.search(r"inet " + re.escape(lip) + r"\b[^\n]*netmask\s+(0x[0-9a-fA-F]{8}|\d+\.\d+\.\d+\.\d+)", out)
        if m:
            v = m.group(1)
            mask = str(ipaddress.ip_address(int(v, 16))) if v.startswith("0x") else v
        if not mask:
            m = re.search(r"inet " + re.escape(lip) + r"/(\d+)", run(["ip", "-4", "addr"], 5))
            if m:
                return int(m.group(1))
    if not mask:
        return None
    try:
        return ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


def scan_network_for(lip, prefix):
    """The network the Scan box should start with. Very large networks are cut to the /22 around this PC."""
    prefix = prefix if prefix and 16 <= prefix <= 30 else 24
    if prefix < 22:
        prefix = 22
    return str(ipaddress.ip_network(f"{lip}/{prefix}", strict=False))


# ==========================================================================
# port scanner
# ==========================================================================
def parse_ports(text):
    text = (text or "").strip().lower()
    if not text or text == "common":
        return list(COMMON_PORTS)
    ports = set()
    for part in re.split(r"[,\s;]+", text):
        if not part:
            continue
        if part == "common":
            ports |= set(COMMON_PORTS)
            continue
        m = re.fullmatch(r"(\d+)\s*-\s*(\d+)", part)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            if a > b:
                a, b = b, a
            ports |= set(range(max(1, a), min(65535, b) + 1))
        elif part.isdigit() and 1 <= int(part) <= 65535:
            ports.add(int(part))
        else:
            raise ValueError(f"'{part}' is not a port or range (examples: 80  or  8000-8100)")
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


def _probe(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        if s.connect_ex((ip, port)) == 0:
            return (time.time() - t0) * 1000
    except OSError:
        pass
    finally:
        s.close()
    return None


def banner(ip, port, timeout=1.5):
    """First line the service says (SSH / FTP / SMTP), or the web server name."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            web = port in (80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090, 10000)
            if web:
                s.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetworkDoctor\r\n\r\n".encode())
            try:
                data = s.recv(600)
            except socket.timeout:
                return ""
        txt = data.decode("latin-1", "replace")
        if txt.startswith("HTTP/"):
            first = txt.split("\r\n")[0]
            srv = re.search(r"^server:\s*(.+)$", txt, re.I | re.M)
            return first + (f" - {srv.group(1).strip()}" if srv else "")
        line = txt.strip().splitlines()[0] if txt.strip() else ""
        return re.sub(r"[^\x20-\x7e]", "", line)[:120]
    except Exception:
        return ""


def port_scan(host, ports, timeout=0.5, workers=300, stop=None, progress=None, grab=True):
    """Returns [{"port","service","ms","banner","risk"}] for open TCP ports."""
    ip = resolve(host)
    found = []
    done = 0
    n = len(ports)
    with cf.ThreadPoolExecutor(max_workers=min(workers, max(1, n))) as ex:
        futs = {}
        it = iter(ports)
        # keep a bounded number of jobs in flight so Stop is quick even for 65535 ports
        for p in it:
            futs[ex.submit(_probe, ip, p, timeout)] = p
            if len(futs) >= workers * 2:
                break
        while futs:
            fin, _ = cf.wait(list(futs), return_when=cf.FIRST_COMPLETED)
            for f in fin:
                p = futs.pop(f)
                done += 1
                ms = f.result()
                if ms is not None:
                    found.append({"port": p, "service": SERVICES.get(p, _servname(p)), "ms": ms, "banner": "",
                                  "risk": RISKY.get(p, "")})
                if stop is not None and stop.is_set():
                    continue
                nxt = next(it, None)
                if nxt is not None:
                    futs[ex.submit(_probe, ip, nxt, timeout)] = nxt
            if progress and (done % 50 == 0 or not futs):
                progress(done, n, len(found))
            if stop is not None and stop.is_set():
                for f in futs:
                    f.cancel()
                break
    found.sort(key=lambda x: x["port"])
    if grab and found and not (stop is not None and stop.is_set()):
        with cf.ThreadPoolExecutor(max_workers=16) as ex:
            for r, b in zip(found, ex.map(lambda r: banner(ip, r["port"]), found)):
                r["banner"] = b
    return ip, found


def _servname(p):
    try:
        return socket.getservbyport(p, "tcp")
    except OSError:
        return ""


# ==========================================================================
# DNS
# ==========================================================================
QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "CAA": 257}
QNAMES = {v: k for k, v in QTYPES.items()}
RCODES = {0: "OK", 1: "format error", 2: "server failure", 3: "name does not exist (NXDOMAIN)", 4: "not supported",
          5: "refused"}
PUBLIC_DNS = [("Cloudflare", "1.1.1.1"), ("Google", "8.8.8.8"), ("Quad9", "9.9.9.9")]


def system_dns_servers():
    servers = []
    if core.IS_WIN:
        out = run(["ipconfig", "/all"], 10)
        for m in re.finditer(r"DNS Servers[ .]*:\s*((?:\s*\d+\.\d+\.\d+\.\d+\s*\r?\n)+)", out):
            servers += re.findall(r"\d+\.\d+\.\d+\.\d+", m.group(1))
        if not servers:
            for m in re.finditer(r"DNS Servers[ .]*:\s*(\d+\.\d+\.\d+\.\d+)((?:\r?\n\s{20,}\d+\.\d+\.\d+\.\d+)*)", out):
                servers += [m.group(1)] + re.findall(r"\d+\.\d+\.\d+\.\d+", m.group(2))
    else:
        txt = run(["scutil", "--dns"], 5) if core.IS_MAC else ""
        servers = re.findall(r"nameserver\[\d+\]\s*:\s*(\d+\.\d+\.\d+\.\d+)", txt)
        if not servers:
            try:
                with open("/etc/resolv.conf") as f:
                    servers = re.findall(r"^nameserver\s+(\d+\.\d+\.\d+\.\d+)", f.read(), re.M)
            except OSError:
                pass
    out = []
    for s in servers:
        if s not in out and not s.startswith("127."):
            out.append(s)
    return out


def _qname(name):
    out = b""
    for part in name.rstrip(".").split("."):
        if part:
            b = part.encode("idna") if not part.isascii() else part.encode()
            if len(b) > 63:
                raise ValueError("a name part is longer than 63 characters")
            out += bytes([len(b)]) + b
    return out + b"\x00"


def _read_name(msg, off, depth=0):
    labels = []
    jumped_end = None
    while True:
        if off >= len(msg) or depth > 20:
            raise ValueError("bad name")
        ln = msg[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", msg[off:off + 2])[0] & 0x3FFF
            if jumped_end is None:
                jumped_end = off + 2
            off = ptr
            depth += 1
            continue
        labels.append(msg[off + 1:off + 1 + ln].decode("latin-1"))
        off += 1 + ln
    return ".".join(labels), (jumped_end if jumped_end is not None else off)


def build_query(name, qtype, qid=None):
    qid = random.randint(0, 65535) if qid is None else qid
    hdr = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return qid, hdr + _qname(name) + struct.pack("!HH", qtype, 1)


def parse_response(msg):
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", msg[:12])
    off = 12
    for _ in range(qd):
        _, off = _read_name(msg, off)
        off += 4
    recs = []
    for section, count in (("answer", an), ("authority", ns)):
        for _ in range(count):
            name, off = _read_name(msg, off)
            typ, _cls, ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
            off += 10
            rd = msg[off:off + rdlen]
            data = _rdata(msg, off, typ, rd)
            off += rdlen
            recs.append({"section": section, "name": name, "type": QNAMES.get(typ, str(typ)), "ttl": ttl, "data": data})
    return {"id": qid, "rcode": flags & 0xF, "tc": bool(flags & 0x0200), "ra": bool(flags & 0x0080),
            "aa": bool(flags & 0x0400), "records": recs}


def _rdata(msg, off, typ, rd):
    try:
        if typ == 1 and len(rd) == 4:
            return socket.inet_ntoa(rd)
        if typ == 28 and len(rd) == 16:
            return socket.inet_ntop(socket.AF_INET6, rd)
        if typ in (2, 5, 12):
            return _read_name(msg, off)[0]
        if typ == 15:
            pref = struct.unpack("!H", rd[:2])[0]
            return f"{pref} {_read_name(msg, off + 2)[0]}"
        if typ == 16:
            parts, i = [], 0
            while i < len(rd):
                ln = rd[i]
                parts.append(rd[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                i += 1 + ln
            return "".join(parts)
        if typ == 6:
            mname, o = _read_name(msg, off)
            rname, o = _read_name(msg, o)
            serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", msg[o:o + 20])
            return f"{mname} {rname} serial {serial} refresh {refresh} retry {retry} expire {expire} min {minimum}"
        if typ == 33:
            pri, w, port = struct.unpack("!HHH", rd[:6])
            return f"{pri} {w} {port} {_read_name(msg, off + 6)[0]}"
        if typ == 257:
            fl, tl = rd[0], rd[1]
            return f"{fl} {rd[2:2 + tl].decode()} \"{rd[2 + tl:].decode('utf-8', 'replace')}\""
    except Exception:
        pass
    return rd.hex()


def ptr_name(ip):
    a = ipaddress.ip_address(ip)
    return a.reverse_pointer


def dns_query(name, qtype="A", server=None, timeout=2.5, port=53):
    """One DNS question to one server (UDP, TCP when the answer is too big). Returns a dict with 'ms' or 'error'."""
    qtype = qtype.upper()
    if qtype == "PTR":
        try:
            name = ptr_name(name.strip())
        except ValueError:
            pass
    code = QTYPES.get(qtype)
    if not code:
        raise ValueError(f"unknown record type {qtype}")
    server = server or (system_dns_servers() or ["8.8.8.8"])[0]
    qid, pkt = build_query(name.strip(), code)
    t0 = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(pkt, (server, port))
            while True:
                data, _ = s.recvfrom(4096)
                if len(data) >= 12 and struct.unpack("!H", data[:2])[0] == qid:
                    break
        finally:
            s.close()
        res = parse_response(data)
        if res["tc"]:
            with socket.create_connection((server, port), timeout=timeout) as t:
                t.settimeout(timeout)
                t.sendall(struct.pack("!H", len(pkt)) + pkt)
                ln = struct.unpack("!H", _recv_exact(t, 2))[0]
                res = parse_response(_recv_exact(t, ln))
        res["ms"] = (time.time() - t0) * 1000
        res["server"] = server
        res["query"] = name
        res["qtype"] = qtype
        return res
    except (socket.timeout, TimeoutError):
        return {"error": "no answer (timeout)", "server": server, "query": name, "qtype": qtype}
    except OSError as e:
        return {"error": str(e), "server": server, "query": name, "qtype": qtype}
    except Exception as e:
        return {"error": f"bad answer ({e})", "server": server, "query": name, "qtype": qtype}


def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise OSError("connection closed")
        b += c
    return b


BENCH_NAMES = ["google.com", "microsoft.com", "youtube.com", "amazon.in", "whatsapp.net", "office.com", "github.com"]


def dns_benchmark(servers, names=None, rounds=2, timeout=2.0):
    """Answer time of each DNS server, and whether it lies about names that do not exist (DNS hijacking)."""
    names = names or BENCH_NAMES
    out = []
    for label, srv in servers:
        times, fails = [], 0
        for _ in range(rounds):
            for n in names:
                r = dns_query(n, "A", srv, timeout)
                if "error" in r or r["rcode"] != 0:
                    fails += 1
                else:
                    times.append(r["ms"])
        bogus = "nd-check-" + "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(12)) + ".com"
        r = dns_query(bogus, "A", srv, timeout)
        hijack = "error" not in r and r["rcode"] == 0 and any(x["type"] == "A" for x in r["records"])
        total = rounds * len(names)
        out.append({"label": label, "server": srv, "median": statistics.median(times) if times else None,
                    "first": times[0] if times else None, "fail_pct": 100.0 * fails / total, "hijack": hijack})
    return out


# ==========================================================================
# Wake-on-LAN
# ==========================================================================
def wake_on_lan(mac, lip=None, prefix=24, target_ip=None):
    """Sends the magic packet to every broadcast that could reach the device. Returns the places it was sent."""
    mac = core.norm_mac(mac)
    if not mac:
        raise ValueError("enter a MAC address like 00:11:22:33:44:55")
    pkt = b"\xff" * 6 + bytes.fromhex(mac.replace(":", "")) * 16
    dests = ["255.255.255.255"]
    if lip:
        try:
            dests.append(str(ipaddress.ip_network(f"{lip}/{prefix or 24}", strict=False).broadcast_address))
        except ValueError:
            pass
    if target_ip:
        dests.append(target_ip)  # works when the switch still knows the port of this device
    sent = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        if lip and not lip.startswith("127."):
            try:
                s.bind((lip, 0))  # leave through the office network card, not a VPN / virtual one
            except OSError:
                pass
        for d in dict.fromkeys(dests):
            for port in (9, 7):
                try:
                    s.sendto(pkt, (d, port))
                    sent.append(f"{d}:{port}")
                except OSError:
                    pass
    finally:
        s.close()
    return mac, sent


# ==========================================================================
# subnet calculator
# ==========================================================================
def subnet_info(text):
    """'192.168.0.10/24', '192.168.0.10 255.255.255.0' or '10.0.0.0/8'. Returns (rows, network)."""
    t = text.strip().replace("  ", " ")
    m = re.fullmatch(r"(\d+\.\d+\.\d+\.\d+)\s*(?:/\s*(\d+\.\d+\.\d+\.\d+|\d{1,2})|\s+(\d+\.\d+\.\d+\.\d+))?", t)
    if not m:
        raise ValueError("enter an address like 192.168.0.10/24 or 192.168.0.10 255.255.255.0")
    ip = ipaddress.ip_address(m.group(1))
    mask = m.group(2) or m.group(3) or "24"
    try:
        net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
    except ValueError:
        raise ValueError(f"'{mask}' is not a valid subnet mask")
    n = net.num_addresses
    hosts = n - 2 if net.prefixlen <= 30 else n
    first = net.network_address + (1 if net.prefixlen <= 30 else 0)
    last = net.broadcast_address - (1 if net.prefixlen <= 30 else 0)
    wildcard = ipaddress.ip_address(int(net.hostmask))
    kind = ("Private (office / home)" if ip.is_private and not ip.is_loopback and not ip.is_link_local else
            "Link-local (169.254 = the device got NO address from DHCP)" if ip.is_link_local else
            "Loopback (this computer)" if ip.is_loopback else "Multicast" if ip.is_multicast else
            "Carrier-grade NAT (100.64/10 - the ISP shares one public IP)" if ip in ipaddress.ip_network("100.64.0.0/10")
            else "Public (internet)")
    rows = [("Address", str(ip)), ("Network", f"{net.network_address}/{net.prefixlen}"),
            ("Subnet mask", str(net.netmask)), ("Wildcard (for ACLs)", str(wildcard)),
            ("Broadcast", str(net.broadcast_address)), ("Usable hosts", f"{first} - {last}"),
            ("Number of usable hosts", f"{hosts:,}"), ("Type", kind),
            ("Binary mask", ".".join(f"{b:08b}" for b in net.netmask.packed))]
    if net.prefixlen < 30:
        half = list(net.subnets(prefixlen_diff=1))
        rows.append(("Split in 2", "  |  ".join(str(s) for s in half)))
    if net.prefixlen <= 28:
        quarter = list(net.subnets(prefixlen_diff=2))
        rows.append(("Split in 4", "  |  ".join(str(s) for s in quarter)))
    if net.prefixlen > 16:
        sup = net.supernet(prefixlen_diff=1)
        rows.append(("Doubled (one size up)", f"{sup} ({sup.num_addresses - 2:,} hosts)"))
    return rows, net


def same_subnet(a, b, prefix_or_mask):
    net = ipaddress.ip_network(f"{a}/{prefix_or_mask}", strict=False)
    return ipaddress.ip_address(b) in net


# ==========================================================================
# ping statistics, MTU
# ==========================================================================
_TIME_RE = re.compile(r"(?:time|zeit|temps|tiempo)\s*([=<])\s*([\d.,]+)\s*ms", re.I)


def ping_times(text):
    """Round-trip times (ms) in a ping output. 'time<1ms' counts as 0.5 ms."""
    out = []
    for op, v in _TIME_RE.findall(text):
        try:
            x = float(v.replace(",", "."))
        except ValueError:
            continue
        out.append(0.5 if op == "<" and x <= 1 else x)
    return out


def ping_stats(ip, count=10):
    if core.IS_WIN:
        cmd = ["ping", "-n", str(count), "-w", "1000", ip]
    elif core.IS_MAC:
        cmd = ["ping", "-c", str(count), "-i", "0.3", "-W", "1000", ip]
    else:
        cmd = ["ping", "-c", str(count), "-i", "0.3", "-W", "1", ip]
    t = ping_times(run(cmd, count * 2 + 10))
    return stats_of(t, count)


def stats_of(times, sent):
    if not times:
        return {"sent": sent, "recv": 0, "loss": 100.0, "min": None, "avg": None, "max": None, "jitter": None}
    jit = statistics.mean(abs(a - b) for a, b in zip(times, times[1:])) if len(times) > 1 else 0.0
    return {"sent": sent, "recv": len(times), "loss": max(0.0, 100.0 * (sent - len(times)) / sent),
            "min": min(times), "avg": statistics.mean(times), "max": max(times), "jitter": jit}


def _df_ping(target, payload):
    """True = the packet got through without being split, False = too big, None = no answer at all."""
    if core.IS_WIN:
        out = run(["ping", "-f", "-l", str(payload), "-n", "1", "-w", "1500", target], 6)
    elif core.IS_MAC:
        out = run(["ping", "-D", "-s", str(payload), "-c", "1", "-W", "1500", target], 6)
    else:
        out = run(["ping", "-M", "do", "-s", str(payload), "-c", "1", "-W", "2", target], 6)
    low = out.lower()
    if re.search(r"ttl[=:]", low) and "fragment" not in low:
        return True
    if "fragment" in low or "message too long" in low or "frag needed" in low or "mtu" in low:
        return False
    return None


def mtu_probe(target, log=lambda s: None, stop=None):
    """Largest packet that reaches the target without being split. Returns the MTU (payload + 28) or None."""
    if _df_ping(target, 32) is not True:
        log(f"{target} does not answer ping - choose another target (for example 8.8.8.8 or the router).")
        return None
    lo, hi = 32, 1472
    if _df_ping(target, hi):
        log("1472 bytes + 28 header = 1500 got through.")
        return 1500
    while hi - lo > 1:
        if stop is not None and stop.is_set():
            return None
        mid = (lo + hi) // 2
        r = _df_ping(target, mid)
        log(f"  {mid + 28} bytes: {'OK' if r else 'too big' if r is False else 'no answer'}")
        if r:
            lo = mid
        else:
            hi = mid
    return lo + 28


def mtu_advice(mtu):
    if mtu is None:
        return ""
    if mtu >= 1500:
        return "MTU 1500 - normal Ethernet, nothing to change."
    if mtu == 1492:
        return ("MTU 1492 - normal for a PPPoE (broadband) internet line. Make sure the router clamps MSS: "
                "MikroTik: /ip firewall mangle add chain=forward protocol=tcp tcp-flags=syn action=change-mss "
                "new-mss=clamp-to-pmtu passthrough=yes  (PPPoE client 'change MSS' does the same).")
    return (f"MTU {mtu} - smaller than normal (a VPN, tunnel or the ISP line). Big downloads / some websites can hang "
            "when MSS is not clamped. Add MSS clamping on the router (see the Commands tab), or set this MTU on the "
            "router's internet interface.")


# ==========================================================================
# internet quality and speed (Cloudflare speed test servers - nearest data centre)
# ==========================================================================
SPEED_HOST = "speed.cloudflare.com"
UA = {"User-Agent": "NetworkDoctor"}


def _get(url, timeout=8):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def public_ip_info():
    """Public IP, ISP and the speed-test data centre. {} when the internet is not reachable."""
    try:
        j = json.loads(_get(f"https://{SPEED_HOST}/meta"))
        return {"ip": j.get("clientIp", ""), "isp": j.get("asOrganization", ""), "asn": j.get("asn", ""),
                "city": j.get("city", ""), "country": j.get("country", ""), "colo": j.get("colo", "")}
    except Exception:
        pass
    try:
        kv = dict(line.split("=", 1) for line in _get("https://www.cloudflare.com/cdn-cgi/trace").splitlines()
                  if "=" in line)
        return {"ip": kv.get("ip", ""), "isp": "", "asn": "", "city": "", "country": kv.get("loc", ""),
                "colo": kv.get("colo", "")}
    except Exception:
        return {}


def _down_stream(deadline, counter, lock, stop, errors):
    while time.time() < deadline and not (stop is not None and stop.is_set()):
        try:
            conn = http.client.HTTPSConnection(SPEED_HOST, timeout=10, context=ssl.create_default_context())
            conn.request("GET", "/__down?bytes=50000000", headers=UA)
            r = conn.getresponse()
            while time.time() < deadline and not (stop is not None and stop.is_set()):
                b = r.read(65536)
                if not b:
                    break
                with lock:
                    counter[0] += len(b)
            conn.close()
        except Exception as e:
            errors.append(str(e))
            time.sleep(0.3)
            if len(errors) > 20:
                return


def _up_stream(deadline, counter, lock, stop, errors):
    chunk = os.urandom(65536)
    while time.time() < deadline and not (stop is not None and stop.is_set()):
        try:
            conn = http.client.HTTPSConnection(SPEED_HOST, timeout=10, context=ssl.create_default_context())
            size = 8 * 1024 * 1024
            conn.putrequest("POST", "/__up")
            conn.putheader("User-Agent", "NetworkDoctor")
            conn.putheader("Content-Type", "application/octet-stream")
            conn.putheader("Content-Length", str(size))
            conn.endheaders()
            sent = 0
            while sent < size and time.time() < deadline and not (stop is not None and stop.is_set()):
                n = min(len(chunk), size - sent)
                conn.send(chunk[:n])
                sent += n
                with lock:
                    counter[0] += n
            if sent >= size:
                conn.getresponse().read()
            conn.close()
        except Exception as e:
            errors.append(str(e))
            time.sleep(0.3)
            if len(errors) > 20:
                return


def throughput(direction, seconds=8, streams=4, stop=None, progress=None):
    """Mbit/s, measured after a 1.5 s warm-up (TCP slow start would make it look slower)."""
    counter, lock, errors = [0], threading.Lock(), []
    warm = 1.5
    t0 = time.time()
    deadline = t0 + warm + seconds
    fn = _down_stream if direction == "down" else _up_stream
    ths = [threading.Thread(target=fn, args=(deadline, counter, lock, stop, errors), daemon=True) for _ in range(streams)]
    for th in ths:
        th.start()
    time.sleep(warm)
    with lock:
        base, tb = counter[0], time.time()
    while time.time() < deadline and not (stop is not None and stop.is_set()):
        time.sleep(0.5)
        if progress:
            with lock:
                c = counter[0]
            el = time.time() - tb
            if el > 0:
                progress((c - base) * 8 / el / 1e6)
    for th in ths:
        th.join(3)
    with lock:
        total = counter[0] - base
    el = max(0.001, min(time.time(), deadline) - tb)
    if total <= 0:
        raise OSError("speed test server not reachable" + (f" ({errors[-1]})" if errors else ""))
    return total * 8 / el / 1e6


class LoadedPinger:
    """Pings a target while a speed test runs: latency under load shows 'bufferbloat' (calls / games lag)."""

    def __init__(self, target):
        self.target, self.times, self.stop = target, [], threading.Event()
        self.th = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self.stop.is_set():
            t = ping_times(run(core.ping_cmd(self.target, 1000), 4))
            if t:
                self.times.append(t[0])
            self.stop.wait(0.4)

    def __enter__(self):
        self.th.start()
        return self

    def __exit__(self, *a):
        self.stop.set()
        self.th.join(3)


def grade_line(down, up, idle_ms, loaded_ms):
    tips = []
    if loaded_ms is not None and idle_ms is not None and loaded_ms - idle_ms > 100:
        tips.append(f"Latency jumps from {idle_ms:.0f} to {loaded_ms:.0f} ms when the line is busy (bufferbloat): "
                    "video calls and ERP screens lag while someone downloads. Fix: a queue on the router "
                    "(MikroTik: /queue simple with max-limit about 90% of the line speed, queue type fq-codel/cake on "
                    "RouterOS 7).")
    if down is not None and down < 10:
        tips.append("Download under 10 Mbit/s - slow for an office. Check the plan with the ISP, and who is using the line "
                    "(Live monitor > Top bandwidth users).")
    if up is not None and down and up < down / 20:
        tips.append("Upload is very small compared to download - cloud backups, CCTV remote viewing and video calls will "
                    "suffer.")
    return tips


# ==========================================================================
# Wi-Fi analyzer
# ==========================================================================
def chan_to_band(ch):
    return "2.4 GHz" if 1 <= ch <= 14 else "6 GHz" if ch > 196 else "5 GHz"


def parse_netsh_networks(text):
    """netsh wlan show networks mode=bssid -> [{"ssid","auth","enc","bssid","signal","radio","band","channel"}]"""
    nets = []
    ssid = auth = enc = ""
    cur = None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line)
        if m:
            ssid, auth, enc = m.group(1).strip(), "", ""
            cur = None
            continue
        kv = re.match(r"^([^:]+?)\s*:\s*(.*)$", line)
        if not kv:
            continue
        k, v = kv.group(1).strip().lower(), kv.group(2).strip()
        if k.startswith("authentication"):
            auth = v
        elif k.startswith("encryption"):
            enc = v
        elif re.match(r"^bssid\s+\d+", k):
            cur = {"ssid": ssid or "(hidden)", "auth": auth, "enc": enc, "bssid": core.norm_mac(v) or v, "signal": None,
                   "radio": "", "band": "", "channel": None}
            nets.append(cur)
        elif cur is not None:
            if k.startswith("signal"):
                mm = re.search(r"(\d+)", v)
                cur["signal"] = int(mm.group(1)) if mm else None
            elif k.startswith("radio type"):
                cur["radio"] = v
            elif k.startswith("band"):
                cur["band"] = v.replace("  ", " ")
            elif k.startswith("channel") and "utilization" not in k:
                mm = re.search(r"(\d+)", v)
                if mm:
                    cur["channel"] = int(mm.group(1))
    for n in nets:
        if n["channel"] and not n["band"]:
            n["band"] = chan_to_band(n["channel"])
    return nets


def parse_netsh_interface(text):
    """netsh wlan show interfaces -> the connected Wi-Fi (dict) or {}"""
    info = {}
    for raw in text.splitlines():
        kv = re.match(r"^\s*([^:]+?)\s*:\s*(.*)$", raw)
        if not kv:
            continue
        k, v = kv.group(1).strip().lower(), kv.group(2).strip()
        if k == "ssid":
            info["ssid"] = v
        elif k == "bssid" or k == "ap bssid":
            info["bssid"] = core.norm_mac(v) or v
        elif k == "state":
            info["state"] = v
        elif k.startswith("signal"):
            mm = re.search(r"(\d+)", v)
            info["signal"] = int(mm.group(1)) if mm else None
        elif k == "channel":
            mm = re.search(r"(\d+)", v)
            info["channel"] = int(mm.group(1)) if mm else None
        elif k.startswith("receive rate"):
            info["rx"] = v
        elif k.startswith("transmit rate"):
            info["tx"] = v
        elif k.startswith("radio type"):
            info["radio"] = v
        elif k == "band":
            info["band"] = v
        elif k == "rssi":
            info["rssi"] = v
        elif k.startswith("physical address"):
            info["mac"] = core.norm_mac(v)
    return info if info.get("ssid") or info.get("state") else {}


def parse_mac_airport(j):
    """system_profiler SPAirPortDataType -json -> (connected dict, networks list)"""
    cur, nets = {}, []

    def entry(n):
        ch = str(n.get("spairport_network_channel", ""))
        mm = re.match(r"(\d+)", ch)
        sn = str(n.get("spairport_signal_noise", ""))
        rssi = re.search(r"(-?\d+)\s*dBm", sn)
        sig = None
        if rssi:
            dbm = int(rssi.group(1))
            sig = max(0, min(100, 2 * (dbm + 100)))  # -50 dBm = 100%, -100 dBm = 0%
        band = "2.4 GHz" if "2GHz" in ch or "2.4" in ch else "5 GHz" if "5GHz" in ch else "6 GHz" if "6GHz" in ch else ""
        c = int(mm.group(1)) if mm else None
        return {"ssid": n.get("_name", "(hidden)"), "auth": str(n.get("spairport_security_mode", "")).replace(
            "spairport_security_mode_", "").replace("_", " "), "enc": "", "bssid": n.get("spairport_network_bssid", ""),
            "signal": sig, "rssi": sn, "radio": str(n.get("spairport_network_phymode", "")),
            "band": band or (chan_to_band(c) if c else ""), "channel": c}
    try:
        for itf in j.get("SPAirPortDataType", [{}])[0].get("spairport_airport_interfaces", []):
            if itf.get("spairport_current_network_information"):
                e = entry(itf["spairport_current_network_information"])
                e["tx"] = str(itf["spairport_current_network_information"].get("spairport_network_rate", "")) + " Mbps"
                cur = e
            for n in itf.get("spairport_airport_other_local_wireless_networks", []) or []:
                nets.append(entry(n))
    except Exception:
        pass
    if cur:
        nets.append(dict(cur))
    return cur, nets


def wifi_scan():
    """Returns (connected, networks, note)."""
    if core.IS_WIN:
        it = parse_netsh_interface(run(["netsh", "wlan", "show", "interfaces"], 10))
        out = run(["netsh", "wlan", "show", "networks", "mode=bssid"], 15)
        if "location" in out.lower() and "permission" in out.lower():
            return it, [], ("Windows needs Location turned on to list Wi-Fi networks: Settings > Privacy & security > "
                            "Location > turn on 'Location services' and 'Let desktop apps access your location'.")
        if "wlan" in out.lower() and "not running" in out.lower():
            return it, [], "This PC has no Wi-Fi adapter (or the WLAN AutoConfig service is stopped)."
        return it, parse_netsh_networks(out), ""
    if core.IS_MAC:
        try:
            j = json.loads(run(["system_profiler", "SPAirPortDataType", "-json"], 40) or "{}")
        except ValueError:
            j = {}
        cur, nets = parse_mac_airport(j)
        note = "" if nets else "No Wi-Fi networks found (is Wi-Fi on?)."
        if nets and all(n["ssid"] in ("", "(hidden)", "<redacted>") for n in nets):
            note = "macOS hides network names unless Network Doctor is allowed Location (System Settings > Privacy)."
        return cur, nets, note
    return {}, [], "Wi-Fi analysis works on Windows and Mac."


CH24_BEST = (1, 6, 11)


def wifi_analyse(nets, connected=None):
    """Channel crowding and advice. Returns (lines, per-channel counts)."""
    lines = []
    counts = {}
    for n in nets:
        if n.get("channel"):
            counts[n["channel"]] = counts.get(n["channel"], 0) + 1
    # 2.4 GHz channels overlap with neighbours up to 4 channels away
    load = {}
    for ch in range(1, 14):
        load[ch] = sum(((n.get("signal") or 30) / 100.0) * (1 - abs(ch - n["channel"]) / 5.0)
                       for n in nets if n.get("channel") and n["channel"] <= 14 and abs(ch - n["channel"]) < 5)
    best24 = min(CH24_BEST, key=lambda c: load[c])
    used5 = {c: v for c, v in counts.items() if c > 14}
    cand5 = [36, 40, 44, 48, 149, 153, 157, 161]
    best5 = min(cand5, key=lambda c: (sum(v for ch, v in used5.items() if abs(ch - c) < 8), c))
    if connected and connected.get("channel"):
        c = connected["channel"]
        lines.append(f"Connected to '{connected.get('ssid', '')}' on channel {c} ({chan_to_band(c)}), signal "
                     f"{connected.get('signal', '?')}%" + (f", link {connected['rx']} Mbps" if connected.get("rx") else ""))
        sig = connected.get("signal")
        if sig is not None and sig < 50:
            lines.append("  ! Weak signal - move the access point closer or add one; weak Wi-Fi causes drops and slow ERP.")
        if c <= 14:
            if c not in CH24_BEST:
                lines.append(f"  ! Channel {c} overlaps two clean channels - set the access point to 1, 6 or 11 "
                             f"(least busy here: {best24}).")
            elif load.get(c, 0) > load[best24] + 0.5:
                lines.append(f"  ! Channel {c} is crowded here - channel {best24} is less busy.")
            lines.append("  Tip: use 5 GHz for PCs and laptops near the access point - more channels, less interference.")
        elif sum(v for ch, v in used5.items() if abs(ch - c) < 8) > 3:
            lines.append(f"  ! 5 GHz channel {c} is shared with many networks - channel {best5} looks freer.")
    lines.append(f"Best 2.4 GHz channel here: {best24}  (only 1, 6 and 11 do not overlap)")
    lines.append(f"Least used 5 GHz channel here: {best5}")
    weak = [n for n in nets if n.get("auth") and re.search(r"\bopen\b|wep|^wpa-personal$|tkip", n["auth"] + " " +
                                                               (n.get("enc") or ""), re.I)]
    for n in weak[:6]:
        lines.append(f"  ! '{n['ssid']}' uses weak security ({n['auth']} {n.get('enc', '')}) - use WPA2/WPA3 with AES.")
    same = {}
    for n in nets:
        same.setdefault(n["ssid"], set()).add(n.get("channel"))
    return lines, counts


# ==========================================================================
# this PC's network adapters
# ==========================================================================
PS_ADAPTERS = r"""
$r = foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue)) {
  $s = Get-NetAdapterStatistics -Name $a.Name -ErrorAction SilentlyContinue
  $ip = Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
  $ipi = Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
  [pscustomobject]@{ name = $a.Name; desc = $a.InterfaceDescription; status = [string]$a.Status;
    speed = [string]$a.LinkSpeed; bps = [int64]$a.ReceiveLinkSpeed; duplex = $a.FullDuplex; mac = $a.MacAddress;
    media = [string]$a.PhysicalMediaType; virtual = [bool]$a.Virtual; hw = [bool]$a.HardwareInterface;
    rxerr = [int64]$s.ReceivedPacketErrors; txerr = [int64]$s.OutboundPacketErrors;
    rxdisc = [int64]$s.ReceivedDiscardedPackets; txdisc = [int64]$s.OutboundDiscardedPackets;
    rx = [int64]$s.ReceivedBytes; tx = [int64]$s.SentBytes; ip = [string]$ip.IPAddress;
    prefix = [int]$ip.PrefixLength; dhcp = [string]$ipi.Dhcp; mtu = [int]$ipi.NlMtu }
}
@($r) | ConvertTo-Json -Depth 3
"""


def adapters():
    """[{"name","desc","status","speed","bps","duplex","mac","wifi","rxerr","txerr",...}]"""
    if core.IS_WIN:
        out = powershell(PS_ADAPTERS, 40).strip()
        try:
            j = json.loads(out[out.find("["):] if "[" in out else out)
        except ValueError:
            return []
        if isinstance(j, dict):
            j = [j]
        res = []
        for a in j:
            a["wifi"] = bool(re.search(r"802\.11|wireless|wi-?fi|wlan", f"{a.get('media')} {a.get('desc')}", re.I))
            a["mac"] = core.norm_mac(a.get("mac") or "")
            res.append(a)
        return res
    return parse_ifconfig_adapters(run(["ifconfig", "-a"], 10),
                                   run(["netstat", "-i", "-b"] if core.IS_MAC else ["netstat", "-i"], 10),
                                   run(["networksetup", "-listallhardwareports"], 10) if core.IS_MAC else "")


def parse_ifconfig_adapters(ifc, nst="", hwports=""):
    res = []
    wifi_devs = set(re.findall(r"Hardware Port:\s*(?:Wi-Fi|AirPort)\s*\nDevice:\s*(\S+)", hwports))
    errs = {}
    for line in nst.splitlines()[1:]:
        p = line.split()
        if len(p) >= 8 and p[0] not in errs and "<Link" in line:
            try:  # Name Mtu Network Address Ipkts Ierrs (Ibytes) Opkts Oerrs ...
                nums = [x for x in p if x.isdigit() or x == "-"]
                if len(nums) >= 5:
                    has_bytes = len(nums) >= 7
                    ierr = nums[2]
                    oerr = nums[5] if has_bytes else nums[4]
                    errs[p[0]] = (int(ierr) if ierr.isdigit() else 0, int(oerr) if oerr.isdigit() else 0)
            except Exception:
                pass
    for block in re.split(r"\n(?=\S)", ifc):
        m = re.match(r"^(\S+?):", block)
        if not m:
            continue
        name = m.group(1)
        if name.startswith(("lo", "gif", "stf", "utun", "awdl", "llw", "anpi", "ap", "bridge", "vmenet", "docker", "veth")):
            continue
        mac = re.search(r"(?:ether|HWaddr)\s+([0-9a-fA-F:]{11,17})", block)
        ip = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", block)
        media = re.search(r"media:\s*(.+)", block)
        status = re.search(r"status:\s*(\w+)", block)
        med = media.group(1).strip() if media else ""
        sp = re.search(r"(\d+)(G|)base", med)
        bps = (int(sp.group(1)) * (1000 if sp.group(2) == "G" else 1)) * 1_000_000 if sp else 0
        duplex = None if not med else ("full-duplex" in med)
        mtu = re.search(r"mtu (\d+)", block)
        e = errs.get(name, (0, 0))
        res.append({"name": name, "desc": med, "status": "Up" if (status and status.group(1) == "active") or
                    (not status and "UP" in block.split("\n")[0] and ip) else "Disconnected",
                    "speed": f"{bps // 1_000_000} Mbps" if bps else "", "bps": bps, "duplex": duplex,
                    "mac": core.norm_mac(mac.group(1)) if mac else "", "wifi": name in wifi_devs or "802.11" in med,
                    "rxerr": e[0], "txerr": e[1], "rxdisc": 0, "txdisc": 0, "ip": ip.group(1) if ip else "",
                    "mtu": int(mtu.group(1)) if mtu else 0, "virtual": False, "hw": True})
    return res


def adapter_findings(ads):
    """Plain-language problems: 100 Mbps cables, half duplex, errors, APIPA, many adapters bridging."""
    out = []
    up = [a for a in ads if str(a.get("status")).lower() == "up" and not a.get("virtual")]
    for a in up:
        nm = f"{a.get('name')} ({a.get('desc', '')[:40]})"
        bps = int(a.get("bps") or 0)
        if not a.get("wifi") and 0 < bps <= 100_000_000:
            out.append(("warning", f"{nm} runs at only {a.get('speed')}. A gigabit link needs all 8 wires - a damaged or "
                                   "badly crimped cable, a cheap 100 Mbps switch, or a dusty port. Replace the patch "
                                   "cable first."))
        if a.get("duplex") is False and not a.get("wifi"):
            out.append(("critical", f"{nm} is in HALF duplex - collisions and slow transfers. One side is set to a fixed "
                                    "speed: set both the PC and the switch port to Auto."))
        errs = int(a.get("rxerr") or 0) + int(a.get("txerr") or 0)
        if errs > 50:
            out.append(("warning", f"{nm} has {errs:,} packet errors - a bad cable, connector or switch port "
                                   "(or electrical noise from motors / VFDs near the cable)."))
        ip = a.get("ip") or ""
        if ip.startswith("169.254."):
            out.append(("critical", f"{nm} has {ip}: it got NO address from DHCP. Check the cable / switch port and "
                                    "whether the router's DHCP pool is full."))
        mtu = int(a.get("mtu") or 0)
        if mtu and mtu < 1400 and not a.get("wifi"):
            out.append(("info", f"{nm} MTU is {mtu} (normal: 1500)."))
    wired = [a for a in up if not a.get("wifi") and a.get("ip")]
    wifi = [a for a in up if a.get("wifi") and a.get("ip")]
    if wired and wifi:
        out.append(("info", "This PC is on cable AND Wi-Fi at the same time. If both are in the office network and "
                            "Windows bridges them (Network Bridge), it can create a loop - check there is no bridge."))
    if not out:
        out.append(("ok", "No adapter problems: link speeds, duplex and error counters look normal."))
    return out


# ==========================================================================
# LAN speed test between two PCs running Network Doctor (TCP 8789)
# ==========================================================================
LAN_PORT = 8789
_MAGIC = b"NDSPD1"


class LanSpeedServer:
    """Answers LAN speed tests from other Network Doctor PCs. Accepts private (office) addresses only."""

    def __init__(self, port=LAN_PORT, max_minutes=60):
        self.port, self.max_minutes = port, max_minutes
        self.sock = None
        self.running = False
        self.served = 0
        self.until = 0

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", self.port))
        s.listen(4)
        s.settimeout(1.0)
        self.sock, self.running = s, True
        self.until = time.time() + self.max_minutes * 60
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass

    def _loop(self):
        while self.running and time.time() < self.until:
            try:
                c, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not is_private(addr[0]):
                c.close()
                continue
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()
        self.stop()

    def _serve(self, c):
        try:
            c.settimeout(15)
            hdr = _recv_exact(c, 8)
            if hdr[:6] != _MAGIC:
                return
            mode, secs = chr(hdr[6]), min(30, max(1, hdr[7]))
            if mode == "U":  # the other PC sends, we count and report
                n, t0 = 0, time.time()
                while True:
                    b = c.recv(262144)
                    if not b:
                        break
                    if b.endswith(b"\x00END"):
                        n += len(b) - 4
                        break
                    n += len(b)
                el = time.time() - t0
                c.sendall(struct.pack("!Qd", n, el))
            elif mode == "D":  # we send to the other PC for <secs> seconds
                chunk = os.urandom(262144)
                end = time.time() + secs
                while time.time() < end:
                    c.sendall(chunk)
            self.served += 1
        except Exception:
            pass
        finally:
            c.close()


def lan_speed_test(ip, seconds=5, progress=lambda s: None):
    """Returns (upload_mbps, download_mbps) between this PC and another PC with the LAN speed receiver on."""
    chunk = os.urandom(262144)
    with socket.create_connection((ip, LAN_PORT), timeout=4) as s:
        s.settimeout(15)
        s.sendall(_MAGIC + b"U" + bytes([seconds]))
        end = time.time() + seconds
        while time.time() < end:
            s.sendall(chunk)
        s.sendall(b"\x00END")
        s.shutdown(socket.SHUT_WR)
        n, el = struct.unpack("!Qd", _recv_exact(s, 16))
    up = n * 8 / max(el, 0.001) / 1e6
    progress(f"This PC -> {ip}: {up:.0f} Mbit/s")
    with socket.create_connection((ip, LAN_PORT), timeout=4) as s:
        s.settimeout(15)
        s.sendall(_MAGIC + b"D" + bytes([seconds]))
        n, t0 = 0, time.time()
        while True:
            b = s.recv(262144)
            if not b:
                break
            n += len(b)
        el = time.time() - t0
    down = n * 8 / max(el, 0.001) / 1e6
    return up, down


def lan_advice(mbps):
    if mbps >= 600:
        return "Gigabit path - cables and switches are fine."
    if mbps >= 250:
        return "Below gigabit - a Wi-Fi hop, a busy switch or a slow PC disk/CPU on one end."
    if 70 <= mbps < 100:
        return ("About 100 Mbit/s - somewhere on the path a link runs at 100 Mbps: a damaged cable (only 4 of 8 wires "
                "working), an old switch, or a port set to 100 Mbps. Check the adapter speed on both PCs (Tools > "
                "This PC's adapters) and the switch port lights.")
    return ("Very slow for a cable network - a bad cable / port (errors), a loop or storm, or Wi-Fi with a weak signal. "
            "Run it again with both PCs on cable, then check the adapters and the Live monitor.")


# ==========================================================================
# web / server check
# ==========================================================================
def web_check(target, timeout=6):
    """DNS, TCP, TLS and HTTP timings plus certificate expiry for a URL or host[:port]. Returns list of (label, value, sev)."""
    t = target.strip()
    if "://" not in t:
        t = ("https://" if re.search(r":(443|8443)$", t) else "http://") + t
    u = urllib.parse.urlsplit(t)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    rows = []
    t0 = time.time()
    try:
        ip = resolve(host)
    except Exception as e:
        return [("DNS", f"'{host}' not found: {e}", "critical")]
    rows.append(("DNS", f"{host} -> {ip}  ({(time.time() - t0) * 1000:.0f} ms)", "ok"))
    t1 = time.time()
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except Exception as e:
        rows.append(("Connect", f"port {port} closed / blocked: {e}", "critical"))
        return rows
    rows.append(("Connect", f"TCP {port} open ({(time.time() - t1) * 1000:.0f} ms)", "ok"))
    sock = raw
    if u.scheme == "https":
        t2 = time.time()
        ctx = ssl.create_default_context()
        try:
            sock = ctx.wrap_socket(raw, server_hostname=host)
            cert = sock.getpeercert()
            exp = ssl.cert_time_to_seconds(cert["notAfter"])
            days = int((exp - time.time()) // 86400)
            issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "")
            rows.append(("TLS", f"{sock.version()} trusted certificate ({(time.time() - t2) * 1000:.0f} ms)", "ok"))
            rows.append(("Certificate", f"expires in {days} days ({cert['notAfter']}), issuer {issuer}",
                         "critical" if days < 0 else "warning" if days < 21 else "ok"))
        except ssl.SSLCertVerificationError as e:
            rows.append(("TLS", f"certificate NOT trusted: {e.verify_message} (normal for routers, cameras and NAS "
                                f"with their own certificate)", "warning"))
            raw.close()
            raw = socket.create_connection((ip, port), timeout=timeout)
            c2 = ssl.create_default_context()
            c2.check_hostname = False
            c2.verify_mode = ssl.CERT_NONE
            sock = c2.wrap_socket(raw, server_hostname=host)
        except Exception as e:
            rows.append(("TLS", f"failed: {e}", "critical"))
            raw.close()
            return rows
    t3 = time.time()
    try:
        sock.settimeout(timeout)
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetworkDoctor\r\nConnection: close\r\n\r\n"
                     .encode())
        data = b""
        while len(data) < 16384:
            b = sock.recv(4096)
            if not b:
                break
            data += b
            if b"\r\n\r\n" in data:
                break
        ttfb = (time.time() - t3) * 1000
        head = data.split(b"\r\n\r\n")[0].decode("latin-1", "replace")
        first = head.split("\r\n")[0]
        m = re.match(r"HTTP/\S+\s+(\d+)", first)
        code = int(m.group(1)) if m else 0
        srv = re.search(r"^server:\s*(.+)$", head, re.I | re.M)
        loc = re.search(r"^location:\s*(.+)$", head, re.I | re.M)
        rows.append(("HTTP", f"{first}  (first byte {ttfb:.0f} ms)",
                     "ok" if 200 <= code < 400 or code == 401 else "warning"))
        if loc:
            rows.append(("Redirects to", loc.group(1).strip(), "ok"))
        if srv:
            rows.append(("Server", srv.group(1).strip(), "ok"))
        if ttfb > 1500:
            rows.append(("Speed", "slow answer (over 1.5 s) - the server is busy or overloaded", "warning"))
    except Exception as e:
        rows.append(("HTTP", f"no answer: {e}", "critical"))
    finally:
        sock.close()
    rows.append(("Total", f"{(time.time() - t0) * 1000:.0f} ms", "ok"))
    return rows


# ==========================================================================
# MAC address lookup
# ==========================================================================
def mac_info(mac, oui):
    m = core.norm_mac(mac)
    if not m:
        raise ValueError("enter a MAC address like 00:11:22:33:44:55 or 00-11-22-33-44-55")
    first = int(m[:2], 16)
    rows = [("MAC", m), ("Vendor", core.vendor_of(m, oui) or "not in the vendor list")]
    if first & 1:
        rows.append(("Type", "multicast / group address (not a single device)"))
    elif first & 2:
        rows.append(("Type", "Locally administered = RANDOMIZED / private MAC (phone, laptop privacy feature, VM, or "
                             "a changed MAC). It can change - turn off 'private address' on that device for this Wi-Fi "
                             "so IP-MAC binding keeps working."))
    else:
        rows.append(("Type", "Real (burned-in) MAC from the manufacturer"))
    rows.append(("Written other ways", f"{m.replace(':', '-')}   {m.replace(':', '').lower()}   "
                                       f"{m.replace(':', '')[:4].lower()}.{m.replace(':', '')[4:8].lower()}."
                                       f"{m.replace(':', '')[8:].lower()}"))
    return rows
