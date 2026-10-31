# -*- coding: utf-8 -*-
"""
Network Doctor - live monitor, traffic analysis and root-cause engine.

Data sources (all standard protocols, nothing logs in to anything):
  * Local sampler      : broadcast packets/s on this PC, gateway ping every 2 s
  * Router log receiver: standard syslog (UDP 514 on Windows, 5514 on Mac) - port up/down, loop, DHCP, conflicts, login attacks
  * Flow receiver      : NetFlow v5 / v9 / IPFIX (UDP 2055) - per-device bandwidth and destinations
  * Packet sniffer     : (optional, Npcap + Scapy) broadcast top senders, STP changes,
                         DHCP requests, ARP spoofing, periodic loop echo test

Thread safety: every structure written by a background thread is guarded by Monitor.lock or
TrafficStore.lock, and readers use the *_copy() snapshot helpers.
"""

import bisect
import datetime as _dt
import ipaddress
import json
import os
import re
import socket
import statistics
import struct
import threading
import time
import urllib.request
from collections import Counter, defaultdict, deque, OrderedDict
from concurrent.futures import ThreadPoolExecutor

import nd_core as core
import nd_tools as tools

FLOW_PORT = 2055
SYSLOG_PORT = 514 if core.IS_WIN else 5514  # macOS/Linux do not let normal apps use ports below 1024
STORM_PPS = 300


def fmt_bytes(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def fmt_rate(bps):
    bits = (bps or 0) * 8
    if bits >= 1e6:
        return f"{bits / 1e6:.1f} Mbps"
    if bits >= 1e3:
        return f"{bits / 1e3:.0f} kbps"
    return f"{bits:.0f} bps"


def tstr(t):
    return time.strftime("%H:%M:%S", time.localtime(t))


def _ip_int(ip):
    try:
        return int(ipaddress.IPv4Address(ip))
    except Exception:
        return None


# ==========================================================================
# threat intelligence (public block lists, cached 12 h)
# ==========================================================================
FEEDS = [
    ("Botnet control server (abuse.ch Feodo Tracker)", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "malware"),
    ("Compromised / attacking host (Emerging Threats)", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "malware"),
    ("Hijacked criminal network (Spamhaus DROP)", "https://www.spamhaus.org/drop/drop.txt", "malicious"),
    ("Known attacker (FireHOL level 1)", "https://iplists.firehol.org/files/firehol_level1.netset", "malicious"),
    ("Tor anonymity network exit", "https://check.torproject.org/torbulkexitlist", "tor"),
]
KIND_RANK = {"malware": 0, "malicious": 1, "tor": 2}


class ThreatIntel:
    """Each feed is kept as its own sorted, merged list of ranges, so overlapping feeds never hide a match."""

    def __init__(self):
        self.path = os.path.join(core.DATA_DIR, "threat_cache_v2.json")
        self.feeds = []  # [(label, kind, starts, ends)]
        self.loaded_at = 0
        self.status = "loading..."
        self.lock = threading.Lock()
        self.version = 0

    def load(self, force=False):
        cached = None
        try:
            with open(self.path, encoding="utf-8") as f:
                cached = json.load(f)
        except Exception:
            cached = None
        data = cached
        if force or not cached or time.time() - cached.get("time", 0) > 12 * 3600:
            data = self._download() or cached
        if data and data.get("feeds"):
            feeds = []
            total = 0
            for label, kind, ranges in data["feeds"]:
                feeds.append((label, kind, [r[0] for r in ranges], [r[1] for r in ranges]))
                total += len(ranges)
            feeds.sort(key=lambda f: KIND_RANK.get(f[1], 9))
            with self.lock:
                self.feeds = feeds
                self.loaded_at = data.get("time", time.time())
                self.version += 1
            age = time.strftime("%d-%b %H:%M", time.localtime(self.loaded_at))
            self.status = f"{len(feeds)} block lists, {total} bad networks (updated {age})"
        else:
            self.status = "block lists not available (no internet?) - safety check limited to port patterns"

    @staticmethod
    def _merge(ranges):
        ranges.sort()
        out = []
        for s, e in ranges:
            if out and s <= out[-1][1] + 1:
                out[-1][1] = max(out[-1][1], e)
            else:
                out.append([s, e])
        return out

    def _download(self):
        feeds, ok = [], 0
        for label, url, kind in FEEDS:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 NetworkDoctor"})
                txt = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace")
            except Exception:
                continue
            ranges = []
            for line in txt.splitlines():
                line = line.strip()
                if not line or line[0] in "#;":
                    continue
                m = re.match(r"(\d+\.\d+\.\d+\.\d+(?:/\d+)?)", line)
                if not m:
                    continue
                try:
                    net = ipaddress.ip_network(m.group(1), strict=False)
                except ValueError:
                    continue
                if net.prefixlen < 8 or not net.is_global or net.is_multicast or net.is_reserved:
                    continue  # never flag private, CGNAT (Jio/Airtel 100.64/10), multicast or huge blocks
                ranges.append((int(net.network_address), int(net.broadcast_address)))
            if ranges:
                ok += 1
                feeds.append([label, kind, self._merge(ranges)])
        if not ok:
            return None
        data = {"time": time.time(), "feeds": feeds}
        try:
            os.makedirs(core.DATA_DIR, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass
        return data

    def check(self, ip):
        """Returns (label, kind) of the most serious list that contains ip, else None."""
        n = _ip_int(ip)
        if n is None:
            return None
        with self.lock:
            for label, kind, starts, ends in self.feeds:
                i = bisect.bisect_right(starts, n) - 1
                if i >= 0 and ends[i] >= n:
                    return label, kind
        return None


# ==========================================================================
# who is behind an internet address (reverse DNS + RDAP registry, cached)
# ==========================================================================
class OrgLookup:
    MAX_PENDING = 300
    MAX_CACHE = 60000

    def __init__(self):
        self.path = os.path.join(core.DATA_DIR, "org_cache.json")
        try:
            with open(self.path, encoding="utf-8") as f:
                self.cache = json.load(f)
        except Exception:
            self.cache = {}
        self.pending = set()
        self.lock = threading.Lock()
        self.ex = ThreadPoolExecutor(4, thread_name_prefix="org")
        self.dirty = 0
        self.closed = False

    def _key24(self, ip):
        return ".".join(ip.split(".")[:3])

    def get(self, ip):
        """Returns {'ptr','org'} (possibly partial) and schedules a lookup if needed."""
        k24 = self._key24(ip)
        with self.lock:
            ptr = self.cache.get("p:" + ip)
            org = self.cache.get("o:" + k24)
            if (ptr is None or org is None) and ip not in self.pending and not self.closed \
                    and len(self.pending) < self.MAX_PENDING:
                self.pending.add(ip)
                try:
                    self.ex.submit(self._work, ip, k24)
                except RuntimeError:
                    self.pending.discard(ip)
        return {"ptr": ptr or "", "org": org or ""}

    def cache_peek(self, ip):
        with self.lock:
            return {"ptr": self.cache.get("p:" + ip) or "", "org": self.cache.get("o:" + self._key24(ip)) or ""}

    def _work(self, ip, k24):
        if self.closed:
            return
        ptr = core.reverse_dns(ip)
        with self.lock:
            need_org = ("o:" + k24) not in self.cache
        org = ""
        if need_org and not self.closed:
            try:
                req = urllib.request.Request(f"https://rdap.org/ip/{ip}",
                                             headers={"User-Agent": "NetworkDoctor", "Accept": "application/rdap+json"})
                j = json.loads(urllib.request.urlopen(req, timeout=10).read().decode("utf-8", "replace"))
                org = self._org(j) or j.get("name", "") or ""
            except Exception:
                org = ""
        with self.lock:
            self.cache["p:" + ip] = ptr
            if need_org:
                self.cache["o:" + k24] = org
            self.pending.discard(ip)
            if len(self.cache) > self.MAX_CACHE:
                for k in list(self.cache)[: self.MAX_CACHE // 3]:
                    self.cache.pop(k, None)
            self.dirty += 1
            text = json.dumps(self.cache) if self.dirty >= 25 else None
            if text:
                self.dirty = 0
        if text:
            self._write(text)

    @staticmethod
    def _org(j):
        for ent in j.get("entities", []) or []:
            roles = ent.get("roles", [])
            if "registrant" in roles or "administrative" in roles or not roles:
                try:
                    for item in ent["vcardArray"][1]:
                        if item[0] == "fn" and item[3]:
                            return str(item[3])[:60]
                except Exception:
                    pass
        return ""

    def _write(self, text):
        try:
            os.makedirs(core.DATA_DIR, exist_ok=True)
            with open(self.path + ".tmp", "w", encoding="utf-8") as f:
                f.write(text)
            os.replace(self.path + ".tmp", self.path)
        except Exception:
            pass

    def save(self):
        with self.lock:
            text = json.dumps(self.cache)
        self._write(text)

    def close(self):
        self.closed = True
        try:
            self.ex.shutdown(wait=False, cancel_futures=True)
        except TypeError:  # Python < 3.9
            self.ex.shutdown(wait=False)
        self.save()


# ==========================================================================
# what app / service is a connection
# ==========================================================================
STATIC_NETS = [("149.154.160.0/20", "Telegram"), ("91.108.0.0/16", "Telegram"), ("157.240.0.0/16", "Facebook / Instagram / WhatsApp"),
               ("31.13.24.0/21", "Facebook / Instagram / WhatsApp"), ("142.250.0.0/15", "Google / YouTube"),
               ("172.217.0.0/16", "Google / YouTube"), ("13.107.0.0/16", "Microsoft 365 / Teams"),
               ("20.0.0.0/8", "Microsoft Azure"), ("52.0.0.0/10", "Amazon AWS"), ("104.16.0.0/13", "Cloudflare")]
STATIC_NETS = [(ipaddress.ip_network(n), a) for n, a in STATIC_NETS]

APP_HINTS = [
    (("googlevideo", "youtube", "ytimg"), "YouTube (video)"),
    (("nflx", "netflix"), "Netflix (video)"),
    (("hotstar", "jiocinema", "sonyliv", "zee5", "mxplayer"), "Indian OTT video"),
    (("aiv-cdn", "primevideo", "pv-cdn"), "Amazon Prime Video"),
    (("fbcdn", "facebook", "instagram", "whatsapp", "meta platforms"), "Facebook / Instagram / WhatsApp"),
    (("tiktok", "bytedance", "byteoversea"), "TikTok"),
    (("snapchat",), "Snapchat"), (("telegram",), "Telegram"), (("twitter", "x corp", "twimg"), "X / Twitter"),
    (("windowsupdate", "delivery.mp.microsoft", "dl.delivery"), "Windows Update"),
    (("onedrive", "sharepoint"), "OneDrive / SharePoint sync"),
    (("microsoft", "msedge", "azure", "office", "live.com", "skype", "teams", "msn"), "Microsoft services"),
    (("1e100.net", "google", "gvt1", "gvt2", "gstatic"), "Google services"),
    (("icloud", "apple", "mzstatic", "aaplimg"), "Apple / iCloud"),
    (("dropbox",), "Dropbox sync"), (("zoom",), "Zoom"), (("anydesk",), "AnyDesk remote access"),
    (("teamviewer",), "TeamViewer remote access"), (("spotify",), "Spotify music"), (("steam", "valve"), "Steam games"),
    (("epicgames", "epic games"), "Epic games"), (("akamai",), "Akamai CDN (updates / video)"),
    (("cloudflare",), "Cloudflare CDN"), (("fastly",), "Fastly CDN"), (("amazonaws", "amazon"), "Amazon / AWS"),
    (("hik-connect", "hikvision", "ezviz"), "Hikvision cloud (CCTV)"), (("dahua", "imou", "easy4ip"), "Dahua cloud (CCTV)"),
]

PORT_APP = {80: "Web (HTTP)", 443: "Web / app (HTTPS)", 53: "DNS", 853: "Encrypted DNS", 123: "Time sync",
            5222: "Chat (WhatsApp/XMPP)", 5228: "Google push", 3478: "Video call", 3479: "Video call", 3480: "Video call",
            3481: "Video call", 8801: "Zoom", 8802: "Zoom", 1935: "Live streaming (RTMP)", 554: "Camera stream (RTSP)",
            22: "SSH", 3389: "Remote Desktop", 5938: "TeamViewer", 7070: "AnyDesk", 6568: "AnyDesk",
            25: "Email sending (SMTP)", 465: "Email", 587: "Email", 993: "Email", 995: "Email", 143: "Email", 110: "Email",
            1194: "OpenVPN", 51820: "WireGuard VPN", 1723: "PPTP VPN", 500: "IPsec VPN", 4500: "IPsec VPN",
            9001: "Tor", 9030: "Tor", 23: "Telnet", 2323: "Telnet", 445: "Windows file sharing (SMB)",
            3333: "Crypto mining", 4444: "Crypto mining / hacking tool", 5555: "Crypto mining", 7777: "Crypto mining",
            14444: "Crypto mining", 45700: "Crypto mining", 21: "FTP", 5900: "VNC remote control"}
RISK_PORTS = {
    23: ("critical", "Telnet to the internet - typical of infected cameras/routers (Mirai-type malware)"),
    2323: ("critical", "Telnet to the internet - typical of infected IoT devices"),
    25: ("warning", "Sends email directly to the internet - spam-bot sign unless it is a mail server"),
    445: ("critical", "Windows file sharing to the internet - worm / ransomware sign"),
    3333: ("critical", "Crypto-mining pool port"), 5555: ("warning", "Crypto-mining / ADB port"),
    7777: ("warning", "Crypto-mining pool port"), 14444: ("critical", "Crypto-mining pool port"),
    45700: ("critical", "Crypto-mining pool port"), 4444: ("critical", "Mining or remote-control (hacking) tool port"),
    9001: ("warning", "Tor anonymity network - can hide what the user does"),
    9030: ("warning", "Tor anonymity network"),
    1194: ("warning", "VPN - can bypass office rules"), 51820: ("warning", "VPN - can bypass office rules"),
    1723: ("warning", "VPN - can bypass office rules"),
    5938: ("info", "TeamViewer remote access - make sure it is authorised"),
    7070: ("info", "AnyDesk remote access - make sure it is authorised"),
    6568: ("info", "AnyDesk remote access - make sure it is authorised"),
}
# a LAN device that ACCEPTS connections from the internet on these ports (port forwarding / DMZ)
EXPOSED = {
    3389: ("critical", "Remote Desktop is open to the internet - the most common way ransomware gets in"),
    445: ("critical", "Windows file sharing is open to the internet"),
    23: ("critical", "Telnet is open to the internet - devices like this get hacked within hours"),
    5900: ("critical", "VNC remote control is open to the internet"),
    22: ("warning", "SSH is open to the internet - password-guessing attacks run all day"),
    21: ("warning", "FTP is open to the internet (passwords travel unencrypted)"),
    554: ("warning", "Camera video (RTSP) is reachable from the internet"),
    37777: ("warning", "Dahua DVR/NVR is reachable from the internet - attackers constantly try its logins"),
    34567: ("warning", "XMeye DVR is reachable from the internet - attackers constantly try its logins"),
    8000: ("warning", "Hikvision DVR/NVR is reachable from the internet - attackers constantly try its logins"),
    80: ("warning", "A web login of this device is reachable from the internet"),
    443: ("info", "A web service of this device is reachable from the internet"),
    8080: ("warning", "A web login of this device is reachable from the internet"),
    8291: ("critical", "MikroTik WinBox is reachable from the internet"),
}
P2P_PORTS = set(range(6881, 6890)) | {51413, 6969}


def _known(p):
    return p in PORT_APP or p in RISK_PORTS or p in P2P_PORTS or p in EXPOSED or p in core.PORTS


def service_port(rport, lport):
    """Which side is the 'service'? Returns (port, inbound). inbound=True means the internet connected to the LAN device."""
    if lport is None:
        return rport, False
    kr, kl = _known(rport), _known(lport)
    if kr and not kl:
        return rport, False
    if kl and not kr:
        return lport, True
    return (rport, False) if rport <= lport else (lport, True)


def classify(remote, port, proto, info, inbound=False):
    """Returns (app_name, risk) where risk is None or (severity, text)."""
    if inbound:
        name = core.PORTS.get(port) or PORT_APP.get(port) or f"port {port}"
        if port in P2P_PORTS:
            return "BitTorrent / P2P (incoming)", ("warning", "Torrent / peer-to-peer download")
        risk = EXPOSED.get(port) or ("info", f"accepts connections from the internet on port {port}")
        return f"Incoming from internet: {name}", risk
    ptr = (info or {}).get("ptr", "").lower()
    org = (info or {}).get("org", "").lower()
    text = ptr + " " + org
    app = None
    for words, nm in APP_HINTS:
        if any(w in text for w in words):
            app = nm
            break
    if app is None:
        try:
            ipobj = ipaddress.IPv4Address(remote)
            for net, nm in STATIC_NETS:
                if ipobj in net:
                    app = nm
                    break
        except Exception:
            pass
    if port in P2P_PORTS:
        return "BitTorrent / P2P", ("warning", "Torrent / peer-to-peer download")
    risk = RISK_PORTS.get(port)
    if app is None:
        app = PORT_APP.get(port) or (f"UDP {port}" if proto == 17 else f"TCP {port}" if proto == 6 else f"proto {proto}")
        if org:
            app += " - " + (info.get("org") or "")[:40]
    return app, risk


# ==========================================================================
# NetFlow / IPFIX receiver
# ==========================================================================
FIELDS = {1: "bytes", 2: "pkts", 4: "proto", 7: "sport", 8: "src", 11: "dport", 12: "dst", 225: "post_src",
          226: "post_dst", 227: "post_sport", 228: "post_dport", 23: "out_bytes", 85: "bytes", 86: "pkts"}
IP_FIELDS = {8, 12, 225, 226}


class FlowParser:
    def __init__(self):
        self.templates = {}

    def parse(self, data, exporter):
        if len(data) < 4:
            return []
        ver = struct.unpack("!H", data[:2])[0]
        try:
            if ver == 5:
                return self._v5(data)
            if ver == 9:
                return self._sets(data, exporter, 20, struct.unpack("!I", data[16:20])[0], 0, False)
            if ver == 10:
                return self._sets(data, exporter, 16, struct.unpack("!I", data[12:16])[0], 2, True)
        except Exception:
            return []
        return []

    @staticmethod
    def _v5(data):
        cnt = struct.unpack("!H", data[2:4])[0]
        out = []
        for i in range(cnt):
            r = data[24 + i * 48: 72 + i * 48]
            if len(r) < 48:
                break
            pkts, octs = struct.unpack("!II", r[16:24])
            sport, dport = struct.unpack("!HH", r[32:36])
            out.append({"src": socket.inet_ntoa(r[0:4]), "dst": socket.inet_ntoa(r[4:8]), "sport": sport,
                        "dport": dport, "proto": r[38], "bytes": octs, "pkts": pkts})
        return out

    def _sets(self, data, exporter, off, domain, tpl_id, ipfix):
        out = []
        end_all = len(data) if not ipfix else min(len(data), struct.unpack("!H", data[2:4])[0])
        while off + 4 <= end_all:
            sid, slen = struct.unpack("!HH", data[off:off + 4])
            if slen < 4:
                break
            body = data[off + 4: off + slen]
            off += slen
            if sid == tpl_id:
                p = 0
                while p + 4 <= len(body):
                    tid, fc = struct.unpack("!HH", body[p:p + 4])
                    p += 4
                    if tid == 0:
                        break
                    fields = []
                    for _ in range(fc):
                        t, ln = struct.unpack("!HH", body[p:p + 4])
                        p += 4
                        ent = False
                        if ipfix and t & 0x8000:
                            t &= 0x7FFF
                            p += 4
                            ent = True
                        fields.append((t, ln, ent))
                    self.templates[(exporter, domain, tid)] = fields
            elif sid >= 256:
                tpl = self.templates.get((exporter, domain, sid))
                if not tpl:
                    continue
                minlen = sum(ln for _, ln, _ in tpl if ln != 65535)
                p = 0
                while len(body) - p >= max(minlen, 1):
                    rec = {}
                    try:
                        for t, ln, ent in tpl:
                            if ln == 65535:
                                ln = body[p]
                                p += 1
                                if ln == 255:
                                    ln = struct.unpack("!H", body[p:p + 2])[0]
                                    p += 2
                            v = body[p:p + ln]
                            p += ln
                            name = None if ent else FIELDS.get(t)
                            if name:
                                if t in IP_FIELDS and ln == 4:
                                    rec[name] = socket.inet_ntoa(v)
                                else:
                                    rec[name] = rec.get(name, 0) + int.from_bytes(v, "big") if name == "bytes" else int.from_bytes(v, "big")
                    except Exception:
                        break
                    if "out_bytes" in rec:
                        rec["bytes"] = rec.get("bytes", 0) + rec.pop("out_bytes")
                    if "src" in rec and "dst" in rec:
                        out.append(rec)
        return out


class UdpReceiver(threading.Thread):
    def __init__(self, port, handler, name, reuse=False):
        super().__init__(daemon=True, name=name)
        self.port, self.handler = port, handler
        self.error = None
        self.running = True
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            if reuse:  # share the port with WinBox, which also listens for neighbour announcements
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            for attempt in range(8):  # a monitor that was just stopped can hold the port for a moment
                try:
                    self.sock.bind(("0.0.0.0", port))
                    break
                except OSError:
                    if attempt == 7:
                        raise
                    time.sleep(0.4)
            self.sock.settimeout(1)
        except Exception as e:
            self.sock = None
            self.error = f"UDP {port} busy or blocked: {e}"

    def run(self):
        if not self.sock:
            return
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                continue
            try:
                self.handler(data, addr[0])
            except Exception:
                pass

    def stop(self):
        self.running = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)  # wakes the receiving thread so the port is free at once
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


# ==========================================================================
# per-device traffic accounting
# ==========================================================================
BUCKET = 10  # seconds


class TrafficStore:
    """remotes key = (remote_ip, service_port, proto, inbound); value = [up, down, flows, first, last]."""

    def __init__(self, lan, threat, orgs, on_event):
        # lan: one network or several separated by commas (cameras / NVR on their own range count as office)
        nets = core.parse_nets(lan) if isinstance(lan, str) else [ipaddress.ip_network(lan, strict=False)]
        self.lan = nets[0]
        self.ranges = [(int(n.network_address), int(n.broadcast_address)) for n in nets]
        self.lo, self.hi = self.ranges[0]
        self.threat, self.orgs, self.on_event = threat, orgs, on_event
        self.sink = None  # usage history: sink(lan, remote, port, proto, nbytes, up, org_text)
        self.lock = threading.Lock()
        self.dev = {}
        self.nat = OrderedDict()
        self.flows = 0
        self.unmatched = 0
        self.first = self.last = None
        self.alerted = set()

    def in_lan(self, ip):
        n = _ip_int(ip)
        return n is not None and any(lo <= n <= hi for lo, hi in self.ranges)

    def _d(self, ip):
        d = self.dev.get(ip)
        if d is None:
            d = self.dev[ip] = {"up": 0, "down": 0, "buckets": deque(), "remotes": {}, "threats": {}, "risks": {}}
        return d

    def add(self, f):
        b = int(f.get("bytes") or 0)
        if b <= 0:
            return
        src, dst = f.get("src"), f.get("dst")
        sport, dport, proto = f.get("sport", 0), f.get("dport", 0), f.get("proto", 0)
        sl, dl = self.in_lan(src), self.in_lan(dst)
        now = time.time()
        with self.lock:
            self.flows += 1
            self.first = self.first or now
            self.last = now
            if sl and dl:
                return  # LAN-to-LAN routed traffic, not internet usage
            if sl:  # LAN device sending to the internet
                lan, remote, rport, lport, up = src, dst, dport, sport, True
                pub = f.get("post_sport") or sport
                self.nat[(remote, rport, proto, pub)] = (lan, sport)
                if len(self.nat) > 60000:
                    for _ in range(10000):
                        self.nat.popitem(last=False)
            elif dl:  # internet -> LAN device (exporter already shows the LAN address)
                lan, remote, rport, lport, up = dst, src, sport, dport, False
            elif f.get("post_dst") and self.in_lan(f["post_dst"]):  # v9/IPFIX NAT fields
                lan, remote, rport, lport, up = f["post_dst"], src, sport, f.get("post_dport") or dport, False
            elif f.get("post_src") and self.in_lan(f["post_src"]):
                lan, remote, rport, lport, up = f["post_src"], dst, dport, f.get("post_sport") or sport, True
            else:  # download seen before NAT: match it to the upload flow of the same connection
                hit = self.nat.get((src, sport, proto, dport))
                if not hit:
                    self.unmatched += b
                    return
                lan, lport = hit
                remote, rport, up = src, sport, False
            svc, inbound = service_port(rport, lport)
            d = self._d(lan)
            d["up" if up else "down"] += b
            bk = d["buckets"]
            slot = int(now // BUCKET) * BUCKET
            if bk and bk[-1][0] == slot:
                bk[-1][1 if up else 2] += b
            else:
                bk.append([slot, b if up else 0, 0 if up else b])
                while bk and bk[0][0] < now - 3600:
                    bk.popleft()
            key = (remote, svc, proto, inbound)
            r = d["remotes"].get(key)
            new = r is None
            if new:
                if len(d["remotes"]) >= 4000:
                    for k, _ in sorted(d["remotes"].items(), key=lambda x: x[1][0] + x[1][1])[:2000]:
                        d["remotes"].pop(k, None)
                r = d["remotes"][key] = [0, 0, 0, now, now]
            r[0 if up else 1] += b
            r[2] += 1
            r[4] = now
        if new:
            self._check(lan, remote, svc, proto, inbound)
        if self.sink and not inbound:
            try:
                info = self.orgs.get(remote) if self.orgs else {}
                self.sink(lan, remote, svc, proto, b, up, f"{info.get('ptr', '')} {info.get('org', '')}".strip())
            except Exception:
                pass

    def _check(self, lan, remote, svc, proto, inbound):
        hit = self.threat.check(remote)
        if inbound:
            risk = EXPOSED.get(svc) or (("warning", "Torrent / peer-to-peer download") if svc in P2P_PORTS else None)
        else:
            risk = RISK_PORTS.get(svc) or (("warning", "Torrent / peer-to-peer download") if svc in P2P_PORTS else None)
        with self.lock:
            d = self.dev.get(lan)
            if d is None:
                return
            if hit:
                d["threats"][remote] = (hit[0], hit[1], inbound)
            if risk:
                d["risks"].setdefault(risk[1], set()).add(remote)
        if hit:
            k = ("t", lan, remote)
            if k not in self.alerted:
                self.alerted.add(k)
                if hit[1] == "tor":
                    self.on_event("info", "Traffic", f"{lan} uses the Tor network ({remote})", "tor", {"ip": lan})
                elif inbound:
                    self.on_event("warning", "Traffic", f"{lan} is being accessed from the internet by {remote} - {hit[0]} "
                                                        f"(port {svc} is open to the internet)", "threat_in",
                                  {"ip": lan, "remote": remote})
                else:
                    self.on_event("critical", "Traffic", f"{lan} connected to {remote} - {hit[0]}", "threat",
                                  {"ip": lan, "remote": remote})
        if risk and risk[0] != "info":
            k = ("r", lan, risk[1])
            if k not in self.alerted:
                self.alerted.add(k)
                self.on_event(risk[0], "Traffic", f"{lan}: {risk[1]} ({remote} port {svc})",
                              "exposed" if inbound else "risk", {"ip": lan, "port": svc})

    def recheck_all(self):
        """Called after the block lists (re)load: checks every destination already seen."""
        with self.lock:
            items = [(lan, k) for lan, d in self.dev.items() for k in d["remotes"]]
        for lan, (remote, svc, proto, inbound) in items:
            if self.threat.check(remote):
                self._check(lan, remote, svc, proto, inbound)

    def rates(self, window=120):
        now = time.time()
        out = {}
        with self.lock:
            w = max(min(window, now - (self.first or now)), BUCKET)
            for ip, d in self.dev.items():
                up = down = 0
                for slot, u, dn in reversed(d["buckets"]):
                    if slot < now - window:
                        break
                    up += u
                    down += dn
                out[ip] = {"up_bps": up / w, "down_bps": down / w, "up_total": d["up"], "down_total": d["down"]}
        return out

    def window_total(self, ip, window):
        now = time.time()
        with self.lock:
            d = self.dev.get(ip)
            if not d:
                return 0, 0
            u = sum(x[1] for x in d["buckets"] if x[0] >= now - window)
            dn = sum(x[2] for x in d["buckets"] if x[0] >= now - window)
        return u, dn

    def remotes(self, ip):
        with self.lock:
            d = self.dev.get(ip)
            if not d:
                return [], {}, {}
            return ([(k, list(v)) for k, v in d["remotes"].items()], dict(d["threats"]),
                    {k: set(v) for k, v in d["risks"].items()})

    def all_threats(self):
        with self.lock:
            return {ip: dict(d["threats"]) for ip, d in self.dev.items() if d["threats"]}

    def all_exposed(self):
        """{lan_ip: {port: n_remote_addresses}} for inbound connections from the internet."""
        out = {}
        with self.lock:
            for ip, d in self.dev.items():
                c = Counter(k[1] for k in d["remotes"] if k[3] and k[1] not in P2P_PORTS)
                if c:
                    out[ip] = dict(c)
        return out


# ==========================================================================
# router / switch log messages (syslog)
# ==========================================================================
RX_IP = r"(\d+\.\d+\.\d+\.\d+)"
RX_MAC = r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"
RX_IFACE = r"\b((?:ether|sfp|wlan|combo|bridge|vlan|eoip|lte|pppoe-)[\w.\-]*)"


def parse_router_line(text):
    """Turns one log line (MikroTik, Cisco, TP-Link, D-Link, generic) into (kind, severity, data)."""
    t = text
    tl = t.lower()
    m = re.search(r"(\S+) link down", t) or re.search(r"Interface (\S+?),? changed state to down", t) or \
        re.search(r"\b(?:port|interface)\s+(\S+?)\s+(?:link\s+)?(?:is\s+)?down\b", t, re.I)
    if m:
        return "link_down", "warning", {"iface": m.group(1).strip(",:")}
    m = re.search(r"(\S+) link up", t) or re.search(r"Interface (\S+?),? changed state to up", t)
    if m:
        sp = re.search(r"speed (\S+)", t)
        return "link_up", "info", {"iface": m.group(1).strip(",:"), "speed": (sp.group(1) if sp else "").strip(",")}
    if "own address as source" in tl or "loop detected" in tl or "loopback detected" in tl or re.search(r"\bloop\b", tl):
        m = re.search(RX_IFACE, t)
        return "loop", "critical", {"iface": m.group(1).rstrip(":") if m else ""}
    if "flapping between" in tl or "mac flap" in tl or "macflap" in tl:
        return "mac_flap", "critical", {}
    if "topology change" in tl:
        return "stp_tc", "warning", {}
    m = re.search(r"conflict by ARP response for " + RX_IP + " from " + RX_MAC, t)
    if m:
        return "conflict", "critical", {"ip": m.group(1), "mac": core.norm_mac(m.group(2))}
    m = re.search(r"offering lease " + RX_IP + r" for " + RX_MAC + " without success", t)
    if m:
        return "dhcp_fail", "warning", {"ip": m.group(1), "mac": core.norm_mac(m.group(2))}
    m = re.search(r"\b(de)?assigned " + RX_IP + r" (?:from|to) " + RX_MAC, t)
    if m:
        return ("dhcp_release" if m.group(1) else "dhcp_assign"), "info", {"ip": m.group(2), "mac": core.norm_mac(m.group(3))}
    m = re.search(r"sending ack.*? to " + RX_IP, t) or re.search(r"received request.*? from " + RX_IP, t)
    if m and m.group(1) != "0.0.0.0":
        return "dhcp_renew", "debug", {"ip": m.group(1)}
    m = re.search(r"chaddr\s*=\s*" + RX_MAC, t)
    if m:
        return "dhcp_renew", "debug", {"mac": core.norm_mac(m.group(1))}
    if "unknown dhcp server" in tl or "rogue" in tl:
        return "rogue_dhcp", "critical", {}
    m = re.search(r"login failure for user (\S+) from " + RX_IP, t)
    if m:
        return "login_fail", "warning", {"user": m.group(1), "ip": m.group(2)}
    if re.search(r"rebooted without proper shutdown|power", tl):
        return "router_power", "critical", {}
    if re.search(r"\b(error|critical|fail\w*|reboot\w*)\b", tl):
        return "router_note", "warning", {}
    return "router_log", "debug", {}


# ==========================================================================
# the live monitor
# ==========================================================================
class Monitor:
    def __init__(self, lan, gw, lip, threat, orgs, flow_port=FLOW_PORT, syslog_port=SYSLOG_PORT, use_sniffer=True):
        self.lan, self.gw, self.lip = lan, gw, lip
        self.threat, self.orgs = threat, orgs
        self.flow_port, self.syslog_port = flow_port, syslog_port
        self.use_sniffer = use_sniffer
        self.lock = threading.Lock()
        self.events = deque(maxlen=5000)
        self.ev_seq = 0
        self.samples = deque(maxlen=1800)        # (t, broadcasts/s, gateway ms) every 2 s = 1 h
        self.bcast_windows = deque(maxlen=1800)  # (t, total, [(mac, n)...]) every 2 s (sniffer)
        self.dhcp_seen = {}                      # mac or ip -> (time, how)
        self.renews = defaultdict(list)          # ip -> [times a DHCP renewal was logged]
        self.dhcp_feed = False                   # router sends DHCP renewals (debug) -> static can be judged
        self.links = defaultdict(list)           # iface -> [(t, 'down'/'up')]
        self.counts = Counter()
        self.traffic = TrafficStore(lan, threat, orgs, self.event)
        self.parser = FlowParser()
        self.started = None
        self.running = False
        self.flow_rx = self.syslog_rx = 0
        self.last_flow = self.last_syslog = None
        self.exporters, self.log_sources = set(), set()
        self.sniffer_state = "starting..."
        self.gw_mac = None
        self._state = {"storm": False, "gw_down": False}
        self.echo_tokens = {}
        self.lease_time = None
        self.self_mac = None  # this PC: its own DHCP test requests are not reported as problems
        self.neighbors = {}   # MikroTik switches / APs / routers announcing themselves (MNDP): mac -> info
        self.nu = None                           # broadcast / multicast counter (Windows)
        self.mcast_total = self.mcast_pps = None
        self.bcast_mixed = False                 # True when only broadcast + multicast together is known

    # ---- events
    def event(self, sev, source, text, kind=None, data=None):
        with self.lock:
            self.ev_seq += 1
            self.events.append({"seq": self.ev_seq, "t": time.time(), "sev": sev, "src": source, "text": text,
                                "kind": kind, "data": data or {}})

    # ---- start / stop
    def start(self):
        self.running = True
        self.started = time.time()
        self.rx_flow = UdpReceiver(self.flow_port, self._on_flow, "flows")
        self.rx_log = UdpReceiver(self.syslog_port, self._on_syslog, "syslog")
        self.rx_mndp = UdpReceiver(tools.MNDP_PORT, self._on_mndp, "mndp", reuse=True)
        if not self.rx_mndp.error:
            self.rx_mndp.start()
        for rx, what in ((self.rx_flow, "Traffic receiver"), (self.rx_log, "Router log receiver")):
            if rx.error:
                self.event("warning", "Monitor", f"{what}: {rx.error} (is another copy of the app or a syslog "
                                                 "program running?)")
            rx.start()
        threading.Thread(target=self._sampler, daemon=True, name="sampler").start()
        if self.use_sniffer:
            threading.Thread(target=self._sniffer, daemon=True, name="sniffer").start()
        else:
            self.sniffer_state = "off"
        self.event("info", "Monitor", f"Live monitor started on {self.lip}, watching router {self.gw or '(none found)'}")

    def stop(self):
        if not self.running:
            return
        self.running = False
        for rx in (getattr(self, "rx_flow", None), getattr(self, "rx_log", None), getattr(self, "rx_mndp", None)):
            if rx:
                rx.stop()
        if self.nu:
            self.nu.stop()
        self.event("info", "Monitor", "Live monitor stopped")

    # ---- receivers
    def _on_mndp(self, data, addr):
        nb = tools.parse_mndp(data)
        if not nb:
            return
        nb.setdefault("ip", addr)
        nb["t"] = time.time()
        with self.lock:
            new = nb["mac"] not in self.neighbors
            self.neighbors[nb["mac"]] = nb
        if new:
            kind = tools.guess_kind(nb) or "device"
            self.event("info", "Discovery", f"Found MikroTik {kind.lower()} '{nb.get('identity', '?')}' "
                                            f"({nb.get('board', '')}) at {nb['ip']}", "neighbor", {"mac": nb["mac"]})

    def neighbors_copy(self):
        with self.lock:
            return {k: dict(v) for k, v in self.neighbors.items()}

    def _on_flow(self, data, addr):
        recs = self.parser.parse(data, addr)
        self.flow_rx += 1
        self.last_flow = time.time()
        self.exporters.add(addr)
        for r in recs:
            self.traffic.add(r)

    def _on_syslog(self, data, addr):
        text = data.decode("utf-8", "replace").strip()
        text = re.sub(r"^<\d+>", "", text).strip()
        self.syslog_rx += 1
        self.last_syslog = time.time()
        self.log_sources.add(addr)
        kind, sev, d = parse_router_line(text)
        now = time.time()
        if kind == "dhcp_fail" and self.self_mac and d.get("mac") == self.self_mac:
            sev = "debug"  # Network Doctor's own rogue-DHCP test, not a real problem
        with self.lock:
            if kind in ("dhcp_assign", "dhcp_renew"):
                how = "router log (lease renewal)" if kind == "dhcp_renew" else "router log (lease given)"
                for k in (d.get("mac"), d.get("ip")):
                    if k:
                        self.dhcp_seen[k] = (now, how)
                if kind == "dhcp_renew" and d.get("ip"):
                    self.dhcp_feed = True
                    lst = self.renews[d["ip"]]
                    if not lst or now - lst[-1] > 20:  # request + ack of one renewal count once
                        lst.append(now)
                        del lst[:-10]
            if kind in ("link_down", "link_up"):
                self.links[d["iface"]].append((now, "down" if kind == "link_down" else "up"))
                del self.links[d["iface"]][:-500]
            self.counts[kind] += 1
        if sev != "debug":
            short = re.sub(r"^[A-Z][a-z]{2}\s+\d+\s+[\d:]+\s+", "", text)
            self.event(sev, f"Router {addr}", short[:220], kind, d)

    # ---- local sampler (every 2 s)
    def _read_nu(self):
        """(source, broadcast count): broadcast only when Windows can split it from multicast."""
        bm = self.nu.read() if self.nu else None
        if bm:
            self.mcast_total = bm[1]
            return "split", bm[0]
        n = core.nonunicast_rx()
        return ("sum", n) if n is not None else (None, None)

    def _sampler(self):
        self.nu = core.NuCounter()
        self.nu.start()
        for _ in range(6):  # give the counter process time to print its first line
            if not self.running or self.nu.read() or not core.IS_WIN:
                break
            time.sleep(0.5)
        src, prev = self._read_nu()
        prev_t = time.time()
        prev_m = self.mcast_total
        fails = hi = 0
        last_echo = 0
        while self.running:
            t0 = time.time()
            ms = None
            if self.gw:
                cmd = core.ping_cmd(self.gw, 1000)
                out = core.run(cmd, 4)
                m = re.search(r"time[=<]\s*([\d.]+)", out)
                if m and re.search(r"ttl", out, re.I):
                    ms = float(m.group(1))
            src_now, cur = self._read_nu()
            now = time.time()
            pps = None
            if cur is not None and prev is not None and cur >= prev and src_now == src:
                pps = (cur - prev) / max(now - prev_t, 0.5)
                self.bcast_mixed = src_now == "sum"
                if src_now == "split" and prev_m is not None and self.mcast_total is not None:
                    self.mcast_pps = max(0, self.mcast_total - prev_m) / max(now - prev_t, 0.5)
            src, prev, prev_t, prev_m = src_now, cur, now, self.mcast_total
            with self.lock:
                if pps is None and self.bcast_windows and now - self.bcast_windows[-1][0] < 5:
                    pps = self.bcast_windows[-1][1] / 2.0
                self.samples.append((now, pps, ms))
            if pps is not None:
                hi = hi + 1 if pps > STORM_PPS else 0
                if hi >= 2 and not self._state["storm"]:
                    self._state["storm"] = True
                    top = self.top_broadcasters(10)
                    tops = ", ".join(f"{m} ({n})" for m, n in top[:3])
                    what = "broadcasts + multicast/s (Windows cannot split them here)" if self.bcast_mixed else "broadcasts/s"
                    self.event("critical" if pps > 1000 else "warning", "Monitor",
                               f"Broadcast storm: {pps:.0f} {what}" + (f" - top senders {tops}" if tops else ""),
                               "storm", {"pps": pps, "top": top, "mixed": self.bcast_mixed})
                elif hi == 0 and self._state["storm"] and pps < STORM_PPS / 2:
                    self._state["storm"] = False
                    self.event("info", "Monitor", f"Broadcast level back to normal ({pps:.0f}/s)", "storm_end")
            if self.gw:
                fails = fails + 1 if ms is None else 0
                if fails >= 3 and not self._state["gw_down"]:
                    self._state["gw_down"] = True
                    self.event("critical", "Monitor", f"Router {self.gw} not answering (3 pings lost)", "gw_down")
                elif ms is not None and self._state["gw_down"]:
                    self._state["gw_down"] = False
                    self.event("info", "Monitor", f"Router answering again ({ms:.0f} ms)", "gw_up")
            if self.sniffer_state == "running" and now - last_echo > 60:
                last_echo = now
                threading.Thread(target=self._echo, daemon=True).start()
            time.sleep(max(0.2, 2 - (time.time() - t0)))

    # ---- sniffer (optional, Npcap + Scapy)
    def _sniffer(self):
        if not core.scapy_ok():
            self.sniffer_state = "not installed (Npcap + Scapy)"
            return
        try:
            from scapy.all import AsyncSniffer, Ether, ARP, BOOTP, conf
            from scapy.layers.l2 import Dot3
            try:
                from scapy.layers.l2 import STP
            except Exception:
                STP = None
            conf.verb = 0
            iface = core._scapy_iface(self.gw)
            win = Counter()
            win_t = [time.time()]
            spoof_seen = Counter()

            def cb(p):
                try:
                    if p.haslayer(Ether):
                        e = p[Ether]
                        etype = e.type
                    elif p.haslayer(Dot3):  # 802.3 frames: spanning tree BPDUs
                        e = p[Dot3]
                        etype = None
                    else:
                        return
                    src = core.norm_mac(e.src)
                    dst = (e.dst or "").lower()
                    if etype == 0x88B5:
                        raw = bytes(p)
                        for tok in list(self.echo_tokens):
                            if tok in raw:
                                self.echo_tokens[tok] += 1
                        return
                    if dst == "ff:ff:ff:ff:ff:ff":
                        win[src] += 1
                    if STP is not None and p.haslayer(STP) and (int(p[STP].bpduflags or 0) & 0x01):
                        self.counts["stp_tc_seen"] += 1
                        if self.counts["stp_tc_seen"] % 10 == 1:
                            self.event("warning", "Sniffer", f"Spanning-tree topology change (from switch {src}) - a port "
                                                             "went up/down or a loop is being blocked", "stp_tc")
                    if p.haslayer(ARP) and p[ARP].op in (1, 2) and p[ARP].psrc == self.gw:
                        mac = core.norm_mac(p[ARP].hwsrc)
                        if self.gw_mac is None:
                            self.gw_mac = mac
                        elif mac != self.gw_mac:
                            spoof_seen[mac] += 1
                            if spoof_seen[mac] in (1, 50):
                                self.event("critical", "Sniffer",
                                           f"ARP spoofing: {mac} claims to be the router {self.gw} (real router "
                                           f"{self.gw_mac}). Someone may be running NetCut / a hacking tool, or a "
                                           "device was given the router's IP.", "arp_spoof", {"mac": mac})
                    if p.haslayer(BOOTP) and p[BOOTP].op == 1:
                        mac = core.norm_mac(bytes(p[BOOTP].chaddr)[:6])
                        if mac:
                            with self.lock:
                                self.dhcp_seen[mac] = (time.time(), "seen asking for an IP by DHCP")
                    now = time.time()
                    if now - win_t[0] >= 2:
                        with self.lock:
                            self.bcast_windows.append((now, sum(win.values()), win.most_common(8)))
                        win.clear()
                        win_t[0] = now
                except Exception:
                    pass

            sn = AsyncSniffer(iface=iface, store=False, prn=cb,
                              filter="broadcast or multicast or arp or ether proto 0x88b5 or (udp and (port 67 or port 68))")
            sn.start()
            self.sniffer_state = "running"
            while self.running:
                time.sleep(1)
            sn.stop()
            self.sniffer_state = "stopped"
        except Exception as e:
            self.sniffer_state = f"not available: {str(e)[:70]}"

    def _echo(self):
        try:
            from scapy.all import Ether, Raw, sendp, get_if_hwaddr
            iface = core._scapy_iface(self.gw)
            tok = ("NDLOOP%08x" % (int(time.time() * 1000) & 0xFFFFFFFF)).encode()
            self.echo_tokens[tok] = 0
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(iface), type=0x88B5) / Raw(load=tok * 4),
                  iface=iface, count=1, verbose=0)
            time.sleep(4)
            seen = self.echo_tokens.pop(tok, 0)
            self.counts["echo_tests"] += 1
            if seen > 2:  # 1 = our own outgoing copy
                self.counts["echo_loops"] += 1
                self.event("critical", "Sniffer", f"LOOP CONFIRMED: 1 test frame came back {seen} times", "loop_echo",
                           {"seen": seen})
        except Exception:
            pass

    # ---- thread-safe snapshots for GUI / RCA
    def samples_copy(self, since=0):
        with self.lock:
            return [s for s in self.samples if s[0] >= since]

    def events_copy(self):
        with self.lock:
            return list(self.events)

    def events_since(self, seq):
        with self.lock:
            return [e for e in self.events if e["seq"] > seq]

    def links_copy(self):
        with self.lock:
            return {k: list(v) for k, v in self.links.items()}

    def dhcp_lookup(self, *keys):
        with self.lock:
            for k in keys:
                if k and k in self.dhcp_seen:
                    return self.dhcp_seen[k]
        return None

    def renew_interval(self):
        """Typical seconds between DHCP renewals of the same device (= half the lease time)."""
        with self.lock:
            gaps = [b - a for lst in self.renews.values() for a, b in zip(lst, lst[1:]) if b - a > 30]
        return statistics.median(gaps) if len(gaps) >= 3 else None

    def top_broadcasters(self, seconds=60):
        c = Counter()
        now = time.time()
        with self.lock:
            wins = [w for w in self.bcast_windows if w[0] >= now - seconds]
        for t, total, top in wins:
            for mac, n in top:
                c[mac] += n
        return c.most_common(8)

    def storm_near(self, t, before=60, after=10):
        """Highest broadcast rate measured just before/at time t (None if nothing was measured)."""
        with self.lock:
            vals = [s[1] for s in self.samples if t - before <= s[0] <= t + after and s[1] is not None]
        return max(vals) if vals else None

    def gw_lost_near(self, t, before=60, after=60):
        with self.lock:
            g = [s for s in self.samples if t - before <= s[0] <= t + after]
        return bool(g) and sum(1 for s in g if s[2] is None) >= 2

    def feed_status(self):
        now = time.time()

        def st(last, n):
            if last is None:
                return "waiting - not receiving yet"
            age = now - last
            return f"receiving ({n} packets, last {int(age)} s ago)" if age < 180 else f"stopped {int(age / 60)} min ago"

        g = self.samples_copy(now - 60)
        ok = [s[2] for s in g if s[2] is not None]
        loss = (100 * (len(g) - len(ok)) / len(g)) if g else 0
        pps = g[-1][1] if g and g[-1][1] is not None else None
        return {"flows": st(self.last_flow, self.flow_rx), "syslog": st(self.last_syslog, self.syslog_rx),
                "sniffer": self.sniffer_state, "bcast": pps, "mcast": self.mcast_pps, "bcast_mixed": self.bcast_mixed,
                "gw": bool(self.gw),
                "gw_avg": (sum(ok) / len(ok)) if ok else None, "gw_max": max(ok) if ok else None, "gw_loss": loss,
                "runtime": int(now - self.started) if self.started else 0}


# ==========================================================================
# DHCP or static?
# ==========================================================================

def ip_type(d, mon, db, raw):
    """Returns (type, evidence). type: DHCP / Static / Likely DHCP / Likely static / Fixed IP / Unknown."""
    mac, ip = d.get("mac"), d.get("ip")
    meta = (raw or {}).get("meta", {})
    if ip and ip == meta.get("gateway"):
        return "Static", "router / gateway address"
    if d.get("self") and meta.get("self_dhcp") is not None:
        return ("DHCP" if meta["self_dhcp"] else "Static"), "read from this PC's own network settings"
    if mon:
        hit = mon.dhcp_lookup(mac, ip)
        if hit:
            return "DHCP", f"{hit[1]} at {tstr(hit[0])}"
    if d.get("conflict"):
        return "Likely static", "answers an IP that another device also uses - usually a manually typed IP"
    with core.DB_LOCK:
        h = dict(db.get("devices", {}).get(mac) or {}) if mac else {}
    ips = list(dict.fromkeys(h.get("ips", [])))
    if len(ips) > 1 and not d.get("random"):
        return "Likely DHCP", "IP changed between scans (" + " > ".join(ips[-3:]) + ")"
    if d.get("random"):
        return "Likely DHCP", "phones/laptops with a private MAC practically always use DHCP"
    if mon and mon.dhcp_feed and d.get("online") and mon.started:
        interval = mon.renew_interval()
        lease = mon.lease_time or meta.get("self_lease") or _lease_from_raw(raw)
        if not interval and lease:
            interval = lease / 2
        watched = time.time() - mon.started
        if interval and watched > interval * 1.5 + 300:
            return "Likely static", (f"monitored {int(watched / 60)} min: DHCP devices renewed about every "
                                     f"{max(1, int(interval / 60))} min, this one never asked")
    if h and d.get("category") in (core.CAT_PRN, core.CAT_CAM, core.CAT_BIO, core.CAT_NET):
        try:
            days = (_dt.datetime.now() - _dt.datetime.strptime(h["first_seen"], "%Y-%m-%d %H:%M")).days
        except Exception:
            days = 0
        if days >= 1 and len(ips) <= 1:
            return "Fixed IP", f"same IP for {days} day(s) - typed on the device or reserved on the router"
    if mon and mon.dhcp_feed:
        return "Unknown", "watching DHCP renewals from the router log - decided after about one lease period"
    if mon and mon.last_syslog:
        return "Unknown", "router log arrives but without DHCP messages - add the 'dhcp' log topic (Setup tab)"
    return "Unknown", "start Live Monitor with the router log (dhcp topic) or Npcap to confirm"


def _lease_from_raw(raw):
    try:
        for v in (raw["meta"]["tests"].get("dhcp") or {}).values():
            if v.get("lease"):
                return v["lease"]
    except Exception:
        pass
    return None


# ==========================================================================
# root cause analysis - whole network
# ==========================================================================
def rca_network(mon, devices, issues, db):
    finds = []
    by_mac = {d["mac"]: d for d in devices if d.get("mac")}
    by_ip = {d["ip"]: d for d in devices if d.get("ip") and d.get("online")}

    def who(mac):
        d = by_mac.get(mac)
        return f"{d['name'] or '?'} {d['ip']} ({mac})" if d else mac

    def name_ip(ip):
        d = by_ip.get(ip)
        return f"{d['name']} ({ip})" if d and d.get("name") else ip

    def add(title, conf, score, evidence, actions):
        finds.append({"title": title, "conf": conf, "score": score, "evidence": evidence, "actions": actions})

    ev = mon.events_copy() if mon else []
    by_kind = defaultdict(list)
    for e in ev:
        by_kind[e["kind"]].append(e)
    loops = by_kind["loop"] + by_kind["loop_echo"] + by_kind["mac_flap"]
    loop_ifaces = {e["data"].get("iface") for e in by_kind["loop"] if e["data"].get("iface")}
    stp = by_kind["stp_tc"]
    storm_times = [e["t"] for e in by_kind["storm"]]
    gwdown = [e["t"] for e in by_kind["gw_down"]]

    # --- ports going up/down
    links = mon.links_copy() if mon else {}
    for iface, lst in links.items():
        downs = [t for t, s in lst if s == "down"]
        if not downs:
            continue
        storm_at = [(t, mon.storm_near(t)) for t in downs]
        with_storm = [(t, p) for t, p in storm_at if p is not None and p > STORM_PPS]
        measured = [t for t, p in storm_at if p is not None]
        with_gw = [t for t in downs if mon.gw_lost_near(t)]
        intervals = [b - a for a, b in zip(downs, downs[1:]) if b - a > 20]
        regular = len(intervals) >= 3 and (max(intervals) - min(intervals)) < 0.2 * (sum(intervals) / len(intervals))
        evid = [f"{iface} went down {len(downs)} time(s): " + ", ".join(tstr(t) for t in downs[-8:])]
        if intervals:
            avg = sum(intervals) / len(intervals)
            evid.append(f"average gap {avg / 60:.1f} min" + (" - very regular, like a timer" if regular else ""))
        if with_storm:
            evid.append(f"{len(with_storm)} of them happened during/just after a broadcast storm "
                        f"(up to {max(p for _, p in with_storm):.0f} broadcasts/s)")
        elif measured:
            evid.append(f"no storm was measured at those moments (broadcasts stayed below {STORM_PPS}/s)")
        else:
            evid.append("broadcast level was not being measured at those moments")
        if with_gw:
            evid.append(f"this PC also lost the router around {len(with_gw)} of them")
        iface_loop = iface in loop_ifaces or (loops and not loop_ifaces)
        if iface_loop:
            evid.append("the router itself reported a LOOP" + (f" on {iface}" if iface in loop_ifaces else ""))
        top = mon.top_broadcasters(3600)
        if with_storm or iface_loop:
            act = [f"The loop is most likely on the switch connected to {iface}: look for a cable with both ends in "
                   "the same switch, two cables between the same two switches, or a wall socket patched back to "
                   "another wall socket.",
                   f"Quick test: unplug the cables of the switch on {iface} and plug them back one at a time while "
                   "watching the Live monitor graph - the cable that brings the storm back is the loop.",
                   f"Router protection (Setup tab): loop-protect on {iface} and RSTP on the bridge."]
            if top:
                act.append("Devices sending most broadcasts during storms (they sit on the looped segment): " +
                           ", ".join(who(m) for m, _ in top[:4]))
            add(f"Network loop / broadcast storm behind {iface}",
                "High" if (with_storm and iface_loop) or len(with_storm) >= 2 else "Medium",
                96 if iface_loop else 90, evid, act)
        else:
            act = [f"1) Replace the patch cable on {iface} and check / re-crimp the RJ45 plugs at both ends.",
                   "2) Watch the switch on that port: if all its lights go off and on, its power adapter is failing "
                   "(very common with small 5 V / 9 V / 12 V adapters) - replace the adapter or the switch.",
                   "3) If the switch powers cameras or access points by PoE, it may be overloaded.",
                   f"4) Test with fixed speed: /interface ethernet set {iface} auto-negotiation=no speed=100Mbps "
                   "full-duplex=yes - if the drops stop, the cable or one of the ports is bad.",
                   f"5) Turn on loop-protect for {iface} (Setup tab). If there IS a loop the router will then log "
                   "'loop detected' and this analysis will say so."]
            if regular:
                act.insert(0, "The drops come at regular intervals: something behind that port is restarting on a "
                              "timer (overheating switch, watchdog, or scheduled reboot).")
            if not measured or not with_storm:
                act.append("Note: a loop behind a port only shows up here if this PC is on the same switched network. "
                           "Step 5 makes the router confirm or rule out a loop.")
            add(f"{iface} keeps going down and up (no loop measured)", "High" if len(downs) >= 3 else "Medium",
                85, evid, act)

    # --- loops / storms not tied to a port
    if loops and not links:
        add("Network loop detected", "High", 92, [f"{tstr(e['t'])}  {e['text']}" for e in loops[-6:]],
            ["Find the cable that connects a switch back into the same network twice and remove it.",
             "Turn on loop protection / RSTP on the router and on managed switches (Setup tab)."])
    if storm_times and not links and not loops:
        top = mon.top_broadcasters(3600)
        add("Broadcast storms (probable loop or faulty device)", "Medium", 75,
            [f"{len(storm_times)} storm(s): " + ", ".join(tstr(t) for t in storm_times[-6:])] +
            ([f"top broadcast senders: " + ", ".join(who(m) for m, _ in top[:4])] if top else []),
            ["If one device dominates the senders, unplug it and see whether storms stop (faulty network card / malware).",
             "Otherwise unplug switch-to-switch cables one at a time to find the loop.",
             "Send the router log to this app (Setup tab) so port drops can be matched with storms."])
    if len(stp) >= 3:
        add("Frequent spanning-tree changes", "Medium", 60, [f"{len(stp)} topology changes seen by the sniffer"],
            ["A port keeps going up/down somewhere, or a loop is repeatedly being blocked. Check managed switch logs."])
    for e in by_kind["arp_spoof"][-1:]:
        add("ARP spoofing (traffic interception / NetCut)", "High", 97, [e["text"]],
            ["Find the device with that MAC (Devices tab > Search) and disconnect it. Tools like NetCut cause exactly "
             "this and also make the network unstable for everyone."])
    if by_kind["router_power"]:
        add("Router restarted without a proper shutdown", "Medium", 70,
            [f"{tstr(e['t'])}  {e['text']}" for e in by_kind["router_power"][-4:]],
            ["Check the router's power adapter and put the router on a UPS."])
    if gwdown and not storm_times and not links:
        add("Router stops answering (no storm seen)", "Medium", 55,
            [f"{len(gwdown)} outage(s): " + ", ".join(tstr(t) for t in gwdown[-6:])],
            ["If this PC is on Wi-Fi, run the monitor on a cabled PC.",
             "Check the router CPU during outages (near 100% means a flood or attack).",
             "Send the router log to this app to see what the router reports at that moment."])
    lf = by_kind["login_fail"]
    if len(lf) >= 5:
        srcs = Counter(e["data"].get("ip") for e in lf)
        add("Someone is guessing passwords on the router", "High" if len(lf) >= 20 else "Medium", 80,
            [f"{len(lf)} failed logins; from: " + ", ".join(f"{ip} ({n}x)" for ip, n in srcs.most_common(5))],
            ["Disable router services not needed from outside: /ip service disable telnet,ftp,www,api,api-ssl",
             "Allow WinBox only from the LAN: /ip service set winbox address=192.168.0.0/24",
             "Use a strong admin password and rename the 'admin' user."])

    # --- traffic based
    if mon and mon.last_flow:
        rates = mon.traffic.rates(600)
        tot = sum(r["down_bps"] + r["up_bps"] for r in rates.values())
        if tot > 0:
            top = sorted(rates.items(), key=lambda x: -(x[1]["down_bps"] + x[1]["up_bps"]))[:3]
            ip, r = top[0]
            share = (r["down_bps"] + r["up_bps"]) / tot
            ev2 = [f"{name_ip(ip)}: {fmt_rate(r['down_bps'])} down / {fmt_rate(r['up_bps'])} up over the last 10 min "
                   f"= {share * 100:.0f}% of all internet traffic"]
            for ip2, r2 in top[1:]:
                ev2.append(f"next: {name_ip(ip2)} {fmt_rate(r2['down_bps'] + r2['up_bps'])}")
            if share > 0.4 and (r["down_bps"] + r["up_bps"]) > 60e3:
                add(f"{name_ip(ip)} is using most of the internet", "High" if share > 0.6 else "Medium", 70, ev2,
                    ["Open this device's analysis (Devices tab > select > Analyse) to see which apps / sites.",
                     "If needed, limit it on the router: /queue simple add target=" + ip + "/32 max-limit=5M/10M"])
        out_bad, in_bad = [], []
        for ip, th in mon.traffic.all_threats().items():
            for remote, (label, kind, inbound) in th.items():
                if kind == "tor":
                    continue
                (in_bad if inbound else out_bad).append(f"{name_ip(ip)} -> {remote}: {label}" if not inbound else
                                                        f"{name_ip(ip)} <- {remote}: {label}")
        if out_bad:
            add("Device(s) connecting to known malicious servers (possible infection)", "High", 98, out_bad[:10],
                ["Disconnect these devices and run a full antivirus scan (Microsoft Defender offline scan).",
                 "For cameras/DVRs: reset, update firmware, change the default password, and block their internet "
                 "access if remote viewing is not needed."])
        exposed = mon.traffic.all_exposed()
        ev3 = []
        for ip, ports in exposed.items():
            for port, n in sorted(ports.items(), key=lambda x: -x[1]):
                sev = (EXPOSED.get(port) or ("info", ""))[0]
                if sev in ("critical", "warning") or n >= 20:
                    ev3.append(f"{name_ip(ip)} port {port} ({core.PORTS.get(port) or PORT_APP.get(port) or 'service'}) "
                               f"- contacted by {n} internet address(es)")
        if in_bad or ev3:
            add("Devices reachable from the internet (port forwarding)", "High" if in_bad else "Medium", 82,
                (ev3 + in_bad)[:12],
                ["Remove port-forward / DMZ rules you do not need: /ip firewall nat print  (look for dst-nat).",
                 "For CCTV use the brand's cloud app (Hik-Connect, DMSS) or a VPN instead of open ports.",
                 "Change default passwords and update firmware on every listed device."])

    # --- from the scan
    for i in issues or []:
        if i["sev"] == "critical" and ("conflict" in i["title"].lower() or "dhcp" in i["title"].lower()):
            add(i["title"], "High", 88, i["items"][:6], [i["fix"]])
    seen_conf = {f["title"] for f in finds}
    for e in by_kind["conflict"][-3:]:
        t = f"IP conflict on {e['data'].get('ip')}"
        if t not in seen_conf:
            seen_conf.add(t)
            add(t + " (reported by router)", "High", 86, [e["text"]],
                ["Find the device with the manually set IP and change it to DHCP or to an IP outside the DHCP range."])

    # --- what data is missing
    missing = []
    if not mon or not mon.running:
        missing.append("Live Monitor is not running. Start it and leave it running until the problem happens again.")
    else:
        missing += feed_notes(mon, (db or {}).get("feeds_seen") or {})
        if mon.sniffer_state != "running":
            missing.append("Packet sniffer is off - install Npcap and build with Scapy for the loop echo test and "
                           "the list of devices sending broadcasts.")
        if mon.started and time.time() - mon.started < 600:
            missing.append(f"Monitor has run only {int((time.time() - mon.started) / 60)} min - intermittent problems "
                           "need time to show up.")
    finds.sort(key=lambda f: -f["score"])
    return finds, missing


def feed_notes(mon, seen, now=None):
    """What to tell the user about the router log and NetFlow feeds. seen = {"syslog"/"flow": {"ts", "lip"}} from
    earlier runs, so a router that is set up but quiet is not reported as missing, and a changed PC IP is named."""
    now = now or time.time()
    out = []
    ran = now - mon.started if mon.started else 0
    fw = ("Setup > Allow in Windows Firewall (Network Doctor running as Administrator)" if core.IS_WIN else
          "allow UDP {port} in this computer's firewall")
    for key, label, last, port, rx, need in (
            ("syslog", "Router log", mon.last_syslog, mon.syslog_port, getattr(mon, "rx_log", None),
             "port up/down (e.g. ether2) can only be seen with it"),
            ("flow", "Traffic data (NetFlow)", mon.last_flow, mon.flow_port, getattr(mon, "rx_flow", None),
             "per-device bandwidth needs it")):
        if rx is not None and getattr(rx, "error", None):
            out.append(f"{label} cannot be received: {rx.error}. Close the other program that uses UDP {port} "
                       "(another copy of Network Doctor, a syslog server), then restart Network Doctor.")
            continue
        h = seen.get(key) or {}
        if h.get("lip") and mon.lip and h["lip"] != mon.lip and (not last or now - last > 300):
            out.append(f"{label} stopped arriving because this PC's IP changed from {h['lip']} to {mon.lip}; the "
                       "router still sends to the old IP. Setup > Copy router commands and paste them in WinBox "
                       "again, and bind this PC's IP in the IP-MAC binding tab so it does not change again.")
            continue
        newest = max(last or 0, h.get("ts") or 0)
        if newest:
            # The router only logs when something happens, so a quiet log is normal for days.
            # NetFlow arrives every minute while there is any traffic.
            if now - newest < (7 * 86400 if key == "syslog" else 300):
                continue
            when = time.strftime("%d %b %H:%M", time.localtime(newest))
            out.append(f"{label} stopped arriving (last received {when}). Check the router still sends to "
                       f"{mon.lip} UDP {port} and {fw.format(port=port)}.")
            continue
        if ran < 120:
            continue  # give the router two minutes after the monitor starts
        out.append(f"{label} is not arriving - {need}. On the router: Setup > Copy router commands, paste them in "
                   f"WinBox (they send to {mon.lip} UDP {port}). Already done? Then {fw.format(port=port)}, and "
                   "check this PC still has that IP.")
    return out


# ==========================================================================
# root cause analysis - one device
# ==========================================================================
def analyse_device(d, mon, orgs):
    ip = d.get("ip")
    out = {"rate": None, "rank": None, "apps": [], "dests": [], "reasons": [], "risks": [], "has_flows": False}
    if not mon or not mon.last_flow:
        return out
    rates = mon.traffic.rates(120)
    r = rates.get(ip)
    order = sorted(rates, key=lambda k: -(rates[k]["down_bps"] + rates[k]["up_bps"]))
    if r:
        out["rate"] = r
        out["rank"] = (order.index(ip) + 1, len(order))
        out["last10"] = mon.traffic.window_total(ip, 600)
    rem, threats, risks = mon.traffic.remotes(ip)
    if not rem:
        return out
    out["has_flows"] = True
    apps = Counter()
    rows = []
    distinct = set()
    rem.sort(key=lambda x: -(x[1][0] + x[1][1]))
    for idx, ((remote, svc, proto, inbound), (up, down, n, first, last)) in enumerate(rem):
        info = orgs.get(remote) if idx < 60 else orgs.cache_peek(remote)
        app, risk = classify(remote, svc, proto, info, inbound)
        th = threats.get(remote)
        if th:
            if th[1] == "tor":
                risk = ("warning", th[0])
            elif inbound:
                risk = ("warning", f"Known attacker trying this device: {th[0]}")
            else:
                risk = ("critical", th[0])
        apps[app] += up + down
        distinct.add(remote)
        rows.append({"remote": remote, "port": svc, "proto": proto, "app": app, "org": info.get("org", ""),
                     "ptr": info.get("ptr", ""), "up": up, "down": down, "conns": n, "last": last, "risk": risk,
                     "inbound": inbound})
    out["dests"] = rows[:200]
    out["apps"] = apps.most_common(12)
    total = sum(apps.values()) or 1
    top_app, top_b = out["apps"][0]
    up_tot = sum(x["up"] for x in rows)
    down_tot = sum(x["down"] for x in rows)
    reasons = []
    if top_b / total > 0.3:
        reasons.append(f"{top_app} uses {top_b / total * 100:.0f}% of this device's data ({fmt_bytes(top_b)}).")
    vid = sum(b for a, b in apps.items() if any(w in a.lower() for w in ("video", "youtube", "ott", "netflix")))
    if vid / total > 0.3:
        reasons.append("Video streaming is the main use (YouTube / OTT / Netflix).")
    if any(("Windows Update" in a or "Microsoft" in a) for a, _ in out["apps"][:2]):
        reasons.append("Microsoft / Windows Update downloads - normal, but can be scheduled outside office hours.")
    if any(("sync" in a.lower() or "icloud" in a.lower()) for a, _ in out["apps"][:3]) and up_tot > down_tot:
        reasons.append("Cloud backup / sync is uploading files.")
    outbound_rows = [x for x in rows if not x["inbound"]]
    p2p = [x for x in rows if x["port"] in P2P_PORTS]
    if p2p or (len(distinct) > 300 and sum(1 for x in outbound_rows if x["port"] > 1024) > 0.8 * max(len(outbound_rows), 1)):
        reasons.append(f"Peer-to-peer pattern: {len(distinct)} different internet addresses - torrent or P2P app.")
    inbound_b = sum(x["up"] + x["down"] for x in rows if x["inbound"])
    if inbound_b > 0.5 * total:
        reasons.append("Most traffic is the internet connecting IN to this device (remote viewing / port forwarding).")
    if up_tot > 3 * down_tot and up_tot > 50e6:
        reasons.append(f"Uploading much more than downloading ({fmt_bytes(up_tot)} up) - backup, camera streaming to "
                       "cloud / remote viewers, or data leaving the network.")
    scan = Counter(x["port"] for x in outbound_rows if x["port"] in (23, 445, 22, 3389))
    for port, n in scan.items():
        if n > 30:
            out["risks"].append(("critical", f"Connects to {n} different addresses on port {port} - this is how worms "
                                             "and infected devices scan the internet."))
    seen = set()
    for x in rows:
        if x["risk"] and x["risk"][0] in ("critical", "warning") and x["risk"][1] not in seen:
            seen.add(x["risk"][1])
            where = f"{x['remote']}:{x['port']} {x['org'] or x['ptr']}".strip()
            out["risks"].append((x["risk"][0], f"{x['risk'][1]} - {where}"))
    out["reasons"] = reasons or ["Normal browsing / app traffic - no single cause dominates."]
    out["up_tot"], out["down_tot"], out["distinct"] = up_tot, down_tot, len(distinct)
    return out


def local_pc_apps():
    """For the PC running the app: which programs have internet connections right now."""
    if not core.IS_WIN:
        return []
    names = {}
    for line in core.run(["tasklist", "/fo", "csv", "/nh"], 15).splitlines():
        p = [x.strip('"') for x in line.split('","')]
        if len(p) >= 2:
            names[p[1]] = p[0]
    c = defaultdict(set)
    for line in core.run(["netstat", "-ano", "-p", "tcp"], 15).splitlines():
        m = re.search(r"TCP\s+\S+:\d+\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+ESTABLISHED\s+(\d+)", line)
        if m:
            try:
                if not ipaddress.IPv4Address(m.group(1)).is_global:
                    continue
            except ValueError:
                continue
            c[names.get(m.group(3), "PID " + m.group(3))].add(m.group(1))
    return sorted(((k, len(v), sorted(v)[:5]) for k, v in c.items()), key=lambda x: -x[1])


def router_setup_commands(lip, flow_port=FLOW_PORT, syslog_port=SYSLOG_PORT, wan="ether1"):
    return f"""# One-time setting on the MikroTik (WinBox > New Terminal). The router only SENDS data to this PC;
# Paste in WinBox, or Setup > Apply router settings now (router login). Any NetFlow/syslog capable router or managed switch works the same way.

# Safe to paste again (for example after this PC got a new IP): the old Network Doctor settings are replaced.
# Keep this PC on a fixed IP (IP-MAC binding tab ticks it for you), otherwise the router keeps sending to the old IP.

# 1) Traffic data per device (bandwidth, apps, dangerous sites)
/ip traffic-flow set enabled=yes interfaces=all active-flow-timeout=1m inactive-flow-timeout=15s
:do {{/ip traffic-flow target remove [find where port={flow_port}]}} on-error={{}}
/ip traffic-flow target add dst-address={lip} port={flow_port} version=9
#    if bandwidth ever looks doubled:  /ip traffic-flow set interfaces=bridge,{wan}

# 2) Router log (port up/down such as ether2, loops, DHCP vs static, IP conflicts, password attacks)
:do {{/system logging remove [find where action=netdoctor]}} on-error={{}}
:do {{/system logging action remove [find where name=netdoctor]}} on-error={{}}
/system logging action add name=netdoctor target=remote remote={lip} remote-port={syslog_port}
/system logging add topics=interface action=netdoctor
/system logging add topics=dhcp action=netdoctor
/system logging add topics=bridge action=netdoctor
/system logging add topics=critical action=netdoctor
/system logging add topics=error action=netdoctor
/system logging add topics=warning action=netdoctor
/system logging add topics=account action=netdoctor
# test message - Network Doctor shows "Router log: receiving" within a few seconds if everything is right
:log warning "Network Doctor router log test"

# 3) Let Network Doctor read the router's device list (read-only SNMP, only from this PC). This finds sleeping
#    phones and cameras on other IP ranges that do not answer a scan.
/snmp set enabled=yes
:do {{/snmp community remove [find where name=netdoctor]}} on-error={{}}
:do {{/snmp community add name=netdoctor addresses={lip}/32 read-access=yes write-access=no}} on-error={{}}

# 4) Recommended loop protection. {wan} is assumed to be the INTERNET port - change it if yours is different.
#    Do this outside busy hours: switching the bridge to RSTP pauses the LAN for 2-3 seconds.
/interface ethernet set [find where name!={wan}] loop-protect=on
/interface bridge set [find] protocol-mode=rstp
#    Note: if loop-protect was ALREADY on and ether2 keeps dropping, the router may be switching ether2 off
#    because it found a loop - the router log will then say "loop detected".
"""
