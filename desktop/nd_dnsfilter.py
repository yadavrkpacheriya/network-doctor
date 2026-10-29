# -*- coding: utf-8 -*-
"""
Network Doctor - website firewall (nd_dnsfilter)
=========================================================
A small DNS server that runs on this PC and blocks websites for every device that
uses it: ads and trackers, adult sites, gambling, social media, or your own list.
Point the router's DHCP "DNS server" at this PC (or set it on single devices) and
every phone, PC and TV on the network is filtered, with no software on them.

Blocked names get the answer 0.0.0.0, so the page simply does not open. Everything
else is passed to the normal DNS server. Safe search makes Google, Bing, YouTube and
DuckDuckGo hide adult results. Plain Python, no extra packages.
"""

import collections
import concurrent.futures as cf
import os
import re
import socket
import struct
import threading
import time
import urllib.request

import nd_core as core
import nd_net as NT

LIST_DIR = os.path.join(core.DATA_DIR, "blocklists")
SETTINGS = os.path.join(core.DATA_DIR, "website_firewall.json")
_HOSTS = "https://raw.githubusercontent.com/StevenBlack/hosts/master/"
CATEGORIES = {  # key: (label, list URL, a few names so the category works before the list is downloaded)
    "ads": ("Ads and trackers", _HOSTS + "hosts",
            ["doubleclick.net", "googlesyndication.com", "googleadservices.com", "adservice.google.com",
             "ads.yahoo.com", "adnxs.com", "taboola.com", "outbrain.com", "scorecardresearch.com", "criteo.com"]),
    "adult": ("Adult websites", _HOSTS + "alternates/porn-only/hosts",
              ["pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com", "redtube.com", "youporn.com",
               "onlyfans.com", "chaturbate.com", "stripchat.com", "spankbang.com"]),
    "gambling": ("Gambling and betting", _HOSTS + "alternates/gambling-only/hosts",
                 ["bet365.com", "betway.com", "1xbet.com", "dream11.com", "pokerstars.com", "williamhill.com",
                  "888casino.com", "stake.com", "parimatch.com", "mpl.live"]),
    "social": ("Social media", _HOSTS + "alternates/social-only/hosts",
               ["facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com", "tiktok.com", "tiktokcdn.com",
                "twitter.com", "x.com", "snapchat.com", "reddit.com", "pinterest.com", "linkedin.com"]),
    "video": ("Video streaming (YouTube, Netflix...)", "",
              ["youtube.com", "googlevideo.com", "ytimg.com", "youtu.be", "netflix.com", "nflxvideo.net",
               "primevideo.com", "hotstar.com", "jiocinema.com", "twitch.tv", "sonyliv.com", "zee5.com"]),
    "games": ("Online games", "",
              ["roblox.com", "epicgames.com", "fortnite.com", "steampowered.com", "steamcommunity.com",
               "pubg.com", "battle.net", "ea.com", "minecraft.net", "garena.com", "freefiremobile.com"]),
}
SAFE_SEARCH = {  # name -> the provider's own "safe" address
    "www.google.com": "forcesafesearch.google.com", "google.com": "forcesafesearch.google.com",
    "www.google.co.in": "forcesafesearch.google.com", "google.co.in": "forcesafesearch.google.com",
    "www.bing.com": "strict.bing.com", "bing.com": "strict.bing.com",
    "www.youtube.com": "restrictmoderate.youtube.com", "m.youtube.com": "restrictmoderate.youtube.com",
    "youtube.com": "restrictmoderate.youtube.com", "youtubei.googleapis.com": "restrictmoderate.youtube.com",
    "duckduckgo.com": "safe.duckduckgo.com", "www.duckduckgo.com": "safe.duckduckgo.com",
}
A, AAAA = 1, 28


# ==========================================================================
# lists
# ==========================================================================
_NAME = re.compile(r"^[a-z0-9_.-]+\.[a-z0-9-]+$")


def parse_list(text):
    """Domains from a hosts file ("0.0.0.0 name") or a plain list (one name per line, # comments)."""
    out = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if not line:
            continue
        parts = line.split()
        name = parts[1] if len(parts) >= 2 and re.match(r"^[0-9.:]+$", parts[0]) else parts[0]
        name = name.strip(".")
        if name.startswith("*."):
            name = name[2:]
        if _NAME.match(name) and name not in ("localhost", "localhost.localdomain", "local", "broadcasthost"):
            out.add(name)
    return out


def load_category(key, download=True, max_age=7 * 86400, fetch=None):
    """Names for one category: the cached list (downloaded weekly) plus the built-in names."""
    label, url, seed = CATEGORIES[key]
    names = set(seed)
    path = os.path.join(LIST_DIR, key + ".txt")
    fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < max_age
    if url and download and not fresh:
        try:
            text = (fetch or _fetch)(url)
            got = parse_list(text)
            if len(got) > 20:
                os.makedirs(LIST_DIR, exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(sorted(got)))
        except Exception:
            pass  # offline: keep the old copy / the built-in names
    try:
        with open(path, encoding="utf-8") as f:
            names |= parse_list(f.read())
    except OSError:
        pass
    return names


def _fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "NetworkDoctor"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode("utf-8", "replace")


def matches(name, names):
    """True when name or any parent domain is in names (blocking facebook.com blocks m.facebook.com too)."""
    p = name.lower().strip(".").split(".")
    return any(".".join(p[i:]) in names for i in range(len(p) - 1))


# ==========================================================================
# DNS messages
# ==========================================================================
def parse_query(msg):
    """(id, flags, name, qtype, end of question) of a DNS query; raises ValueError on garbage."""
    if len(msg) < 17:
        raise ValueError("short")
    qid, flags, qd = struct.unpack("!HHH", msg[:6])
    if flags & 0x8000 or qd != 1:
        raise ValueError("not a single query")
    name, off = NT._read_name(msg, 12)
    qtype, _ = struct.unpack("!HH", msg[off:off + 4])
    return qid, flags, name, qtype, off + 4


def answer(query, qtype, end, ips=(), rcode=0):
    """A reply to query with A / AAAA records for ips (TTL 60 s)."""
    qid, flags = struct.unpack("!HH", query[:4])
    recs = b""
    n = 0
    for ip in ips:
        if qtype == A and ":" not in ip:
            rdata = socket.inet_aton(ip)
        elif qtype == AAAA and ":" in ip:
            rdata = socket.inet_pton(socket.AF_INET6, ip)
        else:
            continue
        recs += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(rdata)) + rdata
        n += 1
    hdr = struct.pack("!HHHHHH", qid, 0x8180 | (flags & 0x0100) | rcode, 1, n, 0, 0)
    return hdr + query[12:end] + recs


def blocked_reply(query, qtype, end):
    return answer(query, qtype, end, ["0.0.0.0", "::"])


# ==========================================================================
# the server
# ==========================================================================
class DnsFilter:
    def __init__(self, upstream=None, blocked=(), allowed=(), safe_search=False, host="0.0.0.0", port=53):
        # "ip" or (ip, port); never this PC itself, or every question would loop back here
        self.upstream = [u for u in (upstream or []) if u] or (
            [d for d in NT.system_dns_servers() if d != host] + ["1.1.1.1", "8.8.8.8"])
        self.blocked, self.allowed = set(blocked), set(allowed)
        self.safe_search = safe_search
        self.addr = (host, port)
        self.sock = None
        self.pool = cf.ThreadPoolExecutor(32)
        self.lock = threading.Lock()
        self.queries = self.blocks = 0
        self.by_client = collections.Counter()
        self.blocked_by_client = collections.Counter()
        self.top_blocked = collections.Counter()
        self.recent = collections.deque(maxlen=300)  # (time, client, name, "blocked" / "safe" / "ok")
        self._safe_ips = {}

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.addr)
        self.addr = self.sock.getsockname()
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def stop(self):
        if self.sock:
            self.sock.close()
            self.sock = None
        self.pool.shutdown(wait=False)

    def _serve(self):
        while self.sock:
            try:
                data, client = self.sock.recvfrom(4096)
            except OSError:
                return
            self.pool.submit(self._handle, data, client)

    def decide(self, name):
        """"ok", "blocked" or "safe" (answered with the safe-search address)."""
        n = name.lower().strip(".")
        if matches(n, self.allowed):
            return "ok"
        if self.safe_search and n in SAFE_SEARCH:
            return "safe"
        return "blocked" if matches(n, self.blocked) else "ok"

    def _handle(self, data, client):
        try:
            qid, flags, name, qtype, end = parse_query(data)
        except (ValueError, struct.error, IndexError):
            return
        what = self.decide(name)
        ip = client[0]
        with self.lock:
            self.queries += 1
            self.by_client[ip] += 1
            if what == "blocked":
                self.blocks += 1
                self.blocked_by_client[ip] += 1
                self.top_blocked[name.lower()] += 1
            self.recent.append((time.time(), ip, name.lower(), what))
        if what == "blocked":
            reply = blocked_reply(data, qtype, end)
        elif what == "safe" and qtype in (A, AAAA) and self._safe(SAFE_SEARCH[name.lower().strip(".")], qtype):
            reply = answer(data, qtype, end, self._safe(SAFE_SEARCH[name.lower().strip(".")], qtype))
        else:  # allowed, or the safe address could not be found (better unfiltered search than none)
            reply = self.forward(data)
        if reply and self.sock:
            try:
                self.sock.sendto(reply, client)
            except OSError:
                pass

    def _safe(self, target, qtype):
        key = (target, qtype)
        if key not in self._safe_ips:
            try:
                up = self.upstream[0]
                host, port = up if isinstance(up, tuple) else (up, 53)
                r = NT.dns_query(target, "A" if qtype == A else "AAAA", host, timeout=2, port=port)
                ips = [x["data"] for x in r.get("records", [])
                       if x["section"] == "answer" and x["type"] in ("A", "AAAA")]
            except Exception:
                ips = []
            if not ips:
                return []
            self._safe_ips[key] = ips
        return self._safe_ips[key]

    def forward(self, data, timeout=2.0):
        for server in self.upstream:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.settimeout(timeout)
                s.sendto(data, server if isinstance(server, tuple) else (server, 53))
                reply, _ = s.recvfrom(4096)
                if reply[:2] == data[:2]:
                    return reply
            except OSError:
                continue
            finally:
                s.close()
        return None

    def snapshot(self):
        with self.lock:
            return {"queries": self.queries, "blocked": self.blocks, "clients": dict(self.by_client),
                    "blocked_clients": dict(self.blocked_by_client), "top": self.top_blocked.most_common(15),
                    "recent": list(self.recent)}
