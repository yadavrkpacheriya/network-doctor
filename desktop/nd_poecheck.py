# -*- coding: utf-8 -*-
r"""Direct PoE camera check - find cameras on a direct link with no router / no DHCP.

Plug the PC straight into the PoE switch that feeds the cameras and run this. Because every device on that
switch is one Layer-2 segment, cameras answer multicast/broadcast discovery even when their IP is on a
different subnet than the PC and there is no DHCP at all. So this tells you WHICH cameras are powered and
connected, with their IP / MAC / brand, without touching the main router or network.

Three discovery protocols, all plain UDP (no admin rights, no raw sockets):
  * ONVIF WS-Discovery   - multicast 239.255.255.250:3702  (SOAP) - almost every modern IP camera
  * Hikvision SADP        - multicast 239.255.255.250:37020 (XML)  - Hikvision + OEMs
  * Dahua DHIP discover   - broadcast 255.255.255.255:37810 (JSON) - Dahua + OEMs

The message builders and response parsers here are pure and unit-tested; the socket I/O is a thin, injectable
runner so a test can feed real sample responses without a network.
"""
import json
import re
import socket
import struct
import time
import uuid

MCAST = "239.255.255.250"
WS_PORT = 3702
SADP_PORT = 37020
DAHUA_PORT = 37810
XMEYE_PORT = 34569       # XMeye / NetSurveillance LAN device-search (what most no-name "XM" cameras use)
XMEYE_SEARCH = 1530


# ------------------------------------------------------------------ ONVIF WS-Discovery
def onvif_probe_msg(mid=None):
    mid = mid or ("uuid:" + str(uuid.uuid4()))
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        '<e:Header><w:MessageID>%s</w:MessageID>'
        '<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
        '<w:Action e:mustUnderstand="true">'
        'http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>'
        '<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>'
        '</e:Envelope>' % mid
    ).encode("utf-8")


def parse_onvif(data, src_ip=""):
    """A WS-Discovery ProbeMatch -> {ip, xaddr, brand, how}. The device's address is in <XAddrs>http://IP/..."""
    try:
        text = data.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None
    if "ProbeMatch" not in text:
        return None
    ip = src_ip
    xaddr = ""
    m = re.search(r"<[^>]*XAddrs[^>]*>(.*?)</[^>]*XAddrs>", text, re.S | re.I)
    if m:
        xaddr = m.group(1).strip().split()[0] if m.group(1).strip() else ""
        u = re.search(r"https?://([0-9]{1,3}(?:\.[0-9]{1,3}){3})", xaddr)
        if u:
            ip = u.group(1)
    scopes = (re.search(r"<[^>]*Scopes[^>]*>(.*?)</[^>]*Scopes>", text, re.S | re.I) or [None, ""])[1]
    return {"ip": ip, "xaddr": xaddr, "brand": _brand_from_scopes(scopes), "how": "ONVIF"}


def _brand_from_scopes(scopes):
    s = (scopes or "").lower()
    for key, name in (("hikvision", "Hikvision"), ("dahua", "Dahua"), ("hanwha", "Hanwha"),
                      ("axis", "Axis"), ("uniview", "Uniview"), ("cp plus", "CP Plus"), ("cpplus", "CP Plus")):
        if key in s:
            return name
    m = re.search(r"onvif://www\.onvif\.org/(?:name|hardware)/([^/ <]+)", s)
    return m.group(1).title() if m else ""


# ------------------------------------------------------------------ Hikvision SADP
def hik_probe_msg(mid=None):
    mid = mid or str(uuid.uuid4())
    return ('<?xml version="1.0" encoding="utf-8"?><Probe><Uuid>%s</Uuid>'
            '<Types>inquiry</Types></Probe>' % mid).encode("utf-8")


def parse_hik(data, src_ip=""):
    try:
        text = data.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None
    if "ProbeMatch" not in text and "<MAC>" not in text:
        return None

    def tag(t):
        m = re.search(r"<%s>(.*?)</%s>" % (t, t), text, re.S | re.I)
        return m.group(1).strip() if m else ""
    ip = tag("IPv4Address") or src_ip
    return {"ip": ip, "mac": tag("MAC").upper().replace("-", ":"),
            "model": tag("DeviceDescription") or tag("DeviceType"), "serial": tag("DeviceSN"),
            "brand": "Hikvision", "how": "SADP"}


# ------------------------------------------------------------------ Dahua DHIP discover
def dahua_probe_msg():
    body = json.dumps({"method": "DHDiscover.search", "params": {"mac": "", "uni": 1}}).encode("utf-8")
    # DHIP header (20 bytes): magic byte 0x20, then two body-length fields, rest zero
    head = struct.pack("<IIIII", 0x20, len(body), len(body), 0, 0)
    return head + body


def parse_dahua(data, src_ip=""):
    i = data.find(b"{")
    if i < 0:
        return None
    try:
        obj = json.loads(data[i:].split(b"\x00")[0].decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return None
    p = obj.get("params", obj) or {}
    dev = p.get("deviceInfo") or p
    ip = (dev.get("IPv4Address") or {}).get("IPAddress") if isinstance(dev.get("IPv4Address"), dict) else \
        dev.get("IPAddress") or dev.get("IP") or src_ip
    return {"ip": ip or src_ip, "mac": (dev.get("mac") or dev.get("MAC") or "").upper().replace("-", ":"),
            "model": dev.get("DeviceType") or dev.get("deviceType") or "", "serial": dev.get("SerialNo") or "",
            "brand": "Dahua", "how": "Dahua"}


# ------------------------------------------------------------------ XMeye / DVRIP LAN search (local brands)
def xmeye_probe_msg():
    """A NetSurveillance device-search packet (DVRIP header, msg 1530) broadcast on 34569. Most cheap/local
    'XM'-chipset cameras answer this even when they are not Hikvision/Dahua and support no SADP."""
    body = b"{ }\n\x00"
    return struct.pack("<BB2xII2xHI", 0xFF, 0, 0, 0, XMEYE_SEARCH, len(body)) + body


def _ip_from_hex(v):
    """XMeye reports HostIP as a little-endian hex word like '0x6401A8C0' -> '192.168.1.100'."""
    try:
        if isinstance(v, str) and v.lower().startswith("0x"):
            n = int(v, 16)
            return "%d.%d.%d.%d" % (n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, (n >> 24) & 0xFF)
    except Exception:  # noqa: BLE001
        pass
    return v if isinstance(v, str) else ""


def parse_xmeye(data, src_ip=""):
    i = data.find(b"{")
    if i < 0:
        return None
    try:
        obj = json.loads(data[i:].rstrip(b"\x00\n ").decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return None
    net = obj.get("NetWork.NetCommon") or obj.get("NetWork") or obj
    ip = _ip_from_hex(net.get("HostIP") or net.get("IPAddress") or "") or src_ip
    mac = (net.get("MAC") or net.get("mac") or "").upper().replace("-", ":")
    name = net.get("HostName") or obj.get("HostName") or ""
    return {"ip": ip or src_ip, "mac": mac, "model": name, "serial": obj.get("SerialNo", ""),
            "brand": "", "how": "XMeye"}


# ------------------------------------------------------------------ brand-agnostic port sweep (catch-all)
def camera_ports_open(ip, connect=None, ports=None, timeout=0.6):
    """Which camera-ish ports answer on `ip`. Finds ANY camera by the service it runs - RTSP (554), web (80),
    XMeye (34567) - so a local/no-name brand with no discovery support is still found. `connect` is injectable."""
    ports = ports or CAM_PORTS
    connect = connect or _tcp_open
    return [p for p in ports if connect(ip, p, timeout)]


def sweep_ports(ips, connect=None, ports=None):
    """Brand-agnostic: scan a list of IPs and return the ones answering a camera port, with which ports and a
    best-guess protocol. Use this for the PC's own subnet on the direct link (set the PC to the cameras'
    subnet, e.g. 192.168.1.x). Returns [{ip, ports, guess}]."""
    out = []
    for ip in ips:
        open_ports = camera_ports_open(ip, connect=connect, ports=ports)
        if open_ports:
            out.append({"ip": ip, "mac": "", "brand": "", "model": "", "serial": "",
                        "seen_by": ["port " + ",".join(str(p) for p in open_ports)],
                        "port": open_ports[0], "guess": _guess(open_ports)})
    return sorted(out, key=lambda d: _ip_key(d["ip"]))


def sweep_many(ips, connect=None, ports=None, workers=100):
    """Parallel brand-agnostic sweep (fast enough for a /24 in a few seconds). Same records as sweep_ports."""
    import concurrent.futures as cf
    ips = list(ips)
    out = []
    try:
        with cf.ThreadPoolExecutor(max_workers=min(workers, max(1, len(ips)))) as ex:
            fut = {ex.submit(camera_ports_open, ip, connect, ports): ip for ip in ips}
            for f in cf.as_completed(fut):
                op = f.result()
                if op:
                    ip = fut[f]
                    out.append({"ip": ip, "mac": "", "brand": "", "model": "", "serial": "",
                                "seen_by": ["port " + ",".join(str(p) for p in op)],
                                "port": op[0], "guess": _guess(op)})
    except Exception:  # noqa: BLE001
        return sweep_ports(ips, connect=connect, ports=ports)
    return sorted(out, key=lambda d: _ip_key(d["ip"]))


def subnet_ips(ip):
    """The /24 around an IP (x.y.z.1 .. x.y.z.254), for sweeping the PC's own link."""
    try:
        a, b, c, _ = ip.split(".")
        return ["%s.%s.%s.%d" % (a, b, c, n) for n in range(1, 255)]
    except Exception:  # noqa: BLE001
        return []


def _guess(ports):
    if 34567 in ports:
        return "XMeye/local DVR camera"
    if 554 in ports:
        return "RTSP camera"
    if 37777 in ports:
        return "Dahua camera"
    if 8000 in ports:
        return "Hikvision camera"
    return "camera (web)"


def _tcp_open(ip, port, timeout=0.6):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        ok = s.connect_ex((ip, port)) == 0
        s.close()
        return ok
    except Exception:  # noqa: BLE001
        return False


# ------------------------------------------------------------------ merge + confirm
CAM_PORTS = (80, 554, 8000, 34567, 37777, 8899, 443)


def merge(found):
    """Collapse responses that are the same camera into one record. Two responses are the same camera when they
    share a non-empty IP OR a non-empty MAC (so an ONVIF hit with only an IP merges with an XMeye/SADP hit that
    also has the MAC). Keeps the richest fields and notes every protocol that saw it."""
    recs = []
    for f in found:
        if not f:
            continue
        ip, mac = f.get("ip", ""), f.get("mac", "")
        if not ip and not mac:
            continue
        hit = None
        for r in recs:
            if (ip and r["ip"] == ip) or (mac and r["mac"] == mac):
                hit = r
                break
        if hit is None:
            recs.append({"ip": ip, "mac": mac, "brand": f.get("brand", ""), "model": f.get("model", ""),
                         "serial": f.get("serial", ""), "seen_by": [f.get("how", "")]})
        else:
            for k in ("ip", "mac", "brand", "model", "serial"):
                if not hit.get(k) and f.get(k):
                    hit[k] = f[k]
            if f.get("how") and f["how"] not in hit["seen_by"]:
                hit["seen_by"].append(f["how"])
    return sorted(recs, key=lambda d: _ip_key(d.get("ip", "")))


def _ip_key(ip):
    try:
        return tuple(int(x) for x in ip.split("."))
    except Exception:  # noqa: BLE001
        return (999,)


def _ip_alive(ip, timeout=0.6, ports=CAM_PORTS):
    """Which camera-ish TCP port answers (confirms it is reachable from here), or None."""
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, p)) == 0:
                s.close()
                return p
            s.close()
        except Exception:  # noqa: BLE001
            pass
    return None


# ------------------------------------------------------------------ the socket runner (real network)
def _collect(messages, timeout=3.0):
    """Broadcast/multicast each probe and gather (how, data, src_ip) until `timeout`. messages is
    [(how, dst_ip, port, payload)]. Best-effort - a blocked protocol just yields nothing."""
    out = []
    socks = []
    for how, dst, port, payload in messages:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            s.settimeout(0.3)
            s.sendto(payload, (dst, port))
            socks.append((how, s))
        except Exception:  # noqa: BLE001
            pass
    end = time.time() + timeout
    while time.time() < end:
        for how, s in socks:
            try:
                data, addr = s.recvfrom(65535)
                out.append((how, data, addr[0]))
            except socket.timeout:
                pass
            except Exception:  # noqa: BLE001
                pass
    for _how, s in socks:
        try:
            s.close()
        except Exception:  # noqa: BLE001
            pass
    return out


def discover(timeout=3.0, collect=None, confirm=True, alive=None):
    """Find cameras on the directly-connected link. Returns merged records:
    [{ip, mac, brand, model, serial, seen_by, port}]. `collect`/`alive` are injectable for tests."""
    collect = collect or _collect
    alive = alive or _ip_alive
    messages = [
        ("ONVIF", MCAST, WS_PORT, onvif_probe_msg()),             # generic - most local brands answer this
        ("XMeye", "255.255.255.255", XMEYE_PORT, xmeye_probe_msg()),  # no-name "XM" cameras
        ("SADP", MCAST, SADP_PORT, hik_probe_msg()),
        ("Dahua", "255.255.255.255", DAHUA_PORT, dahua_probe_msg()),
    ]
    raw = collect(messages, timeout)
    _parse = {"ONVIF": parse_onvif, "XMeye": parse_xmeye, "SADP": parse_hik, "Dahua": parse_dahua}
    parsed = [_parse.get(how, lambda d, s: None)(data, src) for how, data, src in raw]
    cams = merge(parsed)
    if confirm:
        for c in cams:
            c["port"] = alive(c["ip"]) if c.get("ip") else None
    return cams
