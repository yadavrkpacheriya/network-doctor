# -*- coding: utf-8 -*-
"""
Network Doctor - SNMP reader (nd_snmp)
=========================================================
Reads a managed switch or router of ANY brand through standard SNMP, read-only:
  * what it is: name, model / description, location, uptime
  * every port: name, up / down, speed, traffic counters, errors
  * LLDP neighbours: which switch / AP / phone is on which port
  * the MAC address table: which device is plugged into which port

Plain Python, no extra packages. SNMP v1 and v2c (community string).
Reading never changes anything. The only changes it can make (turn a port off / on,
rename a port) need the device's separate write community, and the app asks first.
"""

import random
import re
import socket

# ==========================================================================
# BER encoding / decoding (just the parts SNMP uses)
# ==========================================================================
INTEGER, OCTET_STRING, NULL, OID, SEQUENCE = 0x02, 0x04, 0x05, 0x06, 0x30
IPADDRESS, COUNTER32, GAUGE32, TIMETICKS, OPAQUE, COUNTER64 = 0x40, 0x41, 0x42, 0x43, 0x44, 0x46
NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB = 0x80, 0x81, 0x82
GET, GETNEXT, RESPONSE, SET, GETBULK = 0xA0, 0xA1, 0xA2, 0xA3, 0xA5

ERRORS = {1: "tooBig", 2: "noSuchName", 3: "badValue", 4: "readOnly", 5: "genErr", 6: "noAccess",
          7: "wrongType", 10: "wrongValue", 16: "authorizationError", 17: "notWritable"}
NOT_ALLOWED = ("readOnly", "noAccess", "notWritable", "authorizationError", "noSuchName")


class SnmpError(Exception):
    pass


class Missing:
    """noSuchObject / noSuchInstance / endOfMibView in a response."""

    def __init__(self, tag):
        self.tag = tag

    def __repr__(self):
        return {NO_SUCH_OBJECT: "noSuchObject", NO_SUCH_INSTANCE: "noSuchInstance",
                END_OF_MIB: "endOfMibView"}.get(self.tag, "missing")


def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body):
    return bytes([tag]) + _len(len(body)) + body


def enc_int(v, tag=INTEGER):
    n = max(1, (v.bit_length() + 8) // 8)
    return tlv(tag, v.to_bytes(n, "big", signed=True))


def enc_uint(v, tag):
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    return tlv(tag, (b"\x00" + b) if b[0] & 0x80 else b)


def enc_oid(oid):
    parts = [int(x) for x in str(oid).strip(".").split(".")]
    if len(parts) < 2:
        raise ValueError("OID needs at least two parts: " + str(oid))
    out = bytearray()
    for p in [40 * parts[0] + parts[1]] + parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return tlv(OID, bytes(out))


def dec_oid(b):
    subs, n = [], 0
    for c in b:
        n = (n << 7) | (c & 0x7F)
        if not c & 0x80:
            subs.append(n)
            n = 0
    if not subs:
        return ""
    first = min(subs[0] // 40, 2)
    return ".".join(map(str, [first, subs[0] - 40 * first] + subs[1:]))


def read_tlv(buf, off):
    """Returns (tag, body, next_offset)."""
    if off + 2 > len(buf):
        raise SnmpError("truncated packet")
    tag = buf[off]
    n = buf[off + 1]
    off += 2
    if n & 0x80:
        k = n & 0x7F
        if not k or off + k > len(buf):
            raise SnmpError("bad length")
        n = int.from_bytes(buf[off:off + k], "big")
        off += k
    if off + n > len(buf):
        raise SnmpError("truncated packet")
    return tag, buf[off:off + n], off + n


def dec_value(tag, body):
    if tag == INTEGER:
        return int.from_bytes(body, "big", signed=True) if body else 0
    if tag in (COUNTER32, GAUGE32, TIMETICKS, COUNTER64):
        return int.from_bytes(body, "big") if body else 0
    if tag in (OCTET_STRING, OPAQUE):
        return bytes(body)
    if tag == OID:
        return dec_oid(body)
    if tag == IPADDRESS:
        return ".".join(str(x) for x in body)
    if tag == NULL:
        return None
    if tag in (NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB):
        return Missing(tag)
    return bytes(body)


def build_message(pdu_type, request_id, varbinds, community="public", version=1, a=0, b=0):
    """varbinds = [(oid, None)] for requests. version: 0 = v1, 1 = v2c.
    a / b = error-status / error-index, or non-repeaters / max-repetitions for GETBULK."""
    vbs = b"".join(tlv(SEQUENCE, enc_oid(o) + (_enc_any(v))) for o, v in varbinds)
    pdu = tlv(pdu_type, enc_int(request_id) + enc_int(a) + enc_int(b) + tlv(SEQUENCE, vbs))
    return tlv(SEQUENCE, enc_int(version) + tlv(OCTET_STRING, community.encode()) + pdu)


def _enc_any(v):
    """Encodes a value (used for requests and by the test agent)."""
    if v is None:
        return tlv(NULL, b"")
    if isinstance(v, Missing):
        return tlv(v.tag, b"")
    if isinstance(v, tuple):  # (tag, python value) for typed values
        tag, val = v
        if tag == IPADDRESS:
            return tlv(tag, bytes(int(x) for x in val.split(".")))
        if tag == OID:
            return enc_oid(val)
        return enc_uint(val, tag)
    if isinstance(v, bool):
        return enc_int(int(v))
    if isinstance(v, int):
        return enc_int(v)
    if isinstance(v, (bytes, bytearray)):
        return tlv(OCTET_STRING, bytes(v))
    return tlv(OCTET_STRING, str(v).encode())


def parse_message(buf):
    """Returns dict: version, community, type, request_id, error_status, error_index, varbinds [(oid, value)]."""
    tag, msg, _ = read_tlv(buf, 0)
    if tag != SEQUENCE:
        raise SnmpError("not an SNMP packet")
    _, ver, o = read_tlv(msg, 0)
    _, comm, o = read_tlv(msg, o)
    ptype, pdu, _ = read_tlv(msg, o)
    _, rid, p = read_tlv(pdu, 0)
    _, es, p = read_tlv(pdu, p)
    _, ei, p = read_tlv(pdu, p)
    _, vbl, _ = read_tlv(pdu, p)
    vbs, q = [], 0
    while q < len(vbl):
        _, vb, q = read_tlv(vbl, q)
        _, ob, r = read_tlv(vb, 0)
        vt, vv, _ = read_tlv(vb, r)
        vbs.append((dec_oid(ob), dec_value(vt, vv)))
    return {"version": dec_value(INTEGER, ver), "community": bytes(comm).decode("latin-1"), "type": ptype,
            "request_id": dec_value(INTEGER, rid), "error_status": dec_value(INTEGER, es),
            "error_index": dec_value(INTEGER, ei), "varbinds": vbs}


def oid_key(oid):
    return tuple(int(x) for x in oid.strip(".").split(".") if x)


def in_subtree(oid, root):
    return oid_key(oid)[:len(oid_key(root))] == oid_key(root)


# ==========================================================================
# client
# ==========================================================================
class Snmp:
    def __init__(self, host, community="public", version="2c", port=161, timeout=2.0, retries=1):
        self.host, self.port = host, port
        self.community = community
        self.version = 0 if str(version) in ("1", "v1") else 1
        self.timeout, self.retries = timeout, retries

    def _request(self, pdu_type, oids, a=0, b=0, values=None):
        rid = random.randint(1, 0x7FFFFFFF)
        vbs = list(zip(oids, values)) if values else [(o, None) for o in oids]
        pkt = build_message(pdu_type, rid, vbs, self.community, self.version, a, b)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(self.timeout)
            for _ in range(self.retries + 1):
                s.sendto(pkt, (self.host, self.port))
                try:
                    while True:
                        data, _ = s.recvfrom(65535)
                        try:
                            r = parse_message(data)
                        except SnmpError:
                            continue
                        if r["request_id"] == rid:
                            break
                except socket.timeout:
                    continue
                if r["error_status"]:
                    raise SnmpError(ERRORS.get(r["error_status"], "error %d" % r["error_status"]))
                return r["varbinds"]
        finally:
            s.close()
        raise SnmpError("no answer (SNMP off, wrong community, or blocked)")

    def get(self, *oids):
        """{oid: value}; missing objects are left out."""
        try:
            vbs = self._request(GET, oids)
        except SnmpError as e:
            if str(e) == "noSuchName":  # v1 answers a missing object with an error
                return {}
            raise
        return {o: v for o, v in vbs if not isinstance(v, Missing)}

    def set(self, oid, value):
        """Writes one value. Raises SnmpError with a plain reason when the device refuses."""
        try:
            self._request(SET, [oid], values=[value])
        except SnmpError as e:
            if str(e) in NOT_ALLOWED:
                raise SnmpError("the switch refused the change: use its read-WRITE community, and allow "
                                "this PC's IP to write") from None
            raise

    def walk(self, root, limit=20000):
        """[(oid, value)] under root, in order."""
        out, cur = [], root
        while len(out) < limit:
            try:
                if self.version:
                    vbs = self._request(GETBULK, [cur], 0, 25)
                else:
                    vbs = self._request(GETNEXT, [cur])
            except SnmpError as e:
                if str(e) == "noSuchName":  # v1: end of the MIB
                    break
                raise
            if not vbs:
                break
            for o, v in vbs:
                if isinstance(v, Missing) or not in_subtree(o, root) or oid_key(o) <= oid_key(cur):
                    return out
                out.append((o, v))
                cur = o
        return out

    def table(self, root):
        """{index (string after root): value}."""
        n = len(root.strip(".")) + 1
        return {o.strip(".")[n:]: v for o, v in self.walk(root)}


# ==========================================================================
# standard MIB objects
# ==========================================================================
SYS = {"descr": "1.3.6.1.2.1.1.1.0", "object_id": "1.3.6.1.2.1.1.2.0", "uptime": "1.3.6.1.2.1.1.3.0",
       "contact": "1.3.6.1.2.1.1.4.0", "name": "1.3.6.1.2.1.1.5.0", "location": "1.3.6.1.2.1.1.6.0"}
IF = "1.3.6.1.2.1.2.2.1."      # IF-MIB ifTable
IFX = "1.3.6.1.2.1.31.1.1.1."  # IF-MIB ifXTable
LLDP_REM = "1.0.8802.1.1.2.1.4.1.1."
LLDP_LOC_PORT = "1.0.8802.1.1.2.1.3.7.1."
LLDP_MAN_ADDR = "1.0.8802.1.1.2.1.4.2.1.3"
STP_PORT_STATE = "1.3.6.1.2.1.17.2.15.1.3"
STP_STATES = {1: "disabled", 2: "blocking", 3: "listening", 4: "learning", 5: "forwarding", 6: "broken"}
BRIDGE_PORT_IF = "1.3.6.1.2.1.17.1.4.1.2"
FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"
QFDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
QFDB_STATUS = "1.3.6.1.2.1.17.7.1.2.2.1.3"

# Enterprise numbers in sysObjectID -> brand
VENDORS = {9: "Cisco", 11: "HP", 43: "3Com", 171: "D-Link", 674: "Dell", 1916: "Extreme", 2011: "Huawei",
           2636: "Juniper", 4526: "Netgear", 11863: "TP-Link", 14988: "MikroTik", 14823: "Aruba",
           25506: "H3C", 41112: "Ubiquiti", 12356: "Fortinet", 25461: "Palo Alto", 3955: "Linksys",
           890: "Zyxel", 6486: "Alcatel-Lucent", 30065: "Arista", 8072: "Linux (net-snmp)", 311: "Microsoft",
           1991: "Brocade", 5624: "Enterasys", 6527: "Nokia", 207: "Allied Telesis", 3902: "ZTE",
           34592: "Ruijie", 4881: "Ruijie", 37072: "Ruckus", 25053: "Ruckus", 10002: "Ubiquiti"}

OPER = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}


def text(v):
    """Readable text from an OCTET STRING: words stay words, binary becomes hex (aa:bb:..)."""
    if isinstance(v, (bytes, bytearray)):
        b = bytes(v).rstrip(b"\x00")
        if b and all(32 <= c < 127 or c in (9, 10, 13) for c in b):
            return b.decode("ascii").strip()
        return ":".join("%02X" % c for c in bytes(v))
    return "" if v is None else str(v)


def mac_of(v):
    if isinstance(v, (bytes, bytearray)) and len(v) == 6:
        return ":".join("%02X" % c for c in v)
    return ""


def vendor_of_oid(object_id):
    p = str(object_id or "").strip(".").split(".")
    if len(p) > 6 and p[:6] == ["1", "3", "6", "1", "4", "1"]:
        try:
            return VENDORS.get(int(p[6]), "")
        except ValueError:
            return ""
    return ""


def uptime_text(ticks):
    s = int(ticks or 0) // 100
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    return (f"{d} d " if d else "") + f"{h} h {s // 60} min"


def speed_text(mbps):
    if not mbps:
        return ""
    return f"{mbps // 1000:g} Gbps" if mbps >= 1000 and mbps % 1000 == 0 else (
        f"{mbps / 1000:g} Gbps" if mbps >= 1000 else f"{mbps} Mbps")


def system_info(c):
    r = c.get(*SYS.values())
    info = {k: r.get(o) for k, o in SYS.items()}
    for k in ("descr", "contact", "name", "location"):
        info[k] = text(info[k])
    info["vendor"] = vendor_of_oid(info["object_id"])
    return info


def interfaces(c):
    """[{index, name, alias, type, status, admin, speed_mbps, mac, in_octets, out_octets, in_errors, out_errors}]"""
    cols = {"descr": IF + "2", "type": IF + "3", "speed": IF + "5", "mac": IF + "6", "admin": IF + "7",
            "oper": IF + "8", "in": IF + "10", "in_err": IF + "14", "out": IF + "16", "out_err": IF + "20"}
    t = {k: c.table(o) for k, o in cols.items()}
    try:
        x = {k: c.table(o) for k, o in {"name": IFX + "1", "hc_in": IFX + "6", "hc_out": IFX + "10",
                                         "high": IFX + "15", "alias": IFX + "18"}.items()}
    except SnmpError:
        x = {}
    out = []
    for idx in sorted(t["descr"] or t["oper"], key=lambda s: int(s) if s.isdigit() else 0):
        hi = x.get("high", {}).get(idx)
        sp = t["speed"].get(idx) or 0
        out.append({
            "index": int(idx) if idx.isdigit() else idx,
            "name": text(x.get("name", {}).get(idx)) or text(t["descr"].get(idx)),
            "descr": text(t["descr"].get(idx)),
            "alias": text(x.get("alias", {}).get(idx)),
            "type": t["type"].get(idx),
            "status": OPER.get(t["oper"].get(idx), "?"),
            "admin": {1: "up", 2: "down", 3: "testing"}.get(t["admin"].get(idx), "?"),
            "speed_mbps": hi if hi else (sp // 1_000_000 if sp else 0),
            "mac": mac_of(t["mac"].get(idx)),
            "in_octets": x.get("hc_in", {}).get(idx, t["in"].get(idx)),
            "out_octets": x.get("hc_out", {}).get(idx, t["out"].get(idx)),
            "in_errors": t["in_err"].get(idx, 0),
            "out_errors": t["out_err"].get(idx, 0),
        })
    return out


def lldp_neighbors(c):
    """[{local_port, name, port, port_descr, chassis}] from LLDP-MIB."""
    try:
        cols = {k: c.table(LLDP_REM + n) for k, n in
                {"chassis": "5", "port": "7", "port_descr": "8", "name": "9", "descr": "10"}.items()}
        loc = {k: c.table(LLDP_LOC_PORT + n) for k, n in {"id": "3", "descr": "4"}.items()}
    except SnmpError:
        return []
    ips = {}
    try:  # lldpRemManAddrIfSubtype, index timeMark.localPort.remIndex.addrSubtype.addrLen.addr...
        for idx in c.table(LLDP_MAN_ADDR):
            p = idx.split(".")
            if len(p) == 9 and p[3] == "1" and p[4] == "4":  # IPv4
                ips.setdefault(".".join(p[:3]), ".".join(p[5:]))
    except SnmpError:
        pass
    out = []
    for idx in cols["name"].keys() | cols["chassis"].keys():
        p = idx.split(".")  # timeMark.localPortNum.remIndex
        lp = p[1] if len(p) >= 3 else ""
        out.append({"local_port": text(loc["descr"].get(lp)) or text(loc["id"].get(lp)) or lp,
                    "ip": ips.get(idx, ""),
                    "name": text(cols["name"].get(idx)),
                    "port": text(cols["port"].get(idx)),
                    "port_descr": text(cols["port_descr"].get(idx)),
                    "descr": text(cols["descr"].get(idx)),
                    "chassis": mac_of(cols["chassis"].get(idx)) or text(cols["chassis"].get(idx))})
    return sorted(out, key=lambda n: (n["local_port"], n["name"]))


def mac_table(c, ifs=None):
    """{mac: port name} - which MAC was learned on which port (BRIDGE-MIB, or Q-BRIDGE-MIB for VLAN switches)."""
    names = {i["index"]: i["name"] for i in (ifs or [])}
    try:
        bp_if = {int(k): v for k, v in c.table(BRIDGE_PORT_IF).items() if k.isdigit()}
    except SnmpError:
        bp_if = {}

    def port_name(bp):
        ifx = bp_if.get(bp, bp)
        return names.get(ifx) or f"port {bp}"

    def rows(port_root, status_root, mac_from):
        res = {}
        try:
            ports = c.table(port_root)
            status = c.table(status_root)
        except SnmpError:
            return res
        for idx, bp in ports.items():
            if status.get(idx) not in (None, 3) or not bp:  # 3 = learned (skip own / static / mgmt)
                continue
            mac = mac_from(idx)
            if mac:
                res[mac] = port_name(bp)
        return res

    def mac_tail(idx):
        p = idx.split(".")[-6:]
        try:
            return ":".join("%02X" % int(x) for x in p) if len(p) == 6 else ""
        except ValueError:
            return ""

    res = rows(QFDB_PORT, QFDB_STATUS, mac_tail)  # fdbId.mac
    if not res:
        res = rows(FDB_PORT, FDB_STATUS, mac_tail)  # mac
    return res


def read_device(host, community="public", version="2c", timeout=2.0):
    """Everything readable from one device. Raises SnmpError when it does not answer."""
    c = Snmp(host, community, version, timeout=timeout)
    info = system_info(c)
    if not any(info[k] for k in ("descr", "name", "object_id")):
        raise SnmpError("no answer (SNMP off, wrong community, or blocked)")
    ifs = interfaces(c)
    return {"host": host, "system": info, "interfaces": ifs,
            "neighbors": lldp_neighbors(c), "macs": mac_table(c, ifs)}


def ports_with_devices(macs):
    """{port: [mac, ...]} sorted by port name."""
    by = {}
    for mac, port in macs.items():
        by.setdefault(port, []).append(mac)
    return dict(sorted(by.items(), key=lambda kv: _natural(kv[0])))


def _natural(s):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", s or "")]


# ==========================================================================
# live traffic and loop signs (two counter readings a few seconds apart)
# ==========================================================================
# key: (64-bit ifXTable column, 32-bit ifTable column)
COUNTERS = {"in": (IFX + "6", IF + "10"), "out": (IFX + "10", IF + "16"), "ucast": (IFX + "7", IF + "11"),
            "bcast": (IFX + "9", IF + "12"), "mcast": (IFX + "8", None),
            "in_err": (None, IF + "14"), "out_err": (None, IF + "20"), "in_disc": (None, IF + "13")}
# Normal office traffic stays far below these; a loop multiplies broadcasts on every port of it.
STORM_PPS = 1000      # broadcasts / s into one port: storm, almost always a loop
LOOP_PPS = 300        # broadcasts / s that also outnumber normal (unicast) packets: likely a loop
BUSY_PCT = 80         # port busier than this: congested


def counters(c, clock=None):
    """One reading of every port's counters: {"time", "ports": {ifIndex: {key: value}}, "bits": {key: 32|64}}.
    Uses 64-bit counters where the device has them (they do not wrap on fast ports)."""
    import time
    ports, bits = {}, {}
    for key, (hc, low) in COUNTERS.items():
        col = {}
        if hc:
            try:
                col = c.table(hc)
            except SnmpError:
                col = {}
            bits[key] = 64
        if not col and low:
            col = c.table(low)
            bits[key] = 32  # for "bcast" this is ifInNUcastPkts (broadcast + multicast)
        for idx, v in col.items():
            if idx.isdigit() and isinstance(v, int):
                ports.setdefault(int(idx), {})[key] = v
    return {"time": (clock or time.time)(), "ports": ports, "bits": bits}


def _delta(a, b, bits):
    if a is None or b is None:
        return None
    d = b - a
    if d < 0:
        if bits == 32 and a < 2 ** 32:
            d += 2 ** 32  # the counter wrapped
        else:
            return None   # the device restarted or reset its counters
    return d


def rates(prev, cur):
    """{ifIndex: {key: per second}} between two counters() readings; in / out are bytes per second."""
    secs = cur["time"] - prev["time"]
    if secs <= 0:
        return {}
    out = {}
    for idx, now in cur["ports"].items():
        old = prev["ports"].get(idx, {})
        r = {}
        for key, v in now.items():
            d = _delta(old.get(key), v, cur["bits"].get(key, 32))
            if d is not None:
                r[key] = d / secs
        if r:
            out[idx] = r
    return out


def utilisation(r, speed_mbps):
    """Busiest direction as % of the port speed, or None when the speed is unknown."""
    if not speed_mbps:
        return None
    return max(r.get("in", 0), r.get("out", 0)) * 8 / (speed_mbps * 1e6) * 100


def port_warnings(r, speed_mbps):
    """[(level, text)] for one port's rates."""
    w = []
    b = r.get("bcast", 0)
    if b >= STORM_PPS:
        w.append(("crit", f"broadcast storm: {b:,.0f} broadcasts/s - a network loop is almost certainly behind this port"))
    elif b >= LOOP_PPS and b > r.get("ucast", 0):
        w.append(("crit", f"{b:,.0f} broadcasts/s, more than normal traffic - possible loop behind this port"))
    u = utilisation(r, speed_mbps)
    if u is not None and u >= BUSY_PCT:
        w.append(("warn", f"{u:.0f}% busy - this port is a bottleneck"))
    e = r.get("in_err", 0) + r.get("out_err", 0)
    if e >= 1:
        w.append(("warn", f"{e:,.0f} errors/s - bad cable, connector or duplex mismatch"))
    if r.get("in_disc", 0) >= 10:
        w.append(("warn", f"{r['in_disc']:,.0f} packets/s dropped - the switch is overloaded on this port"))
    return w


def mac_moves(before, after):
    """{(port_a, port_b): [mac, ...]} for MACs that moved between two MAC table readings.
    Several MACs bouncing between the same two ports is the classic sign of a loop through them."""
    moves = {}
    for mac, port in after.items():
        old = before.get(mac)
        if old and old != port:
            pair = tuple(sorted((old, port), key=_natural))
            moves.setdefault(pair, []).append(mac)
    return dict(sorted(moves.items(), key=lambda kv: -len(kv[1])))


# ==========================================================================
# changes (write community only): turn a port off / on, rename it
# ==========================================================================
ADMIN = IF + "7"      # ifAdminStatus: 1 up, 2 down
ALIAS = IFX + "18"    # ifAlias: the port's description


def port_admin(c, index):
    v = c.get(f"{ADMIN}.{index}").get(f"{ADMIN}.{index}")
    return {1: "up", 2: "down", 3: "testing"}.get(v, "?")


def set_port(c, index, up):
    """Turns a port on or off and reads it back. Returns the new state ("up" / "down")."""
    c.set(f"{ADMIN}.{index}", 1 if up else 2)
    return port_admin(c, index)


def set_alias(c, index, name):
    """Sets the port's description (ifAlias). Returns the old one, for undo."""
    old = text(c.get(f"{ALIAS}.{index}").get(f"{ALIAS}.{index}"))
    c.set(f"{ALIAS}.{index}", name.encode("utf-8")[:64])
    return old


def port_risk(port_name, macs, my_macs=()):
    """Why turning this port off is dangerous, or "" - checked before the app asks for confirmation."""
    on = [m for m, p in (macs or {}).items() if p == port_name]
    if any(m in on for m in my_macs):
        return "this PC reaches the switch through this port: you would lose the connection to it"
    if len(on) > 4:
        return f"{len(on)} devices are behind this port (another switch, an AP or the router): all of them go offline"
    return ""


# ==========================================================================
# map of all switches (LLDP) and spanning tree
# ==========================================================================
def stp_states(c, ifs=None):
    """{port name: "forwarding" / "blocking" / ...} from BRIDGE-MIB spanning tree, {} when STP is off."""
    names = {i["index"]: i["name"] for i in (ifs or [])}
    try:
        bp_if = {int(k): v for k, v in c.table(BRIDGE_PORT_IF).items() if k.isdigit()}
        st = c.table(STP_PORT_STATE)
    except SnmpError:
        return {}
    out = {}
    for bp, v in st.items():
        if bp.isdigit() and v != 1:  # 1 = disabled (port not in STP)
            ifx = bp_if.get(int(bp), int(bp))
            out[names.get(ifx) or f"port {bp}"] = STP_STATES.get(v, str(v))
    return out


def discover(seed, community="public", version="2c", max_devices=60, timeout=1.5, progress=None, reader=None):
    """Walks from one switch to every switch it can reach through LLDP neighbours that share the community.
    Returns {"devices": {ip: {system, interfaces, neighbors, macs, stp}}, "links": [(ip_a, port_a, ip_or_name_b,
    port_b)], "unreached": {name: ip}, "loops": [[ip, ...]]}."""
    def read(ip):
        c = Snmp(ip, community, version, timeout=timeout)
        info = system_info(c)
        if not any(info[k] for k in ("descr", "name", "object_id")):
            raise SnmpError("no answer")
        ifs = interfaces(c)
        return {"system": info, "interfaces": ifs, "neighbors": lldp_neighbors(c), "macs": mac_table(c, ifs),
                "stp": stp_states(c, ifs)}
    read = reader or read
    devices, todo, unreached, links = {}, [seed], {}, set()
    by_name = {}
    while todo and len(devices) < max_devices:
        ip = todo.pop(0)
        if ip in devices:
            continue
        if progress:
            progress(ip, len(devices))
        try:
            d = read(ip)
        except (SnmpError, OSError):
            continue
        devices[ip] = d
        by_name[d["system"]["name"]] = ip
        for n in d["neighbors"]:
            if n["ip"] and n["ip"] not in devices and n["ip"] not in todo:
                todo.append(n["ip"])
    for ip, d in devices.items():
        for n in d["neighbors"]:
            other = n["ip"] if n["ip"] in devices else by_name.get(n["name"])
            if other:
                if ip < other:  # each cable once: as the switch with the lower address sees it
                    links.add((ip, n["local_port"], other, n["port_descr"] or n["port"]))
            else:
                unreached[n["name"] or n["chassis"]] = n["ip"]
                links.add((ip, n["local_port"], n["name"] or n["chassis"], n["port_descr"] or n["port"]))
    return {"devices": devices, "links": sorted(links), "unreached": unreached,
            "loops": _cycles(devices, links)}


def _cycles(devices, links):
    """Groups of switches joined by more than one path (a ring). Spanning tree must block one link in each,
    otherwise it is a loop."""
    adj = {}
    for a, _, b, _ in links:
        if a in devices and b in devices and a != b:
            adj.setdefault(a, []).append(b)
            adj.setdefault(b, []).append(a)
    rings, seen = [], set()
    for start in adj:
        if start in seen:
            continue
        comp, stack = set(), [start]
        while stack:
            x = stack.pop()
            if x not in comp:
                comp.add(x)
                stack += adj.get(x, [])
        seen |= comp
        edges = sum(len(adj[x]) for x in comp) // 2  # parallel cables count twice
        if edges >= len(comp):  # a tree has exactly n - 1 links
            rings.append(sorted(comp))
    return rings


def ring_blocked(devices, ring):
    """Ports that spanning tree blocks inside a ring; empty means nothing protects it from a loop."""
    return [(ip, port) for ip in ring for port, st in devices[ip].get("stp", {}).items() if st == "blocking"]
