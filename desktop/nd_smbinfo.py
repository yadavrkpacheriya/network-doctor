# -*- coding: utf-8 -*-
"""Name, domain and Windows version of a PC from its file-sharing port (SMB, TCP 445) - no password needed.

The first step of a Windows login (NTLM "challenge") carries the computer name, domain, DNS name and the Windows
build. Windows PCs that do not answer NetBIOS name queries (blocked by their firewall, NetBIOS off) still give it,
which is how scanners such as nmap name them. Nothing is logged in and no password is sent.
"""

import os
import socket
import struct

NTLM_OID = bytes.fromhex("2b06010401823702020a")
SPNEGO_OID = bytes.fromhex("2b0601050502")
BUILDS = [(26200, "Windows 11 25H2"), (26100, "Windows 11 24H2 / Server 2025"), (22631, "Windows 11 23H2"),
          (22621, "Windows 11 22H2"), (22000, "Windows 11 21H2"), (20348, "Windows Server 2022"),
          (19045, "Windows 10 22H2"), (19044, "Windows 10 21H2"), (19043, "Windows 10 21H1"),
          (19042, "Windows 10 20H2"), (19041, "Windows 10 2004"), (18363, "Windows 10 1909"),
          (17763, "Windows 10 1809 / Server 2019"), (14393, "Windows 10 1607 / Server 2016"),
          (10240, "Windows 10 1507"), (9600, "Windows 8.1 / Server 2012 R2"), (9200, "Windows 8 / Server 2012"),
          (7601, "Windows 7 SP1 / Server 2008 R2"), (7600, "Windows 7")]


def windows_name(major, minor, build):
    if major == 10 and minor == 0:
        for b, name in BUILDS:
            if build >= b:
                return f"{name} (build {build})"
    for b, name in BUILDS:
        if build == b:
            return f"{name} (build {build})"
    return f"Windows {major}.{minor} build {build}" if major else ""


def _der(tag, body):
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = b"\x81" + bytes([n])
    else:
        ln = b"\x82" + struct.pack("!H", n)
    return bytes([tag]) + ln + body


def ntlm_negotiate():
    flags = 0xE2088297
    return b"NTLMSSP\x00" + struct.pack("<II", 1, flags) + b"\x00" * 16 + bytes([6, 1]) + struct.pack("<H", 7601) + \
        b"\x00\x00\x00\x0f"


def spnego_init(token):
    mech = _der(0x30, _der(0x06, NTLM_OID))
    inner = _der(0x30, _der(0xA0, mech) + _der(0xA2, _der(0x04, token)))
    return _der(0x60, _der(0x06, SPNEGO_OID) + _der(0xA0, inner))


def _smb2(cmd, msg_id, body, session=0):
    hdr = b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 0, 0, cmd, 31, 0, 0, msg_id, 0, 0, session) + b"\x00" * 16
    pkt = hdr + body
    return struct.pack("!I", len(pkt)) + pkt


def negotiate_request():
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    body = struct.pack("<HHHHI", 36, len(dialects), 1, 0, 0) + os.urandom(16) + struct.pack("<Q", 0)
    body += b"".join(struct.pack("<H", d) for d in dialects)
    return _smb2(0, 0, body)


def session_request(session=0):
    blob = spnego_init(ntlm_negotiate())
    body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 64 + 24, len(blob), 0) + blob
    return _smb2(1, 1, body, session)


def parse_challenge(data):
    """{'name', 'domain', 'dns_name', 'dns_domain', 'forest', 'os'} from any bytes containing an NTLM challenge."""
    i = data.find(b"NTLMSSP\x00\x02\x00\x00\x00")
    if i < 0:
        return None
    c = data[i:]
    try:
        _flags = struct.unpack("<I", c[20:24])[0]
        ti_len, _, ti_off = struct.unpack("<HHI", c[40:48])
        major, minor, build = c[48], c[49], struct.unpack("<H", c[50:52])[0]
        info = c[ti_off:ti_off + ti_len]
    except (struct.error, IndexError):
        return None
    out = {}
    keys = {1: "name", 2: "domain", 3: "dns_name", 4: "dns_domain", 5: "forest"}
    p = 0
    while p + 4 <= len(info):
        av, ln = struct.unpack("<HH", info[p:p + 4])
        p += 4
        if av == 0:
            break
        if av in keys:
            out[keys[av]] = info[p:p + ln].decode("utf-16-le", "replace")
        p += ln
    if build:
        out["os"] = windows_name(major, minor, build)
    return out if out.get("name") else None


def _recv_msg(s):
    hdr = b""
    while len(hdr) < 4:
        b = s.recv(4 - len(hdr))
        if not b:
            raise ConnectionError("closed")
        hdr += b
    n = struct.unpack("!I", hdr)[0] & 0xFFFFFF
    data = b""
    while len(data) < n:
        b = s.recv(min(65536, n - len(data)))
        if not b:
            break
        data += b
    return data


def smb_info(ip, port=445, timeout=2.0):
    """Computer name etc. of a Windows PC / NAS, or None."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(negotiate_request())
            r = _recv_msg(s)
            if not r.startswith(b"\xfeSMB"):
                return None
            s.sendall(session_request())
            return parse_challenge(_recv_msg(s))
    except (OSError, ConnectionError, struct.error):
        return None
