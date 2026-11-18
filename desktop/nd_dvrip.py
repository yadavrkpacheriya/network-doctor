# -*- coding: utf-8 -*-
"""
Network Doctor - XMeye / NetSurveillance (Xiongmai) cameras and recorders: their own "DVRIP" protocol on TCP
port 34567. Just enough of it for the Login sweep (does the login work, model / serial / name) and for "Line
up cameras" (switch a camera to automatic IP, give a recorder channel a camera's new IP).

A message is a 20-byte header (0xFF, version, session, sequence, message id, length) followed by JSON text
ending in "\\n\\0". Every request is answered by ONE reply; "Ret": 100 means done.
"""
import hashlib
import json
import re
import socket
import string
import struct

PORT = 34567
LOGIN, INFO, CONFIG_SET, CONFIG_GET, TITLES, MACHINE = 1000, 1020, 1040, 1042, 1048, 1450
OK = (100, 515)
NEEDS_RESTART = (603,)
REFUSED = {203: "password refused", 205: "user name refused", 206: "account locked by the device",
           207: "this PC is on the device's blacklist", 204: "login refused"}
_HEAD = "<BB2xII2xHI"
_CHARS = string.digits + string.ascii_uppercase + string.ascii_lowercase


class DvrError(Exception):
    def __init__(self, text, refused=False):
        super().__init__(text)
        self.refused = refused


def sofia_hash(password):
    """The 8-character password form these devices expect (from the MD5 of the password)."""
    md5 = hashlib.md5((password or "").encode("utf-8")).digest()
    return "".join(_CHARS[(a + b) % 62] for a, b in zip(md5[::2], md5[1::2]))


def pack(session, seq, msg, data):
    body = json.dumps(data, separators=(",", ":")).encode("utf-8") + b"\x0a\x00"
    return struct.pack(_HEAD, 0xFF, 0, session, seq, msg, len(body)) + body


def unpack_head(head):
    """(session, sequence, message id, body length) from the 20 header bytes."""
    if len(head) != 20 or head[0] != 0xFF:
        raise DvrError("the device did not answer in the XMeye protocol")
    _ff, _ver, session, seq, msg, size = struct.unpack(_HEAD, head)
    return session, seq, msg, size


def ip_to_hex(ip):
    """'192.168.0.64' -> '0x4000A8C0' (how these devices write addresses in their own settings)."""
    a, b, c, d = (int(x) for x in ip.split("."))
    return "0x%02X%02X%02X%02X" % (d, c, b, a)


def hex_to_ip(text):
    v = int(text, 16)
    return ".".join(str((v >> s) & 0xFF) for s in (0, 8, 16, 24))


class DvrIp:
    def __init__(self, ip, port=PORT, timeout=6, connect=socket.create_connection):
        self.ip, self.port, self.timeout, self._connect = ip, port, timeout, connect
        self.sock, self.session, self.seq = None, 0, 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = None

    def _read(self, n):
        buf = b""
        while len(buf) < n:
            part = self.sock.recv(n - len(buf))
            if not part:
                raise DvrError("the device closed the connection")
            buf += part
        return buf

    def call(self, msg, data):
        """Sends one message, returns the reply as a dict."""
        if self.sock is None:
            self.sock = self._connect((self.ip, self.port), self.timeout)
            self.sock.settimeout(self.timeout)
        self.sock.sendall(pack(self.session, self.seq, msg, data))
        self.seq += 1
        _s, _q, _m, size = unpack_head(self._read(20))
        if size > 4_000_000:
            raise DvrError("the device sent an answer that is too large")
        body = self._read(size).rstrip(b"\x00\x0a \r")
        try:
            return json.loads(body.decode("utf-8", "replace") or "{}")
        except ValueError:
            raise DvrError("the device's answer could not be read") from None

    def login(self, user, pw):
        r = self.call(LOGIN, {"EncryptType": "MD5", "LoginType": "DVRIP-Web", "PassWord": sofia_hash(pw),
                              "UserName": user})
        ret = r.get("Ret")
        if ret not in OK:
            raise DvrError(REFUSED.get(ret, f"login not accepted (code {ret})"), refused=ret in REFUSED)
        try:
            self.session = int(str(r.get("SessionID", "0")), 16)
        except ValueError:
            self.session = 0
        return r

    def _sid(self):
        return "0x%08X" % self.session

    def get(self, name, msg=CONFIG_GET):
        r = self.call(msg, {"Name": name, "SessionID": self._sid()})
        if r.get("Ret") not in OK:
            raise DvrError(f"the device did not give '{name}' (code {r.get('Ret')})")
        return r.get(name)

    def set(self, name, value):
        """Writes one settings block. Returns True when the device says it must restart to use it."""
        r = self.call(CONFIG_SET, {"Name": name, name: value, "SessionID": self._sid()})
        ret = r.get("Ret")
        if ret in NEEDS_RESTART:
            return True
        if ret not in OK:
            raise DvrError(f"the device did not accept the change to '{name}' (code {ret})")
        return False

    def reboot(self):
        try:
            self.call(MACHINE, {"Name": "OPMachine", "OPMachine": {"Action": "Reboot"}, "SessionID": self._sid()})
        except (OSError, DvrError):
            pass  # it drops the connection while restarting


def reboot(ip, user, pw, port=PORT, timeout=6, connect=socket.create_connection):
    """Log in and restart one camera/DVR (DVRIP / XMeye). Returns a short note. The device drops the connection
    as it restarts - that is the expected, successful outcome, not an error."""
    with DvrIp(ip, port, timeout, connect) as c:
        c.login(user, pw)
        c.reboot()
        return "restarting"


def read_info(ip, user, pw, port=PORT, timeout=6, connect=socket.create_connection):
    """Login + what the device says about itself: {"serial","model","firmware","name"} (missing parts are '')."""
    with DvrIp(ip, port, timeout, connect) as c:
        c.login(user, pw)
        out = {"serial": "", "model": "", "firmware": "", "name": ""}
        try:
            info = c.get("SystemInfo", INFO) or {}
            out.update(serial=str(info.get("SerialNo", "")), model=str(info.get("HardWare", "")),
                       firmware=str(info.get("SoftWareVersion", "")))
        except DvrError:
            pass
        try:
            titles = c.get("ChannelTitle", TITLES) or []
            if isinstance(titles, list) and len(titles) == 1:      # a camera has one channel: that is its name
                out["name"] = str(titles[0]).strip()
        except DvrError:
            pass
        if not out["name"]:
            try:
                out["name"] = str((c.get("NetWork.NetCommon") or {}).get("HostName", "")).strip()
            except DvrError:
                pass
        return out


def _ip_in(node):
    """Find an IPv4 address anywhere inside a nested digital-channel config entry (field names vary by
    firmware: DevIP / HostIP / IPAddress / Address ...). Returns '' if none."""
    if isinstance(node, str):
        return node if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", node) and node != "0.0.0.0" else ""
    if isinstance(node, dict):
        for v in node.values():
            got = _ip_in(v)
            if got:
                return got
    elif isinstance(node, list):
        for v in node:
            got = _ip_in(v)
            if got:
                return got
    return ""


def disable_channel(ip, user, pw, chan_index, port=PORT, timeout=6, connect=socket.create_connection):
    """Turn OFF one digital channel on a recorder (the reversible way to remove a duplicate - the channel's
    slot stays, it just stops pulling that camera). chan_index is 0-based. Returns True if it wrote the change.
    Best-effort: the config layout varies by firmware, so it finds the channel list, clears its Enable, and
    writes it back; raises DvrError if it can't read/find the channel."""
    with DvrIp(ip, port, timeout, connect) as c:
        c.login(user, pw)
        for node in ("Digital", "NetWork.Digital", "OPDigitalChannel", "DigitalChannel", "NetWork.NetDigital"):
            try:
                dig = c.get(node)
            except DvrError:
                continue
            arr = _channel_list(dig)
            if not arr or chan_index >= len(arr):
                continue
            entry = arr[chan_index]
            if not _set_enable_off(entry):
                continue
            c.set(node, dig)
            return True
        raise DvrError("could not find a changeable channel %d on this recorder" % (chan_index + 1))


def _set_enable_off(node):
    """Set the first Enable-like flag found inside a channel entry to 0/False. Returns True if one was set."""
    if isinstance(node, dict):
        for k in list(node.keys()):
            if k in ("Enable", "enable"):
                node[k] = False
                return True
        for v in node.values():
            if _set_enable_off(v):
                return True
    elif isinstance(node, list):
        for v in node:
            if _set_enable_off(v):
                return True
    return False


def _channel_list(node):
    """Find the per-channel list inside a digital-channel config, however it's wrapped: the node may be the
    list itself, or a dict holding the list under some key (DigitalChannel / Channels / ...). Returns [] if none."""
    if isinstance(node, list):
        return node
    if isinstance(node, dict):
        for v in node.values():                           # a dict wrapping the list, e.g. {"DigitalChannel":[...]}
            if isinstance(v, list) and v:
                return v
        for v in node.values():                           # one level deeper
            got = _channel_list(v)
            if got:
                return got
    return []


def _find_key(node, keys):
    """First value for any of `keys` found anywhere inside a nested entry, else None."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in keys:
                return v
        for v in node.values():
            got = _find_key(v, keys)
            if got is not None:
                return got
    elif isinstance(node, list):
        for v in node:
            got = _find_key(v, keys)
            if got is not None:
                return got
    return None


def list_channels(ip, user, pw, port=PORT, timeout=6, connect=socket.create_connection):
    """List the channels configured on a recorder (NVR/DVR) - i.e. the cameras already added to it. Returns a
    list of {"chan": 1-based, "name": str, "ip": str, "online": bool|None}. The channel names come straight
    from the recorder (reliable); the per-channel camera IP and online flag are best-effort (the config layout
    differs by firmware), so they can be blank/None on some models."""
    with DvrIp(ip, port, timeout, connect) as c:
        c.login(user, pw)
        names = []
        try:
            t = c.get("ChannelTitle", TITLES) or []
            if isinstance(t, list):
                names = [str(x).strip() for x in t]
        except DvrError:
            pass
        ips, online = {}, {}
        for node in ("Digital", "NetWork.Digital", "OPDigitalChannel", "DigitalChannel", "NetWork.NetDigital"):
            try:
                dig = c.get(node)
            except DvrError:
                continue
            arr = _channel_list(dig)                       # a list of per-channel entries, however it's nested
            if arr:
                for i, entry in enumerate(arr):
                    got = _ip_in(entry)
                    if got:
                        ips[i] = got
                    en = _find_key(entry, ("Enable", "enable"))
                    if en is not None:
                        online[i] = bool(en)
                if ips:
                    break
        try:
            st = c.get("OnlineDigitalChannel")
            if isinstance(st, list):
                for i, e in enumerate(st):
                    if isinstance(e, dict):
                        online[i] = bool(e.get("Online", e.get("Status", online.get(i))))
        except DvrError:
            pass
        out = []
        for i in range(max(len(names), len(ips))):
            nm = names[i].strip() if i < len(names) and names[i] else "CAM%d" % (i + 1)
            out.append({"chan": i + 1, "name": nm, "ip": ips.get(i, ""), "online": online.get(i)})
        return out


def set_dhcp(ip, user, pw, port=PORT, timeout=6, connect=socket.create_connection):
    """Switches the device's wired interface to automatic IP (DHCP). Returns a note for the person."""
    with DvrIp(ip, port, timeout, connect) as c:
        c.login(user, pw)
        cfg = c.get("NetWork.NetDHCP")
        if not isinstance(cfg, list) or not cfg:
            raise DvrError("the device has no automatic-IP setting this app can read")
        eth = next((x for x in cfg if isinstance(x, dict) and str(x.get("Interface", "")).lower() == "eth0"), None)
        if eth is None:
            eth = next((x for x in cfg if isinstance(x, dict)), None)
        if eth is None:
            raise DvrError("the device has no automatic-IP setting this app can read")
        if eth.get("Enable") is True:
            return "already on automatic (DHCP)"
        eth["Enable"] = True
        restart = c.set("NetWork.NetDHCP", cfg)
        if restart:
            c.reboot()
            return "switched to automatic (DHCP); the camera is restarting"
        return "switched to automatic (DHCP)"


def set_static_ip(ip, user, pw, new_ip, mask="255.255.255.0", gw="", port=PORT, timeout=6,
                  connect=socket.create_connection):
    """Give the camera a fixed IP directly from the app (no browser): turn DHCP off and write the address,
    mask and gateway in the device's own format. Returns a note for the person."""
    for v in (new_ip, mask) + ((gw,) if gw else ()):
        a = str(v).split(".")
        if len(a) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in a):
            raise DvrError("'%s' is not a valid address" % v)
    with DvrIp(ip, port, timeout, connect) as c:
        c.login(user, pw)
        dhcp = c.get("NetWork.NetDHCP")                      # turn automatic IP off first, or it overrides us
        if isinstance(dhcp, list) and dhcp:
            for x in dhcp:
                if isinstance(x, dict):
                    x["Enable"] = False
            c.set("NetWork.NetDHCP", dhcp)
        common = c.get("NetWork.NetCommon")
        if not isinstance(common, dict):
            raise DvrError("cannot read the camera's network settings")

        def fmt(cur, val):   # match whatever format the camera already uses (hex 0x.. or dotted)
            return ip_to_hex(val) if isinstance(cur, str) and cur.lower().startswith("0x") else val
        common["HostIP"] = fmt(common.get("HostIP"), new_ip)
        if "Submask" in common or "SubMask" in common:
            key = "Submask" if "Submask" in common else "SubMask"
            common[key] = fmt(common.get(key), mask)
        if gw and ("GateWay" in common or "Gateway" in common):
            key = "GateWay" if "GateWay" in common else "Gateway"
            common[key] = fmt(common.get(key), gw)
        restart = c.set("NetWork.NetCommon", common)
        if restart:
            c.reboot()
            return "set fixed IP %s; the camera is restarting (reconnect to it at the new address)" % new_ip
        return "set fixed IP %s" % new_ip


_MAC_FIELD_NAMES = ("mac", "macaddress", "physicaladdress", "hostmac", "ethernetaddress")


def _norm_mac(m):
    """'a0-00-00-01-7f-f0' / 'a00000017ff0' -> 'A0:00:00:01:7F:F0'. Raises on anything not 6 bytes."""
    hexd = re.sub(r"[^0-9A-Fa-f]", "", str(m or ""))
    if len(hexd) != 12:
        raise DvrError("'%s' is not a valid MAC address" % m)
    return ":".join(hexd[i:i + 2].upper() for i in range(0, 12, 2))


def set_mac(ip, user, pw, new_mac, port=PORT, timeout=6, connect=socket.create_connection):
    """Best-effort: give a camera a unique MAC where its firmware exposes a writable MAC field (many cheap
    A0:00:00 cameras do NOT - their MAC is fixed in firmware). Returns a dict:
    {"ok": bool, "note": str, "old": ..., "new": ...}. Never flashes firmware; only writes the network config.
    On cameras without a MAC setting it changes nothing and says so, so a unique fixed IP is the real fix."""
    nm = _norm_mac(new_mac)
    with DvrIp(ip, port, timeout, connect) as c:
        c.login(user, pw)
        common = c.get("NetWork.NetCommon")
        if not isinstance(common, dict):
            raise DvrError("cannot read the camera's network settings")
        key = next((k for k in common if k.lower() in _MAC_FIELD_NAMES), "")
        if not key:
            return {"ok": False, "old": "", "new": nm,
                    "note": "this camera has no changeable MAC setting - its MAC is fixed in firmware, so a "
                            "unique fixed IP is the permanent fix (already set above)."}
        old = common[key]
        # keep the camera's own separator style (colon / dash / none)
        if isinstance(old, str) and "-" in old:
            common[key] = nm.replace(":", "-")
        elif isinstance(old, str) and ":" not in old and "-" not in old:
            common[key] = nm.replace(":", "")
        else:
            common[key] = nm
        restart = c.set("NetWork.NetCommon", common)
        if restart:
            c.reboot()
        return {"ok": True, "old": old, "new": nm,
                "note": "sent unique MAC %s%s - re-scan to confirm the camera took it (some models ignore it)"
                        % (nm, "; camera is restarting" if restart else "")}


def _replace_ip(node, old, new, hits):
    """Walks a settings tree; an "IPAddress" equal to `old` (dotted or 0x form) becomes `new` in the same form."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "IPAddress" and isinstance(v, str):
                if v == old:
                    node[k] = new
                    hits.append(k)
                elif v.lower() == ip_to_hex(old).lower():
                    node[k] = ip_to_hex(new)
                    hits.append(k)
            else:
                _replace_ip(v, old, new, hits)
    elif isinstance(node, list):
        for v in node:
            _replace_ip(v, old, new, hits)


def recorder_update(ip, user, pw, old, new, port=PORT, timeout=6, connect=socket.create_connection):
    """XMeye recorder: the one remote-camera entry that points at `old` is pointed at `new`.
    Returns (changed, note). Nothing is written unless exactly one entry matches."""
    with DvrIp(ip, port, timeout, connect) as c:
        c.login(user, pw)
        name = "NetWork.RemoteDeviceV3"
        cfg = c.get(name)
        hits = []
        _replace_ip(cfg, old, new, hits)
        if not hits:
            return False, f"no channel on this recorder uses {old}"
        if len(hits) > 1:
            raise DvrError(f"{len(hits)} channels use {old} - not changed, set it by hand")
        c.set(name, cfg)
        return True, f"recorder entry now uses {new}"
