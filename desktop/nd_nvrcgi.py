# -*- coding: utf-8 -*-
"""Read an NVR/DVR's camera channels over its WEB CGI interface (HTTP, port 80) - the path that actually works
on NetSurveillance / Sofia / XMeye recorders whose binary DVRIP API (34567) returns empty/607.

Proven on Rakesh's NVR 192.168.0.74 (24 Nov): its web page reads the channel list via
  POST /cgi-bin/login.cgi      -> a session id
  POST /cgi-bin/getconfig.cgi  -> the per-channel camera config (IP, name, enable)
while every DVRIP config node came back null/[]. So when DVRIP yields nothing, we log in over CGI and read the
digital-channel config the same way the browser does.

Pure/testable: build_* make the request parts; the actual HTTP uses urllib and is injectable (opener=) so tests
never touch the network. channels() returns [{"chan","name","ip","online"}] or [] (never raises on a dead box).
"""
import json
import re
import urllib.request

PORT = 80


def _url(ip, path, port=PORT):
    return "http://%s%s%s" % (ip, "" if port == 80 else ":%d" % port, path)


def build_login(user, pw):
    """NetSurveillance login.cgi body. The device accepts a small JSON with the user and (plain) password; it
    answers with a SessionID used by the following calls."""
    return json.dumps({"EncryptType": "MD5", "LoginType": "Web", "UserName": user, "PassWord": pw}).encode()


def _post(ip, path, body, *, port=PORT, timeout=6, opener=None, headers=None, cookie=None):
    h = {"Content-Type": "application/json", "User-Agent": "NetworkDoctor"}
    if cookie:
        h["Cookie"] = cookie
    if headers:
        h.update(headers)
    req = urllib.request.Request(_url(ip, path, port), data=body, method="POST", headers=h)
    fn = opener or urllib.request.urlopen
    r = fn(req, timeout=timeout)
    raw = r.read()
    try:
        r.close()
    except Exception:  # noqa: BLE001
        pass
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    return raw


def _parse_json(text):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        # some firmwares wrap or append junk; grab the outermost {...}
        m = re.search(r"\{.*\}", text or "", re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except ValueError:
                return None
        return None


def login(ip, user, pw, *, port=PORT, timeout=6, opener=None):
    """Return a session token/cookie dict usable by read_config, or None. Tries the JSON login; the device may
    return a SessionID in the body or set a cookie - we carry whichever we get."""
    try:
        text = _post(ip, "/cgi-bin/login.cgi", build_login(user, pw), port=port, timeout=timeout, opener=opener)
    except Exception:  # noqa: BLE001
        return None
    d = _parse_json(text) or {}
    sid = d.get("SessionID") or d.get("Session") or d.get("sessionID")
    if sid:
        return {"sid": sid}
    return None


def read_config(ip, sess, name, *, port=PORT, timeout=6, opener=None):
    """POST getconfig.cgi for one config Name (e.g. 'NetWork.NetDigital'); returns the parsed dict/list or None."""
    body = json.dumps({"Name": name, "SessionID": sess.get("sid", "")}).encode()
    try:
        text = _post(ip, "/cgi-bin/getconfig.cgi", body, port=port, timeout=timeout, opener=opener,
                     cookie=sess.get("cookie"))
    except Exception:  # noqa: BLE001
        return None
    d = _parse_json(text)
    if not isinstance(d, dict):
        return None
    return d.get(name, d)


# channel-config names the NetSurveillance web UI reads, in the order the browser tries them
_CHANNEL_NAMES = ("NetWork.NetDigital", "NetWork.Digital", "Digital", "DigitalChannel", "Dev")


def _dotted_ip(v):
    """Pull a dotted IPv4 out of a value that may be a dict/str/int (some firmwares store the IP little-endian)."""
    if isinstance(v, str) and re.match(r"\d+\.\d+\.\d+\.\d+$", v.strip()):
        return v.strip()
    if isinstance(v, int) and v:
        return "%d.%d.%d.%d" % (v & 255, (v >> 8) & 255, (v >> 16) & 255, (v >> 24) & 255)
    if isinstance(v, dict):
        for k in ("IPAddress", "HostIP", "DevIP", "IP", "Address"):
            if k in v:
                got = _dotted_ip(v[k])
                if got:
                    return got
    return ""


def _rows_from(block):
    """Turn a channel-config block into [{ip,name,enable}] per channel, however this firmware nests it."""
    rows = []
    if isinstance(block, dict):
        # often {"NetDigitalChannel":[ ... ]} or {"DigitalChannel":[ {"Devices":[{...}]}, ... ]}
        for k in ("NetDigitalChannel", "DigitalChannel", "Channels"):
            if isinstance(block.get(k), list):
                block = block[k]
                break
    if not isinstance(block, list):
        return rows
    for entry in block:
        dev = entry
        if isinstance(entry, dict):
            for k in ("Devices", "DevInfo", "DeviceInfo"):
                v = entry.get(k)
                if isinstance(v, list) and v:
                    dev = v[0]
                    break
                if isinstance(v, dict):
                    dev = v
                    break
        ip = _dotted_ip(dev if isinstance(dev, (dict, str, int)) else "")
        name = ""
        en = None
        if isinstance(dev, dict):
            name = str(dev.get("Name") or dev.get("ChannelName") or entry.get("Name") or "").strip() \
                if isinstance(entry, dict) else str(dev.get("Name") or "").strip()
            e = dev.get("Enable", entry.get("Enable") if isinstance(entry, dict) else None)
            if e is not None:
                en = bool(e)
        rows.append({"ip": ip, "name": name, "enable": en})
    return rows


def channels(ip, user, pw, *, port=PORT, timeout=6, opener=None):
    """Read the recorder's channel list over CGI. Returns [{"chan","name","ip","online"}] (1-based chan) or []."""
    sess = login(ip, user, pw, port=port, timeout=timeout, opener=opener)
    if not sess:
        return []
    for name in _CHANNEL_NAMES:
        block = read_config(ip, sess, name, port=port, timeout=timeout, opener=opener)
        rows = _rows_from(block)
        if any(r["ip"] for r in rows):
            return [{"chan": i + 1, "name": r["name"] or "CAM%d" % (i + 1), "ip": r["ip"],
                     "online": r["enable"]} for i, r in enumerate(rows)]
    return []
