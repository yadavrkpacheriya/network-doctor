# -*- coding: utf-8 -*-
"""
Network Doctor - login sweep: one administrator login (up to three) is tried ONCE on every PC, camera / NVR / DVR,
router and switch of the office network; what each device reports is collected, and the devices whose login was refused
or that gave too little data are listed.

Safety (tested in tests/test_sweep.py):
  * Every login is tried exactly ONE time per device (own digest / basic code - no library retries).
  * Canary + circuit breaker: the first devices of each kind are tried one by one; when a login is refused by the first
    `breaker` devices and accepted by none, the sweep stops using it ("stopped to avoid locking the account").
  * Only private (LAN) addresses are touched. Passwords live in memory for the run only: never saved, never logged.
  * Phones are never logged in to: they are only checked (phone_health) so the IP / block mix-ups cannot repeat.
"""
import base64
import hashlib
import http.client
import ipaddress
import os
import re
import secrets
import socket
import ssl
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

import nd_core as core
import nd_routeros as RO
import nd_tools as T

OK, AUTH, UNREACH, UNSUP, BLOCKED, ERR, SKIP = ("OK", "LOGIN REFUSED", "NOT REACHABLE", "NOT SUPPORTED",
                                                "BLOCKED", "ERROR", "SKIPPED")
KINDS = {"pc": "Windows PCs", "cam": "Cameras / NVR / DVR", "net": "Routers, switches, printers (web / API)"}
EXPECTED = {  # what a sweep of that method should return; missing ones are reported
    "wmi": ("model", "serial", "cpu", "ram_gb", "disk_gb", "os"),
    "dahua": ("model", "serial", "firmware"),
    "hik": ("model", "serial", "firmware"),
    "onvif": ("model", "serial", "firmware"),
    "ros": ("model", "version", "identity"),
    "web": (),
}
METHOD_TITLE = {"wmi": "Windows (WMI)", "dahua": "Dahua web API", "hik": "Hikvision ISAPI", "onvif": "ONVIF",
                "ros": "MikroTik API", "web": "Web login", "xmeye": "XMeye DVR"}
_UNREACH_TEXT = "did not answer"


class Outcome(Exception):
    """Raised by a transport to end the attempt with a status other than OK."""

    def __init__(self, status, detail=""):
        super().__init__(detail)
        self.status, self.detail = status, detail


def is_lan(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private and not a.is_loopback and not a.is_link_local
    except ValueError:
        return False


# --------------------------------------------------------------------------------------------------- who gets what
def methods_for(d):
    """Which login methods fit this device (best first). Phones get none."""
    cat, ports = d.get("category", ""), set(d.get("ports") or [])
    if cat == core.CAT_PHONE:
        return []
    m = []
    if 8728 in ports:
        m.append("ros")
    if cat == core.CAT_CAM or ports & {37777, 34567, 554}:
        if 37777 in ports:
            m.append("dahua")
        if 8000 in ports:
            m.append("hik")
        if 34567 in ports:
            m.append("xmeye")
        if not m or ports & {554, 80, 8080}:
            m += ["onvif", "web"]
    elif cat == core.CAT_PC or ports & {135, 445}:
        m.append("wmi")
    elif ports & {80, 443, 8080, 8443} or cat in (core.CAT_NET, core.CAT_PRN, core.CAT_ROUTER):
        m.append("web")
    return list(dict.fromkeys(m))


def kind_of(method):
    return {"wmi": "pc", "dahua": "cam", "hik": "cam", "onvif": "cam", "xmeye": "cam"}.get(method, "net")


def plan(devices, kinds=("pc", "cam", "net"), gw_ip=""):
    """[{'dev', 'methods'}] for every online LAN device a login can be tried on, in a stable order."""
    out = []
    for d in sorted(core_live(devices), key=lambda x: _ipkey(x.get("ip", ""))):
        if not is_lan(d.get("ip", "")) or d.get("self"):
            continue
        ms = [m for m in methods_for(d) if kind_of(m) in kinds]
        if ms:
            out.append({"dev": d, "methods": ms})
    return out


def core_live(devices):
    return [d for d in devices if d.get("online") and d.get("ip") and d.get("mac")]


def _ipkey(ip):
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999,)


# --------------------------------------------------------------------------------------------------- http (one try)
def _challenge(header):
    kind = header.split(None, 1)[0].lower() if header else ""
    params = dict(re.findall(r'(\w+)="?([^",]*)"?', header or ""))
    return kind, params


def digest_header(method, uri, user, pw, params, cnonce=None, nc="00000001"):
    """RFC 2617 / 7616 digest answer for one request (MD5, qop=auth) - what cameras use."""
    realm, nonce, qop = params.get("realm", ""), params.get("nonce", ""), params.get("qop", "")
    ha1 = hashlib.md5(f"{user}:{realm}:{pw}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    cn = cnonce or secrets.token_hex(8)
    if "auth" in qop:
        resp = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cn}:auth:{ha2}".encode()).hexdigest()
        extra = f', qop=auth, nc={nc}, cnonce="{cn}"'
    else:
        resp = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        extra = ""
    opaque = f', opaque="{params["opaque"]}"' if params.get("opaque") else ""
    return (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{resp}"{extra}{opaque}')


def _conn(ip, port, ssl_on, timeout):
    if ssl_on:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # devices on the LAN use self-signed certificates
        return http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(ip, port, timeout=timeout)


def http_login(ip, port, path, user, pw, ssl_on=False, timeout=6):
    """(status code, body, how). ONE request without a login to learn the method, then ONE request with the login."""
    def once(headers):
        c = _conn(ip, port, ssl_on, timeout)
        try:
            c.request("GET", path, headers=headers)
            r = c.getresponse()
            return r.status, r.read(40000).decode("utf-8", "replace"), r.getheader("WWW-Authenticate") or ""
        finally:
            c.close()
    try:
        code, body, www = once({"User-Agent": "NetworkDoctor", "Connection": "close"})
        if code != 401:
            return code, body, "no login needed"
        kind, params = _challenge(www)
        if kind == "digest":
            auth = digest_header("GET", path, user, pw, params)
        elif kind == "basic":
            auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
        else:
            raise Outcome(UNSUP, "the device asks for a login method this app cannot do")
        code, body, _ = once({"User-Agent": "NetworkDoctor", "Connection": "close", "Authorization": auth})
        return code, body, kind
    except Outcome:
        raise
    except (OSError, http.client.HTTPException) as e:
        raise Outcome(UNREACH, f"{_UNREACH_TEXT} ({e.__class__.__name__})") from None


def _http_port(d, prefer=(80, 8080, 443, 8443)):
    ports = set(d.get("ports") or [])
    for p in prefer:
        if p in ports:
            return p, p in (443, 8443)
    return 80, False


def parse_kv(text):
    """key=value lines (Dahua CGI) -> dict."""
    out = {}
    for ln in (text or "").splitlines():
        k, sep, v = ln.strip().partition("=")
        if sep:
            out[k.strip()] = v.strip()
    return out


def parse_hik(xml_text):
    out = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if el.text and el.text.strip():
            out[tag] = el.text.strip()
    return {"model": out.get("model", ""), "serial": out.get("serialNumber", ""), "firmware": out.get("firmwareVersion", ""),
            "name": out.get("deviceName", ""), "mac": out.get("macAddress", "")}


def onvif_token(user, pw, nonce=None, created=None):
    """WS-Security UsernameToken (password digest) used by ONVIF."""
    raw = nonce if nonce is not None else os.urandom(16)
    created = created or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    digest = base64.b64encode(hashlib.sha1(raw + created.encode() + pw.encode()).digest()).decode()
    return (f"<wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" "
            f"xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
            f"<wsse:UsernameToken><wsse:Username>{_x(user)}</wsse:Username>"
            f"<wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">"
            f"{digest}</wsse:Password><wsse:Nonce>{base64.b64encode(raw).decode()}</wsse:Nonce>"
            f"<wsu:Created>{created}</wsu:Created></wsse:UsernameToken></wsse:Security>")


def _x(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def onvif_envelope(user, pw, nonce=None, created=None):
    return ("<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
            f"<s:Header>{onvif_token(user, pw, nonce, created)}</s:Header><s:Body>"
            "<GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/></s:Body></s:Envelope>")


def parse_onvif(xml_text):
    """(fields, refused). refused is True for a 'not authorized' fault."""
    low = (xml_text or "").lower()
    if "notauthorized" in low or "not authorized" in low or "sender not authorized" in low:
        return {}, True
    out = {}
    try:
        for el in ET.fromstring(xml_text).iter():
            out[el.tag.split("}")[-1]] = (el.text or "").strip()
    except ET.ParseError:
        return {}, False
    return {"vendor": out.get("Manufacturer", ""), "model": out.get("Model", ""), "firmware": out.get("FirmwareVersion", ""),
            "serial": out.get("SerialNumber", "")}, False


# --------------------------------------------------------------------------------------------------- transports
def t_dahua(ip, user, pw, d):
    port, s = _http_port(d)
    code, body, how = http_login(ip, port, "/cgi-bin/magicBox.cgi?action=getSystemInfo", user, pw, s)
    if code == 401:
        raise Outcome(AUTH, "user name or password refused by the Dahua device")
    if code != 200:
        raise Outcome(ERR, f"web API answered {code}")
    kv = parse_kv(body)
    data = {"serial": kv.get("serialNumber", ""), "model": kv.get("deviceType", "") or kv.get("updateSerial", "")}
    code, body, _ = http_login(ip, port, "/cgi-bin/magicBox.cgi?action=getSoftwareVersion", user, pw, s)
    if code == 200:
        data["firmware"] = parse_kv(body).get("version", "")
    if how == "no login needed":
        data["note"] = "answered without a login (open!)"
    return data


def t_hik(ip, user, pw, d):
    port, s = _http_port(d)
    code, body, how = http_login(ip, port, "/ISAPI/System/deviceInfo", user, pw, s)
    if code == 401:
        raise Outcome(AUTH, "user name or password refused by the Hikvision device")
    if code != 200:
        raise Outcome(ERR, f"ISAPI answered {code}")
    data = parse_hik(body)
    if how == "no login needed":
        data["note"] = "answered without a login (open!)"
    return data


def t_onvif(ip, user, pw, d):
    last = None
    for port in [p for p in (80, 8080, 8899, 2020) if p in set(d.get("ports") or []) or not d.get("ports")]:
        c = _conn(ip, port, False, 6)
        try:
            c.request("POST", "/onvif/device_service", body=onvif_envelope(user, pw).encode(),
                      headers={"Content-Type": "application/soap+xml; charset=utf-8", "Connection": "close"})
            r = c.getresponse()
            body = r.read(40000).decode("utf-8", "replace")
        except (OSError, http.client.HTTPException):
            continue
        finally:
            c.close()
        data, refused = parse_onvif(body)
        if refused:
            raise Outcome(AUTH, "user name or password refused (ONVIF)")
        if data.get("model") or data.get("serial"):
            return data
        last = r.status
    raise Outcome(UNSUP if last else UNREACH, "no ONVIF service answered" if last is None else f"ONVIF answered {last} without device data")


def t_web(ip, user, pw, d):
    port, s = _http_port(d)
    code, body, how = http_login(ip, port, "/", user, pw, s)
    if how == "no login needed":
        title = re.search(r"<title>(.*?)</title>", body or "", re.I | re.S)
        raise Outcome(UNSUP, "web page has a login form or none - test the login by hand"
                      + (f" ({title.group(1).strip()[:40]})" if title else ""))
    if code == 401:
        raise Outcome(AUTH, "user name or password refused (web login)")
    if code in (200, 301, 302):
        return {"note": f"web login accepted ({how})"}
    raise Outcome(ERR, f"web page answered {code}")


def t_xmeye(ip, user, pw, d):
    raise Outcome(UNSUP, "XMeye / NetSurveillance DVRs use their own login protocol: test the password in the DVR's web "
                         "page or phone app")


def t_ros(ip, user, pw, d):
    try:
        with RO.RouterOS(ip, user, pw, port=d.get("api_port"), timeout=6) as c:
            res = c.cmd("/system/resource/print")
            ident, ver = c.identity()
            try:
                board = c.cmd("/system/routerboard/print")
            except RO.RosError:
                board = []  # virtual / x86 routers have no routerboard
    except RO.RosError as e:
        msg = str(e)
        if "login refused" in msg:
            raise Outcome(AUTH, "user name or password refused by the router") from None
        raise Outcome(UNREACH, msg[:140]) from None
    except OSError as e:
        raise Outcome(UNREACH, f"{_UNREACH_TEXT} ({e.__class__.__name__})") from None
    r = (res or [{}])[0]
    b = (board or [{}])[0]
    return {"identity": ident or "", "model": r.get("board-name") or b.get("model", ""), "version": r.get("version", "") or ver,
            "serial": b.get("serial-number", ""), "firmware": b.get("current-firmware", ""), "uptime": r.get("uptime", ""),
            "cpu": r.get("cpu", ""), "ram_gb": round(int(r.get("total-memory", 0) or 0) / 2 ** 30, 2)}


def map_wmi_error(err):
    low = (err or "").lower()
    if "wrong user" in low or "access is denied" in low or "not an administrator" in low or "password" in low:
        return AUTH, "user name or password refused (or the user is not an administrator on that PC)"
    if "firewall" in low or "rpc" in low or "unavailable" in low:
        return BLOCKED, "the PC's firewall blocks remote WMI: allow 'Windows Management Instrumentation' or run the PC script once"
    return ERR, (err or "no answer")[:140]


def t_wmi(ip, user, pw, d, runner=None):
    if not core.IS_WIN:
        raise Outcome(UNSUP, "PC details can be read only when Network Doctor runs on Windows")
    env = dict(os.environ, ND_IP=ip, ND_USER=user, ND_PW=pw)
    try:
        r = (runner or subprocess.run)(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "-"],
                                       input=T.remote_inventory_ps(), capture_output=True, text=True, timeout=120, env=env,
                                       creationflags=0x08000000)
        out = r.stdout + "\n" + r.stderr
    except (OSError, subprocess.SubprocessError) as e:
        raise Outcome(ERR, str(e)[:140]) from None
    hw, err = T.parse_remote_inventory(out)
    if not hw:
        raise Outcome(*map_wmi_error(err))
    return {"model": hw.get("model", ""), "maker": hw.get("maker", ""), "serial": hw.get("serial", ""), "cpu": hw.get("cpu", ""),
            "ram_gb": hw.get("ram_gb", ""), "disk_gb": hw.get("disk_gb", ""), "os": hw.get("os_name", ""),
            "hostname": hw.get("hostname", ""), "user": hw.get("logged_on", ""), "hw": hw}


TRANSPORTS = {"wmi": t_wmi, "dahua": t_dahua, "hik": t_hik, "onvif": t_onvif, "ros": t_ros, "web": t_web, "xmeye": t_xmeye}


# --------------------------------------------------------------------------------------------------- the sweep
def missing(method, data):
    return [f for f in EXPECTED.get(method, ()) if data.get(f) in (None, "", 0)]


class Sweep:
    """Runs the plan. Every (device, method, login) is tried once; see the module text for the safety rules."""

    def __init__(self, creds, transports=None, workers=6, breaker=2, force=False, gap=0.1, sleep=time.sleep):
        self.creds = [(u, p) for u, p in creds if u][:3]
        self.tr = transports or TRANSPORTS
        self.workers, self.breaker, self.force, self.gap, self.sleep = workers, max(1, breaker), force, gap, sleep
        self.lock = threading.Lock()
        self.fails, self.oks = {}, {}
        self.stop = threading.Event()
        self.attempts = 0

    def _blocked(self, key):
        with self.lock:
            return (not self.force and self.oks.get(key, 0) == 0 and self.fails.get(key, 0) >= self.breaker)

    def _note(self, key, status):
        with self.lock:
            if status == OK:
                self.oks[key] = self.oks.get(key, 0) + 1
                self.fails[key] = 0
            elif status == AUTH:
                self.fails[key] = self.fails.get(key, 0) + 1

    def one(self, target):
        d = target["dev"]
        ip = d["ip"]
        tried, last, refused = [], None, set()  # refused: logins this device already said no to (never tried again on it)
        for m in target["methods"]:
            fn = self.tr[m]
            for i, (user, pw) in enumerate(self.creds):
                key = (i, m)
                if self.stop.is_set():
                    return self._result(d, m, SKIP, {}, "sweep stopped", tried)
                if i in refused:
                    continue
                if self._blocked(key):
                    last = (m, SKIP, f"login {i + 1} was refused by the first {self.breaker} devices of this kind: not tried "
                                     "here, to avoid locking the account (check the password)")
                    tried.append((i + 1, SKIP))
                    continue
                with self.lock:
                    self.attempts += 1
                try:
                    data = fn(ip, user, pw, d)
                    status, detail = OK, ""
                except Outcome as o:
                    data, status, detail = {}, o.status, o.detail
                except Exception as e:  # noqa: BLE001 - one bad device must not stop the sweep
                    data, status, detail = {}, ERR, f"{e.__class__.__name__}: {str(e)[:100]}"
                tried.append((i + 1, status))
                self._note(key, status)
                self.sleep(self.gap)
                if status == OK:
                    res = self._result(d, m, OK, data, detail, tried)
                    res["login"] = i + 1
                    return res
                if status == AUTH:
                    refused.add(i)
                    last = (m, AUTH, f"login {', '.join(str(n + 1) for n in sorted(refused))} refused: {detail}")
                    continue
                last = (m, status, detail)
                break  # not reachable / unsupported / blocked: another login would not change that
        m, status, detail = last or (target["methods"][0], ERR, "nothing was tried")
        return self._result(d, m, status, {}, detail, tried)

    def _result(self, d, method, status, data, detail, tried):
        miss = missing(method, data) if status == OK else []
        return {"ip": d["ip"], "mac": d.get("mac", ""), "name": d.get("name", ""), "category": d.get("category", ""),
                "method": method, "status": status, "data": data, "detail": detail, "missing": miss, "tried": tried}

    def run(self, targets, on_result=None):
        """Canary phase (the first `breaker` devices of every method, one by one), then the rest in parallel."""
        results, seen, canary, rest = [], {}, [], []
        for t in targets:
            m = t["methods"][0]
            seen[m] = seen.get(m, 0) + 1
            (canary if seen[m] <= self.breaker else rest).append(t)

        def go(t):
            r = self.one(t)
            results.append(r)
            if on_result:
                on_result(r)
        for t in canary:
            go(t)
        with ThreadPoolExecutor(self.workers) as ex:
            list(ex.map(go, rest))
        return results


def summary(results, devices=()):
    c = {}
    for r in results:
        c[r["status"]] = c.get(r["status"], 0) + 1
    return c


def refused(results):
    return [r for r in results if r["status"] == AUTH]


def needs_attention(results):
    """Devices that are not fully read: login refused, blocked, unreachable, unsupported, or data missing."""
    return [r for r in results if r["status"] != OK or r["missing"]]


def csv_text(results):
    rows = [["Name", "IP", "MAC", "Type", "Method", "Result", "Login used", "Model", "Serial", "Firmware / OS", "Missing", "Detail"]]
    for r in results:
        d = r["data"]
        rows.append([r["name"], r["ip"], r["mac"], r["category"], METHOD_TITLE.get(r["method"], r["method"]), r["status"],
                     r.get("login", ""), d.get("model", ""), d.get("serial", ""), d.get("firmware") or d.get("os") or d.get("version", ""),
                     ", ".join(r["missing"]), r["detail"] or d.get("note", "")])
    import csv
    import io
    b = io.StringIO()
    csv.writer(b).writerows(rows)
    return b.getvalue()


# --------------------------------------------------------------------------------------------------- phones
def is_phone(d):
    return d.get("category") == core.CAT_PHONE or bool(re.search(core.PHONE_NAMES, (d.get("name") or "").lower()))


def phone_health(devices, tags=None, filter_rows=None, lease_rows=None, gw_ip="", ranges=None, ip_type_of=None):
    """Findings about phones that cause trouble: a phone sitting on an IP another device owns or on an infrastructure IP,
    a phone with a hand-typed IP, a phone a rule of the app still blocks, a camera / recorder mistaken for a phone, and
    phones the router knows but the scan missed. Each finding: {'level', 'ip', 'mac', 'name', 'text', 'fix'}."""
    tags = tags or {}
    live = core_live(devices)
    nm = lambda d: (tags.get(d["mac"], {}).get("name") or d.get("name") or d["mac"])  # noqa: E731
    by_ip = {}
    for d in live:
        by_ip.setdefault(d["ip"], []).append(d)
    infra = []
    for key in ("infra", "nvr", "cam"):
        lo_hi = (ranges or {}).get(key)
        if lo_hi:
            infra.append((key, _ipkey(lo_hi[0]), _ipkey(lo_hi[1])))
    owner = {}
    for r in lease_rows or []:
        if str(r.get("dynamic", "true")).lower() == "false" and r.get("address") and r.get("mac-address"):
            owner[r["address"]] = r["mac-address"].upper()
    out = []
    phones = [d for d in live if is_phone(d)]
    for d in phones:
        base = {"ip": d["ip"], "mac": d["mac"], "name": nm(d)}
        if len({x["mac"] for x in by_ip.get(d["ip"], [])}) > 1:
            others = ", ".join(nm(x) for x in by_ip[d["ip"]] if x["mac"] != d["mac"])
            out.append(dict(base, level="critical", text=f"shares {d['ip']} with {others}",
                            fix="Devices > Login sweep > Phones, or Bandwidth plan > 3 Fixed IPs > Change IP of selected"))
        if d["ip"] == gw_ip or owner.get(d["ip"], d["mac"]).upper() != d["mac"].upper():
            out.append(dict(base, level="critical", text=f"is on {d['ip']}, which is reserved for another device or the router",
                            fix="move the phone: Fixed IPs > Change IP of selected (phones belong in the mobile block)"))
        for key, lo, hi in infra:
            if lo <= _ipkey(d["ip"]) <= hi:
                out.append(dict(base, level="warning", text=f"is inside the {key} IP block ({d['ip']})",
                                fix="phones belong in the mobile block; reserve a mobile IP for it"))
                break
        if ip_type_of and ip_type_of(d) in ("Static", "Likely static"):
            out.append(dict(base, level="warning", text="has an IP typed by hand", fix="set the phone's Wi-Fi to DHCP (automatic)"))
        ports = set(d.get("ports") or [])
        if ports & {37777, 34567, 554, 8000}:
            out.append(dict(base, level="warning", text="has recorder / camera ports open: it may be a camera or DVR, not a phone",
                            fix="right-click > Set label, or Bandwidth plan > 1 Groups: set its group"))
        for r in filter_rows or []:
            cm = str(r.get("comment", ""))
            if re.match(r"^(ND-rel: )?ND (phone block|isolate|block) ", cm) and (d["mac"].upper() in cm.upper()) \
                    and str(r.get("disabled", "false")).lower() != "true":
                out.append(dict(base, level="critical", text=f"an app rule blocks it ({cm})",
                                fix="Bandwidth plan > 4 > Release auto-defense blocks, or 5. Reset"))
    known = {d["mac"].upper() for d in live}
    for r in lease_rows or []:
        mac = str(r.get("mac-address", "")).upper()
        host = str(r.get("host-name", ""))
        if mac and mac not in known and str(r.get("status", "")).lower() == "bound" and (
                re.search(core.PHONE_NAMES, host.lower()) or (int(mac[:2], 16) & 2 if re.match(r"^[0-9A-F]{2}", mac) else False)):
            out.append({"ip": r.get("address", ""), "mac": mac, "name": host or mac, "level": "info",
                        "text": "the router has this phone but the scan did not see it", "fix": "press Scan again, or scan with 'Deep packet tests'"})
    return out
