# -*- coding: utf-8 -*-
"""
Network Doctor - "line up the cameras": every camera gets one fixed IP in the camera block (for example
192.168.0.71 - .150), in order, so a camera that stops answering is found at a glance.

How a camera is moved (one camera at a time, never several at once):
  1. the router reserves the new IP for the camera's MAC (a DHCP reservation - the same one "IP-MAC binding"
     makes; it has an Undo);
  2. the camera itself is switched from a hand-typed IP to "automatic (DHCP)" through its own web API
     (ONVIF, Hikvision ISAPI, Dahua configManager, XMeye port 34567) with the login from the Login sweep;
  3. the app waits until the camera answers on the new IP. If it does not, the run STOPS there - no other
     camera is touched - and the result says where that camera can be found.

The NVR / DVR stores each camera's IP. For Hikvision, Dahua and XMeye recorders that accepted a login in the sweep,
the channel that pointed at the old IP is given the new one right after the camera has moved (and the app
checks that the channel comes back online). For other recorders it must be typed by hand - the old -> new list
is made for that. Either way the first run moves ONE camera only.

Pure logic + the two small device calls; the window is in nd_sweeptab.py. Device calls go through `send`
(nd_sweep.http_request) so they can be tested without a camera.
"""
import re
import time

import nd_bandwidth as B
import nd_sweep as S

MOVABLE = ("hik", "dahua", "xmeye", "onvif")   # how the camera's "use DHCP" switch can be reached
RECORDER_KINDS = ("hik", "dahua", "xmeye")      # recorders whose channel list this app can change
HIK_IP_PATH = "/ISAPI/System/Network/interfaces/1/ipAddress"


class CamError(Exception):
    pass


# ------------------------------------------------------------------------------------------------ the plan
def candidates(results):
    """{mac: sweep result} for cameras / recorders that accepted a login with a brand we can switch."""
    return {r["mac"]: r for r in results
            if r.get("status") == S.OK and r.get("method") in MOVABLE and r.get("mac") and r.get("login")}


def line_plan(devices, gw_ip, net, ranges, results, tags=None, over=None):
    """One row per camera / recorder on the network, in IP order:
    {"dev","group","ip_now","ip_new","action","why","method","login"}
    action: "keep" (already in its block, or a recorder), "move" (will be moved), "manual" (by hand: brand not
    supported or no working login), "skip" (conflict etc. - the reason is in "why")."""
    rows = B.ip_plan(devices, gw_ip, ranges, {"cam"}, tags, over, None, net)
    can = candidates(results)
    out = []
    for r in rows:
        if r["group"] not in ("cam", "nvr"):
            continue
        res = can.get(r["dev"]["mac"])
        row = dict(r, method=(res or {}).get("method", ""), login=(res or {}).get("login", 0))
        if row["group"] == "nvr" and row["action"] == "keep" and not B._in_range(r["ip_now"], ranges.get("nvr")):
            row["why"] = ("recorder: never moved automatically (port forwards and the viewing apps point at its "
                          "IP) - change it by hand if you want it in the block")
        if row["action"] == "move" and not res:
            row["action"] = "manual"
            row["why"] = ("no working login for this device in the last Login sweep, or a brand this app cannot "
                          "switch: type the new IP on the device by hand")
        elif row["action"] == "move":
            row["why"] = "router reserves the new IP, then the camera is switched to automatic (DHCP)"
        out.append(row)
    return out


def old_new_csv(rows, tags=None):
    """The list to keep: what to type on the NVR / DVR for every moved camera."""
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Name", "MAC", "IP before", "IP now (use this on the NVR / DVR)", "Brand", "Result"])
    for r in rows:
        d = r["dev"]
        t = (tags or {}).get(d["mac"], {})
        w.writerow([t.get("name") or d.get("name") or "", d["mac"], r["ip_now"], r["ip_new"],
                    BRAND.get(r.get("method"), ""), r.get("result", r["action"])])
    return buf.getvalue()


# ------------------------------------------------------------------------------------------- device switches
def hik_set_dhcp(ip, port, ssl_on, user, pw, send=None):
    """Hikvision: read the IP settings, change only 'static' to 'dynamic', write them back. Returns a note."""
    send = send or S.http_request
    code, body, _ = send(ip, port, "GET", HIK_IP_PATH, user, pw, ssl_on=ssl_on)
    if code == 401:
        raise CamError("the camera refused the login")
    if code != 200 or "<addressingType>" not in body:
        raise CamError(f"could not read the camera's IP settings (answer {code})")
    if re.search(r"<addressingType>\s*dynamic\s*</addressingType>", body, re.I):
        return "already on automatic (DHCP)"
    new = re.sub(r"<addressingType>[^<]*</addressingType>", "<addressingType>dynamic</addressingType>", body, count=1)
    code, ans, _ = send(ip, port, "PUT", HIK_IP_PATH, user, pw, body=new, ssl_on=ssl_on,
                        ctype="application/xml")
    if code not in (200, 201):
        raise CamError(f"the camera did not accept the change (answer {code})")
    if re.search(r"reboot\s*required", ans, re.I):
        try:
            send(ip, port, "PUT", "/ISAPI/System/reboot", user, pw, body="", ssl_on=ssl_on)
        except Exception:
            pass  # it drops the connection while restarting - that is the expected answer
        return "switched to automatic (DHCP); the camera is restarting"
    return "switched to automatic (DHCP)"


def dahua_set_dhcp(ip, port, ssl_on, user, pw, send=None):
    """Dahua: turn on DHCP for the camera's default network interface. Returns a note."""
    send = send or S.http_request
    base = "/cgi-bin/configManager.cgi?action="
    code, body, _ = send(ip, port, "GET", base + "getConfig&name=Network", user, pw, ssl_on=ssl_on)
    if code == 401:
        raise CamError("the camera refused the login")
    if code != 200:
        raise CamError(f"could not read the camera's IP settings (answer {code})")
    kv = S.parse_kv(body)
    iface = kv.get("table.Network.DefaultInterface") or "eth0"
    if str(kv.get(f"table.Network.{iface}.DhcpEnable", "")).lower() == "true":
        return "already on automatic (DHCP)"
    code, ans, _ = send(ip, port, "GET", base + f"setConfig&Network.{iface}.DhcpEnable=true", user, pw, ssl_on=ssl_on)
    if code != 200 or "ok" not in ans.lower():
        raise CamError(f"the camera did not accept the change (answer {code})")
    return "switched to automatic (DHCP)"


def xmeye_set_dhcp(ip, port, ssl_on, user, pw, send=None):
    """XMeye / NetSurveillance: its own protocol on port 34567 (the web port and `send` are not used)."""
    import nd_dvrip as DV
    try:
        return DV.set_dhcp(ip, user, pw)
    except DV.DvrError as e:
        raise CamError("the camera refused the login" if e.refused else str(e)) from None
    except OSError as e:
        raise CamError(f"the camera did not answer on port {DV.PORT} ({e.__class__.__name__})") from None


_TDS = 'xmlns="http://www.onvif.org/ver10/device/wsdl"'


def _onvif_fault(text):
    low = (text or "").lower()
    if "notauthorized" in low or "not authorized" in low:
        return "the camera refused the login"
    if "<" in low and "fault" in low:
        m = re.search(r"<[^>]*text[^>]*>([^<]+)<", text, re.I)
        return "the camera answered with an error" + (f": {m.group(1).strip()[:80]}" if m else "")
    return ""


def onvif_set_dhcp(ip, port, ssl_on, user, pw, send=None, call=None):
    """Any ONVIF camera: read its network interface, turn on DHCP for IPv4, restart it only if it asks.
    `call(ip, port, user, pw, body)` -> (status, text) is nd_sweep.onvif_call."""
    call = call or S.onvif_call
    ports = list(dict.fromkeys([port] + list(S.ONVIF_PORTS)))
    found = None
    for p in ports:
        try:
            st, text = call(ip, p, user, pw, f"<GetNetworkInterfaces {_TDS}/>")
        except OSError:
            continue
        err = _onvif_fault(text)
        if err:
            raise CamError(err)
        m = re.search(r"<[^>]*NetworkInterfaces[^>]*\btoken=\"([^\"]+)\"", text)
        if m:
            found = (p, m.group(1), text)
            break
    if not found:
        raise CamError("the camera's ONVIF service did not give its network settings")
    p, token, text = found
    v4 = re.search(r"<[^>]*IPv4\b.*?</[^>]*IPv4>", text, re.S)
    if v4 and re.search(r"<[^>]*DHCP>\s*true\s*<", v4.group(0), re.I):
        return "already on automatic (DHCP)"
    body = (f"<SetNetworkInterfaces {_TDS}><InterfaceToken>{S._x(token)}</InterfaceToken><NetworkInterface>"
            '<IPv4 xmlns="http://www.onvif.org/ver10/schema"><Enabled>true</Enabled><DHCP>true</DHCP></IPv4>'
            "</NetworkInterface></SetNetworkInterfaces>")
    try:
        st, ans = call(ip, p, user, pw, body)
    except OSError:
        # many cameras apply the change at once and drop the connection before answering
        return "switched to automatic (DHCP) - the camera dropped the connection while changing"
    err = _onvif_fault(ans)
    if err or st >= 400:
        raise CamError(err or f"the camera did not accept the change (answer {st})")
    if re.search(r"RebootNeeded>\s*true\s*<", ans, re.I):
        try:
            call(ip, p, user, pw, f"<SystemReboot {_TDS}/>")
        except OSError:
            pass
        return "switched to automatic (DHCP); the camera is restarting"
    return "switched to automatic (DHCP)"


SETTERS = {"hik": hik_set_dhcp, "dahua": dahua_set_dhcp, "xmeye": xmeye_set_dhcp, "onvif": onvif_set_dhcp}
BRAND = {"hik": "Hikvision", "dahua": "Dahua", "xmeye": "XMeye", "onvif": "ONVIF"}


# ------------------------------------------------------------------------------------ recorder (NVR / DVR)
HIK_CH = "/ISAPI/ContentMgmt/InputProxy/channels"


def recorders(rows):
    """Recorders from the plan that accepted a login with a brand whose channel list this app can change."""
    return [r for r in rows if r["group"] == "nvr" and r.get("method") in RECORDER_KINDS and r.get("login")]


def hik_channels(xml_text):
    """[(channel id, IP, whole <InputProxyChannel> block)] from a Hikvision recorder's channel list."""
    out = []
    for block in re.findall(r"<InputProxyChannel\b.*?</InputProxyChannel>", xml_text or "", re.S):
        cid = re.search(r"<id>\s*(\d+)\s*</id>", block)
        ip = re.search(r"<ipAddress>\s*([\d.]+)\s*</ipAddress>", block)
        if cid and ip:
            out.append((cid.group(1), ip.group(1), block))
    return out


def hik_nvr_update(nvr_ip, port, ssl_on, user, pw, old, new, cam_cred=None, send=None):
    """Hikvision recorder: the channel that points at `old` is pointed at `new`. Only the IP is changed; the
    camera's login is written again only when the channel uses the same user name as the login that just
    worked on the camera (a recorder never shows the stored password). Returns (channel id or "", note)."""
    send = send or S.http_request
    code, body, _ = send(nvr_ip, port, "GET", HIK_CH, user, pw, ssl_on=ssl_on)
    if code == 401:
        raise CamError("the recorder refused the login")
    if code != 200:
        raise CamError(f"could not read the recorder's camera list (answer {code})")
    hit = [c for c in hik_channels(body) if c[1] == old]
    if not hit:
        return "", f"no channel on this recorder uses {old}"
    if len(hit) > 1:
        raise CamError(f"{len(hit)} channels use {old} - not changed, set it by hand")
    cid, _ip, block = hit[0]
    new_block = re.sub(r"<ipAddress>[^<]*</ipAddress>", f"<ipAddress>{new}</ipAddress>", block, count=1)
    m = re.search(r"<userName>([^<]*)</userName>", new_block)
    if cam_cred and m and m.group(1) == cam_cred[0] and "<password>" not in new_block:
        from xml.sax.saxutils import escape
        new_block = new_block.replace(m.group(0), m.group(0) + f"<password>{escape(cam_cred[1])}</password>", 1)
    code, _ans, _ = send(nvr_ip, port, "PUT", f"{HIK_CH}/{cid}", user, pw, ssl_on=ssl_on, ctype="application/xml",
                         body='<?xml version="1.0" encoding="UTF-8"?>' + new_block)
    if code not in (200, 201):
        raise CamError(f"the recorder did not accept the new IP for channel {cid} (answer {code})")
    return cid, f"channel {cid} now uses {new}"


def hik_nvr_online(nvr_ip, port, ssl_on, user, pw, cid, send=None):
    """True / False when the recorder says whether that channel is online; None when it does not say."""
    send = send or S.http_request
    code, body, _ = send(nvr_ip, port, "GET", HIK_CH + "/status", user, pw, ssl_on=ssl_on)
    if code != 200:
        return None
    for block in re.findall(r"<InputProxyChannelStatus\b.*?</InputProxyChannelStatus>", body, re.S):
        if re.search(rf"<id>\s*{cid}\s*</id>", block):
            m = re.search(r"<online>\s*(true|false)\s*</online>", block, re.I)
            return m.group(1).lower() == "true" if m else None
    return None


def dahua_nvr_update(nvr_ip, port, ssl_on, user, pw, old, new, cam_cred=None, send=None):
    """Dahua recorder: the remote device whose Address is `old` gets `new`. Returns (key or "", note)."""
    send = send or S.http_request
    base = "/cgi-bin/configManager.cgi?action="
    code, body, _ = send(nvr_ip, port, "GET", base + "getConfig&name=RemoteDevice", user, pw, ssl_on=ssl_on)
    if code == 401:
        raise CamError("the recorder refused the login")
    if code != 200:
        raise CamError(f"could not read the recorder's camera list (answer {code})")
    keys = [k for k, v in S.parse_kv(body).items() if k.endswith(".Address") and v.strip() == old]
    if not keys:
        return "", f"no channel on this recorder uses {old}"
    if len(keys) > 1:
        raise CamError(f"{len(keys)} channels use {old} - not changed, set it by hand")
    key = keys[0][len("table."):] if keys[0].startswith("table.") else keys[0]
    from urllib.parse import quote
    code, ans, _ = send(nvr_ip, port, "GET", base + "setConfig&" + quote(key, safe=".:_-[]") + "=" + new, user, pw,
                        ssl_on=ssl_on)
    if code != 200 or "ok" not in ans.lower():
        raise CamError(f"the recorder did not accept the new IP (answer {code})")
    return key, f"recorder entry now uses {new}"


def update_recorders(nvr_rows, creds, old, new, cam_cred=None, send=None, wait=60, step=5, sleep=time.sleep,
                     clock=time.time, xmeye_update=None, saved=None):
    """After a camera moved from `old` to `new`: tell every recorder we can talk to. Returns a short text for
    the row. Never raises - a recorder that cannot be updated is reported, the camera stays moved."""
    notes, found = [], False
    for n in nvr_rows:
        cred = cred_of(n, creds, saved)
        if not cred:
            notes.append(f"recorder {n['ip_now']}: its login is not filled in")
            continue
        port, ssl_on = S._http_port(n["dev"])
        try:
            if n["method"] == "hik":
                cid, note = hik_nvr_update(n["ip_now"], port, ssl_on, cred[0], cred[1], old, new, cam_cred, send)
                if cid:
                    found, end, state = True, clock() + wait, None
                    while clock() < end:
                        sleep(step)
                        state = hik_nvr_online(n["ip_now"], port, ssl_on, cred[0], cred[1], cid, send)
                        if state is not False:
                            break
                    note += {True: " and is online", False: " but still shows OFFLINE - check the camera "
                             "password on the recorder", None: ""}[state]
                    notes.append(f"recorder {n['ip_now']}: {note}")
            elif n["method"] == "xmeye":
                import nd_dvrip as DV
                try:
                    changed, note = (xmeye_update or DV.recorder_update)(n["ip_now"], cred[0], cred[1], old, new)
                except DV.DvrError as e:
                    raise CamError("the recorder refused the login" if e.refused else str(e)) from None
                except OSError as e:
                    raise CamError(f"the recorder did not answer on port {DV.PORT} ({e.__class__.__name__})") from None
                if changed:
                    found = True
                    notes.append(f"recorder {n['ip_now']}: {note}")
            else:
                key, note = dahua_nvr_update(n["ip_now"], port, ssl_on, cred[0], cred[1], old, new, cam_cred, send)
                if key:
                    found = True
                    notes.append(f"recorder {n['ip_now']}: {note}")
        except CamError as e:
            notes.append(f"recorder {n['ip_now']}: {e}")
        except S.Outcome as o:
            notes.append(f"recorder {n['ip_now']}: {o.detail}")
    if not notes and not found:
        return ("no recorder had a channel on " + old + " (or no recorder login worked): give the camera's new "
                "IP on the NVR / DVR by hand") if nvr_rows else "type the new IP on the NVR / DVR by hand"
    return "; ".join(notes)


# -------------------------------------------------------------------------------------------------- one move
def move_one(row, cred, reserve, alive, set_dhcp=None, wait=120, step=3, sleep=time.sleep, clock=time.time):
    """Moves ONE camera. reserve(row) -> error text or "" (router reservation); alive(ip) -> bool.
    Returns (ok, text). On any failure nothing further is attempted for this camera."""
    d = row["dev"]
    port, ssl_on = S._http_port(d)
    err = reserve(row)
    if err:
        return False, f"router did not reserve {row['ip_new']}: {err} - the camera was NOT touched"
    try:
        note = (set_dhcp or SETTERS[row["method"]])(row["ip_now"], port, ssl_on, cred[0], cred[1])
    except CamError as e:
        return False, f"{e} - the camera keeps {row['ip_now']} (the reservation stays; Undo removes it)"
    except S.Outcome as o:
        return False, f"{o.detail} - the camera keeps {row['ip_now']}"
    end = clock() + wait
    while clock() < end:
        sleep(step)
        if alive(row["ip_new"]):
            return True, f"{note}; answers on {row['ip_new']}"
    if alive(row["ip_now"]):
        return False, (f"{note}, but it still answers on {row['ip_now']}: restart the camera (power off / on) and it "
                       f"takes {row['ip_new']}")
    return False, (f"{note}, but it answers on neither {row['ip_now']} nor {row['ip_new']} after {wait} s: check its "
                   "power / cable; it may have taken another IP from the router (Devices > Scan shows it by its MAC "
                   f"{d['mac']})")


def cred_of(row, creds, saved=None):
    """The (user, password) for a plan row: the login remembered for that device, or the typed one it used."""
    if row.get("login") == S.SAVED:
        return (saved or {}).get(row["dev"].get("mac"))
    n = row.get("login")
    return creds[n - 1] if isinstance(n, int) and 0 < n <= len(creds) else None


def run(rows, creds, reserve, alive, on_row=None, limit=None, after_move=None, saved=None, **kw):
    """Moves the "move" rows one after the other and STOPS at the first failure (the rest stay untouched).
    limit: how many cameras this run may move (1 for the first, pilot run). Each row gets "result".
    after_move(row, cred) -> text: called after each camera that moved (updates the recorder)."""
    done = 0
    for r in rows:
        if r["action"] != "move":
            continue
        if limit is not None and done >= limit:
            break
        cred = cred_of(r, creds, saved)
        if not cred:
            r["result"] = "not moved: the login used in the sweep is no longer filled in"
            if on_row:
                on_row(r, False)
            break
        ok, text = move_one(r, cred, reserve, alive, **kw)
        r["result"] = ("MOVED: " if ok else "FAILED: ") + text
        r["moved"] = ok
        if ok and after_move:
            try:
                r["result"] += " | " + after_move(r, cred)
            except Exception as e:  # noqa: BLE001 - the camera is moved; the recorder part is reported, not fatal
                r["result"] += f" | recorder not updated ({e.__class__.__name__}): type the new IP there by hand"
        if on_row:
            on_row(r, ok)
        if not ok:
            break
        done += 1
    return done
