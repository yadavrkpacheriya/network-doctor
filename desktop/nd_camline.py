# -*- coding: utf-8 -*-
"""
Network Doctor - "line up the cameras": every camera gets one fixed IP in the camera block (for example
192.168.0.71 - .150), in order, so a camera that stops answering is found at a glance.

How a camera is moved (one camera at a time, never several at once):
  1. the router reserves the new IP for the camera's MAC (a DHCP reservation - the same one "IP-MAC binding"
     makes; it has an Undo);
  2. the camera itself is switched from a hand-typed IP to "automatic (DHCP)" through its own web API
     (Hikvision ISAPI, Dahua configManager) with the login from the Login sweep;
  3. the app waits until the camera answers on the new IP. If it does not, the run STOPS there - no other
     camera is touched - and the result says where that camera can be found.

What this does NOT do: the NVR / DVR stores each camera's IP, so every moved camera must be given its new IP
on the recorder (the old -> new list is made for that). This is why the first run moves ONE camera only.

Pure logic + the two small device calls; the window is in nd_sweeptab.py. Device calls go through `send`
(nd_sweep.http_request) so they can be tested without a camera.
"""
import re
import time

import nd_bandwidth as B
import nd_sweep as S

MOVABLE = ("hik", "dahua")          # brands whose "use DHCP" switch this app knows
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
                          "switch (only Hikvision and Dahua): type the new IP on the device by hand")
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
                    {"hik": "Hikvision", "dahua": "Dahua"}.get(r.get("method"), ""), r.get("result", r["action"])])
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


SETTERS = {"hik": hik_set_dhcp, "dahua": dahua_set_dhcp}


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


def run(rows, creds, reserve, alive, on_row=None, limit=None, **kw):
    """Moves the "move" rows one after the other and STOPS at the first failure (the rest stay untouched).
    limit: how many cameras this run may move (1 for the first, pilot run). Each row gets "result"."""
    done = 0
    for r in rows:
        if r["action"] != "move":
            continue
        if limit is not None and done >= limit:
            break
        cred = creds[r["login"] - 1] if 0 < r["login"] <= len(creds) else None
        if not cred:
            r["result"] = "not moved: the login used in the sweep is no longer filled in"
            if on_row:
                on_row(r, False)
            break
        ok, text = move_one(r, cred, reserve, alive, **kw)
        r["result"] = ("MOVED: " if ok else "FAILED: ") + text
        r["moved"] = ok
        if on_row:
            on_row(r, ok)
        if not ok:
            break
        done += 1
    return done
