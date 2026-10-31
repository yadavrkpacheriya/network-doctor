# -*- coding: utf-8 -*-
"""Slow website / slow internet for one person: measure every link between that person and the website, then
name the cause and the fix.

Links checked:  user's device -> office network -> router -> internet line -> DNS -> the website itself,
plus: is the line full right now (and who fills it), is the user's own PC downloading something big, is the
user's PC itself weak (RAM / disk from the PC script), is the router's CPU busy, packet size (MTU), and
optionally the delay while the line is busy (bufferbloat).

measure() does the tests (network access, slow); judge() turns the numbers into findings (pure, tested).
"""

import socket
import ssl
import statistics
import threading
import time
import urllib.parse

import nd_core as core
import nd_net as NT

# Quick choices in the tab: (label, address)
COMMON_SITES = [("Google Sheets / Docs", "https://docs.google.com/spreadsheets/"), ("Gmail", "https://mail.google.com/"),
                ("Google Drive", "https://drive.google.com/"), ("Microsoft 365 / Outlook", "https://outlook.office.com/"),
                ("WhatsApp Web", "https://web.whatsapp.com/"), ("GST portal", "https://services.gst.gov.in/"),
                ("YouTube", "https://www.youtube.com/")]
REFERENCE = ["https://www.google.com/generate_204", "https://www.bing.com/"]
PUBLIC = ["1.1.1.1", "8.8.8.8"]


def norm_url(text):
    t = (text or "").strip()
    if not t:
        return ""
    if "://" not in t:
        t = "https://" + t
    u = urllib.parse.urlsplit(t)
    return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path or "/", u.query, ""))


def http_timing(url, timeout=12, max_bytes=600_000):
    """dns / connect / tls / first byte / total in ms and download speed, like a browser's first request."""
    u = urllib.parse.urlsplit(url)
    host, https = u.hostname or "", u.scheme == "https"
    port = u.port or (443 if https else 80)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    r = {"url": url, "host": host}
    t0 = time.perf_counter()
    try:
        ip = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except Exception as e:
        r["error"] = f"name not found ({e})"
        return r
    r["dns"] = (time.perf_counter() - t0) * 1000
    r["ip"] = ip
    t1 = time.perf_counter()
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except Exception as e:
        r["error"] = f"cannot connect to {ip}:{port} ({e})"
        return r
    r["connect"] = (time.perf_counter() - t1) * 1000
    try:
        if https:
            t2 = time.perf_counter()
            s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
            r["tls"] = (time.perf_counter() - t2) * 1000
        s.settimeout(timeout)
        t3 = time.perf_counter()
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 NetworkDoctor\r\n"
                  f"Accept: */*\r\nConnection: close\r\n\r\n".encode())
        first = s.recv(65536)
        r["ttfb"] = (time.perf_counter() - t3) * 1000
        got = len(first)
        r["status"] = first.split(b"\r\n", 1)[0].decode("latin-1", "replace")[:60]
        t4 = time.perf_counter()
        while got < max_bytes:
            b = s.recv(65536)
            if not b:
                break
            got += len(b)
        dt = time.perf_counter() - t4
        r["bytes"] = got
        r["kbps"] = (got * 8 / 1000 / dt) if dt > 0.05 and got > 50_000 else None
    except Exception as e:
        r["error"] = f"{type(e).__name__}: {e}"
    finally:
        try:
            s.close()
        except Exception:
            pass
    r["total"] = (time.perf_counter() - t0) * 1000
    return r


def best_of(runs):
    """The fastest complete run (the first can include a cold DNS cache); None if all failed."""
    ok = [x for x in runs if "error" not in x and x.get("total")]
    return min(ok, key=lambda x: x["total"]) if ok else None


def dns_time(host, server, timeout=2.5):
    try:
        res = NT.dns_query(host, "A", server, timeout=timeout)
    except Exception as e:
        return {"server": server, "error": str(e)}
    if res.get("error"):
        return {"server": server, "error": res["error"]}
    ips = sorted({x["data"] for x in res.get("records", []) if x.get("type") == "A"})
    rc = res.get("rcode") or 0
    if rc:  # the server answered, but with a failure: not a fast success
        why = {2: "server failure (SERVFAIL)", 3: "name does not exist (NXDOMAIN)", 5: "refused"}.get(rc, f"code {rc}")
        return {"server": server, "error": f"answered: {why}", "rcode": rc}
    return {"server": server, "ms": res.get("ms"), "ips": ips, "rcode": rc}


# ==========================================================================
def measure(url, device, ctx, progress=lambda pct, text: None, stop=None, loaded=False):
    """device: the user's device dict (or None). ctx: dict with gw, lip, mon, usage, db, raw, issues,
    router (RouterOS client or None), line_mbps (internet plan, or None). Returns the measurement dict."""
    stop = stop or threading.Event()
    m = {"url": url, "host": urllib.parse.urlsplit(url).hostname or "", "time": time.time(), "device": None}
    gw = ctx.get("gw")
    jobs = {}

    def bg(name, fn, *a):
        th = threading.Thread(target=lambda: m.__setitem__(name, fn(*a)), daemon=True)
        th.start()
        jobs[name] = th

    progress(5, "Pinging the user's device, the router and the internet...")
    if device and device.get("ip") and device.get("ip") != ctx.get("lip"):
        bg("dev_ping", NT.ping_stats, device["ip"], 20)
    if gw:
        bg("gw_ping", NT.ping_stats, gw, 20)
    bg("inet_ping", NT.ping_stats, PUBLIC[0], 20)
    # DNS: the server this PC uses, the router, a public one
    progress(20, "Timing DNS look-ups...")
    sys_dns = [d for d in NT.system_dns_servers() if d != "127.0.0.1"]
    servers = []
    for label, srv in (("this PC's DNS", sys_dns[0] if sys_dns else None), ("router", gw), ("public 1.1.1.1", "1.1.1.1")):
        if srv and srv not in [s for _, s in servers]:
            servers.append((label, srv))
    m["dns"] = []
    for label, srv in servers:
        if stop.is_set():
            return m
        a = dns_time(m["host"], srv)
        b = dns_time(m["host"], srv)  # second time: from the server's cache
        a["label"], a["cached_ms"] = label, b.get("ms")
        m["dns"].append(a)
    m["dns_rogue"] = bool(sys_dns and gw and sys_dns[0] != gw and core.is_private_ip(sys_dns[0]))
    progress(35, f"Opening {m['host']} (3 times) and a reference site...")
    m["site_runs"] = [http_timing(url) for _ in range(3) if not stop.is_set()]
    m["ref_runs"] = [http_timing(REFERENCE[0]) for _ in range(2) if not stop.is_set()]
    progress(55, "Checking the largest packet that passes (MTU)...")
    try:
        m["mtu"] = NT.mtu_probe(PUBLIC[1], stop=stop)
    except Exception:
        m["mtu"] = None
    for th in jobs.values():
        th.join(45)
    progress(70, "Looking at the traffic right now...")
    mon = ctx.get("mon")
    rates = mon.traffic.rates(60) if mon and mon.last_flow else {}
    names = {d.get("ip"): d.get("name") or d.get("ip") for d in ctx.get("devices") or []}
    m["line"] = {"capacity_mbps": ctx.get("line_mbps"), "have_flows": bool(rates),
                 "down_bps": sum(r["down_bps"] for r in rates.values()) * 8,
                 "up_bps": sum(r["up_bps"] for r in rates.values()) * 8,
                 "top": [(names.get(ip, ip), ip, (r["down_bps"] + r["up_bps"]) * 8)
                         for ip, r in sorted(rates.items(), key=lambda x: -(x[1]["down_bps"] + x[1]["up_bps"]))[:5]]}
    if device:
        dv = {"name": device.get("name") or device.get("ip"), "ip": device.get("ip"),
              "category": device.get("category", ""), "mac": device.get("mac", ""), "self": bool(device.get("self"))}
        r = rates.get(device.get("ip")) or {}
        dv["down_bps"], dv["up_bps"] = r.get("down_bps", 0) * 8, r.get("up_bps", 0) * 8
        apps = []
        if mon and mon.last_flow and device.get("ip"):
            rem, _, _ = mon.traffic.remotes(device["ip"])
            usage = ctx.get("usage")
            for (remote, svc, proto, inbound), (up, down, n, first, last) in sorted(
                    rem, key=lambda x: -(x[1][0] + x[1][1]))[:8]:
                if time.time() - last < 300:
                    app = (usage.app_for(device["ip"], remote) if usage else None) or remote
                    apps.append((app, up + down))
        dv["recent_apps"] = apps
        rep = next((r for r in ((ctx.get("db") or {}).get("pc_reports") or {}).values()
                    if device.get("mac") and device["mac"] in (r.get("macs") or [])), None)
        dv["hw"] = (rep or {}).get("hw") or {}
        dv["links"] = (rep or {}).get("links") or []
        dv["conflict"] = bool(device.get("conflict"))
        m["device"] = dv
    router = ctx.get("router")
    if router:
        progress(78, "Asking the router how busy it is...")
        try:
            with router:
                res = router.cmd("/system/resource/print")
            m["router_cpu"] = int((res[0] if res else {}).get("cpu-load", "0") or 0)
        except Exception as e:
            m["router_err"] = str(e)
    issues = ctx.get("issues") or []
    m["context"] = [i["title"] for i in issues if i.get("sev") in ("critical", "warning") and any(
        w in i["title"].lower() for w in ("loop", "broadcast", "conflict", "rogue", "dhcp", "extra router",
                                          "unstable", "duplicate"))]
    if loaded and not stop.is_set():
        progress(85, "Measuring delay while the line is busy (10 s)...")
        idle = NT.ping_stats(PUBLIC[0], 5)
        with NT.LoadedPinger(PUBLIC[0]) as lp:
            try:
                NT.throughput("down", seconds=8, stop=stop)
            except Exception:
                pass
        m["loaded"] = {"idle": idle.get("avg"), "busy": statistics.median(lp.times) if lp.times else None}
    progress(100, "Done")
    return m


# ==========================================================================
def _f(sev, title, conf, evidence, fixes, action=None, score=50):
    return {"sev": sev, "title": title, "conf": conf, "evidence": evidence, "fixes": fixes, "action": action,
            "score": score}


def judge(m):
    """Findings, most likely cause first. Each: sev, title, conf, evidence [..], fixes [..], action (or None)."""
    out = []
    host = m.get("host", "the site")
    dev = m.get("device") or {}
    who = dev.get("name") or "this user"
    site = best_of(m.get("site_runs") or [])
    ref = best_of(m.get("ref_runs") or [])
    errs = [x["error"] for x in m.get("site_runs") or [] if "error" in x]

    # ---- the site cannot be opened at all
    if not site and errs:
        dns_dead = all("name not found" in e for e in errs)
        out.append(_f("critical", f"{host} cannot be opened from the office" if not dns_dead else
                      f"The name {host} cannot be looked up", "High", errs[:2],
                      (["Check the website address.", "If other sites work: DNS problem - see the DNS finding."]
                       if dns_dead else
                       [f"Check that {host} is not blocked in Tools > Website firewall or on the router.",
                        "If only this site fails, it may be down: check its status page from a phone on mobile data."]),
                      "open:website", 100))

    # ---- DNS
    dns = m.get("dns") or []
    pub = next((d for d in dns if d.get("label", "").startswith("public")), None)
    pub_ms = (pub or {}).get("ms")
    for d in dns:
        if d.get("label", "").startswith("public"):
            continue
        fresh, cached = d.get("ms"), d.get("cached_ms")
        if d.get("error") and not pub_ms:
            out.append(_f("critical", f"DNS does not work: the {d['label']} and public DNS both fail", "Medium",
                          [f"{d['server']}: {d['error']}", f"1.1.1.1: {(pub or {}).get('error', 'no answer')}"],
                          ["The internet connection itself is down, or DNS (port 53) is blocked - check the router's "
                           "internet (WAN) and firewall."], None, 85))
        elif d.get("error") and pub_ms:
            out.append(_f("critical", f"The {d['label']} ({d['server']}) does not answer", "High",
                          [f"{d['server']}: {d['error']}", f"public DNS 1.1.1.1 answers in {pub_ms:.0f} ms"],
                          ["Let the router use fast public DNS servers (button below), then on the user's PC: "
                           "ipconfig /flushdns.",
                           "If the PC's DNS is not the router: a second router or a typed-in DNS - Tools > Network "
                           "guard."], "dns_public", 90))
        elif fresh is not None and (fresh > 300 or (cached or 0) > 60):
            out.append(_f("warning", f"Slow DNS: the {d['label']} needs {fresh:.0f} ms per new name", "High"
                          if fresh > 600 else "Medium",
                          [f"{d['server']}: {fresh:.0f} ms new name, {cached or 0:.0f} ms repeated"] +
                          ([f"public 1.1.1.1: {pub_ms:.0f} ms"] if pub_ms else []),
                          ["Google Sheets / Gmail load parts from 10+ names: every slow look-up adds a wait.",
                           "Use fast public DNS on the router (button below) and keep its cache on."],
                          "dns_public", 70 + min(20, fresh / 100)))
    if m.get("dns_rogue"):
        srv = next((d["server"] for d in dns if d.get("label") == "this PC's DNS"), "?")
        out.append(_f("warning", f"This PC uses DNS {srv}, not the office router", "Medium",
                      [f"DNS server {srv}, router {m.get('gw') or 'gateway'}"],
                      ["A second router or a typed-in DNS answers look-ups. Tools > Network guard > 'All DNS through "
                       "the router', and set PCs to automatic DNS."], "open:guard", 60))

    # ---- the user's own connection (Wi-Fi / cable)
    dp = m.get("dev_ping")
    if dp and dp.get("recv"):
        evid = [f"{who}: loss {dp['loss']:.0f}%, avg {dp['avg']:.0f} ms, max {dp['max']:.0f} ms, jitter "
                f"{dp['jitter']:.0f} ms (healthy cable: 0%, under 2 ms)"]
        if dp["loss"] >= 3 or dp["avg"] > 30 or dp["jitter"] > 20:
            wifi = "phone" in dev.get("category", "").lower() or dp["avg"] > 8
            out.append(_f("critical" if dp["loss"] >= 10 else "warning",
                          f"{who}'s own connection is weak ({'Wi-Fi' if wifi else 'cable / switch port'})", "High",
                          evid,
                          (["Move the PC / laptop closer to the Wi-Fi access point, or use a cable.",
                            "Use the 5 GHz Wi-Fi (Tools > Wi-Fi analyzer shows crowded channels).",
                            "Add an access point if many people share one."] if wifi else
                           ["Replace the patch cable and try another switch port.",
                            "Tools > This PC's network adapters on that PC: speed 100 Mbps or errors = bad cable."]),
                          "open:wifi", 85))
    elif dev and dev.get("ip") and not dev.get("self") and dp is not None:
        out.append(_f("info", f"{who} does not answer ping", "Low",
                      ["phones and PCs with a firewall often do not - the other tests still apply"], [], None, 5))
    for link in dev.get("links") or []:
        if link.get("duplex") is False or (0 < int(link.get("bps") or 0) <= 100_000_000):
            out.append(_f("warning", f"{who}'s cable runs at {link.get('speed', '100 Mbps')}"
                                     f"{' half duplex' if link.get('duplex') is False else ''}", "Medium",
                          [f"adapter {link.get('name', '')} (from the PC script)"],
                          ["Replace the patch cable / try another switch port (gigabit needs all 8 wires)."], None, 55))

    # ---- the office network / router
    gp = m.get("gw_ping")
    if gp and gp.get("recv") and (gp["loss"] >= 2 or gp["avg"] > 10 or gp["jitter"] > 10):
        out.append(_f("critical" if gp["loss"] >= 5 else "warning", "The office network to the router is unstable",
                      "High", [f"router: loss {gp['loss']:.0f}%, avg {gp['avg']:.0f} ms, max {gp['max']:.0f} ms "
                               "(from this PC; healthy: 0%, 1-2 ms)"] + [f"also seen: {c}" for c in m.get("context", [])],
                      ["Everyone is affected, not only this user: look for a loop or a failing switch - Root cause "
                       "tab and Problems tab.", "Restart the switch between this PC and the router if it is hot."],
                      "open:rca", 88))
    elif gp and not gp.get("recv"):
        out.append(_f("critical", "The router does not answer ping from this PC", "Medium",
                      ["100% loss to the router"],
                      ["Check this PC's cable / Wi-Fi first, then the router. If the router blocks ping on purpose, "
                       "allow ICMP from the LAN (IP > Firewall)."], None, 70))
    elif m.get("context"):
        out.append(_f("warning", "Known network problems may slow everyone", "Medium", m["context"][:4],
                      ["Fix the items in the Problems tab first."], "open:problems", 45))
    cpu = m.get("router_cpu")
    if cpu is not None and cpu >= 80:
        out.append(_f("warning", f"The router's processor is busy ({cpu}%)", "Medium" if cpu < 95 else "High",
                      [f"router CPU load {cpu}%"],
                      ["A busy router delays every page. Keep FastTrack on (unless you need speed limits), remove "
                       "unused firewall / mangle rules, and turn off packet sniffing / torch.",
                       "If it stays above 80% at busy hours, the router is too small for the line."], None, 65))

    # ---- the internet line
    ip_ = m.get("inet_ping")
    if ip_ and ip_.get("recv") and (ip_["loss"] >= 2 or ip_["avg"] > 120 or ip_["jitter"] > 30):
        out.append(_f("critical" if ip_["loss"] >= 5 else "warning", "The internet line itself is poor", "High",
                      [f"internet (1.1.1.1): loss {ip_['loss']:.0f}%, avg {ip_['avg']:.0f} ms, jitter "
                       f"{ip_['jitter']:.0f} ms (good: 0%, under 40 ms in India)"],
                      ["Call the internet provider with these numbers (loss / delay at the time).",
                       "If the line is full (see below), the provider is not the cause."], None, 80))
    elif ip_ and not ip_.get("recv"):
        out.append(_f("critical", "No answer from the internet (1.1.1.1)", "Medium", ["100% loss"],
                      ["Check the router's internet connection (WAN), or the provider."], None, 75))
    line = m.get("line") or {}
    cap = line.get("capacity_mbps")
    used = (line.get("down_bps") or 0) / 1e6
    if line.get("have_flows") and cap and used > 0.75 * cap:
        top = line.get("top") or []
        out.append(_f("critical" if used > 0.9 * cap else "warning",
                      f"The internet line is full: {used:.0f} of {cap:.0f} Mbps in use", "High",
                      [f"{n} ({ip}): {b / 1e6:.1f} Mbps" for n, ip, b in top[:4]],
                      [f"Limit the biggest user ({top[0][0]}) - button below." if top else "Limit the biggest users.",
                       "Block video / updates during working hours (Tools > Website firewall), or get a faster line."],
                      f"limit:{top[0][1]}" if top else None, 92))
    elif line.get("have_flows") and not cap and line.get("top"):
        n, ip, b = line["top"][0]
        if b > 20e6:
            out.append(_f("info", f"{n} is using {b / 1e6:.0f} Mbps right now", "Low",
                          ["type your internet plan speed above to judge if the line is full"], [], f"limit:{ip}", 30))
    elif not line.get("have_flows"):
        out.append(_f("info", "Cannot see whether the line is full", "Low",
                      ["no traffic data (NetFlow) from the router"],
                      ["Setup > Apply router settings now, then run this check again."], "open:setup", 10))
    ld = m.get("loaded") or {}
    if ld.get("idle") and ld.get("busy") and ld["busy"] - ld["idle"] > 100:
        out.append(_f("warning", f"Delay jumps to {ld['busy']:.0f} ms when the line is busy (bufferbloat)", "High",
                      [f"idle {ld['idle']:.0f} ms, during a download {ld['busy']:.0f} ms"],
                      ["When someone downloads, every page waits behind it. Add a smart queue on the router: "
                       "limit the line to ~90% of the plan speed with fair queueing (button below).",
                       "Keep big downloads / backups for after office hours."], "queue_fair", 78))
    mtu = m.get("mtu")
    if mtu and mtu < 1500:
        out.append(_f("warning", f"Large packets do not pass (MTU {mtu})", "Medium",
                      [f"largest packet {mtu} bytes (normal 1500) - typical of PPPoE / some fibre lines"],
                      ["Some sites (Google, banks, portals) then hang or load very slowly. Add 'MSS clamp' on the "
                       "router (button below)."], "mss_clamp", 72))

    # ---- the user's own device is busy / weak
    if dev.get("down_bps", 0) + dev.get("up_bps", 0) > 5e6:
        apps = ", ".join(f"{a} {b / 1048576:.0f} MB" for a, b in (dev.get("recent_apps") or [])[:3])
        out.append(_f("warning", f"{who} itself is busy on the internet right now "
                                 f"({(dev['down_bps'] + dev['up_bps']) / 1e6:.0f} Mbps)", "Medium",
                      [f"recent: {apps}" if apps else "large transfer in progress"],
                      ["A Windows Update, cloud backup (OneDrive / Google Drive sync) or video in another tab "
                       "slows its own pages. Pause it or schedule it for the night."], None, 60))
    hw = dev.get("hw") or {}
    try:
        ram = float(hw.get("ram_gb") or 0)
        free = float(hw.get("disk_free_gb") or 0)
    except ValueError:
        ram = free = 0
    if (ram and ram <= 4.5) or (hw.get("disk_free_gb") not in (None, "") and free < 10):
        out.append(_f("warning", f"{who}'s PC itself is weak for heavy web apps", "Medium",
                      ([f"RAM {ram:g} GB (Google Sheets in Chrome wants 8 GB)"] if ram and ram <= 4.5 else []) +
                      ([f"only {free:g} GB free on C:"] if hw.get("disk_free_gb") not in (None, "") and free < 10 else []),
                      ["Close other tabs and programs, free disk space, or add RAM (8 GB is the practical minimum)."],
                      None, 58))
    if dev.get("conflict"):
        out.append(_f("critical", f"{who}'s IP is used by another device too (IP conflict)", "High",
                      [f"IP {dev.get('ip')}"], ["Fix the conflict (Problems tab) - the connection drops randomly."],
                      "open:problems", 95))

    # ---- the website itself
    if site and ref:
        sw, rw = site.get("ttfb", 0) + site.get("tls", 0), ref.get("ttfb", 0) + ref.get("tls", 0)
        ev = [f"{host}: DNS {site.get('dns', 0):.0f} ms, connect {site.get('connect', 0):.0f} ms, secure "
              f"{site.get('tls', 0):.0f} ms, first answer {site.get('ttfb', 0):.0f} ms, total {site['total']:.0f} ms",
              f"reference (google.com): connect {ref.get('connect', 0):.0f} ms, first answer "
              f"{ref.get('ttfb', 0):.0f} ms, total {ref['total']:.0f} ms"]
        if site["total"] > 2500 and sw > 3 * max(rw, 150):
            g = "google" in host
            out.append(_f("warning", f"{host} itself answers slowly", "Medium", ev,
                          (["Google Sheets: very large sheets, many formulas / IMPORTRANGE / add-ons make it slow - "
                            "split the sheet or archive old rows.", "Try in an Incognito window (extensions off) "
                            "and close other tabs.", "Google Workspace status: www.google.com/appsstatus"] if g else
                           ["The server is slow, not the office network - check the site's status or try later."]),
                          None, 50))
        elif site["total"] > 2500 and ref["total"] > 2000:
            out.append(_f("warning", "Every website is slow from the office, not only this one", "Medium", ev,
                          ["See the line / DNS / router findings above."], None, 40))
        m["site_summary"] = ev
    elif site:
        m["site_summary"] = [f"{host}: total {site['total']:.0f} ms"]

    if not [f for f in out if f["sev"] in ("critical", "warning")]:
        out.append(_f("ok", "No network cause found from this PC", "Medium",
                      (m.get("site_summary") or []) + ["DNS, router, internet line and packet size are healthy"],
                      [f"Run the comparison command below on {who}'s PC: if it is slow there but not here, the cause "
                       "is that PC (Wi-Fi, browser, antivirus scanning web pages, proxy / VPN).",
                       "On that PC: ipconfig /flushdns, clear the browser cache, try an Incognito window, disable "
                       "extensions, update the browser.", "Check that PC's RAM / disk in Tools > Inventory."],
                      None, 1))
    out.sort(key=lambda f: -f["score"])
    return out


def compare_command(url):
    """What to run on the user's own PC (Windows 10/11 has curl) to compare with this PC's numbers."""
    return (f'curl.exe -o NUL -s -w "DNS %{{time_namelookup}}s  connect %{{time_connect}}s  secure '
            f'%{{time_appconnect}}s  first answer %{{time_starttransfer}}s  total %{{time_total}}s\\n" "{url}"')


# router fixes (MikroTik), applied with the router login or pasted in WinBox
def fix_script(action, line_mbps=None, lan="", bridge="bridge"):
    if action == "dns_public":
        return ("/ip dns set servers=1.1.1.1,8.8.8.8 allow-remote-requests=yes cache-size=8192KiB\n"
                "/ip dns cache flush\n")
    if action == "mss_clamp":
        return (':do {/ip firewall mangle remove [find where comment="ND: MSS clamp"]} on-error={}\n'
                "/ip firewall mangle add chain=forward protocol=tcp tcp-flags=syn action=change-mss "
                'new-mss=clamp-to-pmtu passthrough=yes comment="ND: MSS clamp"\n')
    if action.startswith("limit:"):
        ip = action.split(":", 1)[1]
        mb = max(2, int((line_mbps or 50) * 0.3))
        return (f':do {{/queue simple remove [find name="ND limit {ip}"]}} on-error={{}}\n'
                f'/queue simple add name="ND limit {ip}" target={ip}/32 max-limit={mb}M/{mb}M comment="ND slow-web"\n')
    if action == "queue_fair":
        mb = int((line_mbps or 0) * 0.9)
        if not mb or not lan:
            return ""
        return (':do {/queue simple remove [find name="ND fair queue"]} on-error={}\n'
                f'/queue simple add name="ND fair queue" target={lan} max-limit={mb}M/{mb}M '
                'queue=pcq-upload-default/pcq-download-default comment="ND: fair share of the line"\n')
    return ""
