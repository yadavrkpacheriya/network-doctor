# -*- coding: utf-8 -*-
"""Network Doctor Pro - "what does the internet see of us?" (Shodan / Censys lookups of your office's public IP).

Shodan and Censys continuously scan the whole internet. Giving them your public IP shows exactly which of your
ports and services are visible from outside - the attacker's first view of you. Both need a free API key, which
you paste in Setup; nothing is sent anywhere without it.
"""
import json
import urllib.error
import urllib.request

import nd_core as core


def public_ip(timeout=6):
    """This network's public (internet) IP address."""
    for url in ("https://api.ipify.org?format=json", "https://ifconfig.co/json"):
        try:
            with core.url_open(url, timeout) if hasattr(core, "url_open") else urllib.request.urlopen(url, timeout=timeout) as r:
                j = json.loads(r.read().decode("utf-8", "replace"))
                return j.get("ip") or j.get("ip_addr")
        except Exception:
            continue
    return None


def _get(url, timeout=10, headers=None):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "NetworkDoctor"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def shodan(ip, api_key, timeout=12):
    """{open_ports, services[], hostnames, vulns[], raw} for an IP from Shodan, or {error}."""
    try:
        j = _get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", timeout)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"ok": True, "found": False, "ports": [], "services": [], "vulns": [],
                    "note": "Shodan has not seen this IP open anything - good."}
        return {"ok": False, "error": f"Shodan: {e.code} {e.reason}"}
    except Exception as e:
        return {"ok": False, "error": f"Shodan: {e}"}
    services = []
    for d in j.get("data", []):
        services.append({"port": d.get("port"), "proto": d.get("transport", "tcp"),
                         "product": d.get("product", "") or d.get("_shodan", {}).get("module", ""),
                         "banner": (d.get("data", "") or "").strip()[:200]})
    return {"ok": True, "found": True, "ports": sorted(j.get("ports", [])), "services": services,
            "hostnames": j.get("hostnames", []), "org": j.get("org", ""), "isp": j.get("isp", ""),
            "vulns": sorted(j.get("vulns", []) or []), "country": j.get("country_name", "")}


def censys(ip, api_id, api_secret, timeout=12):
    """Censys view of an IP (needs an API ID + secret), or {error}."""
    import base64
    tok = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    try:
        j = _get(f"https://search.censys.io/api/v2/hosts/{ip}", timeout,
                 headers={"Authorization": "Basic " + tok, "Accept": "application/json"})
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"ok": True, "found": False, "services": [], "note": "Censys has not seen this IP - good."}
        return {"ok": False, "error": f"Censys: {e.code} {e.reason}"}
    except Exception as e:
        return {"ok": False, "error": f"Censys: {e}"}
    res = (j.get("result") or {})
    services = [{"port": s.get("port"), "proto": s.get("transport_protocol", "").lower(),
                 "product": s.get("service_name", "")} for s in res.get("services", [])]
    return {"ok": True, "found": bool(services), "services": services,
            "as": (res.get("autonomous_system") or {}).get("name", ""),
            "location": (res.get("location") or {}).get("country", "")}


def summary(ip, sh, ce):
    """A plain-English verdict from the Shodan + Censys results."""
    ports = set(sh.get("ports", []) if sh.get("ok") else []) | {s["port"] for s in (ce.get("services", []) if ce.get("ok") else []) if s.get("port")}
    lines = [f"Your office's public IP is {ip}."]
    if not ports:
        lines.append("Good news: neither Shodan nor Censys sees any service open from the internet.")
    else:
        lines.append(f"The internet can see {len(ports)} open port(s): " + ", ".join(str(p) for p in sorted(ports)) + ".")
        risky = sorted(p for p in ports if p in (23, 21, 3389, 5900, 445, 8080, 37777, 34567, 554, 8000))
        if risky:
            lines.append("Risky to expose: " + ", ".join(str(p) for p in risky) +
                         " - close these on the router unless you really need them (use a VPN instead).")
    if sh.get("vulns"):
        lines.append("Shodan flags known vulnerabilities: " + ", ".join(sh["vulns"][:8]) +
                     " - update that device's firmware.")
    return "\n".join(lines)
