# -*- coding: utf-8 -*-
""""Is it down for everyone, or just us?" - for when Outlook/Teams/some site stops working and you need
to know in 10 seconds whether it's your network's problem or Microsoft's before you start troubleshooting
the wrong thing.

Two independent signals, shown together:
1. nd_net.web_check()'s staged DNS -> Connect -> TLS -> HTTP probe (already built for the "Web check"
   tool) - which stage it gets stuck on IS the diagnosis (see verdict()). No API key, no third party,
   works for any hostname.
2. For services that publish a public status page in the common Atlassian Statuspage format (no login
   needed), the official status too. Most big providers with ANY public status page use this exact JSON
   shape - GitHub, Cloudflare, Slack, Zoom, Dropbox, Atlassian, OpenAI, Discord... Microsoft 365/Outlook
   does NOT publish an unauthenticated one (their status page needs a work/school sign-in), so Microsoft
   services fall back to signal #1 alone plus a link to check manually - never a guessed/fabricated
   "Microsoft says..." line.
"""
import json

import nd_net as NT

STATUSPAGE_PRESETS = {
    # display name -> (hostname to probe, statuspage.io-format status JSON URL or None)
    "GitHub": ("github.com", "https://www.githubstatus.com/api/v2/status.json"),
    "Cloudflare": ("cloudflare.com", "https://www.cloudflarestatus.com/api/v2/status.json"),
    "Slack": ("slack.com", "https://status.slack.com/api/v2.0.0/current"),
    "Zoom": ("zoom.us", "https://status.zoom.us/api/v2/status.json"),
    "Dropbox": ("dropbox.com", "https://status.dropbox.com/api/v2/status.json"),
    "Atlassian (Jira/Confluence)": ("atlassian.com", "https://status.atlassian.com/api/v2/status.json"),
    "OpenAI": ("openai.com", "https://status.openai.com/api/v2/status.json"),
    "Discord": ("discord.com", "https://discordstatus.com/api/v2/status.json"),
    # No public, unauthenticated status API exists for these - Microsoft's requires a work/school sign-in.
    # Probed with signal #1 only; the manual link is shown instead of a status line.
    "Microsoft 365 / Outlook": ("outlook.office.com", None),
    "Google Workspace / Gmail": ("www.google.com", None),
    "WhatsApp": ("web.whatsapp.com", None),
}

MANUAL_STATUS_LINKS = {
    "Microsoft 365 / Outlook": "https://portal.office.com/servicestatus (sign in) or https://downdetector.com/status/microsoft365/",
    "Google Workspace / Gmail": "https://www.google.com/appsstatus/dashboard/ or https://downdetector.com/status/google/",
    "WhatsApp": "https://downdetector.com/status/whatsapp/",
}


def verdict(rows):
    """rows: the (label, value, sev) list nd_net.web_check() returns. Which STAGE it got stuck on is
    the diagnosis: the closer the connection got before failing, the more it points at the remote
    service rather than this network. Returns (level, message)."""
    by_label = {}
    for label, val, sev in rows:
        if label not in by_label:  # first occurrence of each stage
            by_label[label] = (val, sev)

    if by_label.get("DNS", ("", ""))[1] == "critical":
        return ("critical", "Could not even resolve the name to an address - this points at THIS "
                             "network (DNS server down, DNS filter blocking it, or no internet at all), "
                             "not at the service itself.")
    if by_label.get("Connect", ("", ""))[1] == "critical":
        return ("critical", "The name resolved fine, but nothing answered on that port - either this "
                             "network/firewall is blocking it, or the service's servers are completely "
                             "unreachable right now. Check the official status page below to tell which.")
    if by_label.get("TLS", ("", ""))[1] == "critical":
        return ("warn", "Got a network connection but the secure handshake failed outright - unusual; "
                        "often a proxy, antivirus, or DNS filter on this network intercepting the "
                        "connection, rather than the service being down.")
    http = by_label.get("HTTP")
    if http and http[1] == "critical":
        return ("critical", "Reached the server and completed the secure handshake, but it never "
                             "answered the actual request - this is the strongest local signal that the "
                             "SERVICE has a problem right now, not this network (a blocked/firewalled "
                             "site almost never gets this far).")
    if http and http[1] == "warning":
        import re
        m = re.search(r"\b(\d{3})\b", http[0])
        code = int(m.group(1)) if m else None
        if code and code >= 500:
            return ("critical", f"The server answered with an error (HTTP {code}) - it's reporting "
                                 f"trouble itself. This is the service's problem, not this network's.")
        return ("warn", f"Reached the server (HTTP {code or '?'}) but with an unusual response - worth "
                        f"a second look, though this network clearly isn't blocking it.")
    return ("ok", "Answered normally - no outage detected from here.")


def official_status(name):
    """For the presets with a public statuspage.io-format JSON endpoint: {"available": True,
    "indicator": "none"/"minor"/"major"/"critical", "description": "..."}. For the rest (no public,
    unauthenticated status API exists - e.g. Microsoft 365), {"available": False, "manual_link": "..."}.
    Never fabricates a status for a service that doesn't publish one."""
    preset = STATUSPAGE_PRESETS.get(name)
    if not preset:
        return {"available": False, "manual_link": ""}
    _, url = preset
    if not url:
        return {"available": False, "manual_link": MANUAL_STATUS_LINKS.get(name, "")}
    try:
        j = json.loads(NT._get(url, timeout=6))
        st = j.get("status", {})
        return {"available": True, "indicator": st.get("indicator", "unknown"),
                "description": st.get("description", "")}
    except Exception as e:
        return {"available": False, "manual_link": MANUAL_STATUS_LINKS.get(name, ""), "error": str(e)}


def check(name_or_host):
    """One call for the UI: resolves a preset name to its host if it is one, runs web_check()+verdict(),
    and attaches official_status() when a preset matches. Works for any arbitrary hostname too -
    official_status() is just skipped for those."""
    preset = STATUSPAGE_PRESETS.get(name_or_host)
    host = preset[0] if preset else name_or_host
    rows = NT.web_check(host)
    level, msg = verdict(rows)
    out = {"host": host, "rows": rows, "level": level, "message": msg}
    if preset:
        out["official"] = official_status(name_or_host)
    return out
