# -*- coding: utf-8 -*-
"""Network Doctor Pro - a safe vulnerability & exposure check (what Nessus / Nuclei look for, made readable).

It only READS: it uses what the scan already found (open ports, web banners, SMB, vendor) and does a few
light, non-destructive probes (a TLS handshake, an LLMNR poison test). It never logs in, never sends an
exploit, never changes a device. Each finding has a severity and a plain-English fix.
"""
import re
import socket
import ssl
import struct
import time

import nd_core as core

# vendor -> the default login that ships on it, so you can be told to change it (we never try it)
DEFAULT_LOGINS = {
    "hikvision": "admin / 12345", "dahua": "admin / admin", "cp plus": "admin / admin",
    "tp-link": "admin / admin", "d-link": "admin / (blank)", "netgear": "admin / password",
    "mikrotik": "admin / (blank)", "ubiquiti": "ubnt / ubnt", "axis": "root / pass",
    "xiongmai": "admin / (blank)", "zte": "admin / admin", "huawei": "admin / admin",
}
RISKY_PORTS = {23: ("Telnet", "Telnet sends the password in clear text. Turn it off; use SSH."),
               21: ("FTP", "FTP sends the password in clear text. Use SFTP / FTPS, or turn it off."),
               3389: ("Remote Desktop", "Remote Desktop open on the LAN is fine; make sure it is NOT forwarded "
                                        "from the internet and uses a strong password + Network Level Auth."),
               5900: ("VNC", "VNC is often unencrypted and unauthenticated. Use a password and a tunnel, or turn "
                             "it off."),
               1900: ("UPnP", "UPnP lets devices open ports on the router by themselves. Turn UPnP off on the "
                              "router unless a device truly needs it.")}


def _f(sev, title, device, detail, fix):
    return {"sev": sev, "title": title, "device": device, "detail": detail, "fix": fix}


def tls_check(ip, port=443, timeout=3):
    """(protocol, cert_days_left, issue) for an HTTPS service. Non-destructive handshake only."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ss:
                proto = ss.version()
                cert = ss.getpeercert()
        days = None
        if cert and cert.get("notAfter"):
            exp = ssl.cert_time_to_seconds(cert["notAfter"])
            days = int((exp - time.time()) / 86400)
        issue = ""
        if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            issue = f"uses old {proto}"
        return proto, days, issue
    except Exception:
        return None, None, ""


def llmnr_probe(lip, timeout=2.0):
    """Sends an LLMNR query for a random name that cannot exist. If anything answers, a poisoner (Responder-
    style credential stealer) is on the network. Returns the list of responder IPs (usually empty = clean)."""
    name = "nd-" + "".join(f"{b:02x}" for b in __import__("os").urandom(6))
    # minimal LLMNR query packet
    tid = 0x1234
    q = struct.pack(">HHHHHH", tid, 0, 1, 0, 0, 0)
    q += bytes([len(name)]) + name.encode() + b"\x00" + struct.pack(">HH", 1, 1)
    responders = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((lip, 0))
        except Exception:
            pass
        s.settimeout(timeout)
        s.sendto(q, ("224.0.0.252", 5355))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                break
            if data[:2] == struct.pack(">H", tid) and addr[0] not in responders:
                responders.append(addr[0])
        s.close()
    except Exception:
        pass
    return responders


def assess(devices, db, mon=None, lip="", active=True, progress=lambda p, t: None):
    """All findings for the current network, most serious first. active=True does the light TLS / LLMNR probes."""
    out = []
    alive = [d for d in devices if d.get("online")]
    exposed = mon.traffic.all_exposed() if (mon and getattr(mon, "traffic", None)) else {}
    n = max(1, len(alive))
    for i, d in enumerate(alive):
        progress(int(90 * i / n), f"Checking {d.get('name') or d.get('ip')}...")
        ip = d.get("ip", "")
        name = d.get("name") or ip
        ports = set(d.get("ports") or [])
        vend = (d.get("vendor") or "").lower()
        http = d.get("http") or {}
        web = " ".join(str(http.get(k, "")) for k in ("title", "server", "realm", "blob")).lower()

        if ip in exposed:
            svc = ", ".join(f"port {p}" for p in sorted(exposed[ip]))
            out.append(_f("critical", "Reachable from the internet", name,
                          f"The internet can open {svc} on this device - attackers find these within days.",
                          "Remove the port-forward / UPnP rule on the router; view cameras through the maker's "
                          "app or a VPN instead."))
        for p, (nm, fix) in RISKY_PORTS.items():
            if p in ports:
                sev = "warning" if p in (3389,) else "critical" if p in (23, 21) else "warning"
                out.append(_f(sev, f"{nm} is open", name, f"{nm} (port {p}) is reachable.", fix))
        brand = next((b for b in DEFAULT_LOGINS if b in vend or b in web), None)
        if brand and (80 in ports or 8080 in ports or 443 in ports or 37777 in ports or 34567 in ports):
            out.append(_f("warning", "May still use its default password", name,
                          f"This looks like a {brand.title()} device. Default logins ({DEFAULT_LOGINS[brand]}) are "
                          "the first thing attackers try.",
                          "Log in and set a strong, unique password; update the firmware."))
        if 445 in ports and re.search(r"\bsmb(v)?1\b", web):
            out.append(_f("critical", "Old file sharing (SMBv1)", name,
                          "SMBv1 is the protocol WannaCry spread through.",
                          "Turn off SMBv1 (Windows Features > SMB 1.0) and update Windows."))
        if active and (443 in ports or 8443 in ports):
            port = 443 if 443 in ports else 8443
            proto, days, issue = tls_check(ip, port)
            if issue:
                out.append(_f("warning", "Weak HTTPS encryption", name, f"{issue} on port {port}.",
                              "Update the device / enable TLS 1.2+ only."))
            if days is not None and days < 0:
                out.append(_f("warning", "Expired HTTPS certificate", name, f"The certificate on port {port} "
                              "expired.", "Renew / regenerate the certificate (browsers will warn users)."))
    # LLMNR / NBT-NS poisoning (Responder) - one probe for the whole network
    if active and lip:
        progress(94, "Testing for a credential poisoner (LLMNR)...")
        resp = llmnr_probe(lip)
        if resp:
            out.append(_f("critical", "A credential poisoner is on the network", ", ".join(resp),
                          "A device answered a name that does not exist - this is how Responder-style tools trick "
                          "PCs into sending their passwords. " + ", ".join(resp) + " is doing it.",
                          "Find and unplug that device; then turn OFF LLMNR and NetBIOS on all PCs (see the "
                          "hardening commands below) so it cannot work again."))
    progress(100, "Done")
    sev_rank = {"critical": 0, "warning": 1, "info": 2}
    out.sort(key=lambda x: sev_rank.get(x["sev"], 3))
    return out


# ---- hardening commands: turn off the weak Windows defaults attackers rely on (run on each PC / via GPO)
HARDENING = [
    ("Turn off LLMNR (stops Responder name poisoning)",
     'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" /v EnableMulticast /t REG_DWORD '
     '/d 0 /f'),
    ("Turn off NetBIOS over TCP/IP (the other poisoning channel)",
     'powershell -NoProfile -Command "Get-ChildItem \'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\'
     'Parameters\\Interfaces\' | ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 2 }"'),
    ("Turn off SMBv1 (the WannaCry protocol)",
     "dism /online /norestart /disable-feature /featurename:SMB1Protocol"),
    ("Require SMB signing (stops relay attacks)",
     'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" /v RequireSecuritySignature '
     '/t REG_DWORD /d 1 /f'),
    ("Turn off WPAD (web-proxy auto-discovery, another poisoning path)",
     'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v EnableAutoProxy'
     'ResultCache /t REG_DWORD /d 0 /f'),
    ("Turn Windows Firewall on for all profiles",
     "netsh advfirewall set allprofiles state on"),
]
