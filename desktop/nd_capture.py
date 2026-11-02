# -*- coding: utf-8 -*-
"""Network Doctor Pro - packet capture & analysis (Wireshark + Zeek, made readable).

Captures packets on the PC for a few seconds, then explains them in plain words: which protocols, who talked
to whom, the DNS names looked up, and anything suspicious (clear-text passwords, a port scan, a SYN flood).
Needs scapy (bundled with the app) and admin rights to capture.
"""
import collections
import threading
import time

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Ether, ARP  # noqa: F401
    HAVE_SCAPY = True
except Exception:
    HAVE_SCAPY = False

CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP", 25: "SMTP", 389: "LDAP"}


class Capture:
    """Runs a capture in the background; analyse() turns it into a readable report."""

    def __init__(self):
        self.pkts = []
        self.running = False
        self._stop = None
        self.error = ""
        self.started = 0

    def start(self, seconds=20, bpf="", on_done=None):
        if not HAVE_SCAPY:
            self.error = "Packet capture needs Npcap (Windows) or libpcap. Install Npcap from npcap.com."
            if on_done:
                on_done(self)
            return False
        self.pkts, self.running, self.error, self.started = [], True, "", time.time()
        self._stop = threading.Event()

        def run():
            try:
                def keep(p):
                    self.pkts.append(p)
                    return len(self.pkts) >= 60000  # safety cap
                sniff(prn=None, timeout=seconds, stop_filter=lambda p: self._stop.is_set() or keep(p),
                      store=True, filter=bpf or None, lfilter=None)
            except PermissionError:
                self.error = "Capture needs administrator rights (Restart as Administrator)."
            except Exception as e:
                self.error = str(e)
            self.running = False
            if on_done:
                on_done(self)
        threading.Thread(target=run, daemon=True).start()
        return True

    def stop(self):
        if self._stop:
            self._stop.set()

    def analyse(self, lan_prefix=""):
        pkts = list(self.pkts)
        protos = collections.Counter()
        talkers = collections.Counter()
        convos = collections.Counter()
        dns_q = collections.Counter()
        syn_from = collections.Counter()
        ports_hit = collections.defaultdict(set)
        cleartext = []
        total_bytes = 0
        for p in pkts:
            total_bytes += len(p)
            if IP in p:
                src, dst = p[IP].src, p[IP].dst
                talkers[src] += len(p)
                convos[(src, dst)] += len(p)
                if TCP in p:
                    protos["TCP"] += 1
                    fl = p[TCP].flags
                    if fl == "S":  # SYN only = a new connection attempt (many = a scan)
                        syn_from[src] += 1
                        ports_hit[src].add((dst, p[TCP].dport))
                    dport = int(p[TCP].dport)
                    if dport in CLEARTEXT_PORTS and bytes(p[TCP].payload):
                        cleartext.append((src, dst, CLEARTEXT_PORTS[dport]))
                elif UDP in p:
                    protos["UDP"] += 1
                    if p.haslayer(DNS) and p.haslayer(DNSQR):
                        try:
                            dns_q[p[DNSQR].qname.decode(errors="replace").rstrip(".")] += 1
                        except Exception:
                            pass
                else:
                    protos[p[IP].proto and "other-IP" or "IP"] += 1
            elif ARP in p:
                protos["ARP"] += 1
            else:
                protos["other"] += 1

        findings = []
        for src, n in syn_from.items():
            targets = ports_hit.get(src, set())
            hosts = {t[0] for t in targets}
            if len(targets) >= 40 or len(hosts) >= 15:
                findings.append(("critical", f"{src} is scanning the network",
                                 f"{src} opened {len(targets)} connections to {len(hosts)} devices in a few seconds "
                                 "- that is a port scan (an intruder mapping the network, or malware spreading)."))
        if cleartext:
            by = collections.Counter(c[2] for c in cleartext)
            findings.append(("warning", "Passwords sent in clear text",
                             "These protocols send the password readable on the wire: " +
                             ", ".join(f"{k} ({v}x)" for k, v in by.items()) +
                             ". Switch to the secure version (HTTPS, SFTP, SSH, IMAPS)."))
        floods = [s for s, n in syn_from.items() if n >= 500]
        if floods:
            findings.append(("critical", "Possible SYN flood",
                             ", ".join(floods) + " sent a flood of connection attempts - a denial-of-service or a "
                             "very aggressive scan."))

        return {
            "packets": len(pkts), "bytes": total_bytes, "seconds": round(time.time() - self.started, 1) if self.started else 0,
            "protocols": protos.most_common(),
            "talkers": [{"ip": ip, "bytes": b} for ip, b in talkers.most_common(15)],
            "conversations": [{"a": a, "b": b, "bytes": n} for (a, b), n in convos.most_common(15)],
            "dns": [{"name": q, "n": n} for q, n in dns_q.most_common(25)],
            "findings": findings,
        }
