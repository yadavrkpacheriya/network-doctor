# -*- coding: utf-8 -*-
"""Recorders: keep the office's usage history complete while the Network Doctor PC is off.

Why days went blank: the router SENDS its traffic data (NetFlow, UDP 2055) and DNS log (syslog) to the
Network Doctor PC only. Nothing on the router keeps it, so every hour that PC (or the app) is off is lost.

The fix: one or more always-on office PCs that already run the Network Doctor PC agent are made "recorders".
The router sends a second copy of the same data to each recorder (UDP 2056 flows, UDP 5516 DNS log). The
recorder only writes what arrives, as it arrives, into 10-minute files on its own disk (no parsing, no
internet), and copies each finished file to the IT share whenever the share is reachable. When this app is on
again it imports every new file through the SAME code path as live traffic, so names, apps and categories come
out exactly as if the app had been running.

No double counting: time is cut into 10-second slices. A slice that the app itself received live is never
imported; otherwise, of all recorders that have data for that slice, the one with the most wins and the others
are skipped. Imported slices are remembered, so a file that arrives twice, or late, can never be counted again.

File formats written by the agent (endpoint/networkdoctor-agent.ps1, -Mode recorder):
  flow-YYYYMMDD-HHMM.ndf  binary, repeated: int64 LE arrival ms (UTC epoch), 4 bytes exporter IPv4,
                          uint16 LE length, payload (one NetFlow/IPFIX datagram as received)
  dns-YYYYMMDD-HHMM.txt   text, one line per syslog message: arrival ms <TAB> exporter <TAB> message
  arp-YYYYMMDD.csv        text: ms,ip,mac (which MAC had which IP, so history stays with the device)
  status.txt              key=value lines (version, ip, updated, last_packet, pending ...)
(file times are UTC; the share keeps them in <endpoint_dir>/collect/<PC NAME>/)
"""
import collections
import glob
import json
import os
import re
import sqlite3
import struct
import threading
import time

FLOW_PORT = 2056          # the recorders' flow port (the app itself keeps 2055 - never touched by these rules)
DNS_PORT = 5516           # the recorders' DNS-log port
SLICE = 10                # seconds
MAX_RECORDERS = 3         # each one is one more copy of the flow export on the router
ONLINE_SECS = 5 * 60      # a recorder whose status is fresher than this is "recording"
CHUNK_RE = re.compile(r"^(flow|dns)-(\d{8}-\d{4})\.(ndf|txt)$")
REC = struct.Struct("<q4sH")
LOG_ACTION = "ndrec-"      # router logging action names start with this (the reset removes them)


# ==========================================================================
# reading the recorder files (pure, never raise)
# ==========================================================================
def read_ndf(path):
    """[(arrival_seconds, exporter_ip, payload)] from a flow file. A cut-off last record is ignored."""
    out = []
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return out
    p, n = 0, len(data)
    while p + REC.size <= n:
        ms, ex, ln = REC.unpack_from(data, p)
        p += REC.size
        if p + ln > n or ms <= 0:
            break
        out.append((ms / 1000.0, ".".join(str(b) for b in ex), data[p:p + ln]))
        p += ln
    return out


def read_dns(path):
    """[(arrival_seconds, exporter_ip, message)] from a DNS-log file. Broken lines are skipped."""
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\r\n").split("\t", 2)
                if len(parts) != 3:
                    continue
                try:
                    out.append((int(parts[0]) / 1000.0, parts[1], parts[2]))
                except ValueError:
                    continue
    except OSError:
        pass
    return out


def read_arp(path):
    """{ip: mac} from a recorder's ARP file (the latest MAC seen for each IP that day)."""
    out = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) == 3 and parts[1] and parts[2]:
                    out[parts[1]] = parts[2]
    except OSError:
        pass
    return out


def read_status(path):
    out = {}
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                if "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def export_time(payload):
    """The router's own clock in a NetFlow v5/v9 or IPFIX header (seconds), or 0."""
    try:
        ver = struct.unpack("!H", payload[:2])[0]
        if ver in (5, 9) and len(payload) >= 12:
            return struct.unpack("!I", payload[8:12])[0]
        if ver == 10 and len(payload) >= 8:
            return struct.unpack("!I", payload[4:8])[0]
    except struct.error:
        pass
    return 0


def packet_time(arrival, payload):
    """When a flow packet counts. The router's clock is the same for the app and every recorder, so PCs whose
    clocks differ a little still agree on the slice. A router whose clock is clearly wrong (no NTP, back in
    1970 after a reboot) is ignored and the arrival time is used instead."""
    rt = export_time(payload)
    if rt and abs(rt - arrival) < 86400:
        return float(rt)
    return float(arrival)


def slice_of(t):
    return int(t // SLICE)


class _Conn:
    """sqlite connection used as 'with': commits (or rolls back) and always closes."""

    def __init__(self, path):
        self.c = sqlite3.connect(path, timeout=10)

    def __enter__(self):
        return self.c

    def __exit__(self, et, ev, tb):
        try:
            if et is None:
                self.c.commit()
            else:
                self.c.rollback()
        finally:
            self.c.close()
        return False


# ==========================================================================
# what the app itself received live, and what was already imported
# ==========================================================================
class Coverage:
    """Slices of time already in the usage history, per kind ('flow' / 'dns') and source ('main' = live)."""

    KEEP_DAYS = 45

    def __init__(self, path):
        self.path = path
        self.pending = collections.Counter()
        self.lock = threading.Lock()
        self._init()

    def _db(self):
        return _Conn(self.path)

    def _init(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS cover (kind TEXT, slice INT, src TEXT, n INT, "
                       "PRIMARY KEY (kind, slice, src))")
            db.execute("CREATE TABLE IF NOT EXISTS collect_files (name TEXT PRIMARY KEY, size INT, t INT, "
                       "owned INT)")
            db.execute("CREATE TABLE IF NOT EXISTS collect_state (k TEXT PRIMARY KEY, v TEXT)")

    def note(self, kind, t, n=1):
        """Live data arrived (called by the monitor for every flow packet / DNS-log line)."""
        with self.lock:
            self.pending[(kind, slice_of(t))] += n

    def flush(self):
        with self.lock:
            rows, self.pending = self.pending, collections.Counter()
        if not rows:
            return
        cut = slice_of(time.time() - self.KEEP_DAYS * 86400)
        with self._db() as db:
            db.executemany("INSERT INTO cover VALUES (?,?,'main',?) ON CONFLICT(kind, slice, src) DO UPDATE SET "
                           "n=n+excluded.n", [(k, s, n) for (k, s), n in rows.items()])
            db.execute("DELETE FROM cover WHERE slice < ?", (cut,))

    def covered(self, kind, lo, hi):
        """Slices between lo and hi (inclusive) already counted by any source."""
        self.flush()
        with self._db() as db:
            return {r[0] for r in db.execute("SELECT DISTINCT slice FROM cover WHERE kind=? AND slice BETWEEN ? AND ?",
                                             (kind, lo, hi))}

    def mark(self, kind, counts, src):
        if not counts:
            return
        with self._db() as db:
            db.executemany("INSERT INTO cover VALUES (?,?,?,?) ON CONFLICT(kind, slice, src) DO UPDATE SET "
                           "n=n+excluded.n", [(kind, s, src, n) for s, n in counts.items()])

    def is_done(self, name, size):
        with self._db() as db:
            r = db.execute("SELECT size FROM collect_files WHERE name=?", (name,)).fetchone()
        return bool(r) and r[0] == size

    def done(self, name, size, owned):
        with self._db() as db:
            db.execute("INSERT OR REPLACE INTO collect_files VALUES (?,?,?,?)", (name, size, int(time.time()), owned))

    def imported_by_pc(self):
        """{pc: (files, last import time)}"""
        out = {}
        with self._db() as db:
            for name, t in db.execute("SELECT name, t FROM collect_files"):
                pc = name.split("/", 1)[0]
                n, last = out.get(pc, (0, 0))
                out[pc] = (n + 1, max(last, t or 0))
        return out

    def get_state(self, k, default=None):
        with self._db() as db:
            r = db.execute("SELECT v FROM collect_state WHERE k=?", (k,)).fetchone()
        if not r:
            return default
        try:
            return json.loads(r[0])
        except ValueError:
            return default

    def set_state(self, k, v):
        with self._db() as db:
            db.execute("INSERT OR REPLACE INTO collect_state VALUES (?,?)", (k, json.dumps(v)))


# ==========================================================================
# templates: NetFlow v9 / IPFIX records can only be read with the router's templates
# ==========================================================================
def templates_to_json(tpl):
    return [[list(k), [list(f) for f in v]] for k, v in tpl.items()]


def templates_from_json(data):
    out = {}
    for k, v in data or []:
        try:
            out[tuple(k)] = [tuple(f) for f in v]
        except (TypeError, ValueError):
            continue
    return out


# ==========================================================================
# import
# ==========================================================================
def pc_dirs(roots):
    """[(pc_name, folder)] under each <root> (= <endpoint_dir>/collect). 'on' is the switch folder, not a PC."""
    out = []
    for root in roots or []:
        if not root or not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            p = os.path.join(root, name)
            if name.lower() != "on" and os.path.isdir(p):
                out.append((name, p))
    return out


def pending_files(roots, cov):
    """{chunk: [(pc, kind, path, size)]} of finished recorder files not imported yet, oldest chunk first."""
    out = collections.defaultdict(list)
    for pc, folder in pc_dirs(roots):
        for fn in os.listdir(folder):
            m = CHUNK_RE.match(fn)
            if not m:
                continue
            path = os.path.join(folder, fn)
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if not cov.is_done(f"{pc}/{fn}", size):
                out[m.group(2)].append((pc, m.group(1), path, size))
    return collections.OrderedDict(sorted(out.items()))


def owners(sources, covered):
    """sources: {src: Counter(slice -> amount)}. Returns {slice: src}: per slice not yet covered, the source
    with the most data (ties: alphabetical, so the choice is always the same)."""
    best = {}
    for src in sorted(sources):
        for s, n in sources[src].items():
            if s in covered or n <= 0:
                continue
            if s not in best or n > best[s][1]:
                best[s] = (src, n)
    return {s: v[0] for s, v in best.items()}


class _NoThreat:
    @staticmethod
    def check(ip):
        return None


class Importer:
    """Reads recorder files from the share and adds them to the usage history.
    store: nd_usage.UsageStore; cov: Coverage; make_traffic(sink) -> nd_monitor.TrafficStore-like with .add(rec)
    (the app passes one built like the live monitor's, with this sink, so LAN / NAT matching is identical);
    make_parser() -> a fresh nd_monitor.FlowParser."""

    def __init__(self, store, cov, make_traffic, make_parser):
        self.store, self.cov = store, cov
        self.make_traffic, self.make_parser = make_traffic, make_parser
        self.parser = make_parser()
        self.parser.templates.update(templates_from_json(cov.get_state("templates", [])))
        self._t = 0.0
        self._acc = None
        self.traffic = make_traffic(self._sink)

    def seed_templates(self, tpl):
        """Templates the live monitor already learned (so the first file can be read at once)."""
        for k, v in (tpl or {}).items():
            self.parser.templates.setdefault(k, v)

    def _sink(self, lan, remote, port, proto, nbytes, up, org=""):
        self.store.add_flow(lan, remote, port, proto, nbytes, up, org, now=self._t, acc=self._acc)

    def run(self, roots, stop=None, max_chunks=None):
        """Imports every finished file not imported yet. Returns {'chunks', 'flows', 'dns', 'skipped', 'pcs'}."""
        res = {"chunks": 0, "flows": 0, "dns": 0, "skipped": 0, "pcs": set()}
        work = pending_files(roots, self.cov)
        arp_cache = {}
        for chunk, files in work.items():
            if stop and stop():
                break
            if max_chunks is not None and res["chunks"] >= max_chunks:
                break
            self._chunk(chunk, files, res, arp_cache)
            res["chunks"] += 1
        self.cov.set_state("templates", templates_to_json(self.parser.templates))
        res["pcs"] = sorted(res["pcs"])
        return res

    def _arp_for(self, pc, folder, chunk, cache):
        key = (pc, chunk[:8])
        if key not in cache:
            cache[key] = read_arp(os.path.join(folder, f"arp-{chunk[:8]}.csv"))
        return cache[key]

    def _chunk(self, chunk, files, res, arp_cache):
        flows, dns, by_src_flow, by_src_dns = {}, {}, {}, {}
        hints = {}
        for pc, kind, path, size in files:
            if kind == "flow":
                pk = read_ndf(path)
                flows[pc] = [(packet_time(t, p), ex, p) for t, ex, p in pk]
                c = collections.Counter()
                for t, _, p in flows[pc]:
                    c[slice_of(t)] += len(p)
                by_src_flow[pc] = c
            else:
                dns[pc] = read_dns(path)
                c = collections.Counter()
                for t, _, _ in dns[pc]:
                    c[slice_of(t)] += 1
                by_src_dns[pc] = c
            hints.update(self._arp_for(pc, os.path.dirname(path), chunk, arp_cache))
        # who owns each slice
        own_f = self._owners("flow", by_src_flow)
        own_d = self._owners("dns", by_src_dns)
        # templates first: every packet of every recorder, in time order (a template may sit in another file)
        for t, ex, p in sorted((x for v in flows.values() for x in v), key=lambda x: x[0]):
            try:
                self.parser.parse(p, ex)
            except Exception:
                pass
        events = []
        for pc, pk in flows.items():
            for t, ex, p in pk:
                if own_f.get(slice_of(t)) == pc:
                    events.append((t, 1, "f", ex, p))
                else:
                    res["skipped"] += 1
        for pc, lines in dns.items():
            for t, ex, msg in lines:
                if own_d.get(slice_of(t)) == pc:
                    events.append((t, 0, "d", ex, msg))
                else:
                    res["skipped"] += 1
        events.sort(key=lambda e: (e[0], e[1]))
        self._acc = self.store.new_acc(hints)
        for t, _, kind, ex, p in events:
            self._t = t
            if kind == "d":
                text = re.sub(r"^<\d+>", "", p).strip()
                try:
                    if self.store.dns_log(text, now=t):
                        res["dns"] += 1
                except Exception:
                    pass
            else:
                try:
                    recs = self.parser.parse(p, ex)
                except Exception:
                    recs = []
                for r in recs:
                    try:
                        self.traffic.add(r)
                        res["flows"] += 1
                    except Exception:
                        pass
        self.store.write_acc(self._acc)
        self._acc = None
        # remember: these slices are in the history now, these files are done
        for kind, own in (("flow", own_f), ("dns", own_d)):
            per_src = collections.defaultdict(collections.Counter)
            src_counts = by_src_flow if kind == "flow" else by_src_dns
            for s, src in own.items():
                per_src[src][s] = src_counts[src][s]
            for src, counts in per_src.items():
                self.cov.mark(kind, counts, src)
        for pc, kind, path, size in files:
            owned = sum(1 for s, src in (own_f if kind == "flow" else own_d).items() if src == pc)
            self.cov.done(f"{pc}/{os.path.basename(path)}", size, owned)
            res["pcs"].add(pc)

    def _owners(self, kind, sources):
        slices = [s for c in sources.values() for s in c]
        if not slices:
            return {}
        return owners(sources, self.cov.covered(kind, min(slices), max(slices)))


# ==========================================================================
# turning a PC into a recorder (share switch + router commands)
# ==========================================================================
def _action_name(ip):
    return LOG_ACTION + ip.replace(".", "-")


def router_add(ip):
    """RouterOS commands that send a COPY of the traffic data and DNS log to a recorder PC. Nothing the app
    already uses changes (its own target on port 2055 and its 'netdoctor' log action stay as they are).
    Safe to run again: the recorder's old entries are replaced."""
    a = _action_name(ip)
    return "\n".join([
        f"# Network Doctor recorder {ip}: a second copy of the traffic data + DNS log (undo: 'Stop recording')",
        "/ip traffic-flow set enabled=yes",
        f":do {{/ip traffic-flow target remove [find where port={FLOW_PORT} and dst-address={ip}]}} on-error={{}}",
        f"/ip traffic-flow target add dst-address={ip} port={FLOW_PORT} version=9",
        f":do {{/system logging remove [find where action={a}]}} on-error={{}}",
        f":do {{/system logging action remove [find where name={a}]}} on-error={{}}",
        f"/system logging action add name={a} target=remote remote={ip} remote-port={DNS_PORT}",
        f"/system logging add topics=dns,!packet action={a}",
    ]) + "\n"


def router_remove(ip=None):
    """Undo for one recorder, or for all recorders (ip=None). Only the recorders' own entries match:
    flow targets on port 2056 and log actions named 'ndrec-...'."""
    if ip:
        a = _action_name(ip)
        return "\n".join([
            f":do {{/ip traffic-flow target remove [find where port={FLOW_PORT} and dst-address={ip}]}} on-error={{}}",
            f":do {{/system logging remove [find where action={a}]}} on-error={{}}",
            f":do {{/system logging action remove [find where name={a}]}} on-error={{}}",
        ]) + "\n"
    return "\n".join([
        f":do {{/ip traffic-flow target remove [find where port={FLOW_PORT}]}} on-error={{}}",
        f':do {{:foreach r in=[/system logging find where action~"^{LOG_ACTION}"] do={{/system logging remove $r}}}} '
        "on-error={}",
        f':do {{/system logging action remove [find where name~"^{LOG_ACTION}"]}} on-error={{}}',
    ]) + "\n"


def switch_dir(central):
    return os.path.join(central, "collect", "on")


def set_switch(central, pc, on, secret):
    """Writes (on) or removes (off) <share>/collect/on/<PC>.txt. The agent records only while this file holds
    the IT secret, and remembers the answer locally so it keeps recording while the share is off."""
    d = switch_dir(central)
    p = os.path.join(d, f"{pc}.txt")
    if on:
        os.makedirs(d, exist_ok=True)
        with open(p, "w", encoding="ascii") as f:
            f.write(secret or "on")
    else:
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
    return p


def switched_on(central):
    d = switch_dir(central)
    try:
        return sorted(f[:-4] for f in os.listdir(d) if f.lower().endswith(".txt"))
    except OSError:
        return []


def status(central, cov=None, now=None, agents=None):
    """One row per recorder (switched on, or with files in the share):
    {pc, ip, on, state, last_data, updated, pending, imported, version}. agents: {pc: ip} from the PC agents'
    reports, so a recorder whose PC changed IP is flagged (the router would still send to the old one)."""
    now = now or time.time()
    root = os.path.join(central, "collect") if central else ""
    on = set(switched_on(central)) if central else set()
    dirs = dict(pc_dirs([root])) if root else {}
    imp = cov.imported_by_pc() if cov else {}
    rows = []
    for pc in sorted(on | set(dirs)):
        st = read_status(os.path.join(dirs[pc], "status.txt")) if pc in dirs else {}
        try:
            upd = float(st.get("updated") or 0) / 1000.0
        except ValueError:
            upd = 0
        try:
            last = float(st.get("last_packet") or 0) / 1000.0
        except ValueError:
            last = 0
        waiting = 0
        if cov and pc in dirs:
            for fn in os.listdir(dirs[pc]):
                if CHUNK_RE.match(fn):
                    try:
                        if not cov.is_done(f"{pc}/{fn}", os.path.getsize(os.path.join(dirs[pc], fn))):
                            waiting += 1
                    except OSError:
                        pass
        ip = st.get("ip", "")
        if pc not in on:
            state = "Off"
        elif not st:
            state = "Waiting for the PC agent"
        elif now - upd > ONLINE_SECS:
            state = "PC off or agent not running"
        elif not last or now - last > 15 * 60:
            state = "On - no data from the router yet"
        else:
            state = "Recording"
        ag = (agents or {}).get(pc)
        rows.append({"pc": pc, "ip": ip, "on": pc in on, "state": state, "last_data": last, "updated": upd,
                     "pending_on_pc": int(st.get("pending") or 0) if str(st.get("pending", "0")).isdigit() else 0,
                     "waiting": waiting, "imported": imp.get(pc, (0, 0))[0], "version": st.get("version", ""),
                     "ip_changed": bool(ag and ip and ag != ip)})
    return rows


def fmt_ago(t, now=None):
    if not t:
        return "never"
    s = max(0, int((now or time.time()) - t))
    if s < 90:
        return "just now"
    if s < 5400:
        return f"{s // 60} min ago"
    if s < 2 * 86400:
        return f"{s // 3600} h ago"
    return f"{s // 86400} days ago"
