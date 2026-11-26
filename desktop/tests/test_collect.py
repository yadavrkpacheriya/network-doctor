"""Recorders (nd_collect): offline hours are filled from recorder PCs, and nothing is ever counted twice."""
import os
import shutil
import socket
import sqlite3
import struct
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_collect as CL  # noqa: E402
import nd_monitor as M  # noqa: E402
import nd_reset as R  # noqa: E402
import nd_usage as U  # noqa: E402

ROUTER = "192.168.0.1"
PCIP = "192.168.0.50"
GOOGLE = "142.250.1.1"
LAN = "192.168.0.0/24"
# fields: src, dst, sport, dport, proto, bytes
TPL_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4)]


def v9_header(count, rtime, seq=1):
    return struct.pack("!HHIIII", 9, count, 1000, int(rtime), seq, 0)


def v9_template(rtime):
    body = struct.pack("!HH", 256, len(TPL_FIELDS)) + b"".join(struct.pack("!HH", t, ln) for t, ln in TPL_FIELDS)
    fs = struct.pack("!HH", 0, 4 + len(body)) + body
    return v9_header(1, rtime) + fs


def v9_data(rtime, flows):
    """flows: [(src, dst, sport, dport, proto, bytes)]"""
    recs = b"".join(socket.inet_aton(s) + socket.inet_aton(d) + struct.pack("!HHBI", sp, dp, pr, b)
                    for s, d, sp, dp, pr, b in flows)
    fs = struct.pack("!HH", 256, 4 + len(recs)) + recs
    return v9_header(len(flows), rtime) + fs


def up_flow(nbytes, ip=PCIP):
    return (ip, GOOGLE, 50000, 443, 6, nbytes)


def write_ndf(path, packets):
    """packets: [(arrival_seconds, payload)]"""
    with open(path, "ab") as f:
        for t, p in packets:
            f.write(CL.REC.pack(int(t * 1000), socket.inet_aton(ROUTER), len(p)) + p)


def chunk_name(t):
    tm = time.gmtime(t)
    return time.strftime("%Y%m%d-%H", tm) + "%02d" % (tm.tm_min // 10 * 10)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = U.UsageStore(os.path.join(self.tmp, "usage.db"))
        self.cov = CL.Coverage(self.store.path)
        self.root = os.path.join(self.tmp, "share", "collect")
        os.makedirs(self.root)
        # a fixed past hour, on a 10-minute boundary
        self.t0 = (int(time.time()) // 3600 - 5) * 3600

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def importer(self):
        def make_traffic(sink):
            t = M.TrafficStore(LAN, CL._NoThreat(), None, lambda *a, **k: None)
            t.sink = sink
            return t
        return CL.Importer(self.store, self.cov, make_traffic, M.FlowParser)

    def pcdir(self, pc):
        d = os.path.join(self.root, pc)
        os.makedirs(d, exist_ok=True)
        return d

    def record(self, pc, start, end, every=10, nbytes=1000, template=True, clock_ok=True, ip=PCIP):
        """A recorder that received one flow packet every `every` s between start and end (seconds)."""
        d = self.pcdir(pc)
        t = start
        first = True
        while t < end:
            rt = t if clock_ok else 100000 + (t - start)
            pk = []
            if template and first:
                pk.append((t, v9_template(rt)))
                first = False
            pk.append((t + 0.1, v9_data(rt, [up_flow(nbytes, ip)])))
            write_ndf(os.path.join(d, f"flow-{chunk_name(t)}.ndf"), pk)
            t += every

    def total_bytes(self):
        with sqlite3.connect(self.store.path) as db:
            return db.execute("SELECT COALESCE(SUM(up+down),0) FROM usage").fetchone()[0]


class Files(Base):
    def test_ndf_round_trip_and_cut_last_record(self):
        p = os.path.join(self.tmp, "f.ndf")
        write_ndf(p, [(self.t0, b"abc"), (self.t0 + 1, b"defg")])
        with open(p, "ab") as f:
            f.write(CL.REC.pack(int(self.t0 * 1000), b"\0\0\0\0", 50) + b"short")   # PC switched off mid-write
        got = CL.read_ndf(p)
        self.assertEqual([x[2] for x in got], [b"abc", b"defg"])
        self.assertEqual(got[0][1], ROUTER)

    def test_router_clock_used_only_when_sane(self):
        p = v9_data(self.t0 + 5, [up_flow(10)])
        self.assertEqual(CL.packet_time(self.t0 + 7, p), self.t0 + 5)       # PC clock 2 s off: router wins
        bad = v9_data(100000, [up_flow(10)])                                  # router back in 1970
        self.assertEqual(CL.packet_time(self.t0 + 7, bad), self.t0 + 7)

    def test_missing_folder_or_no_files(self):
        res = self.importer().run([os.path.join(self.tmp, "nope"), self.root])
        self.assertEqual(res["chunks"], 0)
        self.assertEqual(self.total_bytes(), 0)


class Gaps(Base):
    def test_offline_hour_is_filled(self):
        self.record("PC-A", self.t0, self.t0 + 3600)
        res = self.importer().run([self.root])
        self.assertEqual(res["pcs"], ["PC-A"])
        self.assertEqual(self.total_bytes(), 360 * 1000)

    def test_seconds_the_app_had_live_are_not_counted_again(self):
        # the app was on from t0+30min (live slices noted), the recorder ran the whole hour
        for t in range(self.t0 + 1800, self.t0 + 3600, 10):
            self.cov.note("flow", t, 100)
        self.cov.flush()
        self.record("PC-A", self.t0, self.t0 + 3600)
        self.importer().run([self.root])
        self.assertEqual(self.total_bytes(), 180 * 1000)      # only the first half came from the recorder

    def test_pc_clocks_that_differ_still_match_by_router_clock(self):
        # the app's PC clock is 40 s ahead; it notes live packets exactly as the monitor hook does
        for t in range(self.t0, self.t0 + 600, 10):
            p = v9_data(t, [up_flow(1000)])
            self.cov.note("flow", CL.packet_time(t + 40, p), len(p))
        self.cov.flush()
        self.record("PC-A", self.t0, self.t0 + 1200)
        self.importer().run([self.root])
        self.assertEqual(self.total_bytes(), 60 * 1000)      # only 10-20 min, the part the app did not have

    def test_two_recorders_same_data_counted_once(self):
        self.record("PC-A", self.t0, self.t0 + 1200)
        self.record("PC-B", self.t0, self.t0 + 1200)
        self.importer().run([self.root])
        self.assertEqual(self.total_bytes(), 120 * 1000)

    def test_two_recorders_partly_overlapping_give_the_union(self):
        self.record("PC-A", self.t0, self.t0 + 1200)          # 00-20
        self.record("PC-B", self.t0 + 600, self.t0 + 1800)    # 10-30
        self.importer().run([self.root])
        self.assertEqual(self.total_bytes(), 180 * 1000)      # 00-30 once

    def test_a_late_file_from_a_second_recorder_is_not_double_counted(self):
        self.record("PC-A", self.t0, self.t0 + 600)
        imp = self.importer()
        imp.run([self.root])
        self.record("PC-B", self.t0, self.t0 + 600)            # arrives later (its PC was off too)
        imp.run([self.root])
        self.assertEqual(self.total_bytes(), 60 * 1000)

    def test_running_again_imports_nothing_new(self):
        self.record("PC-A", self.t0, self.t0 + 1200)
        self.importer().run([self.root])
        res = self.importer().run([self.root])                 # a fresh app start reads the same share
        self.assertEqual(res["chunks"], 0)
        self.assertEqual(self.total_bytes(), 120 * 1000)

    def test_recorder_that_was_off_too_leaves_a_true_gap(self):
        self.record("PC-A", self.t0, self.t0 + 600)
        self.record("PC-A", self.t0 + 1800, self.t0 + 2400)   # off from 10 to 30 min
        self.importer().run([self.root])
        self.assertEqual(self.total_bytes(), 120 * 1000)

    def test_template_in_another_recorders_file_or_earlier_chunk(self):
        # PC-B's file has no template; PC-A's earlier chunk had it (kept between chunks and runs)
        self.record("PC-A", self.t0, self.t0 + 600)
        self.importer().run([self.root])
        self.record("PC-B", self.t0 + 600, self.t0 + 1200, template=False)
        self.importer().run([self.root])                        # new importer: templates come from the db
        self.assertEqual(self.total_bytes(), 120 * 1000)

    def test_bad_router_clock_still_imports_by_arrival_time(self):
        self.record("PC-A", self.t0, self.t0 + 600, clock_ok=False)
        self.importer().run([self.root])
        with sqlite3.connect(self.store.path) as db:
            hours = {r[0] for r in db.execute("SELECT hour FROM usage")}
        self.assertEqual(hours, {time.localtime(self.t0).tm_hour})
        self.assertEqual(self.total_bytes(), 60 * 1000)

    def test_unfinished_tmp_files_are_ignored(self):
        self.record("PC-A", self.t0, self.t0 + 600)
        d = self.pcdir("PC-A")
        fn = os.listdir(d)[0]
        os.rename(os.path.join(d, fn), os.path.join(d, fn + ".tmp"))
        self.assertEqual(self.importer().run([self.root])["chunks"], 0)


class Naming(Base):
    def test_dns_log_names_the_traffic_and_arp_keeps_the_device(self):
        d = self.pcdir("PC-A")
        c = chunk_name(self.t0)
        ms = int(self.t0 * 1000)
        with open(os.path.join(d, f"dns-{c}.txt"), "w", encoding="utf-8") as f:
            f.write(f"{ms}\t{ROUTER}\t<30>dns query from {PCIP}: #7 www.youtube.com. A\n")
            f.write(f"{ms + 5}\t{ROUTER}\t<30>dns done query: #7 www.youtube.com {GOOGLE}\n")
        with open(os.path.join(d, f"arp-{c[:8]}.csv"), "w") as f:
            f.write(f"{ms},{PCIP},aa-bb-cc-dd-ee-ff\n")
        self.record("PC-A", self.t0 + 1, self.t0 + 600, nbytes=2_000_000)
        res = self.importer().run([self.root])
        self.assertGreaterEqual(res["dns"], 1)
        with sqlite3.connect(self.store.path) as db:
            rows = db.execute("SELECT dev, app FROM usage").fetchall()
            act = db.execute("SELECT SUM(minutes) FROM active").fetchone()[0]
        self.assertEqual({r[0] for r in rows}, {"AA:BB:CC:DD:EE:FF"})
        self.assertIn("YouTube", {r[1] for r in rows})
        self.assertTrue(act and act >= 5)

    def test_live_add_flow_unchanged(self):
        self.store.add_flow(PCIP, GOOGLE, 443, 6, 5000, True)
        self.store.flush(force=True)
        self.assertEqual(self.total_bytes(), 5000)


class RouterSafety(unittest.TestCase):
    def test_add_and_remove_never_touch_the_apps_own_feed(self):
        add, rem, rem_all = CL.router_add("192.168.0.20"), CL.router_remove("192.168.0.20"), CL.router_remove()
        for s in (add, rem, rem_all):
            self.assertNotIn("2055", s)
            self.assertNotIn("action=netdoctor", s)
            for line in s.splitlines():
                if "remove" in line:
                    self.assertIn("where", line)
                    self.assertNotIn("[find]", line)
                self.assertEqual(line.count("{"), line.count("}"), line)
                self.assertEqual(line.count('"') % 2, 0, line)
        self.assertIn("port=2056", add)
        self.assertIn("ndrec-192-168-0-20", add)

    def test_reset_removes_recorders(self):
        s, _ = R.reset_commands(("limits",))
        self.assertIn("port=2056", s)
        self.assertIn("ndrec-", s)
        self.assertNotIn("port=2055", s)
        found = R.classify({"/ip traffic-flow target": [{"dst-address": "192.168.0.10", "port": "2055"},
                                                         {"dst-address": "192.168.0.20", "port": "2056"}],
                            "/system logging action": [{"name": "netdoctor"}, {"name": "ndrec-192-168-0-20"}]})
        removed = [w for _, w in found["remove"]]
        self.assertEqual(len(removed), 2)
        self.assertTrue(any("192.168.0.20" in w for w in removed))
        self.assertNotIn("netdoctor", removed)


class Status(Base):
    def test_switch_and_states(self):
        central = os.path.dirname(self.root)
        CL.set_switch(central, "PC-A", True, "s3cret")
        with open(os.path.join(central, "collect", "on", "PC-A.txt")) as f:
            self.assertEqual(f.read(), "s3cret")
        rows = CL.status(central, self.cov)
        self.assertEqual(rows[0]["state"], "Waiting for the PC agent")
        now_ms = int(time.time() * 1000)
        with open(os.path.join(self.pcdir("PC-A"), "status.txt"), "w") as f:
            f.write(f"version=1.4.0\nip=192.168.0.20\nupdated={now_ms}\nlast_packet={now_ms}\npending=2\n")
        self.record("PC-A", self.t0, self.t0 + 600)
        r = CL.status(central, self.cov, agents={"PC-A": "192.168.0.21"})[0]
        self.assertEqual(r["state"], "Recording")
        self.assertEqual(r["waiting"], 1)
        self.assertEqual(r["pending_on_pc"], 2)
        self.assertTrue(r["ip_changed"])
        old = now_ms - 3600 * 1000
        with open(os.path.join(self.pcdir("PC-A"), "status.txt"), "w") as f:
            f.write(f"ip=192.168.0.20\nupdated={old}\nlast_packet={old}\n")
        self.assertEqual(CL.status(central, self.cov)[0]["state"], "PC off or agent not running")
        CL.set_switch(central, "PC-A", False, "")
        self.assertEqual(CL.status(central, self.cov)[0]["state"], "Off")

    def test_owners_pick_the_fullest_and_skip_covered(self):
        import collections
        o = CL.owners({"B": collections.Counter({1: 5, 2: 5}), "A": collections.Counter({1: 5, 2: 1, 3: 4})}, {3})
        self.assertEqual(o, {1: "A", 2: "B"})


if __name__ == "__main__":
    unittest.main()


AGENT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "endpoint",
                     "networkdoctor-agent.ps1")


@unittest.skipUnless(sys.platform == "win32", "the PC agent is Windows PowerShell")
class AgentOnWindows(unittest.TestCase):
    def test_powershell_can_parse_the_agent(self):
        import subprocess
        ps = ("$t = $null; $e = $null; "
              f"[void][System.Management.Automation.Language.Parser]::ParseFile('{AGENT}', [ref]$t, [ref]$e); "
              "if ($e) { $e | ForEach-Object { $_.ToString() } }")
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True,
                           errors="replace", timeout=120)
        self.assertEqual((r.stdout + r.stderr).strip(), "")

    @unittest.skipUnless(os.environ.get("GITHUB_ACTIONS"), "writes to ProgramData: only on the CI runner")
    def test_recorder_saves_packets_and_copies_them_to_the_share(self):
        """The real agent in -Mode recorder: receives flow + DNS-log packets, writes them, and when IT switches it
        off it copies everything to the share in the format the importer reads."""
        import subprocess
        nd = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "NetworkDoctor")
        os.makedirs(nd, exist_ok=True)
        share = tempfile.mkdtemp()
        cfg, flag = os.path.join(nd, "central.txt"), os.path.join(nd, "recorder.txt")
        old = open(cfg, encoding="utf-8").read() if os.path.exists(cfg) else None
        try:
            with open(cfg, "w", encoding="ascii") as f:
                f.write(share + "\n")
            with open(flag, "w", encoding="ascii") as f:
                f.write("on")
            p = subprocess.Popen(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", AGENT,
                                  "-Mode", "recorder"])
            time.sleep(8)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            now = time.time()
            payloads = [v9_template(now), v9_data(now, [up_flow(1234)])]
            for pl in payloads:
                s.sendto(pl, ("127.0.0.1", CL.FLOW_PORT))
            s.sendto(b"<30>dns query from 192.168.0.50: #7 www.youtube.com. A", ("127.0.0.1", CL.DNS_PORT))
            time.sleep(2)
            os.remove(flag)                      # IT switched it off: it finishes, copies everything, exits
            p.wait(timeout=150)
            pcdir = os.path.join(share, "collect", os.environ["COMPUTERNAME"])
            files = sorted(os.listdir(pcdir))
            flows = [x for f in files if f.startswith("flow-") for x in CL.read_ndf(os.path.join(pcdir, f))]
            dns = [x for f in files if f.startswith("dns-") for x in CL.read_dns(os.path.join(pcdir, f))]
            self.assertEqual([x[2] for x in flows], payloads)
            self.assertEqual(flows[0][1], "127.0.0.1")
            self.assertLess(abs(flows[0][0] - now), 120)
            self.assertIn("www.youtube.com", dns[0][2])
            self.assertIn("status.txt", files)
            self.assertTrue(all(CL.CHUNK_RE.match(f) or f.startswith(("status", "arp-")) for f in files), files)
        finally:
            if old is None:
                os.remove(cfg)
            else:
                with open(cfg, "w", encoding="utf-8") as f:
                    f.write(old)
            shutil.rmtree(share, ignore_errors=True)
