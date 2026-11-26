# -*- coding: utf-8 -*-
"""Always-on collector buffer + gap-free, dedup-safe merge. The two things that MUST hold:
  1) two agents that both saw the same flow -> counted ONCE (no double count)
  2) re-pulling a buffer after a drop -> only new rows ingested (resumable, no re-count)
plus: a period covered by at least one agent has no gap; a period no agent covered is reported as a gap."""
import os
import tempfile
import unittest
import nd_collector as C


def flow(src, dst, sp, dp, proto, nbytes, start_ts):
    return {"src": src, "dst": dst, "sport": sp, "dport": dp, "proto": proto, "bytes": nbytes, "start_ts": start_ts}


class FlowId(unittest.TestCase):
    def test_same_record_same_id_across_agents(self):
        f = flow("192.168.0.27", "1.2.3.4", 50000, 443, 6, 9000, 1700000000.4)
        # two agents, different arrival clock, same router-reported start -> same id
        a = C.flow_id("192.168.0.1", f["start_ts"], f["src"], f["dst"], f["sport"], f["dport"], f["proto"])
        b = C.flow_id("192.168.0.1", f["start_ts"] + 0.9, f["src"], f["dst"], f["sport"], f["dport"], f["proto"])
        self.assertEqual(a, b)

    def test_different_flow_different_id(self):
        a = C.flow_id("192.168.0.1", 1700000000, "192.168.0.27", "1.2.3.4", 50000, 443, 6)
        b = C.flow_id("192.168.0.1", 1700000000, "192.168.0.28", "1.2.3.4", 50000, 443, 6)
        self.assertNotEqual(a, b)


class Buffer(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.p = os.path.join(self.d, "buf.db")

    def test_add_dedups_same_record_on_one_pc(self):
        b = C.CollectorBuffer(self.p)
        f = [flow("192.168.0.27", "1.2.3.4", 5000, 443, 6, 1000, 1700000000)]
        self.assertEqual(b.add(f, "192.168.0.1"), 1)
        self.assertEqual(b.add(f, "192.168.0.1"), 0)   # same record again -> not re-stored
        self.assertEqual(b.span()[2], 1)

    def test_rows_since_is_incremental(self):
        b = C.CollectorBuffer(self.p)
        b.add([flow("192.168.0.27", "1.2.3.4", 5000, 443, 6, 1000, 1700000000)], "192.168.0.1")
        b.add([flow("192.168.0.28", "1.2.3.4", 5001, 443, 6, 2000, 1700000600)], "192.168.0.1")
        first = b.rows_since(-1)
        self.assertEqual(len(first), 2)
        wm = max(r["bucket"] for r in first)
        self.assertEqual(b.rows_since(wm), [])         # nothing new past the watermark

    def test_bad_rows_skipped(self):
        b = C.CollectorBuffer(self.p)
        n = b.add([{"src": "", "dst": "x", "bytes": 5}, {"src": "a", "dst": "b", "bytes": 0},
                   flow("192.168.0.27", "1.2.3.4", 1, 2, 6, 500, 1700000000)], "192.168.0.1")
        self.assertEqual(n, 1)


class Merge(unittest.TestCase):
    def test_two_agents_same_flow_counted_once(self):
        f = flow("192.168.0.27", "1.2.3.4", 5000, 443, 6, 9000, 1700000000)
        d = tempfile.mkdtemp()
        a1 = C.CollectorBuffer(os.path.join(d, "a1.db"))
        a2 = C.CollectorBuffer(os.path.join(d, "a2.db"))
        a1.add([f], "192.168.0.1")
        a2.add([f], "192.168.0.1")   # the other agent saw the SAME flow
        ms = C.MergeState()
        applied = ms.merge_agent("pc1", a1.rows_since(-1)) + ms.merge_agent("pc2", a2.rows_since(-1))
        total = sum(r["bytes"] for r in applied)
        self.assertEqual(total, 9000)   # NOT 18000

    def test_repull_after_drop_adds_nothing(self):
        f = flow("192.168.0.27", "1.2.3.4", 5000, 443, 6, 9000, 1700000000)
        d = tempfile.mkdtemp()
        a1 = C.CollectorBuffer(os.path.join(d, "a1.db"))
        a1.add([f], "192.168.0.1")
        ms = C.MergeState()
        ms.merge_agent("pc1", a1.rows_since(ms.watermarks.get("pc1", -1)))
        # app restarts with persisted watermark, re-pulls same agent
        ms2 = C.MergeState(watermarks=ms.watermarks)
        again = ms2.merge_agent("pc1", a1.rows_since(ms2.watermarks.get("pc1", -1)))
        self.assertEqual(again, [])

    def test_agents_cover_each_others_gaps(self):
        # agent1 up 00:00-00:10, agent2 up 00:05-00:15 -> together cover 00:00-00:15, no gap
        d = tempfile.mkdtemp()
        a1 = C.CollectorBuffer(os.path.join(d, "a1.db"))
        a2 = C.CollectorBuffer(os.path.join(d, "a2.db"))
        base = 1700000000
        for i in range(0, 11):
            a1.add([flow("192.168.0.27", "1.2.3.4", 5000, 443, 6, 100, base + i * 60)], "192.168.0.1")
        for i in range(5, 16):
            a2.add([flow("192.168.0.28", "1.2.3.5", 5000, 443, 6, 100, base + i * 60)], "192.168.0.1")
        self.assertEqual(C.gaps(covered_sets=[a1.covered_buckets(), a2.covered_buckets()]), 0)

    def test_real_gap_is_reported(self):
        d = tempfile.mkdtemp()
        a1 = C.CollectorBuffer(os.path.join(d, "a1.db"))
        base = 1700000000
        a1.add([flow("192.168.0.27", "1.2.3.4", 5000, 443, 6, 100, base)], "192.168.0.1")
        a1.add([flow("192.168.0.27", "1.2.3.4", 5000, 443, 6, 100, base + 600)], "192.168.0.1")  # 10-min hole
        self.assertGreater(C.gaps(covered_sets=[a1.covered_buckets()]), 0)


if __name__ == "__main__":
    unittest.main()
