# -*- coding: utf-8 -*-
"""Always-on usage collector buffer + gap-free, dedup-safe merge.

Problem: the router streams NetFlow to ONE PC's IP. When that PC is off, flows are lost - a gap in office usage.
Fix: every agent PC (the main PC, and the tamper-proof agents on other PCs) runs this buffer and records the
flows it receives into its own small SQLite file. When the main app is back online it pulls each agent's buffer
and merges - and because two agents may both have been up for the same minute, the merge MUST NOT double-count.

How double-counting is prevented: each buffered flow carries a deterministic flow_id =
  hash(exporter, start_bucket, src, dst, sport, dport, proto)
Two agents that received the SAME NetFlow record compute the SAME flow_id, so the merge keeps it once. A flow
is bucketed to its router-reported start time (not arrival time), so clock skew between agents doesn't split one
flow into two. The main app also tracks, per agent, the last start-bucket it has already merged ('watermark'),
so re-pulling a buffer only ingests new rows - resumable after a connection drop, no re-counting.

This module is pure + unit-tested (no sockets, no router). The agent feeds it parsed flow dicts; the app reads
buffers and calls merge(). Nothing here raises on bad input - a bad row is skipped."""

import hashlib
import os
import sqlite3
import time

# A flow is bucketed to this many seconds of its start time. NetFlow active-flow-timeout is 1m, so 60s lines up
# one exported record to one bucket and makes the id identical across agents that saw the same record.
BUCKET = 60
SCHEMA_VERSION = 1


def flow_id(exporter, start_ts, src, dst, sport, dport, proto):
    """Deterministic id for one flow record, identical on every agent that received the same NetFlow row, so a
    merge keeps it exactly once. Bucketed start time absorbs small clock differences between agents."""
    bucket = int(start_ts // BUCKET) * BUCKET
    key = "%s|%d|%s|%s|%d|%d|%d" % (exporter or "", bucket, src or "", dst or "", int(sport or 0),
                                    int(dport or 0), int(proto or 0))
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


def _norm(flow, exporter, now):
    """Turn a parsed NetFlow dict into a buffer row, or None if unusable. start_ts defaults to now when the
    exporter didn't give a flow start (we still bucket it, so agents that saw it within the same minute agree)."""
    try:
        src = flow["src"]
        dst = flow["dst"]
        nbytes = int(flow.get("bytes") or 0)
        if nbytes <= 0 or not src or not dst:
            return None
        sport = int(flow.get("sport") or 0)
        dport = int(flow.get("dport") or 0)
        proto = int(flow.get("proto") or 0)
        start_ts = float(flow.get("start_ts") or now)
        bucket = int(start_ts // BUCKET) * BUCKET
        fid = flow_id(exporter, start_ts, src, dst, sport, dport, proto)
        pkts = int(flow.get("pkts") or 0)
        return (fid, exporter or "", bucket, src, dst, sport, dport, proto, nbytes, pkts)
    except Exception:  # noqa: BLE001 - one bad row must never stop the buffer
        return None


class CollectorBuffer:
    """One agent's local flow buffer (its own SQLite file). Append-only; de-duped by flow_id so even if the same
    record is written twice on this PC it is stored once. Prunes rows older than keep_days so it can run forever."""

    def __init__(self, path, keep_days=14):
        self.path = path
        self.keep_days = keep_days
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self._init()

    def _db(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def _init(self):
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS flows (fid TEXT PRIMARY KEY, exporter TEXT, bucket INT, "
                       "src TEXT, dst TEXT, sport INT, dport INT, proto INT, bytes INT, pkts INT)")
            db.execute("CREATE INDEX IF NOT EXISTS flows_bucket ON flows(bucket)")
            db.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
            db.execute("INSERT OR IGNORE INTO meta VALUES ('schema', ?)", (str(SCHEMA_VERSION),))

    def add(self, flows, exporter, now=None):
        """Buffer a batch of parsed NetFlow dicts. Returns how many NEW rows were stored (duplicates ignored)."""
        now = now or time.time()
        rows = [r for r in (_norm(f, exporter, now) for f in (flows or [])) if r]
        if not rows:
            return 0
        with self._db() as db:
            before = db.total_changes
            db.executemany("INSERT OR IGNORE INTO flows VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
            added = db.total_changes - before
        return added

    def prune(self, now=None):
        now = now or time.time()
        cutoff = int((now - self.keep_days * 86400) // BUCKET) * BUCKET
        with self._db() as db:
            db.execute("DELETE FROM flows WHERE bucket < ?", (cutoff,))

    def rows_since(self, after_bucket=-1, limit=50000):
        """Flow rows with bucket > after_bucket, oldest first (for the app to pull incrementally). Returns a list
        of dicts. after_bucket is the app's watermark for THIS agent, so a re-pull only returns new rows."""
        with self._db() as db:
            cur = db.execute("SELECT fid, exporter, bucket, src, dst, sport, dport, proto, bytes, pkts "
                             "FROM flows WHERE bucket > ? ORDER BY bucket LIMIT ?", (int(after_bucket), limit))
            cols = ("fid", "exporter", "bucket", "src", "dst", "sport", "dport", "proto", "bytes", "pkts")
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def span(self):
        """(min_bucket, max_bucket, count) - what this buffer covers, for the gap report. (None, None, 0) if empty."""
        with self._db() as db:
            r = db.execute("SELECT MIN(bucket), MAX(bucket), COUNT(*) FROM flows").fetchone()
        return (r[0], r[1], r[2] or 0)

    def covered_buckets(self):
        """The distinct minute-buckets this buffer actually has data for - so the gap report can see holes
        INSIDE an agent's run (a span of min..max would hide a 10-minute outage between them)."""
        with self._db() as db:
            return {r[0] for r in db.execute("SELECT DISTINCT bucket FROM flows").fetchall()}


class MergeState:
    """The main app's memory of what it has already merged from each agent, so re-pulling never double-counts and
    a drop mid-pull is resumable. Keyed by agent id (its PC name / buffer id). Persisted by the caller as a dict."""

    def __init__(self, watermarks=None, seen_cap=200000):
        # watermarks: {agent_id: last_bucket_merged}. seen: recently merged flow_ids (cross-agent de-dup within
        # the overlap window). The watermark handles the bulk; seen catches the same flow arriving from two
        # agents in the SAME still-open bucket.
        self.watermarks = dict(watermarks or {})
        self.seen = set()
        self.seen_cap = seen_cap

    def to_dict(self):
        return {"watermarks": dict(self.watermarks), "schema": SCHEMA_VERSION}

    def merge_agent(self, agent_id, rows):
        """Take one agent's rows_since() output and return the subset to actually apply (new, not already counted
        from another agent). Advances this agent's watermark. rows must be oldest-first."""
        wm = self.watermarks.get(agent_id, -1)
        apply_rows = []
        max_bucket = wm
        for r in rows:
            fid = r.get("fid")
            b = int(r.get("bucket", 0))
            if b < 0 or not fid:
                continue
            if fid in self.seen:          # already counted from another agent in this overlap window
                max_bucket = max(max_bucket, b)
                continue
            self.seen.add(fid)
            apply_rows.append(r)
            max_bucket = max(max_bucket, b)
        if len(self.seen) > self.seen_cap:
            self.seen = set(list(self.seen)[-self.seen_cap // 2:])
        if max_bucket > wm:
            self.watermarks[agent_id] = max_bucket
        return apply_rows


def gaps(spans=None, covered_sets=None, bucket=BUCKET):
    """Minutes between the earliest and latest data that NO agent covered - the true blind spots after merging
    all agents. Pass covered_sets (list of each agent's covered_buckets()) for exact holes INSIDE a run; spans
    (list of (min,max,count)) is accepted for the simple all-or-nothing case but cannot see internal holes.
    Returns the count of uncovered minute-buckets in the overall window, or None if there is no data."""
    covered = set()
    lo = hi = None
    if covered_sets:
        for cs in covered_sets:
            for b in (cs or ()):
                covered.add(b)
                lo = b if lo is None else min(lo, b)
                hi = b if hi is None else max(hi, b)
    elif spans:
        for s in spans:
            if s and s[0] is not None:
                b = s[0]
                while b <= s[1]:
                    covered.add(b)
                    b += bucket
                lo = s[0] if lo is None else min(lo, s[0])
                hi = s[1] if hi is None else max(hi, s[1])
    if lo is None or hi is None:
        return None
    total = (hi - lo) // bucket + 1
    return max(0, total - len(covered))
