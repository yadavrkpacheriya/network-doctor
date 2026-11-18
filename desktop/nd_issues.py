# -*- coding: utf-8 -*-
"""Recurring-issue tracker - pure, no I/O.

Groups the alert log into real *problems* (same kind on the same device), counts how often each comes back,
and separates the ones the app keeps fixing from the ones it can't. The ones it can't fix on its own are the
list worth a permanent root-cause fix - with Claude's help when needed. Everything here is plain data
transforms over the alert items AlertLog already stores (kind, ip, title, fix, count, status, t, last).
"""

import time


def signature(item):
    """What makes two alerts 'the same problem': its kind plus the device it's about (IP). Falls back to the
    title when there's no IP, so e.g. a router-wide issue still groups."""
    kind = item.get("kind") or "other"
    dev = item.get("ip") or item.get("title") or ""
    return kind + "|" + dev


def group(items, now=None, days=1):
    """Collapse the alert items into one row per problem within the last `days` days. Each row:
    {sig, kind, title, ip, fix, count (total times seen), hits (distinct log entries), first, last,
     open (still unresolved), status}. Sorted most-frequent first."""
    now = now or time.time()
    cutoff = now - days * 86400
    by = {}
    for x in items:
        if (x.get("last") or x.get("t") or 0) < cutoff:
            continue
        sig = signature(x)
        g = by.get(sig)
        if g is None:
            g = by[sig] = {"sig": sig, "kind": x.get("kind", "other"), "title": x.get("title", ""),
                           "ip": x.get("ip", ""), "fix": x.get("fix", ""), "count": 0, "hits": 0,
                           "first": x.get("t", now), "last": x.get("last", now), "open": False}
        g["count"] += x.get("count", 1)
        g["hits"] += 1
        g["first"] = min(g["first"], x.get("t", now))
        g["last"] = max(g["last"], x.get("last", now))
        if x.get("status") != "fixed":
            g["open"] = True
    rows = sorted(by.values(), key=lambda r: r["count"], reverse=True)
    for r in rows:
        r["status"] = "still open" if r["open"] else "auto-fixed"
    return rows


def recurring(items, now=None, days=1, min_count=3):
    """The problems that happened at least `min_count` times in the window - the ones worth fixing for good."""
    return [r for r in group(items, now, days) if r["count"] >= min_count]


def top_issues(items, now=None, days=1, n=10):
    """Top N most-frequent problems in the window (for the 'top 10 daily issues' view)."""
    return group(items, now, days)[:n]


def needs_claude(row):
    """A recurring problem the app could NOT fix itself is the one to hand to Claude for a permanent fix:
    it recurs (>=3) and is still open."""
    return row["count"] >= 3 and row["open"]


def _ago(seconds):
    m = int(seconds // 60)
    if m < 60:
        return "%d min" % m
    h = m // 60
    return "%d h" % h if h < 48 else "%d days" % (h // 24)


def claude_report(row, items, code="", brain_note="", now=None):
    """A complete hand-off for Claude: the problem, its history, the app's own reason/fix, and (optionally) the
    exact code that handles it - so Claude understands the whole issue and can design a permanent fix. Markdown.
    `items` is the full alert list (to pull this problem's own occurrences); `code` is the source of the recipe/
    function that raises or fixes it; `brain_note` is the app's learned reasoning."""
    now = now or time.time()
    mine = [x for x in items if signature(x) == row["sig"]]
    mine.sort(key=lambda x: x.get("t", 0), reverse=True)
    lines = []
    lines.append("# Network Doctor - recurring issue for Claude")
    lines.append("")
    lines.append("## The problem")
    lines.append("- Title: %s" % row["title"])
    lines.append("- Kind: `%s`" % row["kind"])
    lines.append("- Device: %s" % (row["ip"] or "(network-wide)"))
    lines.append("- Seen **%d times** in %d log entries; first %s ago, last %s ago."
                 % (row["count"], row["hits"], _ago(now - row["first"]), _ago(now - row["last"])))
    lines.append("- Status: %s (the app %s)."
                 % (row["status"], "could not fix it on its own" if row["open"] else "keeps auto-fixing it"))
    lines.append("")
    lines.append("## What the app already tried")
    lines.append("- Built-in fix: %s" % (row["fix"] or "(none)"))
    if brain_note:
        lines.append("- Brain's reasoning: %s" % brain_note)
    lines.append("")
    lines.append("## History (most recent first)")
    for x in mine[:12]:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(x.get("t", now)))
        lines.append("- %s  x%d  [%s]  %s" % (when, x.get("count", 1), x.get("status", "open"),
                                              (x.get("text", "") or "")[:160]))
    lines.append("")
    lines.append("## Ask")
    lines.append("This issue recurs and the app can't fix it permanently. Using the code and history above, "
                 "find the ROOT CAUSE and give a permanent fix (code change or a network/router change), not "
                 "another patch.")
    if code:
        lines.append("")
        lines.append("## Relevant code")
        lines.append("```python")
        lines.append(code.strip()[:6000])
        lines.append("```")
    return "\n".join(lines)
