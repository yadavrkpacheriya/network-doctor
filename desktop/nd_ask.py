"""Plain-language questions about what Network Doctor already records.

This is the "ask the brain a simple question" layer (Rakesh, 24 Nov): the user types a question like
"which website is used the most", "which device disconnects the most", "who uses the most data",
"which site is slowest" and gets a direct, factual answer built from data the app ALREADY stores:

  * usage.db (nd_usage.UsageStore.summary)  -> per-site / per-app / per-device bytes and visits
  * db["power_log"] (nd_power.summarize)    -> per-device offline minutes (disconnections / downtime)
  * SlowTab watch events (nd_slow.summarize_watch) -> which site dropped, by cause

It is deliberately NOT an LLM: it recognises intent by keywords over STRUCTURED data, so every answer is
exact, offline, and testable. `answer(q, ctx)` returns {"understood": bool, "text": str, "rows": [...]}.
The caller passes a ctx dict with whatever is available; missing sources just yield "no data yet".
"""

import re

# ---- intent keyword sets ----------------------------------------------------------------------------------
_MOST = ("most", "highest", "top", "maximum", "max", "biggest", "heaviest", "hog", "worst")
_LEAST = ("least", "lowest", "fewest", "minimum", "min", "smallest")
_SITE = ("site", "website", "web site", "url", "domain", "page")
_APP = ("app", "application", "service", "program")
_DATA = ("data", "bandwidth", "traffic", "usage", "gb", "mb", "download", "internet", "bytes")
_DEVICE = ("device", "pc", "computer", "machine", "system", "phone", "camera", "cam")
_DISCONN = ("disconnect", "disconnection", "drop", "dropped", "offline", "down", "downtime", "outage",
            "unstable", "flapping", "flap", "lost connection")
_SLOWSITE = ("slow", "slowest", "laggy", "buffering", "not loading", "wont load", "won't load")
_COUNT = ("how many", "count", "number of")
_UPS = ("ups", "power backup", "not on ups", "no ups", "power cut")


def _nice_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return (f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}")
        n /= 1024


def _nice_mins(m):
    m = float(m or 0)
    if m < 60:
        return f"{m:.0f} min"
    h = m / 60
    return f"{h:.1f} h" if h < 24 else f"{h / 24:.1f} days"


def _has(low, words):
    return any(w in low for w in words)


# ---- answers from the usage store -------------------------------------------------------------------------
def _usage_summary(ctx, days):
    store = ctx.get("usage")
    if not store:
        return None
    try:
        return store.summary(days=days)
    except Exception:  # noqa: BLE001 - a bad/locked DB must never crash the answer
        return None


def _days_in(low, default=7):
    m = re.search(r"(\d+)\s*day", low)
    if m:
        return max(1, int(m.group(1)))
    if "today" in low:
        return 1
    if "month" in low or "30 day" in low:
        return 30
    if "week" in low:
        return 7
    return default


def _top_site(ctx, low, want_most=True):
    days = _days_in(low)
    s = _usage_summary(ctx, days)
    if not s:
        return {"understood": True, "text": "I don't have internet-usage data yet. Turn on the Live monitor "
                "(it reads the router's traffic log) and ask again after a while.", "rows": []}
    sites = [x for x in s.get("sites", []) if x.get("bytes")]
    if not sites:
        return {"understood": True, "text": "No site traffic recorded yet for that period.", "rows": []}
    sites.sort(key=lambda x: x["bytes"], reverse=want_most)
    top = sites[:5]
    head = sites[0]
    word = "most" if want_most else "least"
    text = "Over the last %d day(s), the site using the %s data is %s (%s, across %d device(s))." % (
        days, word, head["site"], _nice_bytes(head["bytes"]), head.get("devices", 0))
    rows = [{"site": x["site"], "bytes": _nice_bytes(x["bytes"]), "devices": x.get("devices", 0),
             "visits": x.get("visits", 0)} for x in top]
    return {"understood": True, "text": text, "rows": rows}


def _most_visited_site(ctx, low):
    days = _days_in(low)
    s = _usage_summary(ctx, days)
    if not s:
        return {"understood": True, "text": "I don't have browsing data yet - turn on the Live monitor.",
                "rows": []}
    sites = [x for x in s.get("sites", []) if x.get("visits")]
    if not sites:
        return {"understood": True, "text": "No site visits recorded yet.", "rows": []}
    sites.sort(key=lambda x: x["visits"], reverse=True)
    head = sites[0]
    text = "Over the last %d day(s), the most-visited site is %s (%d visits)." % (days, head["site"], head["visits"])
    rows = [{"site": x["site"], "visits": x["visits"], "bytes": _nice_bytes(x.get("bytes", 0))} for x in sites[:5]]
    return {"understood": True, "text": text, "rows": rows}


def _top_app(ctx, low, want_most=True):
    days = _days_in(low)
    s = _usage_summary(ctx, days)
    if not s:
        return {"understood": True, "text": "No app-usage data yet - turn on the Live monitor.", "rows": []}
    apps = [x for x in s.get("apps", []) if x.get("bytes")]
    if not apps:
        return {"understood": True, "text": "No app traffic recorded yet.", "rows": []}
    apps.sort(key=lambda x: x["bytes"], reverse=want_most)
    head = apps[0]
    word = "most" if want_most else "least"
    text = "Over the last %d day(s), the app using the %s data is %s (%s)." % (
        days, word, head["app"], _nice_bytes(head["bytes"]))
    rows = [{"app": x["app"], "bytes": _nice_bytes(x["bytes"]), "devices": x.get("devices", 0)} for x in apps[:5]]
    return {"understood": True, "text": text, "rows": rows}


def _top_device_data(ctx, low, want_most=True):
    days = _days_in(low)
    s = _usage_summary(ctx, days)
    if not s:
        return {"understood": True, "text": "No per-device usage yet - turn on the Live monitor.", "rows": []}
    devs = [x for x in (s.get("devices") or s.get("devs") or []) if x.get("bytes")]
    if not devs:
        return {"understood": True, "text": "No device traffic recorded yet.", "rows": []}
    devs.sort(key=lambda x: x["bytes"], reverse=want_most)
    head = devs[0]
    word = "most" if want_most else "least"
    text = "Over the last %d day(s), the device using the %s data is %s%s (%s)." % (
        days, word, head.get("name") or head.get("dev"),
        " (%s)" % head["ip"] if head.get("ip") else "", _nice_bytes(head["bytes"]))
    rows = [{"device": x.get("name") or x.get("dev"), "ip": x.get("ip", ""),
             "bytes": _nice_bytes(x["bytes"])} for x in devs[:5]]
    return {"understood": True, "text": text, "rows": rows}


# ---- answers from the power/downtime log ------------------------------------------------------------------
def _power_summary(ctx):
    samples = (ctx.get("db") or {}).get("power_log") if ctx.get("db") else ctx.get("power_log")
    if not samples:
        return None
    try:
        import nd_power as P
        return P.summarize(samples, names=ctx.get("names") or {})
    except Exception:  # noqa: BLE001
        return None


def _most_disconnected(ctx, low, want_most=True):
    summ = _power_summary(ctx)
    if not summ:
        return {"understood": True, "text": "I don't have disconnection history yet. It builds up as the app "
                "scans over days - ask again after it has been running for a while.", "rows": []}
    devs = [d for d in summ["devices"] if d.get("total_min")]
    if not devs:
        return {"understood": True, "text": "No device downtime recorded yet - everything has stayed online.",
                "rows": []}
    devs.sort(key=lambda d: d["total_min"], reverse=want_most)
    head = devs[0]
    word = "most" if want_most else "least"
    text = "The device that disconnects the %s is %s - offline about %s in total (%s/day on average)%s." % (
        word, head.get("name") or head["mac"], _nice_mins(head["total_min"]),
        _nice_mins(head["avg_min_per_day"]), " - not on UPS" if not head.get("on_ups") else "")
    rows = [{"device": d.get("name") or d["mac"], "total_offline": _nice_mins(d["total_min"]),
             "per_day": _nice_mins(d["avg_min_per_day"]), "on_ups": "yes" if d.get("on_ups") else "no"}
            for d in devs[:5]]
    return {"understood": True, "text": text, "rows": rows}


def _ups_answer(ctx, low):
    summ = _power_summary(ctx)
    if not summ:
        return {"understood": True, "text": "No power history yet - the UPS picture builds up over a few days "
                "of scanning.", "rows": []}
    cov = summ["coverage"]
    notups = cov.get("not_on_ups", [])
    name = summ.get("name_of", lambda m: m)
    text = "%d device(s) are NOT on UPS power (they drop in a power cut): %s. %d are protected." % (
        len(notups), ", ".join(name(m) for m in notups[:10]) or "none", len(cov.get("on_ups", [])))
    rows = [{"device": name(m), "on_ups": "no"} for m in notups]
    return {"understood": True, "text": text, "rows": rows}


# ---- answers from the slow-site watch ---------------------------------------------------------------------
def _slowest_site(ctx, low):
    events = ctx.get("watch_events")
    if not events:
        return {"understood": True, "text": "No site-drop watch data yet. Open the 'Slow website' tab and press "
                "'Watch for drops' on the site that keeps disconnecting; then ask again.", "rows": []}
    try:
        import nd_slow as S
        s = S.summarize_watch(events)
    except Exception:  # noqa: BLE001
        return {"understood": True, "text": "Could not read the watch log.", "rows": []}
    if not s.get("total"):
        return {"understood": True, "text": "The watched site has had no drops so far - it looks stable.",
                "rows": []}
    by = s.get("by_cause", {})
    worst = s.get("worst_cause", "")
    text = "The watched site dropped %d time(s). Most drops were '%s'. Likely fix: %s" % (
        s["total"], worst, s.get("likely_fix", ""))
    rows = [{"cause": c, "times": n} for c, n in sorted(by.items(), key=lambda kv: -kv[1])]
    return {"understood": True, "text": text, "rows": rows}


# ---- the router ------------------------------------------------------------------------------------------
def answer(q, ctx=None):
    """Answer one plain-language question from stored data. ctx may hold: usage (UsageStore), db (app db with
    power_log) or power_log, names (mac->name), watch_events. Returns {"understood", "text", "rows"}."""
    ctx = ctx or {}
    low = (q or "").strip().lower()
    if not low:
        return {"understood": False, "text": "", "rows": []}

    least = _has(low, _LEAST) and not _has(low, _MOST)
    most = not least

    # disconnections / downtime / offline (any phrasing)
    if _has(low, _DISCONN):
        return _most_disconnected(ctx, low, want_most=most)

    # UPS / power
    if _has(low, _UPS):
        return _ups_answer(ctx, low)

    # slowest / flapping website (watch)
    if _has(low, _SLOWSITE) and _has(low, _SITE):
        return _slowest_site(ctx, low)

    # most-visited site (visits, not bytes)
    if ("visit" in low or "open" in low or "most used website" in low) and _has(low, _SITE) and not _has(low, _DATA):
        return _most_visited_site(ctx, low)

    # which SITE uses most data
    if _has(low, _SITE) and (_has(low, _DATA) or _has(low, _MOST + _LEAST)):
        return _top_site(ctx, low, want_most=most)

    # which APP uses most data
    if _has(low, _APP) and (_has(low, _DATA) or _has(low, _MOST + _LEAST)):
        return _top_app(ctx, low, want_most=most)

    # which DEVICE uses most data
    if _has(low, _DEVICE) and (_has(low, _DATA) or _has(low, _MOST + _LEAST)):
        return _top_device_data(ctx, low, want_most=most)

    # bare "who/what uses the most data" -> device, then site
    if _has(low, _DATA) and _has(low, _MOST + _LEAST):
        r = _top_device_data(ctx, low, want_most=most)
        if r.get("rows"):
            return r
        return _top_site(ctx, low, want_most=most)

    return {"understood": False,
            "text": "I can answer things like: which website uses the most data, which device uses the most "
                    "data, which device disconnects the most, which devices are not on UPS, or which site is "
                    "dropping. Try one of those.", "rows": []}
