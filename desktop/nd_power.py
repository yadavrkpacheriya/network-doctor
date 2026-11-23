"""Power-cut / UPS tracking for Network Doctor (Rakesh, 23 Nov).

When the office power trips, many devices drop OFF the network in the same moment; the ones that STAY up are the
ones on a UPS. By recording, every scan, which devices are up vs down, we can:
  * spot a power event   - a cluster of fixed devices going offline together in one scan window;
  * report UPS coverage  - which devices rode through the cut (on UPS) and which died (not on UPS);
  * measure downtime     - per device, minutes offline per day, and the monthly average.

Pure logic here (no I/O, no UI) so it is easy to test. The caller feeds one "sample" per scan:
    sample = {"ts": <epoch seconds>, "down": [macs offline now], "up": [macs online now]}
and keeps a rolling list of samples (the power log). Fixed devices only (cameras/NVR/PC/printer/network) matter
for power events - phones and random-MAC devices come and go for their own reasons.
"""
from collections import defaultdict
from datetime import datetime

# A power event = at least this many fixed devices drop OFF between two consecutive scans, together.
POWER_DROP_MIN = 4


def detect_events(samples, drop_min=POWER_DROP_MIN):
    """Find power-cut events in an ordered list of samples. An event is a scan where `drop_min`+ devices that
    were UP in the previous sample are DOWN in this one. Returns a list of:
        {"ts", "dropped": [macs], "survived": [macs that stayed up = on UPS], "count"}
    `survived` is the set of devices that were up before AND stayed up through the drop - i.e. UPS-backed."""
    events = []
    prev = None
    for s in samples:
        up = set(s.get("up") or [])
        down = set(s.get("down") or [])
        if prev is not None:
            prev_up = set(prev.get("up") or [])
            dropped = prev_up & down            # were up last scan, down now
            if len(dropped) >= drop_min:
                survived = sorted(prev_up - dropped)      # up before, still up = rode the cut on UPS
                events.append({"ts": s.get("ts"), "dropped": sorted(dropped),
                               "survived": survived, "count": len(dropped)})
        prev = s
    return events


def ups_coverage(samples, drop_min=POWER_DROP_MIN):
    """Across all detected power events, classify each device: did it EVER survive a cut (on UPS) or did it drop
    in every cut it was present for (not on UPS)? Returns {"on_ups": [macs], "not_on_ups": [macs],
    "events": <n>}. A device that survived at least one real power event is counted as UPS-backed."""
    events = detect_events(samples, drop_min)
    survived_any, dropped_ever = set(), set()
    for e in events:
        survived_any.update(e["survived"])
        dropped_ever.update(e["dropped"])
    on_ups = survived_any
    not_on_ups = dropped_ever - survived_any      # only ever seen dropping, never riding through
    return {"on_ups": sorted(on_ups), "not_on_ups": sorted(not_on_ups), "events": len(events)}


def _day(ts):
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
    except Exception:
        return ""


def downtime_by_day(samples, scan_gap_sec=120):
    """Minutes each device was offline, per day. Between two consecutive samples a device that is DOWN in the
    later one is counted as down for that gap (capped at a sane max so one missing scan doesn't look like hours).
    Returns {mac: {day: minutes}}. `scan_gap_sec` is the normal spacing between scans - a longer real gap is
    capped to 2x it, so a laptop that was simply off overnight doesn't dwarf the chart."""
    by = defaultdict(lambda: defaultdict(float))
    prev = None
    cap = scan_gap_sec * 2
    for s in samples:
        if prev is not None:
            gap = min(max((s.get("ts", 0) - prev.get("ts", 0)), 0), cap)
            mins = gap / 60.0
            day = _day(s.get("ts"))
            for mac in (s.get("down") or []):
                by[mac][day] += mins
        prev = s
    return {m: dict(d) for m, d in by.items()}


def monthly_average(samples, mac, scan_gap_sec=120):
    """Average offline MINUTES PER DAY for one device over the days we have samples for (its "monthly average").
    Averaged over distinct days seen, so a few quiet days don't skew it."""
    dd = downtime_by_day(samples, scan_gap_sec).get(mac, {})
    if not dd:
        return 0.0
    return round(sum(dd.values()) / len(dd), 1)


def summarize(samples, names=None, scan_gap_sec=120, drop_min=POWER_DROP_MIN):
    """One bundle for the UI: power events, UPS coverage, and per-device daily + monthly-average downtime.
    `names` maps mac -> display name. Returns a dict ready to chart/table."""
    names = names or {}
    cov = ups_coverage(samples, drop_min)
    dbyday = downtime_by_day(samples, scan_gap_sec)
    devices = []
    for mac, days in dbyday.items():
        total = sum(days.values())
        avg = round(total / len(days), 1) if days else 0.0
        devices.append({"mac": mac, "name": names.get(mac, ""), "days": days,
                        "total_min": round(total, 1), "avg_min_per_day": avg,
                        "on_ups": mac in cov["on_ups"]})
    devices.sort(key=lambda d: -d["total_min"])
    return {"coverage": cov, "devices": devices,
            "events": detect_events(samples, drop_min),
            "name_of": lambda m: names.get(m, m)}
