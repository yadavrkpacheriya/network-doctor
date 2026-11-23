import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_power as P

T0 = 1700000000  # a fixed base epoch


def s(ts_off, up, down):
    return {"ts": T0 + ts_off, "up": up, "down": down}


def test_power_event_detected_when_many_drop_together():
    # scan 1: all 6 up. scan 2: 5 of them drop together (power cut), 1 stays (UPS).
    samples = [
        s(0,   ["nvr", "c1", "c2", "c3", "pc1", "pc2"], []),
        s(120, ["nvr"], ["c1", "c2", "c3", "pc1", "pc2"]),
    ]
    ev = P.detect_events(samples)
    assert len(ev) == 1
    assert ev[0]["count"] == 5
    assert ev[0]["survived"] == ["nvr"]            # the UPS-backed one
    assert set(ev[0]["dropped"]) == {"c1", "c2", "c3", "pc1", "pc2"}


def test_single_device_drop_is_not_a_power_event():
    samples = [s(0, ["nvr", "c1", "c2"], []), s(120, ["nvr", "c2"], ["c1"])]
    assert P.detect_events(samples) == []          # one camera off is not a power cut


def test_ups_coverage_splits_backed_from_unbacked():
    samples = [
        s(0,   ["nvr", "c1", "c2", "c3", "pc1"], []),
        s(120, ["nvr"], ["c1", "c2", "c3", "pc1"]),     # power cut: nvr survives
        s(240, ["nvr", "c1", "c2", "c3", "pc1"], []),   # power back
    ]
    cov = P.ups_coverage(samples)
    assert cov["on_ups"] == ["nvr"]
    assert set(cov["not_on_ups"]) == {"c1", "c2", "c3", "pc1"}
    assert cov["events"] == 1


def test_downtime_by_day_counts_offline_minutes():
    # c1 is down for two 2-min gaps on the same day = 4 minutes
    samples = [
        s(0,   ["c1"], []),
        s(120, [], ["c1"]),      # down (gap 2 min)
        s(240, [], ["c1"]),      # still down (gap 2 min)
        s(360, ["c1"], []),      # back
    ]
    dd = P.downtime_by_day(samples)
    day = P._day(T0 + 120)
    assert round(dd["c1"][day]) == 4


def test_a_huge_gap_is_capped():
    # a 10-hour gap (PC off overnight) must not count as 600 minutes - capped at 2x the scan gap (4 min here)
    samples = [s(0, ["pc1"], []), s(36000, [], ["pc1"])]
    dd = P.downtime_by_day(samples, scan_gap_sec=120)
    day = P._day(T0 + 36000)
    assert dd["pc1"][day] <= 4.0


def test_monthly_average_is_per_day():
    # down 4 min on day 1, 0 on day 2 -> average 2 min/day over 2 days
    d1 = T0
    d2 = T0 + 86400
    samples = [
        {"ts": d1, "up": ["c1"], "down": []},
        {"ts": d1 + 120, "up": [], "down": ["c1"]},
        {"ts": d1 + 240, "up": [], "down": ["c1"]},
        {"ts": d1 + 360, "up": ["c1"], "down": []},
        {"ts": d2, "up": ["c1"], "down": []},
        {"ts": d2 + 120, "up": ["c1"], "down": []},
    ]
    # day1 downtime ~4 min across 2 days seen in the down-log... only day1 has downtime
    avg = P.monthly_average(samples, "c1")
    assert avg == 4.0   # only 1 day had any downtime in the log, so average over that day is 4


def test_summarize_bundles_everything():
    samples = [
        s(0,   ["nvr", "c1", "c2", "c3", "pc1"], []),
        s(120, ["nvr"], ["c1", "c2", "c3", "pc1"]),
    ]
    out = P.summarize(samples, names={"nvr": "Main NVR", "c1": "Gate Cam"})
    assert out["coverage"]["on_ups"] == ["nvr"]
    assert len(out["events"]) == 1
    assert any(d["name"] == "Gate Cam" and not d["on_ups"] for d in out["devices"])
