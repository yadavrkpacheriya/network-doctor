

def test_learned_priority_targets_picks_productive_only():
    import tempfile, os, nd_usage as U
    p = os.path.join(tempfile.mkdtemp(), "u.db")
    s = U.UsageStore(p)
    s.ip_name["142.250.1.1"] = {"docs.google.com": 5}
    s.ip_name["142.250.1.2"] = {"sheets.google.com": 3}
    s.ip_name["9.9.9.9"] = {"facebook.com": 2}
    s.summary = lambda days=1, dev=None, end=None: {"sites": [
        {"site": "docs.google.com", "cat": U.WORK, "visits": 50, "bytes": 10000},
        {"site": "facebook.com", "cat": U.PERSONAL, "visits": 40, "bytes": 9000},
    ]}
    r = s.learned_priority_targets()
    assert [x["site"] for x in r["sites"]] == ["docs.google.com"]   # productive only
    assert "142.250.1.1" in r["ips"]
    assert "9.9.9.9" not in r["ips"]                                 # personal excluded


def test_learned_priority_targets_handles_no_data():
    import tempfile, os, nd_usage as U
    p = os.path.join(tempfile.mkdtemp(), "u.db")
    s = U.UsageStore(p)
    r = s.learned_priority_targets()
    assert r == {"sites": [], "ips": []} or r["ips"] == []            # empty store -> no crash


def test_naming_blindness_detects_unnamed_traffic():
    import tempfile, os, datetime as dt, nd_usage as U
    p = os.path.join(tempfile.mkdtemp(), "u.db")
    s = U.UsageStore(p)
    today = dt.date.today().isoformat()
    # seed raw usage rows directly: mostly VAGUE (unnamed) traffic -> blind
    with s._db() as db:
        vague = sorted(U.VAGUE_APPS)[0] if U.VAGUE_APPS else "other"
        db.execute("INSERT INTO usage(day,hour,app,cat,dev,up,down,site) VALUES(?,?,?,?,?,?,?,?)",
                   (today, 10, vague, "neutral", "d1", 9000, 0, ""))
        db.execute("INSERT INTO usage(day,hour,app,cat,dev,up,down,site) VALUES(?,?,?,?,?,?,?,?)",
                   (today, 10, "Google Docs", "work", "d1", 1000, 0, "docs.google.com"))
    assert s.naming_blindness() >= 0.25        # 90% unnamed -> blind, auto-naming should trigger
