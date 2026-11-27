

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


def test_dashboard_has_all_four_top10_charts():
    """Rakesh (27 Nov): dashboard must show top-10 users, top-10 sites, top-10 productive, top-10 unproductive."""
    import tempfile, os, time
    import nd_usage as U
    d = tempfile.mkdtemp()
    s = U.UsageStore(os.path.join(d, "u.db"))
    now = time.time()
    s.add_flow("192.168.0.57", "142.250.1.1", 443, 6, 5_000_000, False, "google.com", now)
    s.add_flow("192.168.0.58", "31.13.1.1", 443, 6, 9_000_000, False, "instagram.com", now)
    html = U.dashboard_html(s)
    for cid in ("ch_topusers", "ch_topsites", "ch_topprod", "ch_topunprod"):
        assert cid in html, cid
    for fn in ("drawTopUsers", "drawTopSites", "drawTopProd", "drawTopUnprod", "function topByCat", "function hbar"):
        assert fn in html, fn
    # all four are wired into draw()
    assert "drawTopUsers();drawTopSites();drawTopProd();drawTopUnprod()" in html
