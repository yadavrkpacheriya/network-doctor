

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
