import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_nvrmap as M


def test_set_and_coverage():
    db = {}
    M.set_map(db, "192.168.0.74", [
        {"chan": 1, "ip": "192.168.0.143", "name": "FG AREA"},
        {"chan": 4, "ip": "192.168.0.151", "name": "Gate No 2"},
        {"chan": 2, "ip": "", "name": "blank"},   # no IP -> dropped
    ], name="FAN-AIR")
    rec = M.get_map(db, "192.168.0.74")
    assert rec["name"] == "FAN-AIR"
    assert len(rec["channels"]) == 2             # blank dropped

    cov = M.coverage(db, live_ips=["192.168.0.143"])   # .151 is offline
    c = cov[0]
    assert c["total"] == 2
    assert [x["ip"] for x in c["online"]] == ["192.168.0.143"]
    assert [x["ip"] for x in c["offline"]] == ["192.168.0.151"]


def test_multiple_recorders():
    db = {}
    M.set_map(db, "192.168.0.74", [{"chan": 1, "ip": "192.168.0.143"}], name="NVR1")
    M.set_map(db, "192.168.0.75", [{"chan": 1, "ip": "192.168.0.200"}], name="DVR1")
    assert set(M.all_mapped_ips(db)) == {"192.168.0.143", "192.168.0.200"}
    cov = M.coverage(db, ["192.168.0.143", "192.168.0.200"])
    assert len(cov) == 2 and all(len(c["online"]) == 1 for c in cov)


def test_orphan_cameras():
    db = {}
    M.set_map(db, "192.168.0.74", [{"chan": 1, "ip": "192.168.0.143"}], name="NVR1")
    orphans = M.orphan_cameras(db, [{"ip": "192.168.0.143"}, {"ip": "192.168.0.250", "name": "rogue"}])
    assert len(orphans) == 1 and orphans[0]["ip"] == "192.168.0.250"
