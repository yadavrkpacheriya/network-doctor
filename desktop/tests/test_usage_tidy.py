"""Usage names a person can read: one line per real app, never a whois text or a server host name."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_usage as U  # noqa: E402
import nd_tools as T  # noqa: E402


def test_real_site_beats_company_bucket():
    for app in ("CDN (various)", "Microsoft (other)", "acronis.com", "Acronis Asia Pte Ltd administrator"):
        assert U.tidy(app, "acronis.com")[0] == "Acronis Cloud Backup"
    assert U.tidy("Acronis Asia Pte Ltd administrator", "acronis asia pte ltd administrator")[0] == \
        "Acronis Cloud Backup"
    assert U.APP_INFO["Acronis Cloud Backup"][0] == U.WORK
    assert U.tidy("Amazon cloud (AWS)", "logicmojo.com") == ("logicmojo.com", "logicmojo.com")
    assert U.tidy("CDN (various)", "digicert.com")[0] == "Certificate checks"


def test_buckets_without_a_name_stay():
    assert U.tidy("CDN (various)", "Akamai CDN (downloads, updates, video)")[0] == "CDN (various)"
    assert U.tidy("CDN (various)", "akamaized.net")[0] == "CDN (various)"
    assert U.tidy("Google (service not known)", "Google server (service not named)")[0] == \
        "Google (service not known)"
    assert U.tidy("Google (shared address)", "drive.google.com")[0] == "Google (shared address)"
    assert U.tidy("Instagram", "cdninstagram.com") == ("Instagram", "cdninstagram.com")
    assert U.tidy("VPN", "Airtel network")[0] == "VPN"


def test_host_names_and_whois_texts_are_not_apps():
    assert U.tidy("xx-fbcdn-shv-01-del2.fbcdn.net meta-mnt", "")[0] == "Facebook"
    assert U.tidy("instagram-p3-shv-01-del3.fbcdn.net meta-", "")[0] == "Instagram"
    assert U.tidy("whatsapp-cdn-shv-01-del2.fbcdn.net", "")[0] == "WhatsApp"
    assert U.tidy("172-236-162-42.ip.linodeusercontent.com ", "")[0] == U.HOSTING
    assert U.tidy("UCLOUD INFORMATION TECHNOLOGY HK LIMITED", "")[0] == U.HOSTING
    assert U.tidy("143955071.sgp.cdn77.com DATACAMP-MNT", "")[0] == "CDN (various)"
    assert U.tidy("Reliance Jio Infocomm Limited", "")[0] == U.ISP_DIRECT
    assert U.tidy("netutils-mnt", "netutils-mnt") == (U.UNNAMED, "owner: netutils")
    assert U.tidy("Shailesh Gupta", "shailesh gupta") == (U.UNNAMED, "owner: Shailesh Gupta")
    assert U.tidy("somecompany.in", "somecompany.in") == ("somecompany.in", "somecompany.in")
    for a, st in (("Acronis Cloud Backup", "acronis.com"), (U.UNNAMED, "owner: netutils"), (U.HOSTING, "x.com")):
        assert U.tidy(*U.tidy(a, st)) == U.tidy(a, st)        # doing it twice changes nothing


def test_history_is_renamed_once_and_merged():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        s = U.UsageStore(os.path.join(tmp, "u.db"))
        with s._db() as db:
            db.execute("PRAGMA user_version = 0")
            db.executemany("INSERT INTO usage VALUES (?,?,?,?,?,?,?,?,?)", [
                ("2026-11-10", 9, "d1", "CDN (various)", "acronis.com", "neutral", 10, 100, 1),
                ("2026-11-10", 9, "d1", "acronis.com", "acronis.com", "neutral", 5, 50, 1),
                ("2026-11-10", 9, "d1", "Instagram", "cdninstagram.com", "personal", 1, 7, 1),
                ("2026-11-10", 9, "d1", "netutils-mnt", "netutils-mnt", "neutral", 2, 3, 1)])
            db.executemany("INSERT INTO active VALUES (?,?,?,?,?,?)", [
                ("2026-11-10", 9, "d1", "acronis.com", "neutral", 40),
                ("2026-11-10", 9, "d1", "Acronis Asia Pte Ltd administrator", "neutral", 55)])
        assert s.retidy() == 3
        got = {(a, st): (c, u, d) for a, st, c, u, d in
               s._rows("SELECT app, site, cat, up, down FROM usage")}
        assert got == {("Acronis Cloud Backup", "acronis.com"): ("work", 15, 150),
                       ("Instagram", "cdninstagram.com"): ("personal", 1, 7),
                       (U.UNNAMED, "owner: netutils"): ("neutral", 2, 3)}
        assert s._rows("SELECT app, cat, minutes FROM active") == [("Acronis Cloud Backup", "work", 55)]
        assert s.retidy() == 0                                   # already done: not run again


def test_new_traffic_is_tidied():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        s = U.UsageStore(os.path.join(tmp, "u.db"))
        s.add_flow("192.168.0.9", "23.1.2.3", 443, 6, 5000, False, org="Acronis Asia Pte Ltd administrator")
        s.add_flow("192.168.0.9", "45.1.2.3", 443, 6, 700, False, org="netutils-mnt")
        s.flush(force=True)
        apps = {a["app"] for a in s.summary(1)["apps"]}
        assert apps == {"Acronis Cloud Backup", U.UNNAMED}


def test_no_name_share():
    rows = [("d", 9, "CDN (various)", "neutral", "a", 600), ("d", 9, "Instagram", "personal", "a", 300),
            ("d", 9, "DNS look-ups (Google DNS)", "neutral", "a", 50),
            ("d", 9, "DNS look-ups (Google DNS)", "neutral", "b", 50)]
    r = U.no_name_share(rows)
    assert r["bytes"] == 600 and abs(r["share"] - 0.6) < 1e-9 and r["own_dns_devs"] == 2
    assert U.no_name_share([])["share"] == 0.0


def test_two_addresses_sort_by_first_ip():
    order = T.sorted_order([(1, "192.168.0.80"), (2, "192.168.0.9, 192.168.0.200"), (3, "192.168.0.100")])
    assert order == [2, 1, 3]


def test_leak_rows():
    rows = [("2026-11-13", "a", "Google Drive / Docs", 400e6), ("2026-11-13", "a", "Gmail", 100e6),
            ("2026-11-13", "b", "MEGA (file sharing)", 150e6), ("2026-11-13", "b", "Instagram", 900e6),
            ("2026-11-13", "c", "Acronis Cloud Backup", 9e9), ("2026-11-13", "c", U.UNNAMED, 2e9),
            ("2026-11-13", "d", "AnyDesk", 2e9)]
    got = U.leak_rows(rows, trusted=lambda app: app == "AnyDesk")
    assert [(r["dev"], r["app"], r["high"]) for r in got] == [
        ("c", U.UNNAMED, True), ("a", "Google Drive / Docs", False), ("b", "MEGA (file sharing)", True)]


def test_leak_insight_names_person_and_place():
    import datetime as dt
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        s = U.UsageStore(os.path.join(tmp, "u.db"))
        s.set_devices([{"mac": "AA:00:00:00:00:01", "ip": "192.168.0.57", "name": "Hitesh", "online": True}],
                      {"AA:00:00:00:00:01": {"dept": "Accounts"}})
        s.learn_names([("5.5.5.5", "wetransfer.com")])
        s.add_flow("192.168.0.57", "5.5.5.5", 443, 6, 250_000_000, True)
        s.flush(force=True)
        hit = [i for i in s.insights(today=dt.date.today()) if i["title"].startswith("Large uploads")]
        assert len(hit) == 1 and hit[0]["sev"] == "critical"
        assert "Hitesh - Accounts (192.168.0.57) sent" in hit[0]["text"] and "WeTransfer" in hit[0]["text"]


def test_proc_app_names_the_flow(tmp_path):
    import os as _os
    s = U.UsageStore(_os.path.join(str(tmp_path), "u.db"))
    s.set_devices([{"mac": "AA:00:00:00:00:01", "ip": "192.168.0.57", "name": "ACC1", "online": True}], {})
    s.set_proc_app({("192.168.0.57", "5.5.5.5"): "AnyDesk"})
    s.add_flow("192.168.0.57", "5.5.5.5", 443, 6, 1_000_000, True, org="Some Hosting Ltd")
    s.flush(force=True)
    apps = {a["app"] for a in s.summary(1)["apps"]}
    assert apps == {"AnyDesk"}
    assert s.app_for("192.168.0.57", "5.5.5.5") == "AnyDesk"
