"""Reading the LeakWatch endpoint agent's USB logs."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_endpoint as E  # noqa: E402


def _write(folder, name, rows):
    with open(os.path.join(folder, name), "w", encoding="utf-8", newline="") as fh:
        fh.write("time,pc,user,event,detail,drive,size_kb\n")
        for r in rows:
            fh.write(",".join(str(x) for x in r) + "\n")


def test_read_merges_files_and_drops_old(tmp_path):
    now = time.mktime(time.strptime("2026-11-14 16:00:00", "%Y-%m-%d %H:%M:%S"))
    _write(str(tmp_path), "leak-ACC1-202611.csv", [
        ("2026-11-14 10:00:00", "ACC1", "hitesh", "USB_IN", "Removable drive connected", "E:", 0),
        ("2026-11-14 10:01:00", "ACC1", "hitesh", "COPY_TO_USB", '"E:\\clients,list.xlsx"', "E:", 2048),
        ("2026-11-01 09:00:00", "ACC1", "hitesh", "COPY_TO_USB", "old.txt", "E:", 50)])   # >7 days old
    _write(str(tmp_path), "leak-SALES2-202611.csv", [
        ("2026-11-14 11:00:00", "SALES2", "ramesh", "COPY_TO_USB", "deck.pptx", "F:", 1024),
        ("bad line", "x", "x", "x", "x", "x", "x")])
    ev = E.read_events(str(tmp_path), since_days=7, now=now)
    assert [e["time"] for e in ev] == ["2026-11-14 11:00:00", "2026-11-14 10:01:00", "2026-11-14 10:00:00"]
    assert ev[1]["detail"] == "E:\\clients,list.xlsx" and ev[1]["kb"] == 2048   # comma inside quotes kept


def test_summarize_and_alerts(tmp_path):
    now = time.mktime(time.strptime("2026-11-14 16:00:00", "%Y-%m-%d %H:%M:%S"))
    _write(str(tmp_path), "leak-ACC1-202611.csv", [
        ("2026-11-14 10:00:00", "ACC1", "hitesh", "USB_IN", "x", "E:", 0),
        ("2026-11-14 10:01:00", "ACC1", "hitesh", "COPY_TO_USB", "E:\\a.xlsx", "E:", 30720),
        ("2026-11-14 10:02:00", "ACC1", "hitesh", "COPY_TO_USB", "E:\\b.pdf", "E:", 1024)])
    ev = E.read_events(str(tmp_path), now=now)
    s = E.summarize(ev)[0]
    assert s["pc"] == "ACC1" and s["usb_in"] == 1 and s["copies"] == 2 and s["users"] == ["hitesh"]
    al = E.leak_alerts(ev, min_copy_mb=20, who=lambda pc, u: f"{u}-Accounts")
    assert len(al) == 1 and al[0][0] == "critical"
    assert "hitesh-Accounts copied 2 file(s) to USB (31 MB)" == al[0][1]
    assert "a.xlsx" in al[0][2] and "b.pdf" in al[0][2]


def test_empty_and_missing_folder():
    assert E.read_events("/no/such/folder") == []
    assert E.summarize([]) == [] and E.leak_alerts([]) == []


def test_proc_app_native_only():
    assert E.proc_app("WhatsApp.exe") == "WhatsApp"
    assert E.proc_app("AnyDesk.exe") == "AnyDesk"
    assert E.proc_app("TrueImage.exe") == "Acronis Cloud Backup"
    assert E.proc_app("chrome.exe") is None        # a browser keeps its DNS-based website name
    assert E.proc_app("msedge") is None
    assert E.proc_app("unknownthing.exe") is None


def test_read_reports_adds_lan_ip(tmp_path):
    import json
    (tmp_path / "pc-ACC1.json").write_text(json.dumps({
        "hostname": "ACC1", "user": "hitesh", "os": "Windows 11",
        "adapters": [{"mac": "AA-BB-CC-00-00-01", "ip": "8.8.8.8,192.168.0.57", "status": "Up"}],
        "hw": {"model": "OptiPlex"}}), encoding="utf-8")
    (tmp_path / "pc-bad.json").write_text("{not json", encoding="utf-8")
    reps = E.read_reports(str(tmp_path))
    assert len(reps) == 1 and reps[0]["ip"] == "192.168.0.57" and reps[0]["hostname"] == "ACC1"


def test_proc_name_map_newest_wins(tmp_path):
    import time as _t
    now = _t.mktime(_t.strptime("2026-11-14 16:00:00", "%Y-%m-%d %H:%M:%S"))
    with open(tmp_path / "conn-ACC1-202611.csv", "w", encoding="utf-8", newline="") as fh:
        fh.write("time,pc,user,process,local_ip,remote_ip,remote_port\n")
        fh.write("2026-11-14 10:00:00,ACC1,h,chrome.exe,192.168.0.57,142.250.1.1,443\n")   # browser: ignored
        fh.write("2026-11-14 10:01:00,ACC1,h,WhatsApp.exe,192.168.0.57,5.5.5.5,443\n")
        fh.write("2026-11-14 10:05:00,ACC1,h,AnyDesk.exe,192.168.0.57,5.5.5.5,443\n")       # newer: wins
    m = E.proc_name_map(E.read_conns(str(tmp_path), since_days=1, now=now))
    assert m == {("192.168.0.57", "5.5.5.5"): "AnyDesk"}


def test_readers_accept_a_list_of_folders(tmp_path):
    import time as _t
    a = tmp_path / "share"; b = tmp_path / "local"; a.mkdir(); b.mkdir()
    now = _t.mktime(_t.strptime("2026-11-14 16:00:00", "%Y-%m-%d %H:%M:%S"))
    (a / "leak-PC1-202611.csv").write_text(
        "time,pc,user,event,detail,drive,size_kb\n2026-11-14 10:00:00,PC1,u,USB_IN,x,E:,0\n", encoding="utf-8")
    (b / "leak-PC2-202611.csv").write_text(
        "time,pc,user,event,detail,drive,size_kb\n2026-11-14 11:00:00,PC2,u,USB_IN,x,F:,0\n", encoding="utf-8")
    ev = E.read_events([str(a), str(b)], since_days=7, now=now)
    assert {e["pc"] for e in ev} == {"PC1", "PC2"}


def test_reports_dedup_newest_per_pc(tmp_path):
    import json
    import os as _os
    import time as _t
    a = tmp_path / "share"; b = tmp_path / "local"; a.mkdir(); b.mkdir()
    (a / "pc-PC1.json").write_text(json.dumps({"hostname": "PC1", "os": "old",
                                   "adapters": [{"ip": "192.168.0.5"}]}), encoding="utf-8")
    (b / "pc-PC1.json").write_text(json.dumps({"hostname": "PC1", "os": "new",
                                   "adapters": [{"ip": "192.168.0.5"}]}), encoding="utf-8")
    _os.utime(str(b / "pc-PC1.json"), (_t.time() + 10, _t.time() + 10))     # newer
    reps = E.read_reports([str(a), str(b)])
    assert len(reps) == 1 and reps[0]["os"] == "new"


def test_bom_csv_from_powershell(tmp_path):
    import time as _t
    now = _t.mktime(_t.strptime("2026-11-14 16:00:00", "%Y-%m-%d %H:%M:%S"))
    # Windows PowerShell 5.1 Out-File utf8 writes a BOM and CRLF line ends - the readers must still parse it
    for name, body in (("leak-PC1-202611.csv",
                        "time,pc,user,event,detail,drive,size_kb\r\n2026-11-14 10:00:00,PC1,u,USB_IN,x,E:,0\r\n"),
                       ("conn-PC1-202611.csv",
                        "time,pc,user,process,local_ip,remote_ip,remote_port\r\n"
                        "2026-11-14 10:00:00,PC1,u,AnyDesk.exe,192.168.0.9,5.5.5.5,443\r\n")):
        with open(tmp_path / name, "wb") as fh:
            fh.write(b"\xef\xbb\xbf" + body.encode("utf-8"))
    assert len(E.read_events(str(tmp_path), now=now)) == 1
    conns = E.read_conns(str(tmp_path), since_days=7, now=now)
    assert len(conns) == 1 and conns[0]["process"] == "AnyDesk.exe"
    assert E.proc_name_map(conns) == {("192.168.0.9", "5.5.5.5"): "AnyDesk"}
