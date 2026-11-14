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
