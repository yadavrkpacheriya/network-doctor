"""Bind only devices already inside their fixed range; DVRIP reboot helper."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_bandwidth as BW  # noqa: E402
import nd_dvrip as DV  # noqa: E402


def _row(mac, ip, group, action="keep"):
    return {"dev": {"mac": mac, "ip": ip}, "group": group, "ip_now": ip, "ip_new": ip, "action": action}


def test_confirmed_rows_only_in_range():
    ranges = {"cam": ("192.168.0.121", "192.168.0.199")}
    rows = [_row("A", "192.168.0.130", "cam"),      # in range -> confirmed
            _row("B", "192.168.0.60", "cam"),       # outside range -> not confirmed
            _row("C", "192.168.0.140", "pc")]       # no range for its group -> skipped
    got = {r["dev"]["mac"] for r in BW.confirmed_rows(rows, ranges)}
    assert got == {"A"}


def test_confirmed_skips_blank_range_and_non_actions():
    ranges = {"cam": ("", "")}
    assert BW.confirmed_rows([_row("A", "192.168.0.130", "cam")], ranges) == []
    ranges = {"cam": ("192.168.0.100", "192.168.0.200")}
    assert BW.confirmed_rows([_row("A", "192.168.0.130", "cam", action="skip")], ranges) == []


class _FakeConn:
    def __init__(self, *a, **k):
        self.sent = []

    def sendall(self, b):
        self.sent.append(b)

    def recv(self, n):
        return b""

    def close(self):
        pass

    def settimeout(self, t):
        pass


def test_reboot_logs_in_and_calls_reboot(monkeypatch):
    calls = {}

    class FakeDvr:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def login(self, u, p):
            calls["login"] = (u, p)

        def reboot(self):
            calls["reboot"] = True

    monkeypatch.setattr(DV, "DvrIp", FakeDvr)
    assert DV.reboot("192.168.0.50", "admin", "pw") == "restarting"
    assert calls == {"login": ("admin", "pw"), "reboot": True}
