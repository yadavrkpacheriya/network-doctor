"""Finding a device by its MAC alone, and telling two people with the same name apart in usage alerts."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_tools as T  # noqa: E402
import nd_usage as U  # noqa: E402

DEVS = [{"mac": "00:22:46:53:F7:89", "ip": "192.168.0.44", "ips": ["192.168.0.44"], "name": "cam-gate", "category": "Cameras"},
        {"mac": "AA:BB:CC:00:00:01", "ip": "192.168.0.57", "ips": ["192.168.0.57"], "name": "Hitesh", "category": "Computers"}]


def test_mac_query_formats():
    for t in ("00:22:46:53:f7:89", "00-22-46-53-F7-89", "0022.4653.f789", "00224653F789", " 002246 53f789 "):
        assert T.mac_query(t) == "00:22:46:53:F7:89"
    for t in ("", "hitesh", "192.168.0.44", "00:22:46", "cafe", "0022465"):
        assert T.mac_query(t) == ""


def test_search_by_mac_any_format():
    for q in ("00-22-46-53-f7-89", "0022.4653.F789", "00224653f789", "00:22:46:53:F7:89"):
        got = T.filter_devices(DEVS, q)
        assert [d["name"] for d in got] == ["cam-gate"], q
    assert T.filter_devices(DEVS, "00-11-22-33-44-55") == []
    assert len(T.filter_devices(DEVS, "192.168.0.57")) == 1          # an IP is not taken for a MAC


def _text(lines):
    return "\n".join(t for t, _k in lines)


def test_locate_known_and_self():
    out = _text(T.locate_mac("00:22:46:53:f7:89", DEVS, {}, None, self_mac="00:22:46:53:F7:89"))
    assert "THIS PC" in out and "cam-gate" in out and "not asked" in out


def test_locate_router_only_no_ip():
    router = {"arp": [], "leases": [], "hosts": [{"mac-address": "00:22:46:53:F7:99", "on-interface": "ether4"}]}
    out = _text(T.locate_mac("00:22:46:53:F7:99", DEVS, {}, router))
    assert "Not in the device list" in out and "ether4" in out and "no IP address" in out


def test_locate_other_range_and_lease():
    router = {"arp": [{"mac-address": "00:22:46:53:F7:99", "address": "192.168.1.10", "interface": "bridge"}],
              "leases": [{"mac-address": "00-22-46-53-F7-99", "address": "192.168.1.10", "host-name": "IPC",
                          "status": "bound"}], "hosts": []}
    out = _text(T.locate_mac("00:22:46:53:F7:99", DEVS, {}, router))
    assert "192.168.1.10" in out and "'IPC'" in out and "outside the range" in out


def test_locate_nowhere_and_history():
    router = {"arp": [], "leases": [], "hosts": []}
    out = _text(T.locate_mac("00:22:46:53:F7:99", DEVS,
                             {"00:22:46:53:F7:99": {"ip": "192.168.0.9", "last_seen": "2026-11-01"}}, router))
    assert "earlier scan" in out and "2026-11-01" in out and "does not know this MAC" in out


def test_who_shows_department_and_ip():
    names = {"a": {"name": "Hitesh", "ip": "192.168.0.57", "dept": "Accounts"},
             "b": {"name": "Hitesh", "ip": "192.168.0.61", "dept": ""},
             "c": {"name": "192.168.0.80", "ip": "192.168.0.80"}}
    w = U.UsageStore.who
    assert w(names, "a") == "Hitesh - Accounts (192.168.0.57)"
    assert w(names, "b") == "Hitesh (192.168.0.61)"
    assert w(names, "c") == "192.168.0.80"
    assert w(names, "zz") == "zz"
    assert w(names, "a") != w(names, "b")
