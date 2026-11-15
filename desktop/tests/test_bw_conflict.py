"""IP-conflict auto-resolve in the fixed-IP plan: movable device moves off a shared IP; device-side stays flagged."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_bandwidth as BW  # noqa: E402


def _dev(mac, ip, random=False, conflict=False):
    return {"mac": mac, "ip": ip, "ips": [ip], "online": True, "random": random, "conflict": conflict}


def _types(static_macs):
    return lambda d: "static" if d["mac"] in static_macs else "dhcp"


def test_conflict_moves_dhcp_device_keeps_handtyped():
    # two devices answer 192.168.0.62: one hand-typed (static), one DHCP -> DHCP one moves, static one keeps
    devs = [_dev("AA", "192.168.0.62"), _dev("BB", "192.168.0.62")]
    plan = BW.ip_plan(devs, "192.168.0.1", {}, (), ip_type_of=_types({"AA"}),
                      net="192.168.0.0/24", auto_resolve=True)
    by = {r["dev"]["mac"]: r for r in plan}
    assert by["AA"]["action"] == "keep"          # hand-typed keeps the IP
    assert by["BB"]["action"] == "move"          # DHCP one moves to a free IP
    assert by["BB"]["ip_new"] != "192.168.0.62" and by["BB"]["ip_new"] not in ("192.168.0.1",)


def test_without_auto_resolve_still_skips():
    devs = [_dev("AA", "192.168.0.62"), _dev("BB", "192.168.0.62")]
    plan = BW.ip_plan(devs, "192.168.0.1", {}, (), ip_type_of=_types({"AA"}), net="192.168.0.0/24")
    assert all(r["action"] == "skip" for r in plan)   # default behaviour unchanged


def test_two_handtyped_conflict_flags_device_side():
    devs = [_dev("AA", "192.168.0.62"), _dev("BB", "192.168.0.62")]
    plan = BW.ip_plan(devs, "192.168.0.1", {}, (), ip_type_of=_types({"AA", "BB"}),
                      net="192.168.0.0/24", auto_resolve=True)
    acts = sorted(r["action"] for r in plan)
    assert acts == ["keep", "skip"]   # one keeps, the other must be changed on the device
    skip = [r for r in plan if r["action"] == "skip"][0]
    assert "on the device" in skip["why"]
