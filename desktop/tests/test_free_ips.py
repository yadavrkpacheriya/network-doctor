"""Free-IP list: subnet hosts minus used, gateway excluded, compact ranges."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_core as C  # noqa: E402


def test_free_ips_excludes_used_and_gateway():
    used = {"192.168.0.10", "192.168.0.11", "192.168.0.50"}
    free = C.free_ips("192.168.0.0/24", used, gw="192.168.0.1")
    assert "192.168.0.1" not in free            # gateway excluded
    assert "192.168.0.10" not in free and "192.168.0.50" not in free
    assert "192.168.0.2" in free and "192.168.0.254" in free
    assert len(free) == 254 - 3 - 1             # 254 hosts - 3 used - gateway


def test_collapse_ranges():
    r = C.collapse_ranges(["192.168.0.2", "192.168.0.3", "192.168.0.4", "192.168.0.9"])
    assert r == ["192.168.0.2 - 192.168.0.4", "192.168.0.9"]
    assert C.collapse_ranges([]) == []


def test_bad_net_returns_empty():
    assert C.free_ips("not-a-subnet", set()) == []
