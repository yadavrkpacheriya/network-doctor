"""A device with a live IP + a stale router-only IP should resolve to the live one (no double entry)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_core as C  # noqa: E402


def test_stale_router_ip_demoted_when_a_live_ip_exists():
    # .205 answered the scan (ping); .61 is only in the router's ARP -> stale
    live, stale = C.resolve_ips({"192.168.0.61", "192.168.0.205"},
                                router_arp={"192.168.0.61": "AA"}, ping={"192.168.0.205"})
    assert live == {"192.168.0.205"} and stale == ["192.168.0.61"]


def test_two_live_ips_both_kept():
    live, stale = C.resolve_ips({"192.168.0.80", "192.168.0.206"},
                                router_arp={}, ping={"192.168.0.80", "192.168.0.206"})
    assert live == {"192.168.0.80", "192.168.0.206"} and stale == []


def test_fully_asleep_device_keeps_its_router_ip():
    # no live IP at all (only the router sees it) -> do not strip, or it would vanish
    live, stale = C.resolve_ips({"192.168.0.61"}, router_arp={"192.168.0.61": "AA"}, ping=set())
    assert live == {"192.168.0.61"} and stale == []
