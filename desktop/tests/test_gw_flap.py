"""Repeated short gateway drops are diagnosed as ARP/storm/loop, not an internet outage, and get a permanent fix."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_monitor as M  # noqa: E402
import nd_alerts as A  # noqa: E402
import nd_tools as T  # noqa: E402


def ev(dt, kind, **data):
    return {"t": 1000.0 + dt, "kind": kind, "data": data}


def test_arp_cause_named_with_macs():
    now = 1200.0
    events = ([ev(i * 30, "gw_down") for i in range(4)]
              + [ev(10, "ip_conflict", mac="A0:00:00:01:81:0E"),
                 ev(40, "dhcp_conflict", mac="5A:5A:02:8C:D6:12")])
    r = M.gateway_drop_cause(events, now=now)
    assert r["flapping"] and r["drops"] == 4 and r["cause"] == "arp"
    assert "A0:00:00:01:81:0E" in r["macs"] and "NOT the internet" in r["text"]


def test_storm_cause_pulls_top_senders():
    now = 1200.0
    events = ([ev(i * 20, "gw_down") for i in range(3)]
              + [ev(5, "storm", top=[["00:22:46:53:F7:89", 394], ["A0:00:00:01:7F:F0", 7]])])
    r = M.gateway_drop_cause(events, now=now)
    assert r["cause"] == "storm" and "00:22:46:53:F7:89" in r["macs"]


def test_loop_cause():
    now = 1200.0
    r = M.gateway_drop_cause([ev(i * 10, "gw_down") for i in range(3)] + [ev(5, "loop", iface="ether3")], now=now)
    assert r["cause"] == "loop"


def test_not_flapping_when_few_drops_or_no_evidence():
    now = 1200.0
    assert not M.gateway_drop_cause([ev(0, "gw_down"), ev(30, "gw_down")], now=now)["flapping"]
    # 3 drops but no ARP/storm/loop evidence -> still flagged, cause 'unknown'
    r = M.gateway_drop_cause([ev(i * 10, "gw_down") for i in range(3)], now=now)
    assert r["flapping"] and r["cause"] == "unknown"
    # old drops outside the window do not count
    assert not M.gateway_drop_cause([ev(-5000, "gw_down") for _ in range(5)], now=now)["flapping"]


def test_recipe_routes_to_permanent_fix():
    r = A.recipe("Router keeps dropping for a few seconds (12 times in ~15 min) - this is NOT the internet "
                 "going down. Cause: ARP conflicts. Devices: A0:00:00:01:81:0E.")
    assert r["kind"] == "gw_flap"
    joined = " ".join(r["steps"]).lower()
    assert "binding" in joined and "reply-only" in joined and "netcut" in joined
    assert r["kind"] not in A.AUTO_SAFE          # never auto-applied: it can cut a device off


def test_gw_protect_guard_is_reversible_and_needs_binding_first():
    a, u = T.guard_commands({"gw_protect": True}, [], "192.168.0.70", "bridge",
                            "192.168.0.1", "CC:2D:E0:B6:DE:5B")
    assert "arp=reply-only" in a and "add address=192.168.0.1 mac-address=CC:2D:E0:B6:DE:5B" in a
    assert "AFTER every device is bound" in a            # the safety warning is present
    assert "arp=enabled" in u and "add-arp=no" in u      # fully undoable
