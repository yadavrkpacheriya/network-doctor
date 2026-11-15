"""WiFi/LAN access guard: reply-only ARP detection, pool health, reversible fix, whitelist - no router needed."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_access as A  # noqa: E402


def test_find_blockers_only_lan_reply_only():
    ifaces = [{"name": "bridge", "type": "bridge", "arp": "reply-only", ".id": "*1"},
              {"name": "ether1-wan", "type": "ether", "arp": "reply-only", ".id": "*2"},  # still LAN-kind -> counts
              {"name": "wlan1", "type": "wlan", "arp": "enabled", ".id": "*3"},
              {"name": "pppoe-out1", "type": "pppoe-out", "arp": "reply-only", ".id": "*4"}]  # WAN -> ignored
    b = A.find_blockers(ifaces)
    names = {x["name"] for x in b}
    assert "bridge" in names and "pppoe-out1" not in names and "wlan1" not in names


def test_pool_health_flags_tight_and_waiting():
    leases = [{"dynamic": "true", "status": "bound"}] * 48 + [{"dynamic": "false"}] * 2
    pool = A.pool_health(leases, [{"ranges": "192.168.0.100-192.168.0.149"}])  # 50 addresses, 50 used
    assert pool["static"] == 2 and pool["dynamic"] == 48 and pool["tight"] is True
    ok = A.pool_health([{"dynamic": "true", "status": "bound"}], [{"ranges": "192.168.0.100-192.168.0.200"}])
    assert ok["tight"] is False


def test_assess_prefers_arp_block_then_pool():
    a = A.assess([{"name": "bridge", "id": "*1", "arp": "reply-only"}], {"tight": True})
    assert a["kind"] == "arp_block"
    a2 = A.assess([], {"tight": True, "used": 50, "waiting": 3})
    assert a2["kind"] == "dhcp_full"
    assert A.assess([], {"tight": False}) is None


class _Client:
    def __init__(self):
        self.calls = []
        self.ifaces = [{"name": "bridge", "type": "bridge", "arp": "reply-only", ".id": "*1"}]

    def cmd(self, path, **kw):
        if path == "/interface/print":
            return self.ifaces
        if path == "/ip/dhcp-server/lease/print":
            return [{"dynamic": "true", "status": "bound"}]
        if path == "/ip/pool/print":
            return [{"ranges": "192.168.0.100-192.168.0.200"}]
        return []

    def talk(self, words, check=True):
        self.calls.append(words)
        return []


def test_read_then_apply_then_undo_roundtrip():
    c = _Client()
    info, alert = A.read(c)
    assert alert and alert["kind"] == "arp_block" and info["blockers"][0]["name"] == "bridge"
    undo = A.apply_fix(c, info["blockers"])
    assert ["/interface/set", "=.id=*1", "=arp=enabled"] in c.calls
    assert undo == [{"id": "*1", "arp": "reply-only"}]
    A.undo_fix(c, undo)
    assert ["/interface/set", "=.id=*1", "=arp=reply-only"] in c.calls


def test_read_survives_router_without_sections():
    class Boom:
        def cmd(self, *a, **k):
            raise RuntimeError("no")
    info, alert = A.read(Boom())
    assert info["blockers"] == [] and alert is None


def test_whitelist_add_norm_remove():
    wl = A.add_to_whitelist([], "AA-BB-CC-DD-EE-FF", "Boss laptop")
    assert A.is_whitelisted(wl, "aa:bb:cc:dd:ee:ff")
    wl = A.add_to_whitelist(wl, "aa:bb:cc:dd:ee:ff")   # idempotent
    assert len(wl) == 1
    wl = A.remove_from_whitelist(wl, "AA:BB:CC:DD:EE:FF")
    assert not A.is_whitelisted(wl, "aa:bb:cc:dd:ee:ff")
