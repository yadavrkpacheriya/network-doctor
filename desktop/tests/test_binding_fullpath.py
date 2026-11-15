"""IP-MAC binding must use FULL command paths so it works over the API, not only pasted in WinBox."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_tools as T  # noqa: E402


def test_binding_uses_full_paths_not_context():
    rows = [{"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.0.130", "name": "Cam 1"}]
    a, u = T.binding_commands(rows, {})
    assert "/ip dhcp-server lease add address=192.168.0.130" in a
    assert "/ip dhcp-server lease remove [find" in a and "/ip dhcp-server lease remove [find" in u
    # the bare WinBox context line (a lone '/ip dhcp-server lease' with no sub-command) must NOT be an executed line
    for line in a.splitlines():
        s = line.strip()
        if s.startswith("#") or not s:
            continue
        assert s != "/ip dhcp-server lease", "bare context line would do nothing over the API"


def test_strict_and_random_also_full_path():
    rows = [{"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.0.130", "name": "x"}]
    a, _ = T.binding_commands(rows, {}, strict_arp=True, block_random=True)
    assert "/ip arp add address=192.168.0.130" in a
    assert "/interface bridge filter add chain=input" in a
    assert "\n/interface bridge filter\n" not in a   # no bare context line
