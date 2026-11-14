"""Fake/cloned and duplicate MACs (the real cause of the gateway flap on a flat network) are flagged + fixed."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_tools as T  # noqa: E402
import nd_alerts as A  # noqa: E402


def dev(ip, mac, cat="Cameras", name="", online=True):
    return {"ip": ip, "ips": [ip], "mac": mac, "category": cat, "name": name, "online": online}


def test_bogus_camera_macs_flagged():
    devs = [dev("192.168.0.76", "A0:00:00:01:81:0E", name="Office Cam"),
            dev("192.168.0.77", "A0:00:00:01:7F:F0"),
            dev("192.168.0.70", "F8:75:A4:8D:B7:FA", cat="Computers", name="RAKESH-IT")]
    out = T.mac_health_issues(devs)
    titles = [i["title"] for i in out]
    bogus = next(i for i in out if "fake / cloned" in i["title"])
    assert "(2)" in bogus["title"] and any("Office Cam" in x for x in bogus["items"])
    assert not any("RAKESH-IT" in x for i in out for x in i["items"])        # real vendor MAC is fine


def test_duplicate_mac_flagged():
    devs = [dev("192.168.0.55", "11:22:33:44:55:66"), dev("192.168.0.69", "11:22:33:44:55:66")]
    out = T.mac_health_issues(devs)
    dup = next(i for i in out if "same MAC" in i["title"])
    assert "192.168.0.55" in dup["items"][0] and "192.168.0.69" in dup["items"][0]


def test_offline_and_clean_network_no_issue():
    assert T.mac_health_issues([dev("192.168.0.76", "A0:00:00:01:81:0E", online=False)]) == []
    assert T.mac_health_issues([dev("192.168.0.70", "F8:75:A4:8D:B7:FA", cat="Computers")]) == []


def test_recipe_gives_unique_ip_fix_not_binding():
    r = A.recipe("Devices with a fake / cloned MAC address (3)")
    joined = " ".join(r["steps"]).lower()
    assert r["kind"] == "bogus_mac" and "fixed ip" in joined and "separate switch" in joined
    assert "do not ip-mac bind" in joined and r["kind"] not in A.AUTO_SAFE


def test_router_port_summary():
    hosts = [{"mac-address": "A0:00:00:01:7F:F0", "on-interface": "ether4"},
             {"mac-address": "A0:00:00:01:81:0E", "on-interface": "ether4"},
             {"mac-address": "A0:00:00:01:81:0E", "on-interface": "ether4"},     # duplicate row: counted once
             {"mac-address": "F8:75:A4:8D:B7:FA", "on-interface": "ether2"},
             {"mac-address": "CC:2D:E0:B6:DE:5B", "on-interface": "bridge", "local": "true"}]  # router itself: skip
    devs = [{"mac": "F8:75:A4:8D:B7:FA", "ip": "192.168.0.70", "name": "RAKESH-IT"},
            {"mac": "A0:00:00:01:81:0E", "ip": "192.168.0.76", "name": "Office Cam"}]
    r = T.router_port_summary(hosts, devs, {})
    ports = dict(r)
    assert r[0][0] == "ether4" and ports["ether4"]["count"] == 2 and ports["ether4"]["bogus"] == 2
    assert "Office Cam (192.168.0.76)" in ports["ether4"]["named"]
    assert ports["ether2"]["count"] == 1 and ports["ether2"]["bogus"] == 0
    assert "bridge" not in ports        # the router's own interface is not a port with devices
