"""problem_key is count-independent; fake/cloned-MAC is only a warning on a real clash."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_core as C  # noqa: E402
import nd_tools as T  # noqa: E402


def test_problem_key_ignores_counts():
    a = C.problem_key("4 device(s) are connected but have no IP in any scanned range")
    b = C.problem_key("7 device(s) are connected but have no IP in any scanned range")
    assert a == b and a != ""
    assert C.problem_key("Devices with a fake / cloned MAC address (4)") == \
           C.problem_key("Devices with a fake / cloned MAC address (2)")


def _cam(mac, ip):
    return {"online": True, "mac": mac, "ip": ip, "category": "CCTV cameras / DVR / NVR", "name": ""}


def test_unique_bogus_macs_are_not_reported():
    # unique (if fake) MACs don't clash, so they are harmless and no longer surfaced at all (not even info)
    devs = [_cam("A0:00:00:01:7F:EB", "192.168.0.123"), _cam("A0:00:00:01:7F:EF", "192.168.0.125")]
    issues = T.mac_health_issues(devs)
    assert not [i for i in issues if "fake / cloned" in i["title"]]


def test_duplicated_bogus_macs_stay_warning():
    devs = [_cam("A0:00:00:01:7F:EB", "192.168.0.123"), _cam("A0:00:00:01:7F:EB", "192.168.0.140")]
    issues = T.mac_health_issues(devs)
    # the real clash is reported, and the bogus note is a warning
    assert any("same MAC" in i["title"] for i in issues)
    bog = [i for i in issues if "fake / cloned" in i["title"]]
    assert bog and bog[0]["sev"] == "warning"
