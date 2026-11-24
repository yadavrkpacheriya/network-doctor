import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_ask as A


class FakeStore:
    def summary(self, days=1, dev=None):
        return {
            "sites": [{"site": "youtube.com", "bytes": 5e9, "devices": 4, "visits": 120},
                      {"site": "docs.google.com", "bytes": 1e9, "devices": 8, "visits": 300}],
            "apps": [{"app": "YouTube", "cat": "personal", "bytes": 5e9, "devices": 4},
                     {"app": "Docs", "cat": "work", "bytes": 1e9, "devices": 8}],
            "devices": [{"dev": "d1", "name": "Shankar PC", "ip": "192.168.0.158", "bytes": 6e9},
                        {"dev": "d2", "name": "Gate Cam", "ip": "192.168.0.151", "bytes": 3e8}],
        }


T = 1700000000
POWER = [
    {"ts": T, "up": ["nvr", "c1", "c2", "c3", "pc1"], "down": []},
    {"ts": T + 120, "up": ["nvr"], "down": ["c1", "c2", "c3", "pc1"]},   # power cut: nvr on UPS
    {"ts": T + 240, "up": ["nvr", "c1", "c2", "c3", "pc1"], "down": []},
]
CTX = {"usage": FakeStore(), "db": {"power_log": POWER},
       "names": {"c1": "Gate Cam", "nvr": "Main NVR", "pc1": "Shankar PC", "c2": "C2", "c3": "C3"}}


def test_which_site_uses_most_data():
    r = A.answer("which website uses the most data", CTX)
    assert r["understood"] and "youtube.com" in r["text"]
    assert r["rows"][0]["site"] == "youtube.com"


def test_which_device_uses_most_data():
    r = A.answer("which device uses the most data", CTX)
    assert r["understood"] and "Shankar PC" in r["text"]


def test_which_app_uses_most_data():
    r = A.answer("which app uses most data", CTX)
    assert r["understood"] and "YouTube" in r["text"]


def test_most_visited_site():
    r = A.answer("which site is most visited", CTX)
    assert r["understood"] and "docs.google.com" in r["text"]


def test_which_device_disconnects_most():
    r = A.answer("which device disconnects the most", CTX)
    assert r["understood"]
    # one of the dropped devices tops the list (nvr survived, so NOT nvr)
    assert "Main NVR" not in r["text"]


def test_not_on_ups():
    r = A.answer("which devices are not on ups", CTX)
    assert r["understood"] and "Main NVR" not in [row["device"] for row in r["rows"]]


def test_least_variant():
    r = A.answer("which website uses the least data", CTX)
    assert r["understood"] and r["rows"][0]["site"] == "docs.google.com"


def test_unknown_question_is_polite():
    r = A.answer("what's the weather", {})
    assert r["understood"] is False and "which website" in r["text"]


def test_no_data_does_not_crash():
    r = A.answer("which device disconnects the most", {})
    assert r["understood"] and "history" in r["text"].lower()
