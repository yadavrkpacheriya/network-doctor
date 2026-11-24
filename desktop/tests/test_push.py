import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_push as P


class FakeResp:
    def __init__(self, code=200): self.status = code
    def close(self): pass


def test_new_topic_is_random_and_prefixed():
    a, b = P.new_topic(), P.new_topic()
    assert a.startswith("nd-") and b.startswith("nd-")
    assert a != b and len(a) >= 10


def test_topic_url():
    assert P.topic_url("nd-abc") == "https://ntfy.sh/nd-abc"
    assert P.topic_url("/nd-abc") == "https://ntfy.sh/nd-abc"


def test_build_payload_headers():
    url, data, headers = P.build_payload("nd-x", "Title here", "Body message", click="nd://open")
    assert url == "https://ntfy.sh/nd-x"
    assert headers["Priority"] == "high" and headers["Title"] == "Title here"
    assert headers["Click"] == "nd://open"
    assert data == b"Body message"


def test_send_success_and_failure():
    sent = {}
    def ok_opener(req, timeout=8):
        sent["url"] = req.full_url
        sent["body"] = req.data
        return FakeResp(200)
    assert P.send("nd-x", "t", "m", opener=ok_opener) is True
    assert sent["url"] == "https://ntfy.sh/nd-x"

    def bad_opener(req, timeout=8):
        raise OSError("offline")
    assert P.send("nd-x", "t", "m", opener=bad_opener) is False       # never raises


def test_send_no_topic_is_false():
    assert P.send("", "t", "m") is False


def test_approval_push_counts():
    calls = []
    def opener(req, timeout=8):
        calls.append(req.headers.get("Title"))
        return FakeResp(200)
    assert P.approval_push("nd-x", 1, "DHCP fix", opener=opener) is True
    assert P.approval_push("nd-x", 3, "DHCP fix", opener=opener) is True
    assert P.approval_push("nd-x", 0, "x", opener=opener) is False    # nothing pending
    assert "approval" in calls[0].lower()


def test_unicode_body_does_not_break():
    def opener(req, timeout=8):
        req.data.decode("ascii")   # must be ascii-safe
        return FakeResp(200)
    assert P.send("nd-x", "café ☕", "naïve — message", opener=opener) is True
