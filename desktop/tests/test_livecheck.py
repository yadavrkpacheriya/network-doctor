"""Camera liveness: frozen / dark / no-signal detection and baseline tracking - no network, no image library."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_livecheck as L  # noqa: E402

BIG_A = b"\xff\xd8" + b"ABCDEFGH" * 500   # a "detailed" frame (~4KB)
BIG_B = b"\xff\xd8" + b"HGFEDCBA" * 500   # a different detailed frame


def test_ok_when_two_frames_differ_and_full_size():
    r = L.compare(BIG_A, BIG_B, baseline_bytes=len(BIG_A))
    assert r["status"] == "ok" and r["kind"] == ""


def test_frozen_when_identical():
    r = L.compare(BIG_A, BIG_A, baseline_bytes=len(BIG_A))
    assert r["status"] == "frozen" and r["kind"] == "camera_down" and r["sev"] == "critical"


def test_dark_when_far_smaller_than_baseline():
    small = b"\xff\xd8" + b"\x00" * 1000   # black frame compresses tiny
    r = L.compare(BIG_A, small, baseline_bytes=len(BIG_A))
    assert r["status"] == "dark" and r["kind"] == "camera_tamper"


def test_nosignal_when_almost_no_bytes():
    r = L.compare(BIG_A, b"\xff\xd8", baseline_bytes=len(BIG_A))
    assert r["status"] == "nosignal" and r["kind"] == "camera_down"


def test_baseline_ema_tracks_without_jumping():
    b = L.update_baseline(0, 1000)          # first frame sets it
    assert b == 1000
    b2 = L.update_baseline(1000, 1500)      # moves toward, not to, the new size
    assert 1000 < b2 < 1500


def test_fetch_bad_url_returns_empty_not_raise():
    assert L.fetch("http://127.0.0.1:1/none.jpg", timeout=1) == b""
