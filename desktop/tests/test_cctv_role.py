"""Auto NVR/DVR vs camera split - no tagging needed."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_core as C  # noqa: E402


def _cam(**kw):
    d = {"category": C.CAT_CAM, "ip": "192.168.0.50", "ports": [554], "name": "", "vendor": "Hikvision",
         "http": {}, "upnp": {}, "names": {}, "random": False, "mac": "AA"}
    d.update(kw)
    return d


def test_recorder_detected_from_web_text():
    d = _cam(http={"title": "NVR Login", "blob": "NetSurveillance WEB NVR"})
    assert C.cctv_role(d) == "nvr"
    assert "DVR / NVR" in C.auto_name(d)


def test_plain_camera_is_camera():
    d = _cam(http={"title": "IP Camera", "blob": "ipc web"})
    assert C.cctv_role(d) == "camera"
    assert "Camera" in C.auto_name(d) and "NVR" not in C.auto_name(d)


def test_user_tag_wins():
    assert C.cctv_role(_cam(kind="DVR / NVR")) == "nvr"
    assert C.cctv_role(_cam(kind="Camera", http={"title": "dvr"})) == "camera"


def test_non_cctv_role_blank():
    assert C.cctv_role({"category": C.CAT_PC}) == ""
