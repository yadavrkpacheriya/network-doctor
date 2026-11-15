"""Multi-brand camera reboot: Hikvision ISAPI, Dahua CGI, refused-login detection - with a mock sender."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_camline as CL  # noqa: E402


def test_hikvision_reboot():
    def send(ip, port, method, path, user, pw, **k):
        return (200, "", "") if path == "/ISAPI/System/reboot" and method == "PUT" else (404, "", "")
    assert "Hikvision" in CL.reboot_camera("192.168.0.80", "admin", "pw", send=send)


def test_dahua_reboot():
    def send(ip, port, method, path, user, pw, **k):
        return (200, "ok", "") if "magicBox.cgi?action=reboot" in path else (404, "", "")
    assert "Dahua" in CL.reboot_camera("192.168.0.80", "admin", "pw", send=send)


def test_refused_login_raises_clear_error():
    def send(ip, port, method, path, user, pw, **k):
        return (401, "", "")
    try:
        CL.reboot_camera("192.168.0.80", "admin", "bad", send=send)
        assert False, "should have raised"
    except CL.CamError as e:
        assert "refused" in str(e)


def test_no_method_answers():
    def send(ip, port, method, path, user, pw, **k):
        return (404, "", "")
    try:
        CL.reboot_camera("192.168.0.80", "admin", "pw", ports=(80,), send=send)
        assert False
    except CL.CamError as e:
        assert "no known reboot" in str(e)
