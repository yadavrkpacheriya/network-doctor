import io, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_nvrcgi as C


class Resp(io.BytesIO):
    def close(self):
        pass


def _opener(channel_block):
    def opener(req, timeout=6):
        url = req.full_url
        if "login.cgi" in url:
            return Resp(json.dumps({"Ret": 100, "SessionID": "0x1"}).encode())
        if "getconfig.cgi" in url:
            name = json.loads(req.data.decode())["Name"]
            if name == "NetWork.NetDigital":
                return Resp(json.dumps({name: channel_block}).encode())
            return Resp(json.dumps({name: []}).encode())
        return Resp(b"{}")
    return opener


def test_channels_over_cgi():
    block = [
        {"Devices": [{"Name": "FG AREA", "IPAddress": "192.168.0.143", "Enable": True}]},
        {"Devices": [{"Name": "GATE", "IPAddress": "192.168.0.146", "Enable": True}]},
    ]
    out = C.channels("192.168.0.74", "admin", "p", opener=_opener(block))
    assert out[0] == {"chan": 1, "name": "FG AREA", "ip": "192.168.0.143", "online": True}
    assert out[1]["ip"] == "192.168.0.146"


def test_little_endian_hex_ip():
    # some firmwares store the IP as a little-endian int (0x4A00A8C0 -> 192.168.0.74)
    block = [{"Devices": [{"Name": "X", "IPAddress": 0x4A00A8C0, "Enable": True}]}]
    out = C.channels("192.168.0.74", "admin", "p", opener=_opener(block))
    assert out[0]["ip"] == "192.168.0.74"


def test_login_fail_returns_empty():
    def opener(req, timeout=6):
        return Resp(json.dumps({"Ret": 205}).encode())   # no SessionID
    assert C.channels("1.2.3.4", "x", "y", opener=opener) == []


def test_dead_box_never_raises():
    def opener(req, timeout=6):
        raise OSError("refused")
    assert C.channels("1.2.3.4", "x", "y", opener=opener) == []
