# -*- coding: utf-8 -*-
"""Fake IP cameras / NVRs for the sandbox.

  FakeXmeye     - speaks the real XMeye/DVRIP binary protocol on a fake socket, so nd_dvrip (login, read_info,
                  set_dhcp, recorder_update, reboot) runs unchanged via its `connect=` seam.
  FakeHttpCam   - a `send(ip,port,method,path,user,pw,...)` drop-in for nd_camline's Hikvision / Dahua setters.
  FakeOnvifCam  - a `call(ip,port,user,pw,body)` drop-in for nd_camline's ONVIF setter.
"""
import json
import struct

import nd_dvrip as DV


# --------------------------------------------------------------- XMeye / DVRIP
class FakeXmeye:
    """In-memory XMeye device. Seed credentials and config; get a `connect` callable for nd_dvrip."""
    def __init__(self, user="admin", pw="", model="HB-X", serial="SN123", name="front-gate"):
        self.user, self.pw = user, pw
        self.info = {"SerialNo": serial, "HardWare": model, "SoftWareVersion": "V5.00"}
        self.name = name
        self.config = {
            "NetWork.NetDHCP": [{"Interface": "eth0", "Enable": False}],
            "NetWork.NetCommon": {"HostName": name},
            "NetWork.RemoteDeviceV3": [],
        }
        self.rebooted = False

    def connect(self):
        """Return a `connect(addr, timeout)` callable for DvrIp(..., connect=...)."""
        def _connect(addr, timeout):
            return _XmeyeSock(self)
        return _connect


class _XmeyeSock:
    def __init__(self, dev):
        self.dev = dev
        self.session = 0x0001
        self._out = b""
        self.closed = False

    def settimeout(self, _):
        pass

    def sendall(self, data):
        _ff, _ver, session, seq, msg, size = struct.unpack(DV._HEAD, data[:20])
        req = json.loads(data[20:20 + size].rstrip(b"\x00\x0a \r").decode("utf-8", "replace") or "{}")
        self._out += self._reply(msg, req)

    def recv(self, n):
        if not self._out:
            raise OSError("closed")
        chunk, self._out = self._out[:n], self._out[n:]
        return chunk

    def close(self):
        self.closed = True

    def _reply(self, msg, req):
        d = self.dev
        if msg == DV.LOGIN:
            ok = req.get("UserName") == d.user and req.get("PassWord") == DV.sofia_hash(d.pw)
            body = {"Ret": 100, "SessionID": "0x%08X" % self.session} if ok else {"Ret": 203}
            return DV.pack(self.session, 0, DV.LOGIN + 100, body)
        if msg == DV.INFO:
            return self._named(DV.INFO + 100, "SystemInfo", d.info)
        if msg == DV.TITLES:
            return self._named(DV.TITLES + 100, "ChannelTitle", [d.name])
        if msg == DV.CONFIG_GET:
            name = req.get("Name", "")
            return self._named(DV.CONFIG_GET + 100, name, d.config.get(name))
        if msg == DV.CONFIG_SET:
            name = req.get("Name", "")
            d.config[name] = req.get(name)
            restart = name == "NetWork.NetDHCP"   # pretend DHCP change needs a reboot
            return DV.pack(self.session, 0, DV.CONFIG_SET + 100, {"Ret": 603 if restart else 100})
        if msg == DV.MACHINE:
            d.rebooted = True
            return DV.pack(self.session, 0, DV.MACHINE + 100, {"Ret": 100})
        return DV.pack(self.session, 0, msg + 100, {"Ret": 100})

    def _named(self, msg, name, value):
        return DV.pack(self.session, 0, msg, {"Ret": 100, "Name": name, name: value})


def xmeye_connect(dev):
    return dev.connect()


# --------------------------------------------------------------- Hikvision / Dahua over HTTP
class FakeHttpCam:
    """A `send` drop-in. brand='hik' or 'dahua'. Tracks state so DHCP<->static changes can be asserted."""
    def __init__(self, brand="hik", user="admin", pw="pw", addressing="static", dhcp_enable=False):
        self.brand, self.user, self.pw = brand, user, pw
        self.addressing = addressing      # hik: 'static' | 'dynamic'
        self.dhcp_enable = dhcp_enable     # dahua: bool
        self.rebooted = False
        self.calls = []

    def __call__(self, ip, port, method, path, user, pw, body="", ssl_on=False, ctype=None):
        self.calls.append((method, path))
        if user != self.user or pw != self.pw:
            return 401, "", {}
        if path == "/ISAPI/System/reboot":
            self.rebooted = True
            return 200, "<ResponseStatus><statusString>OK</statusString></ResponseStatus>", {}
        if self.brand == "hik" and path.startswith("/ISAPI/System/Network/interfaces"):
            if method == "GET":
                xml = ("<IPAddress><ipVersion>v4</ipVersion>"
                       f"<addressingType>{self.addressing}</addressingType>"
                       "<ipAddress>192.168.0.64</ipAddress></IPAddress>")
                return 200, xml, {}
            if method == "PUT":
                if "<addressingType>dynamic</addressingType>" in body:
                    self.addressing = "dynamic"
                return 200, "<ResponseStatus><statusString>OK</statusString></ResponseStatus>", {}
        if self.brand == "dahua" and path.startswith("/cgi-bin/configManager.cgi"):
            if "getConfig" in path:
                en = "true" if self.dhcp_enable else "false"
                return 200, ("table.Network.DefaultInterface=eth0\r\n"
                             f"table.Network.eth0.DhcpEnable={en}\r\n"
                             "table.Network.eth0.IPAddress=192.168.0.65\r\n"), {}
            if "setConfig" in path and "DhcpEnable=true" in path:
                self.dhcp_enable = True
                return 200, "OK", {}
        if self.brand == "dahua" and path == "/cgi-bin/magicBox.cgi?action=reboot":
            self.rebooted = True
            return 200, "OK", {}
        return 404, "", {}


def http_against(cam):
    return cam


# --------------------------------------------------------------- ONVIF
class FakeOnvifCam:
    """A `call(ip, port, user, pw, body) -> (status, text)` drop-in for onvif_set_dhcp."""
    def __init__(self, user="admin", pw="pw", dhcp=False, port=80, reboot_needed=False):
        self.user, self.pw, self.dhcp = user, pw, dhcp
        self.port, self.reboot_needed = port, reboot_needed
        self.rebooted = False

    def __call__(self, ip, port, user, pw, body):
        if user != self.user or pw != self.pw:
            return 401, ('<s:Fault><s:Code><s:Subcode><s:Value>ter:NotAuthorized</s:Value>'
                         '</s:Subcode></s:Code></s:Fault>')
        if port != self.port:
            raise OSError("no onvif here")
        if "GetNetworkInterfaces" in body:
            dhcp = "true" if self.dhcp else "false"
            return 200, (f'<NetworkInterfaces token="eth0"><IPv4><Config><DHCP>{dhcp}</DHCP>'
                         "</Config></IPv4></NetworkInterfaces>")
        if "SetNetworkInterfaces" in body:
            self.dhcp = True
            rn = "true" if self.reboot_needed else "false"
            return 200, f"<SetNetworkInterfacesResponse><RebootNeeded>{rn}</RebootNeeded></SetNetworkInterfacesResponse>"
        if "SystemReboot" in body:
            self.rebooted = True
            return 200, "<SystemRebootResponse/>"
        return 200, "<ok/>"


def onvif_against(cam):
    return cam
