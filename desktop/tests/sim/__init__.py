# -*- coding: utf-8 -*-
"""Simulation sandbox for Network Doctor.

A fake MikroTik router (speaks the real RouterOS binary API wire protocol) and fake IP cameras / NVRs
(XMeye-DVRIP on 34567, Hikvision ISAPI, Dahua CGI, ONVIF over HTTP). The point: exercise the SAME code
paths the app uses against a real device - binding, DHCP<->static, leases/arp/firewall reads, camera move,
restart, config backup, SNMP - entirely in memory, so an update can be proven before it ships.

Everything here is test-only: nothing in this package is imported by the shipping app.
"""
from .fake_router import FakeRouter, router_socket, RouterOS_against  # noqa: F401
from .fake_camera import (  # noqa: F401
    FakeXmeye, xmeye_connect, FakeHttpCam, FakeOnvifCam, http_against, onvif_against,
)
