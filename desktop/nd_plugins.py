# -*- coding: utf-8 -*-
"""
Network Doctor - device plugins (nd_plugins)
=========================================================
One plugin per protocol or brand, all with the same shape, so the rest of the
app never needs to know which brand a switch or router is:

    probe(host, creds) -> True when this plugin can talk to the device
    read(host, creds)  -> {"host", "system", "interfaces", "neighbors", "macs"}

Standard-protocol plugins come first because one of them covers hundreds of
models. Vendor plugins (MikroTik API, TP-Link Omada, UniFi, Cisco SSH...) are
added later for what the standards cannot do. Every plugin is read-only until
it sets can_change, and changes will always come with a preview and an undo.
"""

import nd_snmp


class DevicePlugin:
    name = ""
    kind = "standard"   # "standard" (any brand) or "vendor"
    can_change = False  # read-only

    def probe(self, host, creds):
        raise NotImplementedError

    def read(self, host, creds):
        raise NotImplementedError


class SnmpPlugin(DevicePlugin):
    name = "SNMP"

    @staticmethod
    def _args(creds):
        return creds.get("community") or "public", creds.get("version") or "2c"

    def probe(self, host, creds):
        community, version = self._args(creds)
        try:
            info = nd_snmp.system_info(nd_snmp.Snmp(host, community, version, timeout=1.5, retries=0))
        except (nd_snmp.SnmpError, OSError):
            return False
        return bool(info["descr"] or info["name"] or info["object_id"])

    def read(self, host, creds):
        community, version = self._args(creds)
        return nd_snmp.read_device(host, community, version)


PLUGINS = [SnmpPlugin()]


def find(host, creds):
    """The first plugin that can talk to host, or None."""
    for p in PLUGINS:
        if p.probe(host, creds):
            return p
    return None
