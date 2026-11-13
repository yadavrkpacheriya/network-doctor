# -*- coding: utf-8 -*-
"""Per-device bandwidth via SNMP switch port counters - the fallback for NetFlow (nd_monitor.py's
Traffic.rates()), which only sees traffic that crosses the router. A camera talking only to a local NVR
on the same switch never reaches the router, so NetFlow reports nothing for it; the switch's own port
counters still see it, because every byte in or out of a port is counted there regardless of where it
is headed.

Pure logic only here (no window code, no sockets, no sleeping) so it can be tested without a screen or a
real switch; the sampling loop that does the actual two-reads-a-few-seconds-apart SNMP I/O lives in
NetworkDoctor.py, the same split nd_snmp.py / nd_toolstab.py already use.

Only ports where EXACTLY ONE MAC was learned are attributed to a device - a port with 2+ MACs is a small
unmanaged switch (or a hub) cascading off this one, and splitting its shared total between the devices
behind it would be a guess. Those are left blank, same as today (no NetFlow data either), rather than
showing a number that could be wrong.
"""
import nd_snmp as SNMP

CACHE_MAX_AGE = 90  # seconds - a reading older than this is not shown (the switch may be unreachable now)


def get_switches(db):
    """[{ip, community, version, name}] - the switches to sample. Saved once from the Switches (SNMP) tab."""
    return list(db.get("snmp_switches") or [])


def set_switches(db, switches):
    db["snmp_switches"] = switches


def add_switch(db, ip, community, version="2c", name=""):
    """Adds (or updates, by IP) one switch to sample for port bandwidth."""
    xs = [s for s in get_switches(db) if s.get("ip") != ip]
    xs.append({"ip": ip, "community": community, "version": version or "2c", "name": name})
    set_switches(db, xs)
    return xs


def remove_switch(db, ip):
    set_switches(db, [s for s in get_switches(db) if s.get("ip") != ip])


def single_mac_ports(macs):
    """{mac: port_name} - only for ports where exactly one MAC was learned (see module docstring)."""
    by_port = SNMP.ports_with_devices(macs)
    return {ms[0]: port for port, ms in by_port.items() if len(ms) == 1}


def mac_bandwidth(ifs, macs, port_rates):
    """ifs: nd_snmp.interfaces() list. macs: nd_snmp.mac_table() {mac: port_name}. port_rates:
    nd_snmp.rates(prev, cur) {ifIndex: {"in": bytes/s, "out": bytes/s, ...}}. Returns {mac: {"down_bps",
    "up_bps"}} (bytes/second, same units as nd_monitor.Traffic.rates()) for the confidently-attributable
    devices only. "in" at the switch (device -> switch) is the device's upload; "out" (switch -> device)
    is the device's download."""
    idx_by_name = {i["name"]: i["index"] for i in ifs}
    out = {}
    for mac, port in single_mac_ports(macs).items():
        idx = idx_by_name.get(port)
        r = port_rates.get(idx) if idx is not None else None
        if r:
            out[mac] = {"up_bps": r.get("in") or 0, "down_bps": r.get("out") or 0}
    return out


def merge_caches(caches):
    """Combines the per-switch {mac: {...}} results from sample_switch() calls into one {mac: {...}}."""
    out = {}
    for c in caches:
        out.update(c or {})
    return out


def sample_switch(ip, community, version="2c", timeout=2.0, gap=1.2, sleep=None):
    """Does the real SNMP I/O for one switch: two counter readings `gap` seconds apart, then
    mac_bandwidth() on the result. Returns {mac: {down_bps, up_bps}}, or {} if the switch did not answer
    (never raises - a switch that's rebooting or unreachable should just mean 'no fallback data this
    round', not a crash of the periodic sampler)."""
    import time
    sleep = sleep or time.sleep
    try:
        c = SNMP.Snmp(ip, community or "public", version or "2c", timeout=timeout)
        ifs = SNMP.interfaces(c)
        macs = SNMP.mac_table(c, ifs)
        if not single_mac_ports(macs):
            return {}
        prev = SNMP.counters(c)
        sleep(gap)
        cur = SNMP.counters(c)
    except Exception:
        return {}
    return mac_bandwidth(ifs, macs, SNMP.rates(prev, cur))
