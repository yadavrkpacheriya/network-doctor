# -*- coding: utf-8 -*-
"""A saved channel->camera-IP map per NVR/DVR, so the app always knows which cameras belong to which recorder
even when the recorder's own API/web is locked or encrypted and can't be read live.

Why this exists: some recorders (Rakesh's NVR 192.168.0.74) encrypt their whole web API end-to-end and refuse
the binary DVRIP API, so the app cannot read their channel list programmatically at all. But the list rarely
changes. So we store it once (read from the recorder's web page), and then EVERY scan cross-checks each stored
camera IP against what's actually live on the network - giving live "which NVR camera is online/offline/missing"
without ever logging into the recorder again. Refresh the stored map only when cameras are added/removed.

The map lives in the app db under db["nvr_map"] = { "<nvr_ip>": {"name":..., "channels":[{"chan","ip","name"}]}}.
Pure helpers here; the app owns the db.
"""


def set_map(db, nvr_ip, channels, name=""):
    """Store/replace the channel list for one recorder. channels: [{"chan","ip","name"(opt)}]."""
    m = db.setdefault("nvr_map", {})
    m[nvr_ip] = {"name": name or m.get(nvr_ip, {}).get("name", ""),
                 "channels": [{"chan": c.get("chan", i + 1), "ip": c.get("ip", ""),
                               "name": c.get("name", "")} for i, c in enumerate(channels) if c.get("ip")]}
    return m[nvr_ip]


def get_map(db, nvr_ip):
    return (db.get("nvr_map") or {}).get(nvr_ip)


def all_mapped_ips(db):
    """Every camera IP known to belong to any recorder -> {ip: (nvr_ip, chan, name)}."""
    out = {}
    for nvr_ip, rec in (db.get("nvr_map") or {}).items():
        for c in rec.get("channels", []):
            if c.get("ip"):
                out[c["ip"]] = (nvr_ip, c.get("chan"), c.get("name", ""))
    return out


def coverage(db, live_ips):
    """Cross-check the stored maps against the IPs seen live on the network this scan.
    live_ips: a set/list of IP strings currently online. Returns per-recorder:
      {"nvr": ip, "name":..., "total": n, "online": [...], "offline": [...]}
    where online/offline are [{"chan","ip","name"}]. This is the live camera-health answer, no recorder login."""
    live = set(live_ips or [])
    out = []
    for nvr_ip, rec in (db.get("nvr_map") or {}).items():
        on, off = [], []
        for c in rec.get("channels", []):
            (on if c.get("ip") in live else off).append(c)
        out.append({"nvr": nvr_ip, "name": rec.get("name", ""), "total": len(rec.get("channels", [])),
                    "online": on, "offline": off})
    return out


def orphan_cameras(db, live_cameras):
    """Cameras seen live on the network that are NOT on any recorder's stored map - i.e. a camera nobody is
    recording. live_cameras: [{"ip","name"(opt)}]. Returns the subset not in any map."""
    mapped = set(all_mapped_ips(db))
    return [c for c in (live_cameras or []) if c.get("ip") and c["ip"] not in mapped]
