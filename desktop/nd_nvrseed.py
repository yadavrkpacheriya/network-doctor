# -*- coding: utf-8 -*-
"""Built-in channel maps for recorders whose web API is encrypted/locked and can't be read programmatically.

These were read ONCE from the recorder's own web page (Remote Setting > IP Channels) and are baked in so the
app knows each recorder's cameras from the first run. apply() seeds them only if the user has no map for that
recorder yet, so a later live read or a user refresh always wins. Refresh a recorder's list by re-reading it
(the NVR cameras screen saves whatever it reads).

NVR 192.168.0.74 ("FAN-AIR", 32ch) - read live from its web UI on 2026-11-24 (Rakesh).
"""
import nd_nvrmap as M

# nvr_ip -> (name, [(channel, camera_ip), ...])
SEED = {
    "192.168.0.74": ("FAN-AIR", [
        (1, "192.168.0.143"), (2, "192.168.0.161"), (3, "192.168.0.82"), (4, "192.168.0.151"),
        (5, "192.168.0.139"), (6, "192.168.0.196"), (7, "192.168.0.126"), (8, "192.168.0.149"),
        (9, "192.168.0.199"), (10, "192.168.0.159"), (11, "192.168.0.147"), (12, "192.168.0.55"),
        (13, "192.168.0.130"), (14, "192.168.0.33"), (15, "192.168.0.36"), (16, "192.168.0.146"),
        (17, "192.168.0.81"), (18, "192.168.0.148"), (19, "192.168.0.60"), (20, "192.168.0.154"),
        (21, "192.168.0.137"), (22, "192.168.0.79"), (23, "192.168.0.157"), (24, "192.168.0.123"),
        (25, "192.168.0.160"), (26, "192.168.0.132"), (27, "192.168.0.153"), (28, "192.168.0.158"),
        (29, "192.168.0.138"), (30, "192.168.0.31"), (31, "192.168.0.152"), (32, "192.168.0.77"),
    ]),
    # NVR 192.168.0.22 (11 cameras; CH12-32 empty) - read live from its web UI on 2026-11-24 (Rakesh).
    "192.168.0.22": ("NVR .22", [
        (1, "192.168.0.142"), (2, "192.168.0.141"), (3, "192.168.0.157"), (4, "192.168.0.144"),
        (5, "192.168.0.125"), (6, "192.168.0.34"), (7, "192.168.0.150"), (8, "192.168.0.156"),
        (9, "192.168.0.195"), (10, "192.168.0.135"), (11, "192.168.0.162"),
    ]),
}


def apply(db):
    """Seed any recorder the user has no map for yet. Returns the number of recorders seeded."""
    existing = db.get("nvr_map") or {}
    n = 0
    for ip, (name, chans) in SEED.items():
        if ip in existing and (existing[ip].get("channels")):
            continue                      # user already has a map (live read or refresh) - never overwrite
        M.set_map(db, ip, [{"chan": c, "ip": i, "name": ""} for c, i in chans], name=name)
        n += 1
    return n
