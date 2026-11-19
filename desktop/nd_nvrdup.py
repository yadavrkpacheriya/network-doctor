# -*- coding: utf-8 -*-
"""Find duplicate cameras across and within NVRs/DVRs - pure, no I/O.

Two problems a site runs into:
  * within one NVR  - the same camera is added to two channels, wasting a channel and a licence.
  * across NVRs     - the same camera is recorded by two different NVRs, so storage and bandwidth double and
                      it's unclear which recording is authoritative.

The caller passes what it read from each recorder; this module just matches cameras (by IP, or MAC when the
recorder gives one) and reports the duplicates. Deleting anything is the caller's job, on confirmation.
"""


def _key(ch):
    """What identifies the camera on a channel - its MAC if present (survives IP changes), else its IP."""
    mac = (ch.get("mac") or "").strip().upper()
    if mac:
        return "mac:" + mac
    ip = (ch.get("ip") or "").strip()
    return ("ip:" + ip) if ip else ""


def find_duplicates(nvrs):
    """nvrs: list of {"nvr": <ip>, "name": <nvr name>, "channels": [<list_channels output>]}.
    Returns {"within": [...], "cross": [...]}.
      within: {"nvr","name","camera","channels":[chan numbers]}  - same camera on 2+ channels of ONE recorder.
      cross:  {"camera","on":[{"nvr","name","chan"}]}             - same camera on 2+ DIFFERENT recorders.
    """
    within, seen = [], {}            # seen: camera key -> list of (nvr_ip, nvr_name, chan, cam_label)
    for rec in nvrs:
        nip, nname = rec.get("nvr", ""), rec.get("name", "") or rec.get("nvr", "")
        by_cam = {}
        for ch in rec.get("channels", []):
            k = _key(ch)
            if not k:
                continue
            label = ch.get("ip") or ch.get("name") or k.split(":", 1)[-1]
            by_cam.setdefault(k, []).append((ch.get("chan"), label))
            seen.setdefault(k, []).append((nip, nname, ch.get("chan"), label))
        for k, hits in by_cam.items():
            if len(hits) > 1:
                within.append({"nvr": nip, "name": nname, "camera": hits[0][1],
                               "channels": sorted(h[0] for h in hits if h[0] is not None)})
    cross = []
    for k, hits in seen.items():
        recs = {h[0] for h in hits}
        if len(recs) > 1:                        # the camera is on more than one recorder
            cross.append({"camera": hits[0][3],
                          "on": [{"nvr": h[0], "name": h[1], "chan": h[2]} for h in hits]})
    return {"within": within, "cross": cross}


def find_orphans(nvrs, live_cameras):
    """Cameras live on the network but on NO recorder - i.e. not being recorded. `live_cameras` is a list of
    {"ip","name"} (the scanned cameras that are not themselves recorders). Any whose IP is not a channel IP on
    any recorder, and is not a recorder's own IP, is an orphan. Returns [{"ip","name"}]."""
    in_nvr, recorder_ips = set(), set()
    for rec in nvrs:
        recorder_ips.add((rec.get("nvr") or "").strip())
        for ch in rec.get("channels", []):
            ip = (ch.get("ip") or "").strip()
            if ip:
                in_nvr.add(ip)
    out, done = [], set()
    for c in live_cameras or []:
        ip = (c.get("ip") or "").strip()
        if not ip or ip in done or ip in in_nvr or ip in recorder_ips:
            continue
        done.add(ip)
        out.append({"ip": ip, "name": c.get("name") or ""})
    return out


def summary(dups):
    w, c = len(dups.get("within", [])), len(dups.get("cross", []))
    return w, c
