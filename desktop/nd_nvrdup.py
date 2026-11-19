# -*- coding: utf-8 -*-
"""Find duplicate cameras across and within NVRs/DVRs - pure, no I/O.

Two problems a site runs into:
  * within one NVR  - the same camera is added to two channels, wasting a channel and a licence.
  * across NVRs     - the same camera is recorded by two different NVRs, so storage and bandwidth double and
                      it's unclear which recording is authoritative.

The caller passes what it read from each recorder; this module just matches cameras (by IP, or MAC when the
recorder gives one) and reports the duplicates. Deleting anything is the caller's job, on confirmation.
"""


def _norm(s):
    """Loose name key: lowercase, keep only letters+digits, so 'Gangway to Reception', 'gangway_reception' and
    'GANGWAY  RECEPTION' all match. Used to tie an NVR channel (name only, on firmwares that hide the camera IP)
    to the scanned camera of the same name - which DOES have an IP and MAC."""
    return "".join(c for c in (s or "").lower() if c.isalnum())


def _key(ch):
    """What identifies the camera on a channel - MAC (best, survives IP changes), else IP, else its name. The
    name fallback is what makes duplicate/orphan detection work on recorders that only report channel NAMES."""
    mac = (ch.get("mac") or "").strip().upper()
    if mac:
        return "mac:" + mac
    ip = (ch.get("ip") or "").strip()
    if ip:
        return "ip:" + ip
    nm = _norm(ch.get("name"))
    # skip the default placeholder names (CAM1, D06...) - they are not real identities and would false-match
    import re as _re
    if nm and not _re.fullmatch(r"(cam|d|ch|ipc|channel)\d+", nm):
        return "name:" + nm
    return ""


def enrich_from_scan(nvrs, scanned):
    """Fill each NVR channel's missing IP/MAC by matching its NAME to a scanned camera. `scanned` is the device
    list (each {"ip","mac","name"}). On firmwares that report channel names but not camera IPs, this is what
    lets the app still know which real camera sits on each channel. Mutates and returns nvrs."""
    by_name = {}
    for d in scanned or []:
        nm = _norm(d.get("name"))
        if nm and nm not in by_name:
            by_name[nm] = d
    for rec in nvrs:
        for ch in rec.get("channels", []):
            if (ch.get("ip") or "").strip() or (ch.get("mac") or "").strip():
                continue
            hit = by_name.get(_norm(ch.get("name")))
            if hit:
                ch["ip"] = hit.get("ip") or ch.get("ip", "")
                ch["mac"] = hit.get("mac") or ch.get("mac", "")
                ch["matched_by"] = "name"
    return nvrs


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
