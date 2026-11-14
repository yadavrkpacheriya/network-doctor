"""Camera stream liveness - catch a camera that still answers ping but whose picture is frozen, black, or
tampered with.

A ping only proves the camera's network chip is alive; the lens can be covered, the sensor frozen, or the feed a
black screen while ping still succeeds. The honest, dependency-free way to tell from a PC is the camera's own
still-image URL (most IP cameras expose a JPEG snapshot over HTTP - ONVIF 'snapshot', or a vendor path like
/snapshot.jpg, /cgi-bin/snapshot.cgi, /onvifsnapshot/...). We grab two snapshots a few seconds apart and judge:

  * FROZEN  - the two images are byte-for-byte identical (a live scene is never pixel-perfect still; sensor noise
              alone changes bytes). Strong, false-positive-resistant signal.
  * TAMPER  - the image is suddenly far smaller than this camera's normal snapshot size. A covered or black frame
              compresses to a fraction of a detailed scene, so a big drop from the learned baseline flags a lens
              that was covered, sprayed, or unplugged-into-black.

No image library is needed (we never decode the JPEG), so this stays tiny and runs on any PC. The baseline size is
learned per camera over time and stored by the caller. Any detection here raises the brain kinds already seeded -
'camera_down' (frozen) and 'camera_tamper' (blacked-out) - which stay reviewed, never auto-acted."""
import hashlib


def _digest(b):
    return hashlib.sha1(b or b"").hexdigest()


def compare(shot_a, shot_b, baseline_bytes=0, drop_ratio=0.45, min_bytes=800):
    """Judge two snapshots (raw bytes). baseline_bytes: this camera's usual snapshot size (0 = not learned yet).
    Returns a dict: {status: 'ok'|'frozen'|'dark'|'nosignal', detail, size, kind, sev} - kind/sev set only when
    there is something to raise."""
    sa, sb = shot_a or b"", shot_b or b""
    size = len(sb)
    if size < min_bytes:  # almost no data came back - not a real frame
        return {"status": "nosignal", "detail": f"snapshot was only {size} bytes - no real picture",
                "size": size, "kind": "camera_down", "sev": "warning"}
    if _digest(sa) == _digest(sb) and len(sa) >= min_bytes:
        return {"status": "frozen", "detail": "two snapshots taken seconds apart are byte-for-byte identical - "
                                              "the picture is frozen even though the camera answers",
                "size": size, "kind": "camera_down", "sev": "critical"}
    if baseline_bytes and size < baseline_bytes * drop_ratio:
        return {"status": "dark", "detail": f"snapshot shrank to {size} bytes vs a usual ~{baseline_bytes} - the "
                                            f"view may be covered, blacked-out or sprayed (possible tampering)",
                "size": size, "kind": "camera_tamper", "sev": "warning"}
    return {"status": "ok", "detail": "picture is changing normally", "size": size, "kind": "", "sev": "info"}


def update_baseline(baseline_bytes, size, alpha=0.2):
    """Slowly track a camera's normal snapshot size (exponential moving average), so day/night changes don't
    false-alarm. Only fed with healthy ('ok') frames by the caller."""
    if size <= 0:
        return baseline_bytes
    if not baseline_bytes:
        return size
    return int((1 - alpha) * baseline_bytes + alpha * size)


# common vendor snapshot paths to try when the exact URL is not configured (first that returns a JPEG wins)
SNAPSHOT_PATHS = ("/snapshot.jpg", "/snap.jpg", "/image/jpeg.cgi", "/cgi-bin/snapshot.cgi",
                  "/onvif-http/snapshot", "/onvifsnapshot/media_service/snapshot", "/tmpfs/auto.jpg",
                  "/cgi-bin/api.cgi?cmd=Snap&channel=0")


def fetch(url, timeout=4, auth=None):
    """Grab one snapshot over HTTP. auth=(user,pass) for Basic auth. Returns bytes, or b'' on any failure. Only
    http(s) to a private host should be passed in by the caller - this does no network policy of its own."""
    import urllib.request
    import base64
    req = urllib.request.Request(url)
    if auth and auth[0]:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        req.add_header("Authorization", "Basic " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - caller passes a trusted LAN URL
            if r.status != 200:
                return b""
            return r.read(2_000_000)  # cap: a snapshot is tens-to-hundreds of KB
    except Exception:  # noqa: BLE001
        return b""
