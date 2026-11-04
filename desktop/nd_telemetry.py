# -*- coding: utf-8 -*-
"""
Network Doctor - anonymous usage & crash reports, OFF until the person switches it on in Setup.

Helps the developer find real problems and see which features people actually use, without collecting
anything that could identify a person, a company or a device:
  * no IP addresses, host names, MAC addresses, user names, passwords, or any router / camera / scan data
  * a random install id (not derived from hardware, not the device name) so one install can be told apart
    from another, with nothing that maps it back to a person or a place
  * feature-use counts ("ran a login sweep" x3) - never what was scanned or found
  * crash details: the exception type, its message, and which function/line in Network Doctor's own code -
    never a local file path beyond the file name, never a variable's value

Nothing is recorded until the person turns this on, and nothing is ever sent anywhere until they also fill
in an "admin address" (Setup) - the developer's own Remote access tunnel (nd_tunnel.py), reusing the same
sign-in-free /api/telemetry endpoint nd_share.py already rate-limits and size-caps. Turning it off again
does not recall anything already sent, but stops anything further being recorded or sent.
"""
import json
import platform
import secrets
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request

UA = {"User-Agent": "NetworkDoctor-telemetry", "Content-Type": "application/json"}
MAX_CRASHES = 20
SEND_EVERY = 3600  # seconds between automatic sends while the app runs and this is switched on
TIMEOUT = 12
OWN_FILE_RE = ("nd_", "networkdoctor.py")  # which frame of a traceback is "our" code, for the crash location


def new_install_id():
    """16 random hex characters - not derived from the machine, the network or the person."""
    return secrets.token_hex(8)


def _basename(path):
    return str(path or "").replace("\\", "/").rsplit("/", 1)[-1]


def where(tb):
    """'file.py:123 in function' for the deepest frame that is Network Doctor's own code - no local path
    beyond the file name, no variable values. '?' if nothing usable is there."""
    frames = traceback.extract_tb(tb)
    for fr in reversed(frames):
        name = _basename(fr.filename).lower()
        if name.startswith(OWN_FILE_RE[0]) or name == OWN_FILE_RE[1]:
            return f"{_basename(fr.filename)}:{fr.lineno} in {fr.name}"
    if frames:
        fr = frames[-1]
        return f"{_basename(fr.filename)}:{fr.lineno} in {fr.name}"
    return "?"


class Telemetry:
    """One per app run. note(event) counts a feature use; note_error(context, exc) counts + remembers a
    sanitised crash. Both are no-ops while switched off, so nothing is even held in memory before consent.

    store: a dict persisted by save_fn() (the same settings dict the rest of the app already uses) -
    settings persist across runs (install id, on/off, admin address); counts and crashes are this run only
    and are cleared once successfully sent."""

    def __init__(self, app_name, version, store, save_fn, admin_url_fn=None):
        self.app_name, self.version = app_name, version
        self.store, self.save_fn, self.admin_url_fn = store, save_fn, admin_url_fn
        t = self.store.setdefault("telemetry", {})
        if not t.get("install_id"):
            t["install_id"] = new_install_id()
            try:
                self.save_fn()
            except Exception:
                pass
        self.lock = threading.Lock()
        self._counts = {}
        self._crashes = []
        self._timer = None

    # ---- settings
    @property
    def install_id(self):
        return self.store.get("telemetry", {}).get("install_id", "")

    @property
    def enabled(self):
        return bool(self.store.get("telemetry", {}).get("enabled", False))

    def set_enabled(self, on):
        self.store.setdefault("telemetry", {})["enabled"] = bool(on)
        if not on:
            with self.lock:
                self._counts, self._crashes = {}, []
        self.save_fn()

    def admin_url(self):
        if self.admin_url_fn:
            try:
                return self.admin_url_fn() or ""
            except Exception:
                return ""
        return self.store.get("telemetry", {}).get("admin_url", "")

    def set_admin_url(self, url):
        self.store.setdefault("telemetry", {})["admin_url"] = str(url or "").strip()
        self.save_fn()

    # ---- what the app does while it runs (no-ops until switched on)
    def note(self, event):
        if not self.enabled:
            return
        with self.lock:
            self._counts[event] = self._counts.get(event, 0) + 1

    def note_error(self, context, exc):
        if not self.enabled:
            return
        with self.lock:
            key = f"error:{str(context)[:40]}"
            self._counts[key] = self._counts.get(key, 0) + 1
            if len(self._crashes) < MAX_CRASHES:
                self._crashes.append({"context": str(context)[:60], "type": type(exc).__name__,
                                      "message": str(exc)[:200],
                                      "where": where(getattr(exc, "__traceback__", None))})

    def install_hook(self):
        """Unhandled exceptions outside Tkinter callbacks (a background thread, the main loop before the
        window exists) would otherwise just vanish if no console is open."""
        prev = sys.excepthook

        def hook(etype, value, tb):
            try:
                self.note_error("unhandled", value)
            except Exception:
                pass
            if prev:
                prev(etype, value, tb)
            else:
                traceback.print_exception(etype, value, tb)
        sys.excepthook = hook
        return hook

    def install_tk_hook(self, widget):
        """Tkinter swallows exceptions raised inside a button/menu callback by routing them to
        widget.report_callback_exception instead of sys.excepthook - catch those too."""
        prev = getattr(widget, "report_callback_exception", None)

        def hook(etype, value, tb):
            try:
                self.note_error("tk_callback", value)
            except Exception:
                pass
            if prev:
                prev(etype, value, tb)
        widget.report_callback_exception = hook
        return hook

    # ---- building + sending a report
    def pending_report(self):
        """What would be sent right now - shown to the person as 'what gets sent', for transparency."""
        with self.lock:
            return {"install_id": self.install_id, "app": self.app_name, "kind": "desktop",
                    "version": self.version, "platform": platform.platform(),
                    "sent_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "counts": dict(self._counts), "crashes": list(self._crashes)}

    def send_now(self, opener=None):
        """POSTs the pending report to the configured admin address and clears it on success.
        Returns (ok, detail). Never raises."""
        if not self.enabled:
            return False, "reports are switched off"
        url = self.admin_url().strip()
        if not url:
            return False, "no admin address set"
        rep = self.pending_report()
        if not rep["counts"] and not rep["crashes"]:
            return True, "nothing to send yet"
        body = json.dumps(rep).encode("utf-8")
        req = urllib.request.Request(url.rstrip("/") + "/api/telemetry", data=body, method="POST",
                                     headers={**UA, "Content-Length": str(len(body))})
        send = opener or urllib.request.urlopen
        try:
            with send(req, timeout=TIMEOUT) as r:
                r.read()
        except urllib.error.URLError as e:
            return False, str(e)
        except Exception as e:  # noqa: BLE001 - shown to the person, never raised
            return False, str(e)
        with self.lock:
            self._counts, self._crashes = {}, []
        return True, "sent"

    def start_background(self, interval=SEND_EVERY):
        """Sends automatically every `interval` seconds while this stays switched on with an address set."""
        def tick():
            try:
                if self.enabled:
                    self.send_now()
            except Exception:
                pass
            if self._timer is not None:  # not cancelled meanwhile
                self._timer = threading.Timer(interval, tick)
                self._timer.daemon = True
                self._timer.start()
        self._timer = threading.Timer(interval, tick)
        self._timer.daemon = True
        self._timer.start()

    def stop_background(self):
        if self._timer:
            self._timer.cancel()
            self._timer = None
