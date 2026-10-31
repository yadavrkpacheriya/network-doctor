# -*- coding: utf-8 -*-
"""
Network Doctor - phone link (PC viewer).

The PC app offers a small JSON API on the office LAN so the Network Doctor phone app can show the
PC's devices, problems, live monitor, top bandwidth users and root-cause findings.

  * Off by default; switched on in the Setup tab.
  * LAN only: requests from internet (public) addresses are refused.
  * Pairing: the phone sends the 6-digit code shown on the PC and receives a long random token.
    5 wrong codes lock pairing for 5 minutes. Paired phones can be removed in the Setup tab.
  * Discovery: the phone broadcasts "NETWORK-DOCTOR-DISCOVER" on UDP 8788; the PC answers.

Endpoints (port 8787):
  GET  /api/hello                  -> app name, version, PC name (no token needed)
  POST /api/pair   {"code","phone"}-> {"token"}
  GET  /api/state                  -> full snapshot           (header X-ND-Token)
  POST /api/scan                   -> starts a scan on the PC (header X-ND-Token)
  POST /api/action {"action","args"} -> runs an action on the PC (tag, bind, block, fix an alert, ping, slow-site
                                     check, router command...) and answers {"ok","message"} or {"job": id}
                                     (poll with action "job"; header X-ND-Token)
  POST /api/report                 -> a PC fix script reports its name / MACs (header X-ND-Report)
"""

import hmac
import ipaddress
import json
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HTTP_PORT = 8787
DISCOVERY_PORT = 8788
DISCOVER_MSG = b"NETWORK-DOCTOR-DISCOVER"
API_VERSION = 3  # 3: accounts (sign-in), audit, auto-defense, remote


def _lan_only(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


class ShareServer:
    """snapshot_fn() -> dict (built on demand); command_fn(name) -> str; store = dict persisted by save_fn()."""

    def __init__(self, app_name, version, snapshot_fn, command_fn, store, save_fn, report_fn=None, auth=None):
        self.app_name, self.version = app_name, version
        self.snapshot_fn, self.command_fn = snapshot_fn, command_fn
        self.auth = auth  # nd_auth.Accounts (Pro): sign-in + per-action roles. None = no accounts (old behaviour)
        self.store, self.save_fn = store, save_fn
        self.store.setdefault("phones", {})  # token -> {"name":..., "paired":...}
        if not self.store.get("report_key"):  # only lets the PC fix script report; it can read nothing
            self.store["report_key"] = secrets.token_urlsafe(18)
        self.report_fn = report_fn
        self.pairing_enabled = True  # False when only PC reports are accepted (phone link switched off)
        self.code = self.new_code()
        self.fails = 0
        self.locked_until = 0
        self.lock = threading.Lock()
        self.httpd = None
        self.udp = None
        self.error = None
        self.last_client = None
        self._cache = (0, None)

    @staticmethod
    def new_code():
        return f"{secrets.randbelow(1000000):06d}"

    # ---- life cycle
    def start(self):
        self.error = None
        try:
            server = self

            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *a):
                    pass

                def do_GET(self):
                    server._handle(self, "GET")

                def do_POST(self):
                    server._handle(self, "POST")

            self.httpd = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)
            self.httpd.daemon_threads = True
            threading.Thread(target=self.httpd.serve_forever, daemon=True, name="share-http").start()
        except Exception as e:
            self.httpd = None
            self.error = f"TCP {HTTP_PORT} is busy or blocked ({e})"
            return False
        try:
            self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp.bind(("0.0.0.0", DISCOVERY_PORT))
            self.udp.settimeout(1)
            threading.Thread(target=self._discovery, daemon=True, name="share-udp").start()
        except Exception as e:
            self.udp = None
            self.error = f"discovery port UDP {DISCOVERY_PORT} unavailable ({e}) - phones can still connect by IP"
        return True

    def stop(self):
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                pass
            self.httpd = None
        if self.udp:
            try:
                self.udp.close()
            except Exception:
                pass
            self.udp = None

    @property
    def running(self):
        return self.httpd is not None

    def _discovery(self):
        sock = self.udp
        while sock is not None and self.udp is sock:
            try:
                data, addr = sock.recvfrom(512)
            except socket.timeout:
                continue
            except Exception:
                break
            if data.strip() == DISCOVER_MSG and _lan_only(addr[0]):
                reply = json.dumps({"app": "network-doctor", "name": socket.gethostname(), "port": HTTP_PORT,
                                    "version": self.version, "api": API_VERSION}).encode()
                try:
                    sock.sendto(reply, addr)
                except Exception:
                    pass

    # ---- request handling
    def _send(self, h, code, obj):
        body = json.dumps(obj, default=str).encode("utf-8")
        h.send_response(code)
        h.send_header("Content-Type", "application/json; charset=utf-8")
        h.send_header("Content-Length", str(len(body)))
        h.send_header("Cache-Control", "no-store")
        h.end_headers()
        h.wfile.write(body)

    def _authorised(self, h):
        tok = h.headers.get("X-ND-Token", "")
        with self.lock:
            for known in list(self.store["phones"]):
                if tok and hmac.compare_digest(tok, known):
                    self.store["phones"][known]["last_seen"] = time.strftime("%Y-%m-%d %H:%M")
                    return True
        return False

    def _handle(self, h, method):
        client = h.client_address[0]
        # The LAN and loopback (a tunnel such as Cloudflare / Tailscale terminates on localhost) are always fine.
        # A real public client is accepted only when the owner turned on remote access AND accounts are set up,
        # so an outside connection can do nothing until it signs in.
        if not _lan_only(client):
            if not (getattr(self, "remote_enabled", False) and self.auth and self.auth.has_users()):
                return self._send(h, 403, {"error": "remote access is off on this PC"})
        path = h.path.split("?")[0]
        try:
            if path == "/api/hello" and method == "GET":
                return self._send(h, 200, {"app": "network-doctor", "name": socket.gethostname(),
                                           "version": self.version, "api": API_VERSION})
            if path == "/api/pair" and method == "POST":
                if not self.pairing_enabled:
                    return self._send(h, 403, {"error": "the phone link is switched off on the PC"})
                return self._pair(h, client)
            if path == "/api/report" and method == "POST":
                return self._report(h, client)
            if not self._authorised(h):
                return self._send(h, 401, {"error": "not paired"})
            self.last_client = (client, time.time())
            if path in ("/api/login", "/api/logout") and method == "POST":
                return self._auth_ep(h, path, client)
            # Pro with accounts set up: everything past here needs a signed-in user
            if self.auth and self.auth.has_users() and not self.auth.who(h.headers.get("X-ND-User", "")):
                return self._send(h, 401, {"error": "please sign in", "login": True})
            if path == "/api/state" and method == "GET":
                now = time.time()
                t, snap = self._cache
                if snap is None or now - t > 3:  # several phones refreshing share one snapshot
                    snap = self.snapshot_fn()
                    snap["api"] = API_VERSION
                    self._cache = (now, snap)
                return self._send(h, 200, snap)
            if path == "/api/scan" and method == "POST":
                return self._send(h, 200, {"result": self.command_fn("scan")})
            if path == "/api/action" and method == "POST":
                try:
                    n = int(h.headers.get("Content-Length", "0"))
                    req = json.loads(h.rfile.read(min(n, 16384)).decode("utf-8") or "{}")
                    if not isinstance(req, dict):
                        raise ValueError
                except Exception:
                    return self._send(h, 400, {"error": "bad request"})
                args = req.get("args") or {}
                if isinstance(args, dict):  # carry the signed-in user token to the command (role check + audit)
                    args["_auth"] = h.headers.get("X-ND-User", "")
                    args["_ip"] = client
                res = self.command_fn(str(req.get("action", "")), args)
                if not isinstance(res, dict):
                    res = {"ok": True, "message": str(res)}
                self._cache = (0, None)  # the next /api/state shows the change
                return self._send(h, 200, res)
            return self._send(h, 404, {"error": "unknown request"})
        except Exception as e:
            return self._send(h, 500, {"error": f"{type(e).__name__}: {e}"})

    def _auth_ep(self, h, path, client):
        """Sign in / out a user (Pro). The device must already be paired to reach here."""
        if not self.auth:
            return self._send(h, 404, {"error": "accounts are not enabled on this PC"})
        if path == "/api/logout":
            self.auth.logout(h.headers.get("X-ND-User", ""))
            return self._send(h, 200, {"ok": True})
        try:
            n = int(h.headers.get("Content-Length", "0"))
            req = json.loads(h.rfile.read(min(n, 4096)).decode("utf-8") or "{}")
        except Exception:
            return self._send(h, 400, {"error": "bad request"})
        with self.lock:
            now = time.time()
            if now < getattr(self, "_login_lock", 0):
                return self._send(h, 429, {"error": "too many wrong passwords - wait a minute"})
            sess = self.auth.login(str(req.get("user", "")), str(req.get("password", "")), client,
                                   str(req.get("device", "phone")))
            if not sess:
                self._login_fails = getattr(self, "_login_fails", 0) + 1
                if self._login_fails >= 5:
                    self._login_lock = now + 60
                    self._login_fails = 0
                return self._send(h, 403, {"error": "wrong user name or password"})
            self._login_fails = 0
        return self._send(h, 200, sess)

    def _pair(self, h, client):
        try:
            n = int(h.headers.get("Content-Length", "0"))
            req = json.loads(h.rfile.read(min(n, 4096)).decode("utf-8") or "{}")
        except Exception:
            return self._send(h, 400, {"error": "bad request"})
        with self.lock:
            now = time.time()
            if now < self.locked_until:
                return self._send(h, 429, {"error": f"too many wrong codes - try again in "
                                                    f"{int(self.locked_until - now) // 60 + 1} min"})
            code = str(req.get("code", "")).strip()
            if not hmac.compare_digest(code.encode(), self.code.encode()):
                self.fails += 1
                if self.fails >= 5:
                    self.locked_until = now + 300
                    self.fails = 0
                return self._send(h, 403, {"error": "wrong code"})
            self.fails = 0
            token = secrets.token_urlsafe(32)
            self.store["phones"][token] = {"name": str(req.get("phone", "phone"))[:40], "ip": client,
                                           "paired": time.strftime("%Y-%m-%d %H:%M")}
            self.code = self.new_code()  # a code works once
        self.save_fn()
        return self._send(h, 200, {"token": token, "name": socket.gethostname(), "version": self.version})

    def _report(self, h, client):
        key = h.headers.get("X-ND-Report", "")
        if not self.report_fn or not key or not hmac.compare_digest(key, self.store.get("report_key", "")):
            return self._send(h, 403, {"error": "not accepted"})
        try:
            n = int(h.headers.get("Content-Length", "0"))
            if n > 65536:
                return self._send(h, 413, {"error": "too large"})
            body = h.rfile.read(n).decode("utf-8-sig", "replace")
            data = json.loads(body or "{}")
            if not isinstance(data, dict):
                raise ValueError
        except Exception:
            return self._send(h, 400, {"error": "bad request"})
        self.report_fn(client, data)
        return self._send(h, 200, {"result": "thanks"})

    # ---- management from the PC window
    def phones(self):
        with self.lock:
            return [(tok, dict(v)) for tok, v in self.store["phones"].items()]

    def forget(self, token):
        with self.lock:
            self.store["phones"].pop(token, None)
        self.save_fn()
