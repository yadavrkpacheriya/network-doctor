# -*- coding: utf-8 -*-
"""
Network Doctor - a tunnel so the phone app can reach this office PC from outside the office, with no port
forwarded on the router and no public IP needed (the usual ISP connection in India is behind CGNAT, so port
forwarding often cannot work at all). Uses Cloudflare Tunnel (`cloudflared`), a free outbound-only connection.

Two tiers:
  * Quick tunnel - one click, no account, a random https://xxxx.trycloudflare.com address that lasts while this PC
    keeps it running and changes every time it is started. Good for trying it out right now.
  * Permanent address - needs a free Cloudflare account and a domain already on Cloudflare (for example a
    pacheriya.com subdomain). Creates a named tunnel through the Cloudflare API, points a subdomain at it, and
    installs it as a Windows service so the address keeps working even after a reboot, without Network Doctor
    running. The API token is used once to set this up and is never saved by this module.

Either way, the tunnel only forwards the single local port the Remote access server listens on (nd_share.HTTP_PORT):
outside callers can reach nothing else on this PC or the network through it, and everything they do still has to
sign in (nd_share / nd_auth) and is written to the audit log.
"""
import json
import os
import platform
import re
import shutil
import subprocess
import threading
import urllib.error
import urllib.request

CF_REPO = "cloudflare/cloudflared"
CF_LATEST_API = f"https://api.github.com/repos/{CF_REPO}/releases/latest"
API_BASE = "https://api.cloudflare.com/client/v4"
UA = {"User-Agent": "NetworkDoctor-tunnel"}
QUICK_URL_RE = re.compile(r"https://[-a-z0-9]+\.trycloudflare\.com")
IS_WIN = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"


class TunnelError(Exception):
    pass


def _get(url, headers=None, timeout=20):
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    return urllib.request.urlopen(req, timeout=timeout)


def _api(path, token, method="GET", body=None, timeout=20):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{API_BASE}{path}", data=data, method=method,
                                 headers={**UA, "Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            out = json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        try:
            out = json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            raise TunnelError(f"Cloudflare API error {e.code}") from None
    if not out.get("success"):
        msg = "; ".join(x.get("message", "") for x in out.get("errors") or []) or "unknown error"
        raise TunnelError(f"Cloudflare API: {msg}")
    return out.get("result")


# ------------------------------------------------------------------ getting the cloudflared binary
def _asset_name():
    if IS_WIN:
        return "cloudflared-windows-amd64.exe"
    if IS_MAC:
        return "cloudflared-darwin-amd64.tgz"
    return "cloudflared-linux-amd64"


def _bin_name():
    return "cloudflared.exe" if IS_WIN else "cloudflared"


def locate(data_dir=""):
    """Path to an already-installed cloudflared (PATH, or this app's own copy), or '' if not found."""
    p = shutil.which("cloudflared")
    if p:
        return p
    own = os.path.join(data_dir, "bin", _bin_name())
    return own if os.path.isfile(own) else ""


def latest_download_url(timeout=20):
    with _get(CF_LATEST_API, {"Accept": "application/vnd.github+json"}, timeout) as r:
        rel = json.loads(r.read().decode("utf-8", "replace"))
    name = _asset_name()
    for a in rel.get("assets", []):
        if a.get("name") == name:
            return a["browser_download_url"], rel.get("tag_name", "")
    raise TunnelError(f"no {name} in the latest cloudflared release")


def ensure_installed(data_dir, progress=None):
    """Returns a usable cloudflared path, downloading the official binary from GitHub if needed."""
    found = locate(data_dir)
    if found:
        return found
    if progress:
        progress("Downloading cloudflared (one-time, about 20 MB)...")
    url, _tag = latest_download_url()
    out_dir = os.path.join(data_dir, "bin")
    os.makedirs(out_dir, exist_ok=True)
    dest = os.path.join(out_dir, _bin_name())
    tmp = dest + ".part"
    with _get(url, timeout=120) as r, open(tmp, "wb") as f:
        shutil.copyfileobj(r, f)
    if url.endswith(".tgz"):
        import tarfile
        with tarfile.open(tmp) as tf:
            member = next(m for m in tf.getmembers() if m.name.endswith("cloudflared"))
            member.name = os.path.basename(member.name)
            tf.extract(member, out_dir, filter="data")
        os.remove(tmp)
    else:
        os.replace(tmp, dest)
    if not IS_WIN:
        os.chmod(dest, 0o755)
    return dest


# ------------------------------------------------------------------ tier 1: quick tunnel (no account)
class QuickTunnel:
    """`cloudflared tunnel --url http://localhost:PORT`: a free random *.trycloudflare.com address. Stops when the
    PC shuts down or Network Doctor closes it; a new one gets a different address."""

    def __init__(self, cloudflared_path, local_port, popen=subprocess.Popen):
        self.path, self.port, self._popen = cloudflared_path, local_port, popen
        self.proc = None
        self.url = ""
        self.error = ""
        self.ready = threading.Event()

    def start(self):
        kw = {"stdout": subprocess.PIPE, "stderr": subprocess.STDOUT, "text": True, "bufsize": 1}
        if IS_WIN:
            kw["creationflags"] = 0x08000000  # no console window
        self.proc = self._popen([self.path, "tunnel", "--url", f"http://localhost:{self.port}", "--no-autoupdate"],
                                **kw)
        threading.Thread(target=self._watch, daemon=True).start()
        return self

    def _watch(self):
        try:
            for line in self.proc.stdout or []:
                m = QUICK_URL_RE.search(line)
                if m and not self.url:
                    self.url = m.group(0)
                    self.ready.set()
                if "error" in line.lower() and not self.url:
                    self.error = line.strip()[:200]
        except Exception as e:
            self.error = str(e)[:200]
        finally:
            self.ready.set()  # unblocks a waiter even on failure (self.url stays "")

    def wait_url(self, timeout=25):
        self.ready.wait(timeout)
        return self.url

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass

    @property
    def running(self):
        return bool(self.proc) and self.proc.poll() is None


# ------------------------------------------------------------------ tier 2: permanent address (own domain)
def verify_token(token):
    """(ok, detail). A read-only check - never writes anything."""
    try:
        r = _api("/user/tokens/verify", token)
        return True, r.get("status", "active")
    except TunnelError as e:
        return False, str(e)


def zone_id_of(token, domain):
    r = _api(f"/zones?name={domain}", token)
    if not r:
        raise TunnelError(f"'{domain}' is not a domain on this Cloudflare account")
    return r[0]["id"]


def account_id_of(token):
    r = _api("/accounts", token)
    if not r:
        raise TunnelError("this token has no Cloudflare account to use")
    return r[0]["id"]


def create_named_tunnel(token, account_id, name):
    """Returns {'id', 'token'} - 'token' is the run-token (`cloudflared service install <token>` / `tunnel run`)."""
    import base64
    import secrets as _secrets
    secret = base64.b64encode(_secrets.token_bytes(32)).decode()
    r = _api(f"/accounts/{account_id}/cfd_tunnel", token, "POST", {"name": name, "tunnel_secret": secret})
    run_token = r.get("token") or _api(f"/accounts/{account_id}/cfd_tunnel/{r['id']}/token", token)
    return {"id": r["id"], "token": run_token}


def set_ingress(token, account_id, tunnel_id, hostname, local_port):
    """One hostname -> this PC's Remote-access server; everything else is refused (no open catch-all)."""
    cfg = {"config": {"ingress": [{"hostname": hostname, "service": f"http://localhost:{local_port}"},
                                  {"service": "http_status:404"}]}}
    _api(f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations", token, "PUT", cfg)


def point_dns(token, zone_id, hostname, tunnel_id):
    name = hostname.split(".")[0]
    _api(f"/zones/{zone_id}/dns_records", token, "POST",
        {"type": "CNAME", "name": name, "content": f"{tunnel_id}.cfargotunnel.com", "proxied": True})


def setup_permanent(token, domain, subdomain, local_port, tunnel_name="network-doctor"):
    """Does the whole thing: verify token, find the zone, create the tunnel, point the subdomain at it, set the
    ingress rule. Returns {'hostname', 'tunnel_id', 'run_token'}. Raises TunnelError with a plain-language reason."""
    ok, why = verify_token(token)
    if not ok:
        raise TunnelError(f"that Cloudflare API token does not work ({why}). Create one at "
                          "dash.cloudflare.com > My Profile > API Tokens > 'Edit zone DNS' template, and also tick "
                          "'Account - Cloudflare Tunnel - Edit' permission.")
    zone = zone_id_of(token, domain)
    account = account_id_of(token)
    hostname = f"{subdomain}.{domain}"
    t = create_named_tunnel(token, account, tunnel_name)
    set_ingress(token, account, t["id"], hostname, local_port)
    point_dns(token, zone, hostname, t["id"])
    return {"hostname": hostname, "tunnel_id": t["id"], "run_token": t["token"]}


def install_service(cloudflared_path, run_token, run=subprocess.run):
    """Installs cloudflared as a service so the permanent address works even after a reboot, with Network Doctor
    closed. Windows / Mac only (`cloudflared service install`); returns the command to run by hand otherwise."""
    cmd = [cloudflared_path, "service", "install", run_token]
    if IS_WIN or IS_MAC:
        r = run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            raise TunnelError((r.stderr or r.stdout or "service install failed")[:300])
        return True
    return False  # Linux: no single command across distros - show it instead


def uninstall_service(cloudflared_path, run=subprocess.run):
    try:
        run([cloudflared_path, "service", "uninstall"], capture_output=True, text=True, timeout=30)
    except Exception:
        pass


def remove_tunnel_and_dns(token, account_id, tunnel_id, zone_id="", dns_record_id=""):
    """Undo for setup_permanent: deletes the tunnel (and the DNS record, if its id is known)."""
    if zone_id and dns_record_id:
        try:
            _api(f"/zones/{zone_id}/dns_records/{dns_record_id}", token, "DELETE")
        except TunnelError:
            pass
    _api(f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}", token, "DELETE")


def find_dns_record_id(token, zone_id, hostname):
    r = _api(f"/zones/{zone_id}/dns_records?name={hostname}", token)
    return r[0]["id"] if r else ""


def phone_instructions(url_or_hostname, pair_code=""):
    """Plain steps for the phone app, with the real address filled in."""
    host = url_or_hostname if url_or_hostname.startswith("http") else f"https://{url_or_hostname}"
    steps = [f"1. On the office PC, make sure Remote access is turned ON (Setup > Users & sign-in) and this tunnel "
             "is running (the address below only works while it shows as running).",
             f"2. On the phone, open Network Doctor > Office PC > PC menu > 'Reach from outside' and enter:\n   {host}",
             "3. Sign in with a user name and password you added under Setup > Users & sign-in (not the router "
             "login) - a new phone cannot do anything until it signs in."]
    if pair_code:
        steps.append(f"4. First time only: pairing code {pair_code} (shown on the PC, valid a few minutes).")
    return "\n".join(steps)
