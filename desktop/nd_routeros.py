# -*- coding: utf-8 -*-
"""Optional direct connection to a MikroTik router through its API (TCP 8728, or 8729 with TLS).

Network Doctor works without it (it then shows commands to paste in WinBox). With a router login saved in
Setup it can apply its own commands directly - IP-MAC binding, rogue DHCP / DNS guard, random-MAC block,
speed limits - run router commands from the Commands tab and show their output, and read the DHCP leases
(host names) for the inventory.

Only the standard library is used. The password is stored encrypted for the Windows user (DPAPI).
"""

import base64
import ctypes
import hashlib
import os
import re
import socket
import ssl
import time

IS_WIN = os.name == "nt"
API_PORT, API_SSL_PORT = 8728, 8729


class RosError(Exception):
    pass


# --------------------------------------------------------------------------- wire format
def enc_len(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x4000:
        return (n | 0x8000).to_bytes(2, "big")
    if n < 0x200000:
        return (n | 0xC00000).to_bytes(3, "big")
    if n < 0x10000000:
        return (n | 0xE0000000).to_bytes(4, "big")
    return b"\xf0" + n.to_bytes(4, "big")


def enc_word(w):
    b = w.encode("utf-8") if isinstance(w, str) else w
    return enc_len(len(b)) + b


def enc_sentence(words):
    return b"".join(enc_word(w) for w in words) + b"\x00"


def read_len(recv):
    c = recv(1)[0]
    if c < 0x80:
        return c
    if c < 0xC0:
        return ((c & 0x3F) << 8) | recv(1)[0]
    if c < 0xE0:
        return ((c & 0x1F) << 16) | int.from_bytes(recv(2), "big")
    if c < 0xF0:
        return ((c & 0x0F) << 24) | int.from_bytes(recv(3), "big")
    return int.from_bytes(recv(4), "big")


def read_sentence(recv):
    words = []
    while True:
        n = read_len(recv)
        if n == 0:
            return words
        words.append(recv(n).decode("utf-8", "replace"))


def attrs(words):
    out = {}
    for w in words:
        if w.startswith("="):
            k, _, v = w[1:].partition("=")
            out[k] = v
    return out


# --------------------------------------------------------------------------- RouterOS script quoting
def ros_quote(text):
    """A RouterOS string literal ("...") for any text."""
    return '"' + str(text).replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace(
        "\r", "").replace("\n", "\\n") + '"'


# commands that never end by themselves in a terminal (Ctrl+C) get a time limit when run from here
ENDLESS = (
    (re.compile(r"^/tool torch\b(?!.*\bduration=)"), " duration=10s"),
    (re.compile(r"^/interface ethernet monitor\b(?!.*\bonce\b)"), " once"),
    (re.compile(r"^/ping\b(?!.*\bcount=)"), " count=10"),
)


def bounded(cmd):
    c = cmd.strip()
    for rx, add in ENDLESS:
        if rx.search(c):
            c += add
    return c


# --------------------------------------------------------------------------- password storage
class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def protect(text):
    """Encrypts for this Windows user (DPAPI). Elsewhere only encoded - the settings file is the user's own."""
    raw = (text or "").encode("utf-8")
    if IS_WIN:
        try:
            buf = ctypes.create_string_buffer(raw, len(raw))
            src, dst = _Blob(len(raw), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), _Blob()
            if ctypes.windll.crypt32.CryptProtectData(ctypes.byref(src), None, None, None, None, 0,
                                                      ctypes.byref(dst)):
                data = ctypes.string_at(dst.pbData, dst.cbData)
                ctypes.windll.kernel32.LocalFree(dst.pbData)
                return "dpapi:" + base64.b64encode(data).decode()
        except Exception:
            pass
    return "b64:" + base64.b64encode(raw).decode()


def unprotect(blob):
    if not blob:
        return ""
    kind, _, data = blob.partition(":")
    raw = base64.b64decode(data or "")
    if kind == "dpapi" and IS_WIN:
        try:
            buf = ctypes.create_string_buffer(raw, len(raw))
            src, dst = _Blob(len(raw), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), _Blob()
            if ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(src), None, None, None, None, 0,
                                                        ctypes.byref(dst)):
                out = ctypes.string_at(dst.pbData, dst.cbData)
                ctypes.windll.kernel32.LocalFree(dst.pbData)
                return out.decode("utf-8")
        except Exception:
            return ""
        return ""
    return raw.decode("utf-8", "replace") if kind == "b64" else ""


# --------------------------------------------------------------------------- client
class RouterOS:
    def __init__(self, host, user, password, port=None, use_ssl=False, timeout=8):
        self.host, self.user, self.password = host, user, password
        self.use_ssl = use_ssl
        self.port = port or (API_SSL_PORT if use_ssl else API_PORT)
        self.timeout = timeout
        self.sock = None

    # ---- connection
    def connect(self):
        try:
            s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as e:
            raise RosError(f"cannot connect to {self.host}:{self.port} ({e}). Turn the API on: WinBox > IP > "
                           f"Services > api (8728) - allow only this PC's IP there.") from None
        if self.use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # routers use self-signed certificates
            s = ctx.wrap_socket(s, server_hostname=self.host)
        s.settimeout(self.timeout)
        self.sock = s
        self._buf = b""
        r = self.talk(["/login", "=name=" + self.user, "=password=" + self.password], check=False)
        if any(t == "!trap" for t, _ in r):
            self.close()
            raise RosError("login refused - check user name and password (the user needs 'api' and 'read' / "
                           "'write' policy)")
        ret = next((attrs(w).get("ret") for t, w in r if t == "!done" and attrs(w).get("ret")), None)
        if ret:  # RouterOS before 6.43: challenge / response
            md = hashlib.md5(b"\x00" + self.password.encode() + bytes.fromhex(ret)).hexdigest()
            r = self.talk(["/login", "=name=" + self.user, "=response=00" + md], check=False)
            if any(t == "!trap" for t, _ in r):
                self.close()
                raise RosError("login refused - check user name and password")
        return self

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = None

    def __enter__(self):
        return self.connect() if self.sock is None else self

    def __exit__(self, *a):
        self.close()

    def _recv(self, n):
        out = b""
        while len(out) < n:
            try:
                chunk = self.sock.recv(n - len(out))
            except socket.timeout:
                raise RosError("the router stopped answering (timeout)") from None
            if not chunk:
                raise RosError("the router closed the connection")
            out += chunk
        return out

    # ---- requests
    def talk(self, words, check=True):
        """Sends one command; returns [(reply_type, words)] up to !done. Raises RosError on !trap if check."""
        if not self.sock:
            raise RosError("not connected")
        self.sock.sendall(enc_sentence(words))
        out = []
        while True:
            s = read_sentence(self._recv)
            if not s:
                continue
            out.append((s[0], s[1:]))
            if s[0] == "!fatal":
                raise RosError("router: " + " ".join(s[1:]))
            if s[0] == "!done":
                break
        if check:
            for t, w in out:
                if t == "!trap":
                    raise RosError("router: " + attrs(w).get("message", "error"))
        return out

    def cmd(self, path, **kw):
        words = [path] + [f"={k.replace('_', '-')}={v}" for k, v in kw.items() if not k.startswith("q_")]
        words += [f"?{k[2:].replace('_', '-')}={v}" for k, v in kw.items() if k.startswith("q_")]
        return [attrs(w) for t, w in self.talk(words) if t == "!re"]

    def identity(self):
        r = self.cmd("/system/identity/print")
        v = self.cmd("/system/resource/print")
        return (r[0].get("name", "") if r else ""), (v[0].get("version", "") if v else "")

    def leases(self):
        return self.cmd("/ip/dhcp-server/lease/print")

    # ---- scripts (the same text people would paste in WinBox > New Terminal)
    def run_script(self, source, name="netdoctor-run"):
        """Runs a RouterOS script on the router. Returns the router's error text, or '' when it ran to the end."""
        for x in self.cmd("/system/script/print", q_name=name):
            self.talk(["/system/script/remove", "=.id=" + x[".id"]], check=False)
        self.talk(["/system/script/add", "=name=" + name, "=source=" + source,
                   "=policy=read,write,policy,test,sensitive,reboot"])
        try:
            r = self.talk(["/system/script/run", "=number=" + name], check=False)
            err = next((attrs(w).get("message", "error") for t, w in r if t == "!trap"), "")
        finally:
            for x in self.cmd("/system/script/print", q_name=name):
                self.talk(["/system/script/remove", "=.id=" + x[".id"]], check=False)
        return err

    def run_cli(self, command):
        """Runs one terminal command and returns its text output (RouterOS 7: as-string; 6: through a file)."""
        command = bounded(command)
        var = "ndout"
        err = self.run_script(f":global {var} [:execute script={ros_quote(command)} as-string]")
        if not err:
            env = [x for x in self.cmd("/system/script/environment/print") if x.get("name") == var]
            text = env[0].get("value", "") if env else ""
            for x in env:
                self.talk(["/system/script/environment/remove", "=.id=" + x[".id"]], check=False)
            return text
        # RouterOS 6 has no 'as-string': write the output to a file and read it back
        fname = "nd-out"
        err = self.run_script(f":execute script={ros_quote(command)} file={fname}")
        if err:
            raise RosError(err)
        for _ in range(30):
            time.sleep(0.5)
            f = [x for x in self.cmd("/file/print") if x.get("name", "").startswith(fname)]
            if f and f[0].get("contents") is not None and int(f[0].get("size", "1") or 0) >= 0:
                text = f[0].get("contents", "")
                self.talk(["/file/remove", "=.id=" + f[0][".id"]], check=False)
                return text
        raise RosError("the command gave no output in 15 seconds")


def from_settings(st, gw=None):
    """A RouterOS client from the saved Setup values, or None when no login is saved."""
    r = (st or {}).get("router_api") or {}
    if not r.get("user"):
        return None
    return RouterOS(r.get("host") or gw, r["user"], unprotect(r.get("pw", "")), int(r.get("port") or 0) or None,
                    bool(r.get("ssl")))
