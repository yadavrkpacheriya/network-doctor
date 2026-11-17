# -*- coding: utf-8 -*-
"""A fake MikroTik RouterOS, driven through the real binary API wire protocol (nd_routeros).

The app never needs to know it is fake: we patch socket.create_connection so nd_routeros.RouterOS opens a
FakeSocket instead of a real TCP socket. The FakeSocket decodes each API sentence the client sends, asks an
in-memory RouterModel for the answer, and buffers the encoded reply for recv(). This means the app's own
enc/read code, login handshake, cmd() path-and-query handling, script runner and lease/arp/firewall readers
all run exactly as against a real router.

Supported well enough for the sandbox:
  * /login            plaintext (post-6.43) OK
  * .../print         returns the model's rows for that path, honouring ?name=.. style query words
  * add / set / remove  mutate the model (IP-MAC binding, DHCP server network, firewall, addresses...)
  * /system/script/add|run|remove + environment  -> run_cli(): :execute ... as-string returns CLI text
  * ROS6 flag: when ros6=True, as-string is refused (no !trap needed - we just omit the var) so the
    file-based fallback path in run_cli is exercised too.
"""
import re
import socket as _socket
from contextlib import contextmanager

import nd_routeros as RO


# ----------------------------------------------------------------- in-memory router
class RouterModel:
    def __init__(self, identity="OfficeRouter", version="7.14", ros6=False):
        self.identity = identity
        self.version = version
        self.ros6 = ros6
        self._id = 0
        # path -> list[dict rows]. Keys use RouterOS dotted names (".id", "address", "mac-address"...).
        self.tables = {
            "/ip/dhcp-server/lease": [],
            "/ip/dhcp-server/network": [],
            "/ip/arp": [],
            "/ip/firewall/filter": [],
            "/ip/firewall/address-list": [],
            "/ip/address": [],
            "/interface": [],
            "/ip/pool": [],
        }
        self.scripts = {}      # name -> source
        self.environment = {}  # name -> value
        self.files = {}        # name -> contents
        self.cli = {}          # exact command text -> output text (for run_cli as-string)
        self.ran = []          # every CLI command the app executed, in order

    # -- helpers for tests to seed the router
    def nid(self):
        self._id += 1
        return "*%X" % self._id

    def add_lease(self, address, mac, host="", status="bound", dynamic="true", server="dhcp1"):
        row = {".id": self.nid(), "address": address, "mac-address": mac, "host-name": host,
               "status": status, "dynamic": dynamic, "server": server}
        self.tables["/ip/dhcp-server/lease"].append(row)
        return row

    def add_arp(self, address, mac, interface="bridge", dynamic="true"):
        row = {".id": self.nid(), "address": address, "mac-address": mac, "interface": interface,
               "dynamic": dynamic}
        self.tables["/ip/arp"].append(row)
        return row

    # -- command dispatch ------------------------------------------------------
    def handle(self, words):
        """words -> list of reply sentences (each a list, e.g. ['!re','=k=v'] or ['!done'])."""
        if not words:
            return [["!done"]]
        path = words[0]
        attrs = _parse(words[1:])
        if path == "/login":
            return [["!done"]]  # plaintext accepted; no challenge
        if path == "/system/identity/print":
            return [["!re", "=name=" + self.identity], ["!done"]]
        if path == "/system/resource/print":
            return [["!re", "=version=" + self.version, "=board-name=hAP", "=uptime=1d"], ["!done"]]

        verb = path.rsplit("/", 1)[-1]
        base = path[: -(len(verb) + 1)] if "/" in path else path

        # script / environment / file have their own stores - handle before the generic table verbs
        if base == "/system/script/environment":
            if verb == "print":
                return self._print(base, attrs)
            if verb == "remove":
                self.environment.pop(_byid_name(self.environment, attrs), None)
                return [["!done"]]
        if base == "/system/script":
            if verb == "print":
                return self._print(base, attrs)
            return self._script(verb, attrs)
        if base == "/file":
            if verb == "print":
                return self._print(base, attrs)
            if verb == "remove":
                self.files.pop(_byid_name(self.files, attrs), None)
                return [["!done"]]

        if verb == "print":
            return self._print(base, attrs)
        if verb == "add":
            return self._add(base, attrs)
        if verb == "set":
            return self._set(base, attrs)
        if verb == "remove":
            return self._remove(base, attrs)
        # unknown command: succeed quietly (the app tolerates empty results)
        return [["!done"]]

    def _print(self, base, attrs):
        if base == "/system/script":
            rows = [{".id": n, "name": n, "source": s} for n, s in self.scripts.items()]
        elif base == "/system/script/environment":
            rows = [{".id": k, "name": k, "value": v} for k, v in self.environment.items()]
        elif base == "/file":
            rows = [{".id": n, "name": n, "contents": c, "size": str(len(c))}
                    for n, c in self.files.items()]
        else:
            rows = self.tables.get(base, [])
        out = []
        for r in rows:
            if _match(r, attrs):
                out.append(["!re"] + [f"={k}={v}" for k, v in r.items()])
        out.append(["!done"])
        return out

    def _add(self, base, attrs):
        row = dict(attrs)
        row[".id"] = self.nid()
        self.tables.setdefault(base, []).append(row)
        return [["!done", "=ret=" + row[".id"]]]

    def _set(self, base, attrs):
        rows = self.tables.get(base, [])
        target = _find(rows, attrs)
        if target is not None:
            for k, v in attrs.items():
                if k not in (".id", "numbers"):
                    target[k] = v
        return [["!done"]]

    def _remove(self, base, attrs):
        rows = self.tables.get(base, [])
        rid = attrs.get(".id") or attrs.get("numbers")
        self.tables[base] = [r for r in rows if r.get(".id") != rid]
        return [["!done"]]

    def _script(self, verb, attrs):
        if verb == "add":
            self.scripts[attrs.get("name", "s")] = attrs.get("source", "")
            return [["!done"]]
        if verb == "remove":
            self.scripts.pop(_byid_name(self.scripts, attrs), None)
            return [["!done"]]
        if verb == "run":
            name = attrs.get("number") or attrs.get(".id")
            source = self.scripts.get(name, "")
            if self.ros6 and self._AS.search(source):
                # real RouterOS 6 has no :execute ... as-string -> it traps; drives the file fallback
                return [["!trap", "=message=bad command name as-string"], ["!done"]]
            self._run_script(source)
            return [["!done"]]
        return [["!done"]]

    # Emulate the two shapes run_cli() produces:
    #   ROS7: :global ndout [:execute script="<cmd>" as-string]
    #   ROS6: :execute script="<cmd>" file=nd-out
    _AS = re.compile(r':global\s+(\w+)\s+\[:execute\s+script=(".*?"|\S+)\s+as-string\]', re.S)
    _FILE = re.compile(r':execute\s+script=(".*?"|\S+)\s+file=(\S+)', re.S)

    def _run_script(self, source):
        m = self._AS.search(source)
        if m and not self.ros6:
            cmd = _unquote(m.group(2))
            self.ran.append(cmd)
            self.environment[m.group(1)] = self.cli.get(cmd, "")
            return
        m = self._FILE.search(source)
        if m:
            cmd = _unquote(m.group(1))
            self.ran.append(cmd)
            self.files[m.group(2)] = self.cli.get(cmd, "")


# ----------------------------------------------------------------- wire glue
def _parse(words):
    out = {}
    for w in words:
        if w.startswith("="):
            k, _, v = w[1:].partition("=")
            out[k] = v
        elif w.startswith("?"):
            k, _, v = w[1:].partition("=")
            out[k] = v
    return out


def _match(row, query):
    for k, v in query.items():
        if k in (".proplist",):
            continue
        if str(row.get(k, "")) != str(v):
            return False
    return True


def _find(rows, attrs):
    rid = attrs.get(".id") or attrs.get("numbers")
    for r in rows:
        if r.get(".id") == rid:
            return r
    return None


def _byid(d, attrs):
    rid = attrs.get(".id")
    return rid if rid in d else next((k for k in d if k == rid), None)


def _byid_name(d, attrs):
    return attrs.get(".id") or attrs.get("name")


def _unquote(tok):
    if tok.startswith('"') and tok.endswith('"'):
        return tok[1:-1].replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")
    return tok


class FakeSocket:
    """Looks enough like a socket for nd_routeros: sendall / recv / settimeout / close."""
    def __init__(self, model):
        self.model = model
        self._in = b""      # bytes the client has sent, awaiting a full sentence
        self._out = b""     # encoded replies waiting for recv()
        self.closed = False

    def settimeout(self, _):
        pass

    def sendall(self, data):
        self._in += data
        while True:
            words, rest = _take_sentence(self._in)
            if words is None:
                break
            self._in = rest
            for sentence in self.model.handle(words):
                self._out += RO.enc_sentence(sentence)

    def recv(self, n):
        if not self._out:
            raise _socket.timeout("no data")
        chunk, self._out = self._out[:n], self._out[n:]
        return chunk

    def close(self):
        self.closed = True


def _take_sentence(buf):
    """Decode one API sentence from buf. Returns (words, remaining) or (None, buf) if incomplete."""
    words = []
    i = 0
    n = len(buf)
    while True:
        if i >= n:
            return None, buf
        c = buf[i]
        if c < 0x80:
            ln, i = c, i + 1
        elif c < 0xC0:
            if i + 2 > n:
                return None, buf
            ln, i = ((c & 0x3F) << 8) | buf[i + 1], i + 2
        elif c < 0xE0:
            if i + 3 > n:
                return None, buf
            ln, i = ((c & 0x1F) << 16) | int.from_bytes(buf[i + 1:i + 3], "big"), i + 3
        elif c < 0xF0:
            if i + 4 > n:
                return None, buf
            ln, i = ((c & 0x0F) << 24) | int.from_bytes(buf[i + 1:i + 4], "big"), i + 4
        else:
            if i + 5 > n:
                return None, buf
            ln, i = int.from_bytes(buf[i + 1:i + 5], "big"), i + 5
        if ln == 0:
            return words, buf[i:]
        if i + ln > n:
            return None, buf
        words.append(buf[i:i + ln].decode("utf-8", "replace"))
        i += ln


class FakeRouter:
    """Convenience wrapper tests seed and then connect against."""
    def __init__(self, **kw):
        self.model = RouterModel(**kw)


@contextmanager
def router_socket(model):
    """Patch nd_routeros so every RouterOS() connects to this model; keep-open pooling off for determinism."""
    RO.close_all()
    saved_create = RO.socket.create_connection
    saved_keep = RO.KEEP_OPEN
    RO.KEEP_OPEN = False
    RO.socket.create_connection = lambda addr, timeout=None, **kw: FakeSocket(model)
    try:
        yield model
    finally:
        RO.socket.create_connection = saved_create
        RO.KEEP_OPEN = saved_keep
        RO.close_all()


def RouterOS_against(model, host="192.168.0.1", user="admin", pw="pw"):
    """A connected nd_routeros.RouterOS talking to `model` (use inside `with router_socket(model):`)."""
    return RO.RouterOS(host, user, pw).connect()
