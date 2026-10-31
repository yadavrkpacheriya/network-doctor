# -*- coding: utf-8 -*-
"""A tiny fake MikroTik API server for tests: login, print, add/remove, scripts with :execute as-string."""

import re
import socket
import threading

import nd_routeros as R


class FakeRouter:
    def __init__(self, user="admin", password="pw", v7=True):
        self.user, self.password, self.v7 = user, password, v7
        self.scripts, self.env, self.ran, self.files = {}, {}, [], {}
        self.leases = [{".id": "*1", "address": "192.168.0.70", "mac-address": "F8:75:A4:8D:B7:FA",
                        "host-name": "SALES-PC", "dynamic": "true", "status": "bound"}]
        self.outputs = {"/system resource print": "uptime: 1d\nversion: 7.15"}
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(5)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        def recv(n):
            b = b""
            while len(b) < n:
                x = c.recv(n - len(b))
                if not x:
                    raise EOFError
                b += x
            return b

        def send(*sentences):
            c.sendall(b"".join(R.enc_sentence(s) for s in sentences))
        logged = False
        try:
            while True:
                w = R.read_sentence(recv)
                cmd, a = w[0], R.attrs(w[1:])
                q = {x[1:].split("=", 1)[0]: x.split("=", 1)[1] for x in w[1:] if x.startswith("?")}
                if cmd == "/login":
                    if a.get("name") == self.user and a.get("password") == self.password:
                        logged = True
                        send(["!done"])
                    else:
                        send(["!trap", "=message=invalid user name or password (6)"], ["!done"])
                    continue
                if not logged:
                    send(["!fatal", "not logged in"])
                    return
                if cmd == "/system/identity/print":
                    send(["!re", "=name=Office-Router"], ["!done"])
                elif cmd == "/system/resource/print":
                    send(["!re", "=version=7.15 (stable)"], ["!done"])
                elif cmd == "/ip/dhcp-server/lease/print":
                    send(*[["!re"] + [f"={k}={v}" for k, v in x.items()] for x in self.leases], ["!done"])
                elif cmd == "/ip/dns/cache/all/print":
                    send(*[["!re", f"=name={n}", "=type=A", f"=data={ip}"] for ip, n in getattr(self, "dns", [])],
                         ["!done"])
                elif cmd == "/system/script/print":
                    rows = [["!re", f"=.id={i}", f"=name={n}"] for n, (i, _) in self.scripts.items()
                            if not q.get("name") or q["name"] == n]
                    send(*rows, ["!done"])
                elif cmd == "/system/script/add":
                    self.scripts[a["name"]] = (f"*{len(self.ran) + 10}", a["source"])
                    send(["!done", "=ret=*A"])
                elif cmd == "/system/script/remove":
                    for n, (i, _) in list(self.scripts.items()):
                        if i == a.get(".id"):
                            del self.scripts[n]
                    send(["!done"])
                elif cmd == "/system/script/run":
                    src = self.scripts[a["number"]][1]
                    self.ran.append(src)
                    m = re.match(r':global (\w+) \[:execute script=("(?:[^"\\]|\\.)*") as-string\]', src)
                    if m and not self.v7:
                        send(["!trap", "=message=expected end of command (line 1 column 40)"], ["!done"])
                    elif m:
                        inner = m.group(2)[1:-1].replace('\\"', '"').replace("\\$", "$").replace("\\\\", "\\")
                        self.env[m.group(1)] = self.outputs.get(inner, f"ran: {inner}")
                        send(["!done"])
                    elif "fail-me" in src:
                        send(["!trap", "=message=syntax error (line 1 column 1)"], ["!done"])
                    else:
                        m = re.match(r':execute script=("(?:[^"\\]|\\.)*") file=(\S+)', src)
                        if m:
                            inner = m.group(1)[1:-1].replace('\\"', '"')
                            self.files[m.group(2) + ".txt"] = self.outputs.get(inner, f"ran: {inner}")
                        send(["!done"])
                elif cmd == "/system/script/environment/print":
                    send(*[["!re", f"=.id=*E{k}", f"=name={k}", f"=value={v}"] for k, v in self.env.items()],
                         ["!done"])
                elif cmd == "/system/script/environment/remove":
                    self.env.clear()
                    send(["!done"])
                elif cmd == "/file/print":
                    send(*[["!re", f"=.id=*F{i}", f"=name={n}", f"=size={len(v)}", f"=contents={v}"]
                           for i, (n, v) in enumerate(self.files.items())], ["!done"])
                elif cmd == "/file/remove":
                    self.files.clear()
                    send(["!done"])
                else:
                    send(["!trap", f"=message=no such command ({cmd})"], ["!done"])
        except (EOFError, OSError):
            pass
        finally:
            c.close()

    def close(self):
        self.srv.close()
