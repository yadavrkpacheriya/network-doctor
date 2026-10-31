# -*- coding: utf-8 -*-
"""Network Doctor Pro - user accounts, sign-in and an append-only audit log.

Every change an operator or the phone makes (block a device, isolate it, apply a router fix, change a
setting) is allowed only for a signed-in user with the right role, and is written to the audit log so you
can always see who did what and when. Passwords are stored only as salted PBKDF2 hashes.

Files (under DATA_DIR/pro):
  accounts.json   {"users": {name: {role, salt, hash, created, disabled, last_login}}}
  audit.log       one JSON object per line: {t, user, role, action, detail, result, ip}
"""
import hashlib
import hmac
import json
import os
import secrets
import threading
import time

import nd_core as core

ROLES = ("admin", "operator", "viewer")
ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}
# what each role may do (action -> least role needed)
NEEDS = {
    "view": "viewer", "job": "viewer", "audit": "viewer", "defense": "viewer", "hardening": "viewer",
    "scan": "operator", "ping": "operator", "trace": "operator", "quick": "operator", "slow": "operator",
    "capture": "operator", "vuln": "operator", "exposure": "operator", "wol": "operator",
    "tag": "operator", "guard": "operator", "bind": "operator", "router_cmd": "operator", "alert_fix": "operator",
    "alert_status": "operator", "set_category": "operator",
    "block": "operator", "unblock": "operator", "isolate": "operator", "unisolate": "operator",
    "router_reboot": "admin", "poweroff": "admin", "defense_config": "admin", "defense_arm": "admin",
    "defense_release": "operator",
    "account": "admin", "settings": "admin",
}
SESSION_TTL = 12 * 3600
_ITER = 200_000


def _dir():
    d = os.path.join(core.DATA_DIR, "pro")
    os.makedirs(d, exist_ok=True)
    return d


def _hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), _ITER).hex()


class Accounts:
    """User accounts and live sign-in sessions (tokens). Thread-safe."""

    def __init__(self):
        self.path = os.path.join(_dir(), "accounts.json")
        self.lock = threading.RLock()
        self.sessions = {}  # token -> {"user", "role", "exp", "ip", "device"}
        try:
            with open(self.path, encoding="utf-8") as f:
                self.data = json.load(f)
        except Exception:
            self.data = {"users": {}}
        self.data.setdefault("users", {})

    # ---- persistence
    def _save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=1)
        os.replace(tmp, self.path)

    # ---- accounts
    def has_users(self):
        with self.lock:
            return any(not u.get("disabled") for u in self.data["users"].values())

    def users(self):
        with self.lock:
            return {n: {"role": u["role"], "disabled": bool(u.get("disabled")),
                        "created": u.get("created", ""), "last_login": u.get("last_login", "")}
                    for n, u in self.data["users"].items()}

    def add_user(self, name, password, role="operator"):
        name = (name or "").strip()
        if not name or len(name) > 40:
            raise ValueError("Enter a user name (up to 40 letters).")
        if role not in ROLES:
            raise ValueError("Role must be admin, operator or viewer.")
        if len(password or "") < 6:
            raise ValueError("The password must be at least 6 characters.")
        with self.lock:
            salt = secrets.token_hex(16)
            self.data["users"][name] = {"role": role, "salt": salt, "hash": _hash(password, salt),
                                        "created": core.now_s(), "disabled": False}
            self._save()

    def set_password(self, name, password):
        with self.lock:
            u = self.data["users"].get(name)
            if not u:
                raise ValueError("No such user.")
            if len(password or "") < 6:
                raise ValueError("The password must be at least 6 characters.")
            u["salt"] = secrets.token_hex(16)
            u["hash"] = _hash(password, u["salt"])
            self._save()

    def set_role(self, name, role):
        with self.lock:
            if role not in ROLES:
                raise ValueError("Bad role.")
            if name in self.data["users"]:
                admins = [n for n, u in self.data["users"].items()
                          if u["role"] == "admin" and not u.get("disabled")]
                if admins == [name] and role != "admin":
                    raise ValueError("This is the last admin - make another admin first.")
                self.data["users"][name]["role"] = role
                self._save()

    def disable(self, name, disabled=True):
        with self.lock:
            if name in self.data["users"]:
                admins = [n for n, u in self.data["users"].items()
                          if u["role"] == "admin" and not u.get("disabled")]
                if disabled and admins == [name]:
                    raise ValueError("This is the last admin - cannot disable it.")
                self.data["users"][name]["disabled"] = bool(disabled)
                for t, s in list(self.sessions.items()):
                    if s["user"] == name:
                        del self.sessions[t]
                self._save()

    # ---- sign-in
    def login(self, name, password, ip="", device=""):
        with self.lock:
            u = self.data["users"].get(name)
            if not u or u.get("disabled"):
                return None
            if not hmac.compare_digest(_hash(password, u["salt"]), u["hash"]):
                return None
            token = secrets.token_urlsafe(32)
            self.sessions[token] = {"user": name, "role": u["role"], "exp": time.time() + SESSION_TTL,
                                    "ip": ip, "device": device}
            u["last_login"] = core.now_s()
            self._save()
            return {"token": token, "user": name, "role": u["role"]}

    def who(self, token):
        with self.lock:
            s = self.sessions.get(token or "")
            if not s:
                return None
            if s["exp"] < time.time():
                del self.sessions[token]
                return None
            return dict(s)

    def logout(self, token):
        with self.lock:
            self.sessions.pop(token or "", None)

    def may(self, token, action):
        """Returns (ok, session_or_reason). An unknown action needs admin, to fail safe."""
        s = self.who(token)
        if not s:
            return False, "please sign in"
        need = NEEDS.get(action, "admin")
        if ROLE_RANK[s["role"]] < ROLE_RANK[need]:
            return False, f"needs the {need} role (you are {s['role']})"
        return True, s


class AuditLog:
    """Append-only log of every change, newest readable first. Never rewritten."""

    def __init__(self):
        self.path = os.path.join(_dir(), "audit.log")
        self.lock = threading.Lock()

    def add(self, user, role, action, detail="", result="done", ip=""):
        rec = {"t": time.time(), "ts": core.now_s(), "user": user or "-", "role": role or "-",
               "action": action, "detail": str(detail)[:400], "result": str(result)[:200], "ip": ip}
        try:
            with self.lock, open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            pass
        return rec

    def recent(self, n=300):
        try:
            with open(self.path, encoding="utf-8") as f:
                lines = f.readlines()[-n:]
        except Exception:
            return []
        out = []
        for ln in lines:
            try:
                out.append(json.loads(ln))
            except Exception:
                pass
        return out[::-1]
