# -*- coding: utf-8 -*-
"""Owner activation: the app's OWNER (Rakesh) unlocks Pro on his own build by signing in with his personal email
and an activation secret he set once - no publisher licence file needed.

This is legitimate because it is HIS app and HIS build: the owner registers an email + a secret ONCE on the PC
(stored only on the PC), and from then on signing in with that email+secret activates Pro. The activation licence
is signed with HMAC-SHA256 using the owner secret that lives only on this PC, so the PC both issues and verifies
it and the secret never travels. A random person who doesn't know the owner secret cannot activate anything.

This does NOT touch or weaken the publisher's Ed25519 licence path in nd_license - it's an additional, owner-only
unlock that sits beside it. Pro turns on if EITHER a valid publisher licence OR a valid owner activation is present."""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

OWNER_FILE = "owner.json"            # {email, secret} - the owner's registration, PC-only, never sent anywhere
ACT_FILE = "owner_activation.txt"    # the signed activation token that unlocks Pro (like a licence)


def _dir(data_dir):
    d = os.path.join(data_dir, "pro")
    os.makedirs(d, exist_ok=True)
    return d


def _b64u(b):
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def owner_config(data_dir):
    """The registered owner {email, secret} or None. Secret is only ever used on this PC to sign/verify."""
    try:
        with open(os.path.join(_dir(data_dir), OWNER_FILE), encoding="utf-8") as f:
            d = json.load(f)
        if d.get("email") and d.get("secret"):
            return d
    except Exception:  # noqa: BLE001
        pass
    return None


def set_owner(data_dir, email, secret=""):
    """Register (once) the owner email + activation secret. If no secret is given, a strong one is generated and
    returned so the owner can type it on the phone. Returns the secret. Idempotent email update keeps the secret
    unless a new one is passed."""
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        raise ValueError("A valid email is required.")
    cur = owner_config(data_dir) or {}
    secret = (secret or "").strip() or cur.get("secret") or secrets.token_urlsafe(9)
    path = os.path.join(_dir(data_dir), OWNER_FILE)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"email": email, "secret": secret}, f)
    os.replace(tmp, path)
    return secret


def clear_owner(data_dir):
    for n in (OWNER_FILE, ACT_FILE):
        try:
            os.remove(os.path.join(_dir(data_dir), n))
        except OSError:
            pass


def _sign(secret, body):
    return hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()


def make_activation(data_dir, email, days=0):
    """Issue an owner activation token for `email`, signed with the owner secret. days>0 sets an expiry.
    Returns (ok, token_or_reason). Only works when `email` matches the registered owner."""
    cfg = owner_config(data_dir)
    if not cfg:
        return False, "no owner registered on this PC"
    if (email or "").strip().lower() != cfg["email"]:
        return False, "email does not match the owner"
    payload = {"email": cfg["email"], "plan": "pro", "by": "owner",
               "iat": int(time.time()), "exp": int(time.time() + days * 86400) if days else 0}
    body = _b64u(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = _b64u(_sign(cfg["secret"], body))
    return True, body + "." + sig


def verify_activation(data_dir, token):
    """(ok, payload, reason) for an owner activation token, checked against the registered owner secret."""
    cfg = owner_config(data_dir)
    if not cfg:
        return False, None, "no owner registered"
    if not token or "." not in token:
        return False, None, "no token"
    try:
        body, sig = token.strip().rsplit(".", 1)
        want = _sign(cfg["secret"], body)
        if not hmac.compare_digest(want, _b64u_dec(sig)):
            return False, None, "signature invalid"
        payload = json.loads(_b64u_dec(body))
    except Exception as e:  # noqa: BLE001
        return False, None, "malformed (%s)" % e
    if payload.get("email", "").lower() != cfg["email"]:
        return False, payload, "email mismatch"
    exp = int(payload.get("exp", 0) or 0)
    if exp and time.time() > exp:
        return False, payload, "expired"
    return True, payload, "ok"


def read_activation(data_dir):
    try:
        with open(os.path.join(_dir(data_dir), ACT_FILE), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def save_activation(data_dir, token):
    ok, payload, reason = verify_activation(data_dir, token)
    if not ok:
        return False, payload, reason
    path = os.path.join(_dir(data_dir), ACT_FILE)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(token.strip() + "\n")
    os.replace(tmp, path)
    return True, payload, "ok"


def is_owner_activated(data_dir):
    """(ok, payload) - True when a valid owner activation token is stored on this PC."""
    ok, payload, _ = verify_activation(data_dir, read_activation(data_dir))
    return ok, (payload if ok else None)


def activate_with_login(data_dir, email, secret):
    """The phone calls this (via the PC): the owner signs in with email + the activation secret. If they match
    the registration, Pro is activated on this PC and (ok, payload) is returned. This is the 'login with my
    personal email' flow - owner-only, secret verified locally, nothing leaves the PC."""
    cfg = owner_config(data_dir)
    if not cfg:
        return False, "No owner is set on this PC yet. On the PC: Setup > Pro / owner, set your email first."
    if (email or "").strip().lower() != cfg["email"]:
        return False, "This email is not the owner of this PC."
    if not hmac.compare_digest((secret or "").strip(), cfg["secret"]):
        return False, "Wrong activation secret."
    ok, token = make_activation(data_dir, email)
    if not ok:
        return False, token
    ok2, payload, reason = save_activation(data_dir, token)
    return (True, payload) if ok2 else (False, reason)
