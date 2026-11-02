"""Network Doctor - signed licence check (pure Python, no third-party deps).

The advanced ("Pro") features ship inside the normal public app but stay
locked.  They unlock only when a licence file is present that was signed with
the owner's private key.  Only the owner holds that private key, so no other
user - and no internal tester - can unlock the features, and the same
mechanism issues paid licences later.

A licence is a string  <body>.<sig>  where <body> is base64url(JSON payload)
and <sig> is base64url(Ed25519 signature of the <body> ascii bytes).
Payload: {"email","plan","iat","exp"}  (exp 0 = perpetual).

Ed25519 verification is implemented here in pure Python (RFC 8032) so the
packaged exe needs no extra wheels.
"""
import base64
import hashlib
import json
import os
import time

# Owner's public verification key (base64, 32 raw bytes). The matching private
# key is held only by the owner and never ships in the app.
PUBLIC_KEY_B64 = "yFo8F0mMge775xQv/61TzDpCdup3+IsXVRyg+4vyN+w="

# ---------------------------------------------------------------------------
# Ed25519 verify - RFC 8032 reference arithmetic (verify only).
# ---------------------------------------------------------------------------
_p = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_d = (-121665 * pow(121666, _p - 2, _p)) % _p
_I = pow(2, (_p - 1) // 4, _p)


def _inv(x):
    return pow(x, _p - 2, _p)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p != 0:
        x = (x * _I) % _p
    if x % 2 != 0:
        x = _p - x
    return x


_By = (4 * _inv(5)) % _p
_Bx = _xrecover(_By)
_B = (_Bx % _p, _By % _p, 1, (_Bx * _By) % _p)


def _edwards_add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = ((y1 - x1) * (y2 - x2)) % _p
    b = ((y1 + x1) * (y2 + x2)) % _p
    c = (t1 * 2 * _d * t2) % _p
    dd = (z1 * 2 * z2) % _p
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    x3 = e * f
    y3 = g * h
    t3 = e * h
    z3 = f * g
    return (x3 % _p, y3 % _p, z3 % _p, t3 % _p)


def _scalarmult(P, e):
    if e == 0:
        return (0, 1, 1, 0)
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _encodeint(y):
    return y.to_bytes(32, "little")


def _decodeint(s):
    return int.from_bytes(s, "little")


def _decodepoint(s):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != (int.from_bytes(s, "little") >> 255) & 1:
        x = _p - x
    P = (x, y, 1, (x * y) % _p)
    if not _isoncurve(P):
        raise ValueError("point not on curve")
    return P


def _isoncurve(P):
    x, y, z, t = P
    return (
        z % _p != 0
        and (x * y) % _p == (z * t) % _p
        and (y * y - x * x - z * z - _d * t * t) % _p == 0
    )


def _hint(m):
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return True iff signature is a valid Ed25519 signature of message."""
    try:
        if len(signature) != 64 or len(public_key) != 32:
            return False
        R = _decodepoint(signature[:32])
        A = _decodepoint(public_key)
        S = _decodeint(signature[32:])
        if S >= _L:
            return False
        h = _hint(signature[:32] + public_key + message)
        lhs = _scalarmult(_B, S)
        rhs = _edwards_add(R, _scalarmult(A, h))
        # compare in affine coords
        lx, ly, lz, _ = lhs
        rx, ry, rz, _ = rhs
        return (lx * rz - rx * lz) % _p == 0 and (ly * rz - ry * lz) % _p == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Licence API
# ---------------------------------------------------------------------------
def _b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def license_path(data_dir: str) -> str:
    return os.path.join(data_dir, "pro", "license.txt")


def verify_license(lic: str):
    """(ok, payload, reason). ok True only if signature valid and not expired."""
    if not lic or "." not in lic:
        return False, None, "no licence"
    lic = lic.strip()
    try:
        body, sig = lic.rsplit(".", 1)
        pub = base64.b64decode(PUBLIC_KEY_B64)
        if not ed25519_verify(pub, body.encode("ascii"), _b64u_dec(sig)):
            return False, None, "signature invalid"
        payload = json.loads(_b64u_dec(body))
    except Exception as e:
        return False, None, "malformed (%s)" % e
    exp = int(payload.get("exp", 0) or 0)
    if exp and time.time() > exp:
        return False, payload, "expired"
    if not payload.get("email"):
        return False, payload, "no subject"
    return True, payload, "ok"


def read_license(data_dir: str) -> str:
    try:
        with open(license_path(data_dir), "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""


def is_licensed(data_dir: str):
    """(ok, payload) from the licence file stored under data_dir."""
    env = os.environ.get("ND_LICENSE", "").strip()
    lic = env or read_license(data_dir)
    if not lic:
        return False, None
    ok, payload, _ = verify_license(lic)
    return ok, payload


def save_license(data_dir: str, lic: str):
    """Verify then persist. Returns (ok, payload, reason)."""
    ok, payload, reason = verify_license(lic)
    if not ok:
        return ok, payload, reason
    d = os.path.join(data_dir, "pro")
    os.makedirs(d, exist_ok=True)
    with open(license_path(data_dir), "w", encoding="utf-8") as f:
        f.write(lic.strip() + "\n")
    return True, payload, "ok"


def clear_license(data_dir: str):
    try:
        os.remove(license_path(data_dir))
    except Exception:
        pass
