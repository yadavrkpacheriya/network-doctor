"""Signed-licence unlock: the pure-Python Ed25519 verifier accepts a licence signed with the matching
private key, and rejects tampering, a wrong key, expiry, and garbage. Also checks the save/read/clear and
is_licensed() helpers against a temporary DATA_DIR."""
import base64
import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_license as L  # noqa: E402

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: F401
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False


def _b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _sign(priv, email, exp=0, plan="pro"):
    payload = {"email": email, "plan": plan, "iat": int(time.time()), "exp": exp}
    body = _b64u(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    sig = _b64u(priv.sign(body.encode()))
    return body + "." + sig


@unittest.skipUnless(HAVE_CRYPTO, "cryptography needed to sign test licences")
class Verify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        cls.priv = Ed25519PrivateKey.generate()
        pub = cls.priv.public_key().public_bytes(serialization.Encoding.Raw,
                                                 serialization.PublicFormat.Raw)
        # point the module at this test key for the duration of the test
        cls._real_pub = L.PUBLIC_KEY_B64
        L.PUBLIC_KEY_B64 = base64.b64encode(pub).decode()
        # a second, unrelated key - its signatures must be rejected
        cls.other = Ed25519PrivateKey.generate()

    @classmethod
    def tearDownClass(cls):
        L.PUBLIC_KEY_B64 = cls._real_pub

    def test_valid(self):
        lic = _sign(self.priv, "owner@example.com")
        ok, info, reason = L.verify_license(lic)
        self.assertTrue(ok, reason)
        self.assertEqual(info["email"], "owner@example.com")

    def test_tampered_email_rejected(self):
        lic = _sign(self.priv, "owner@example.com")
        body, sig = lic.rsplit(".", 1)
        p = json.loads(base64.urlsafe_b64decode(body + "=="))
        p["email"] = "attacker@evil.com"
        nb = _b64u(json.dumps(p, separators=(",", ":"), sort_keys=True).encode())
        ok, _i, reason = L.verify_license(nb + "." + sig)
        self.assertFalse(ok)
        self.assertEqual(reason, "signature invalid")

    def test_wrong_key_rejected(self):
        lic = _sign(self.other, "owner@example.com")
        ok, _i, _r = L.verify_license(lic)
        self.assertFalse(ok)

    def test_expired_rejected(self):
        lic = _sign(self.priv, "owner@example.com", exp=int(time.time()) - 10)
        ok, _i, reason = L.verify_license(lic)
        self.assertFalse(ok)
        self.assertEqual(reason, "expired")

    def test_future_expiry_ok(self):
        lic = _sign(self.priv, "owner@example.com", exp=int(time.time()) + 3600)
        ok, _i, _r = L.verify_license(lic)
        self.assertTrue(ok)

    def test_garbage_rejected(self):
        for bad in ("", "not-a-licence", "a.b", "...", "x." + "y" * 10):
            ok, _i, _r = L.verify_license(bad)
            self.assertFalse(ok)

    def test_save_read_clear(self):
        d = tempfile.mkdtemp()
        lic = _sign(self.priv, "owner@example.com")
        self.assertFalse(L.is_licensed(d)[0])
        ok, info, _r = L.save_license(d, lic)
        self.assertTrue(ok)
        self.assertTrue(L.is_licensed(d)[0])
        self.assertEqual(L.is_licensed(d)[1]["email"], "owner@example.com")
        L.clear_license(d)
        self.assertFalse(L.is_licensed(d)[0])

    def test_save_refuses_invalid(self):
        d = tempfile.mkdtemp()
        ok, _i, _r = L.save_license(d, _sign(self.other, "owner@example.com"))
        self.assertFalse(ok)
        self.assertFalse(os.path.exists(L.license_path(d)))


@unittest.skipUnless(HAVE_CRYPTO, "cryptography needed to sign test licences")
class RealEmbeddedKey(unittest.TestCase):
    """With the real shipped public key, a licence signed by an unrelated key must never verify."""

    def test_foreign_signature_rejected(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        lic = _sign(Ed25519PrivateKey.generate(), "owner@example.com")
        ok, _i, _r = L.verify_license(lic)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
