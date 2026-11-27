# -*- coding: utf-8 -*-
"""Owner Pro activation: the app owner unlocks Pro on his own build by signing in with his email + a secret set
once on the PC (Rakesh, 27 Nov). Owner-only, secret verified locally, never leaves the PC."""
import tempfile
import unittest
import nd_owner as OW


class OwnerActivation(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.email = "yadavrkpacheriya@gmail.com"
        self.secret = OW.set_owner(self.d, self.email)

    def test_secret_is_issued_and_email_registered(self):
        self.assertTrue(self.secret)
        self.assertEqual((OW.owner_config(self.d) or {})["email"], self.email)

    def test_correct_login_activates_pro(self):
        ok, p = OW.activate_with_login(self.d, self.email, self.secret)
        self.assertTrue(ok)
        self.assertEqual(p["plan"], "pro")
        self.assertTrue(OW.is_owner_activated(self.d)[0])

    def test_wrong_email_or_secret_rejected(self):
        self.assertFalse(OW.activate_with_login(self.d, "someone@else.com", self.secret)[0])
        self.assertFalse(OW.activate_with_login(self.d, self.email, "wrong-secret")[0])
        # and nothing got activated
        self.assertFalse(OW.is_owner_activated(self.d)[0])

    def test_email_is_case_insensitive(self):
        ok, _ = OW.activate_with_login(self.d, self.email.upper(), self.secret)
        self.assertTrue(ok)

    def test_tampered_token_fails_verify(self):
        ok, tok = OW.make_activation(self.d, self.email)
        self.assertTrue(ok)
        bad = tok[:-4] + ("aaaa" if not tok.endswith("aaaa") else "bbbb")
        self.assertFalse(OW.verify_activation(self.d, bad)[0])

    def test_no_owner_means_no_activation(self):
        d2 = tempfile.mkdtemp()
        self.assertFalse(OW.is_owner_activated(d2)[0])
        self.assertFalse(OW.activate_with_login(d2, self.email, self.secret)[0])


if __name__ == "__main__":
    unittest.main()
