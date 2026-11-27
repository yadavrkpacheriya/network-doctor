# -*- coding: utf-8 -*-
"""Forgot-password help is the OFFICIAL owner reset (brand-specific), never a cracker (Rakesh, 27 Nov)."""
import unittest
import nd_pwreset as P


class ResetGuide(unittest.TestCase):
    def test_brands_map_to_their_official_reset(self):
        self.assertIn("SADP", " ".join(P.reset_guide("Hikvision camera")[1]))
        self.assertIn("QR", " ".join(P.reset_guide("Dahua NVR")[1]))
        self.assertIn("date", " ".join(P.reset_guide("XMeye DVR")[1]).lower())

    def test_unknown_brand_gets_generic_owner_reset(self):
        title, steps = P.reset_guide("Millennial Net")
        self.assertTrue(steps)
        self.assertIn("RESET", " ".join(steps))

    def test_router_says_you_already_have_access(self):
        self.assertIn("logged in", " ".join(P.reset_guide("MikroTik")[1]).lower())

    def test_guide_text_states_it_is_not_a_cracker(self):
        self.assertIn("does not crack", P.guide_text("Hikvision").lower() if False else P.guide_text("Hikvision"))


if __name__ == "__main__":
    unittest.main()
