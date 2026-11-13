"""Devices that used to sit under "Unknown devices" now get a best guess with a "likely ..." reason."""
import unittest

import nd_core as core


def dev(ports=(), ttl=None, vendor="", name="", random=False):
    return {"ip": "192.168.0.90", "ports": list(ports), "vendor": vendor, "name": name, "upnp": {},
            "http": {}, "names": {}, "random": random, "ttl": ttl}


class LastClues(unittest.TestCase):
    def cat(self, **kw):
        return core.categorize(dev(**kw), "192.168.0.1")

    def test_ssh_or_snmp_only_is_managed_equipment(self):
        c, why = self.cat(ports=(22,), ttl=64)
        self.assertEqual(c, core.CAT_NET)
        self.assertIn("likely", why)

    def test_web_page_only_is_an_appliance(self):
        c, why = self.cat(ports=(80,), ttl=64)
        self.assertEqual(c, core.CAT_IOT)
        self.assertIn("likely", why)

    def test_answers_ping_ttl_64_with_nothing_open_is_a_likely_phone(self):
        c, why = self.cat(ttl=64)
        self.assertEqual(c, core.CAT_PHONE)
        self.assertIn("likely", why)

    def test_strong_clues_still_win(self):
        self.assertEqual(self.cat(ports=(554, 80), ttl=64)[0], core.CAT_CAM)
        self.assertEqual(self.cat(ports=(445,), ttl=128)[0], core.CAT_PC)
        self.assertEqual(self.cat(ports=(80,), ttl=64, vendor="Hikvision Digital")[0], core.CAT_CAM)

    def test_nothing_at_all_is_still_unknown(self):
        self.assertEqual(self.cat()[0], core.CAT_UNK)


if __name__ == "__main__":
    unittest.main()
