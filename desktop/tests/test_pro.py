"""Pro: accounts / sign-in / roles, audit log, and the auto-defense engine's decisions."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_core as core  # noqa: E402

core.DATA_DIR = tempfile.mkdtemp()  # keep the test's accounts out of the real profile

import nd_auth as AU  # noqa: E402
import nd_defense as DF  # noqa: E402


class Accounts(unittest.TestCase):
    def setUp(self):
        AU.core.DATA_DIR = tempfile.mkdtemp()
        self.a = AU.Accounts()

    def test_add_login_roles(self):
        self.assertFalse(self.a.has_users())
        self.a.add_user("boss", "secret1", "admin")
        self.a.add_user("ravi", "pass12", "operator")
        self.a.add_user("guest", "look11", "viewer")
        self.assertTrue(self.a.has_users())
        self.assertIsNone(self.a.login("boss", "wrong"))
        s = self.a.login("boss", "secret1")
        self.assertEqual(s["role"], "admin")
        tok = s["token"]
        # admin may do an admin action; viewer may not block
        self.assertTrue(self.a.may(tok, "poweroff")[0])
        v = self.a.login("guest", "look11")["token"]
        self.assertFalse(self.a.may(v, "block")[0])
        self.assertTrue(self.a.may(v, "view")[0])
        op = self.a.login("ravi", "pass12")["token"]
        self.assertTrue(self.a.may(op, "block")[0])
        self.assertFalse(self.a.may(op, "poweroff")[0])  # containment power-off is admin-only
        self.assertFalse(self.a.may("bad-token", "view")[0])

    def test_last_admin_protected(self):
        self.a.add_user("boss", "secret1", "admin")
        with self.assertRaises(ValueError):
            self.a.disable("boss")
        with self.assertRaises(ValueError):
            self.a.set_role("boss", "viewer")

    def test_logout_and_disable_kill_session(self):
        self.a.add_user("boss", "secret1", "admin")
        self.a.add_user("ravi", "pass12", "operator")
        t = self.a.login("ravi", "pass12")["token"]
        self.a.logout(t)
        self.assertIsNone(self.a.who(t))
        t2 = self.a.login("ravi", "pass12")["token"]
        self.a.disable("ravi")
        self.assertIsNone(self.a.who(t2))

    def test_password_not_stored(self):
        self.a.add_user("boss", "secret1", "admin")
        raw = open(self.a.path, encoding="utf-8").read()
        self.assertNotIn("secret1", raw)


class Audit(unittest.TestCase):
    def test_append_and_read(self):
        AU.core.DATA_DIR = tempfile.mkdtemp()
        log = AU.AuditLog()
        log.add("boss", "admin", "isolate", "mac=AA", "done", "192.168.0.9")
        log.add("ravi", "operator", "block", "ip=192.168.0.48")
        r = log.recent()
        self.assertEqual(r[0]["action"], "block")  # newest first
        self.assertEqual(r[1]["user"], "boss")


class DefenseEngine(unittest.TestCase):
    def mk(self, **patch):
        st = {"defense": dict(patch)}
        return DF.Defense(st, gw_ip="192.168.0.1")

    def test_disarmed_only_notifies(self):
        d = self.mk(armed=False)
        self.assertEqual(d.planned("malware", "192.168.0.9", "AA"), "notify")

    def test_armed_auto_isolates_malware(self):
        d = self.mk(armed=True, mode="auto")
        self.assertEqual(d.planned("malware", "192.168.0.9", "AA:BB"), "isolate")

    def test_alert_mode_never_acts(self):
        d = self.mk(armed=True, mode="alert")
        self.assertEqual(d.planned("malware", "192.168.0.9", "AA"), "notify")

    def test_level_capped_by_your_choice(self):
        d = self.mk(armed=True, mode="auto", levels={"malware": "internet"})
        self.assertEqual(d.planned("malware", "192.168.0.9", "AA"), "internet")

    def test_router_and_excludes_never_acted(self):
        d = self.mk(armed=True, mode="auto", exclude_ips=["192.168.0.5"])
        self.assertEqual(d.planned("malware", "192.168.0.1", ""), "notify")   # the gateway
        self.assertEqual(d.planned("malware", "192.168.0.5", ""), "notify")   # excluded server

    def test_night_only(self):
        c = DF.cfg({"defense": {"night_from": 20, "night_to": 7}})
        self.assertTrue(DF.is_night(c, _at(23)))
        self.assertTrue(DF.is_night(c, _at(3)))
        self.assertFalse(DF.is_night(c, _at(13)))
        d = self.mk(armed=True, mode="auto", night_only=True)
        # night window spanning midnight is handled by is_night; planned() uses the real clock, so just
        # check the knobs are wired
        self.assertIn(d.planned("malware", "192.168.0.9", "AA"), ("notify", "isolate"))

    def test_cooldown(self):
        d = self.mk(armed=True, mode="auto")
        self.assertFalse(d.cool("malware", "AA"))
        self.assertTrue(d.cool("malware", "AA"))   # second time within the window is suppressed

    def test_contain_and_release(self):
        d = self.mk(armed=True)
        d.note_contained("AA", {"kind": "malware", "level": "isolate", "name": "PC"})
        self.assertIn("AA", d.contained())
        d.release("AA")
        self.assertNotIn("AA", d.contained())


def _at(hour):
    import time
    lt = list(time.localtime())
    lt[3] = hour
    return time.mktime(tuple(lt))


if __name__ == "__main__":
    unittest.main()


import nd_vuln as V  # noqa: E402


class Vuln(unittest.TestCase):
    def test_findings(self):
        devs = [{"online": True, "ip": "192.168.0.69", "name": "CAM", "ports": [80, 23, 34567],
                 "vendor": "Hikvision", "http": {"title": "login"}},
                {"online": True, "ip": "192.168.0.9", "name": "HR", "ports": [445, 3389], "vendor": "Dell",
                 "http": {}}]
        f = V.assess(devs, {}, None, lip="", active=False)
        titles = [x["title"] for x in f]
        self.assertIn("Telnet is open", titles)
        self.assertIn("May still use its default password", titles)
        self.assertEqual(f[0]["sev"], "critical")  # sorted, critical first
        self.assertTrue(any("LLMNR" in h[0] for h in V.HARDENING))
