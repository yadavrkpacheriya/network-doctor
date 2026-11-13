"""Login sweep: the login that works for a device is remembered (encrypted) and tried first next time."""
import unittest

import nd_camline as CL
import nd_sweep as S

MAC = "AA:BB:CC:00:00:64"


def target(mac=MAC):
    return {"dev": {"ip": "192.168.0.64", "mac": mac, "name": "cam", "category": "", "ports": [80]},
            "methods": ["onvif"]}


def sweep(creds, accept, saved=None):
    calls = []

    def tr(ip, user, pw, d):
        calls.append((user, pw))
        if (user, pw) == accept:
            return {"model": "M", "serial": "S"}
        raise S.Outcome(S.AUTH, "refused")
    return S.Sweep(creds, transports={"onvif": tr}, gap=0, sleep=lambda s: None, saved=saved), calls


class Store(unittest.TestCase):
    def test_password_is_not_kept_in_plain_text_and_reads_back(self):
        store = {}
        S.saved_put(store, MAC, "admin", "S3cret!", "onvif")
        self.assertNotIn("S3cret!", repr(store))
        self.assertEqual(S.saved_get(store, MAC), ("admin", "S3cret!"))
        self.assertEqual(S.saved_all(store), {MAC: ("admin", "S3cret!")})
        self.assertIsNone(S.saved_get(store, "11:22:33:44:55:66"))
        self.assertIsNone(S.saved_get({MAC: "garbage"}, MAC))


class Remembered(unittest.TestCase):
    def test_remembered_login_is_tried_first_and_nothing_needs_typing(self):
        sw, calls = sweep([], ("admin", "pw1"), saved={MAC: ("admin", "pw1")})
        r = sw.one(target())
        self.assertEqual((r["status"], r["login"]), (S.OK, S.SAVED))
        self.assertEqual(calls, [("admin", "pw1")])

    def test_changed_password_forgets_it_and_typed_logins_get_one_try_each(self):
        sw, calls = sweep([("admin", "old"), ("admin", "new")], ("admin", "new"), saved={MAC: ("admin", "old")})
        r = sw.one(target())
        self.assertEqual((r["status"], r["login"]), (S.OK, 2))
        self.assertEqual(calls, [("admin", "old"), ("admin", "new")])     # the refused one is never sent twice
        self.assertEqual(sw.stale, {MAC})

    def test_no_typed_and_no_remembered_login_is_skipped_not_an_error(self):
        sw, calls = sweep([], ("admin", "pw1"))
        r = sw.one(target())
        self.assertEqual(r["status"], S.SKIP)
        self.assertEqual(calls, [])

    def test_a_remembered_login_never_counts_towards_the_lockout_breaker(self):
        sw, _ = sweep([("admin", "typed")], ("admin", "typed"), saved={MAC: ("x", "y")})
        sw.one(target())
        self.assertEqual(sum(sw.fails.values()), 0)


class LineUpUsesThem(unittest.TestCase):
    def test_cred_of(self):
        row = {"dev": {"mac": MAC}, "login": S.SAVED}
        self.assertEqual(CL.cred_of(row, [], {MAC: ("admin", "pw")}), ("admin", "pw"))
        self.assertIsNone(CL.cred_of(row, [("a", "b")], {}))
        self.assertEqual(CL.cred_of({"dev": {"mac": MAC}, "login": 2}, [("a", "b"), ("c", "d")]), ("c", "d"))
        self.assertIsNone(CL.cred_of({"dev": {"mac": MAC}, "login": 3}, [("a", "b")]))
        self.assertIsNone(CL.cred_of({"dev": {"mac": MAC}, "login": 0}, [("a", "b")]))

    def test_a_remembered_login_makes_the_device_a_candidate(self):
        res = {"mac": MAC, "method": "onvif", "status": S.OK, "login": S.SAVED, "data": {}}
        self.assertIn(MAC, CL.candidates([res]))


if __name__ == "__main__":
    unittest.main()
