"""Automatic login check after a scan: findings -> alerts, results -> inventory."""
import unittest

import nd_alerts as AL
import nd_core as core
import nd_sweep as S
import nd_tools as T

CAM, NVR, PC = "AA:00:00:00:00:64", "AA:00:00:00:01:41", "AA:00:00:00:00:30"


def dev(ip, mac, cat=core.CAT_CAM, online=True, name="", ports=(80, 554)):
    return {"ip": ip, "mac": mac, "online": online, "category": cat if online else core.CAT_OFF, "name": name,
            "ports": list(ports), "notes": [] if online else [f"was: {cat}"], "vendor": "", "names": {}}


def result(mac, ip, status, tried_saved=True, name="Gate cam", detail=""):
    return {"mac": mac, "ip": ip, "name": name, "category": core.CAT_CAM, "method": "onvif", "status": status,
            "data": {}, "detail": detail, "missing": [], "tried": [(S.SAVED, status)] if tried_saved else [(1, status)]}


class Targets(unittest.TestCase):
    def test_only_devices_with_a_remembered_login_are_asked(self):
        devs = [dev("192.168.0.64", CAM), dev("192.168.0.65", "AA:00:00:00:00:65")]
        t = S.auto_targets(devs, {CAM: ("admin", "x")})
        self.assertEqual([x["dev"]["mac"] for x in t], [CAM])
        self.assertEqual(S.auto_targets(devs, {}), [])


class Findings(unittest.TestCase):
    def test_refused_remembered_login_is_a_password_change(self):
        f = S.auto_findings([result(CAM, "192.168.0.64", S.AUTH)], [dev("192.168.0.64", CAM)], {CAM})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0][0], "critical")
        self.assertEqual(AL.explain(f[0][1], f[0][0])["kind"], "password_changed")
        self.assertIn("192.168.0.64", f[0][1])

    def test_online_but_login_service_silent(self):
        f = S.auto_findings([result(CAM, "192.168.0.64", S.UNREACH, detail="timed out")],
                            [dev("192.168.0.64", CAM)], {CAM})
        self.assertEqual(AL.explain(f[0][1], f[0][0])["kind"], "device_down")

    def test_camera_gone_from_the_network(self):
        devs = [dev("192.168.0.64", CAM, online=False, name="Gate cam"), dev("192.168.0.30", PC, core.CAT_PC, False)]
        f = S.auto_findings([], devs, {CAM, PC})
        self.assertEqual(len(f), 1)                      # the switched-off PC is not a camera alarm
        self.assertIn("Gate cam (192.168.0.64)", f[0][1])
        r = AL.explain(f[0][1], f[0][0])
        self.assertEqual((r["kind"], r["prio"]), ("device_down", 1))

    def test_all_fine_or_a_typed_login_refused_raises_nothing(self):
        devs = [dev("192.168.0.64", CAM)]
        self.assertEqual(S.auto_findings([result(CAM, "192.168.0.64", S.OK)], devs, {CAM}), [])
        self.assertEqual(S.auto_findings([result(CAM, "192.168.0.64", S.AUTH, tried_saved=False)], devs, set()), [])

    def test_new_kinds_are_never_auto_fixed(self):
        self.assertFalse({"password_changed", "device_down"} & AL.AUTO_SAFE)


class Inventory(unittest.TestCase):
    def test_sweep_details_and_login_state_reach_the_inventory(self):
        db = {"devices": {}, "pc_reports": {}, "tags": {}, "labels": {},
              "sweep": {CAM: {"data": {"model": "H42", "serial": "1D7F", "firmware": "V5.0", "name": "Gate cam"}}},
              "sweep_status": {CAM: {"status": S.OK, "time": "2026-11-13 23:50"},
                               NVR: {"status": S.AUTH, "time": "2026-11-13 23:50"}}}
        devs = [dev("192.168.0.64", CAM), dev("192.168.0.141", NVR)]
        rows = {r["mac"]: r for r in T.inventory_rows(devs, db)}
        cam = rows[CAM]
        self.assertEqual((cam["model"], cam["serial"], cam["firmware"], cam["device_name"]),
                         ("H42", "1D7F", "V5.0", "Gate cam"))
        self.assertTrue(cam["login_check"].startswith("OK"))
        self.assertIn("LOGIN REFUSED", rows[NVR]["login_check"])
        self.assertIn("login check: login refused", rows[NVR]["flag_text"])
        self.assertIn("Login check", [c[1] for c in T.INV_COLS])


if __name__ == "__main__":
    unittest.main()
