# -*- coding: utf-8 -*-
"""Remote agent deployment: encrypted admin-credential store, target picking, command building, and the sweep
(with an injected runner so nothing touches the network)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_deploy as D  # noqa: E402


class CredStore(unittest.TestCase):
    def test_password_is_encrypted_and_reads_back(self):
        store = []
        D.admin_set(store, "office-admin", "Administrator", "S3cr3t!")
        self.assertNotIn("S3cr3t!", repr(store))                 # never in plain text
        self.assertEqual(D.admin_list(store), [("office-admin", "Administrator")])
        self.assertEqual(D.admin_creds(store), [("office-admin", "Administrator", "S3cr3t!")])

    def test_replace_by_label_and_delete(self):
        store = []
        D.admin_set(store, "a", "u1", "p1")
        D.admin_set(store, "a", "u2", "p2")                      # same label replaces
        self.assertEqual(len(store), 1)
        self.assertEqual(D.admin_creds(store), [("a", "u2", "p2")])
        D.admin_del(store, "a")
        self.assertEqual(store, [])


class Targets(unittest.TestCase):
    def test_only_online_computers(self):
        devs = [{"ip": "192.168.0.70", "name": "RAKESH", "category": "Computers / laptops", "online": True},
                {"ip": "192.168.0.64", "name": "CAM", "category": "CCTV cameras / DVR", "online": True},
                {"ip": "192.168.0.71", "name": "OFF", "category": "Computers / laptops", "online": False}]
        t = D.windows_targets(devs)
        self.assertEqual([x["name"] for x in t], ["RAKESH"])     # no camera, no offline PC


class Commands(unittest.TestCase):
    def test_schtasks_create_is_system_highest_and_replaces(self):
        argv = D.schtasks_create_argv("192.168.0.70", "adm", "pw", D.TASK_BG, D.agent_run_cmd("background"),
                                      ("ONLOGON",))
        self.assertEqual(argv[:4], ["schtasks", "/S", "192.168.0.70", "/U"])
        for flag in ("/RU", "SYSTEM", "/RL", "HIGHEST", "/F", "/SC", "ONLOGON"):
            self.assertIn(flag, argv)
        self.assertIn("-Mode background", " ".join(argv))

    def test_once_task_has_a_start_time(self):
        argv = D.schtasks_create_argv("ip", "u", "p", D.TASK_FIX, D.agent_run_cmd("fix"), ("ONCE", "00:00"))
        self.assertIn("/ST", argv)

    def test_plan_registers_both_tasks_then_runs(self):
        steps = [lbl for lbl, _ in D.deploy_plan("ip", "u", "p")]
        self.assertEqual(steps, ["register background task", "register fix task", "start the agent now"])


class Sweep(unittest.TestCase):
    def test_deploy_one_happy_path(self):
        calls = []

        def run(argv, timeout=40):
            calls.append(argv[0] + " " + (argv[1] if len(argv) > 1 else ""))
            return 0, "OK"
        res = D.deploy_one("192.168.0.70", "adm", "pw", r"\\IT\share", "/src",
                           run=run, place=lambda ip, src, central: None)
        self.assertTrue(res["ok"])
        self.assertIn("net use", calls[0])
        self.assertEqual(calls[-1], "net use")                  # always disconnects at the end

    def test_auth_failure_is_reported_clearly(self):
        def run(argv, timeout=40):
            if argv[:2] == ["net", "use"] and "/delete" not in argv:
                return 2, "System error 5 has occurred. Access is denied."
            return 0, ""
        res = D.deploy_one("192.168.0.71", "adm", "bad", "", "/src", run=run, place=lambda ip, src, central: None)
        self.assertFalse(res["ok"])
        self.assertEqual(res["step"], "connect")
        self.assertIn("refused", res["detail"])

    def test_deploy_all_tries_next_credential_only_on_auth_failure(self):
        seen = []

        def run(argv, timeout=40):
            if argv[:2] == ["net", "use"] and "/delete" not in argv:
                user = argv[3]
                seen.append(user)
                # 'bad' fails as a plain wrong-authority ("not supported"), which IS worth another user form;
                # 'good' then connects. Keeps the "fall through to the next credential" behaviour under test.
                return (0, "OK") if "good" in user else (2, "The request is not supported.")
            return 0, ""
        targets = [{"ip": "192.168.0.70", "name": "PC1"}]
        creds = [("bad", "bad", "x"), ("good", "good", "y")]
        res = D.deploy_all(targets, creds, "", "/src", run=run, place=lambda ip, src, central: None)
        self.assertTrue(res[0]["ok"])
        # 'bad' tried host-qualified then bare ("not supported" => worth another form), then 'good' connects on
        # its first (qualified) form.
        self.assertEqual(seen, [r"/user:192.168.0.70\bad", "/user:bad", r"/user:192.168.0.70\good"])

    def test_wrong_password_does_not_retry_other_user_forms(self):
        # error 86 (bad password) is the same for every user form, so we must NOT waste a second attempt on it
        seen = []

        def run(argv, timeout=40):
            if argv[:2] == ["net", "use"] and "/delete" not in argv:
                seen.append(argv[3])
                return 2, "System error 86 has occurred. The specified network password is not correct."
            return 0, ""
        res = D.deploy_one("192.168.0.70", "Administrator", "wrong", "", "/src",
                           run=run, place=lambda ip, src, central: None)
        self.assertFalse(res["ok"])
        self.assertIn("wrong password", res["detail"])
        self.assertEqual(seen, [r"/user:192.168.0.70\Administrator"])   # only ONE form tried


if __name__ == "__main__":
    unittest.main()
