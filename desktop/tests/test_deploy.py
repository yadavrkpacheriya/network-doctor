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
            if argv[:1] == ["reg"]:
                return 1, "remote registry disabled"      # the UAC-enabler can't help here; no C$ retry after it
            if argv[:2] == ["net", "use"] and argv[2].endswith(r"\C$") and "/delete" not in argv:
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

    def test_uac_enabler_sets_token_policy_then_connects(self):
        # workgroup PC: C$ first says "request is not supported" (UAC). After the Remote-Registry key is set, the
        # C$ retry connects. Verifies the one-click LocalAccountTokenFilterPolicy enabler path.
        c_hits, reg_set = [], []

        def run(argv, timeout=40):
            if argv[:1] == ["reg"]:
                reg_set.append(argv)
                return 0, ""                               # remote registry available; key written
            if argv[:2] == ["net", "use"] and argv[2].endswith(r"\C$") and "/delete" not in argv:
                c_hits.append(argv[3])
                return (0, "OK") if len(c_hits) > 2 else (2, "The request is not supported.")
            return 0, ""
        res = D.deploy_one("192.168.0.70", "Administrator", "pw", "", "/src",
                           run=run, place=lambda ip, src, central: None)
        self.assertTrue(res["ok"])
        self.assertTrue(reg_set)                            # the policy key was pushed
        self.assertIn("LocalAccountTokenFilterPolicy", reg_set[0])


if __name__ == "__main__":
    unittest.main()


def test_enabler_script_opens_doors_and_installs():
    import nd_deploy as D
    s = D.enabler_script(r"\\RAKESH-IT\LeakLog")
    # self-elevates
    assert "RunAs" in s and "net session" in s
    # opens every door Windows shuts by default
    assert "LocalAccountTokenFilterPolicy" in s
    assert "AutoShareWks" in s
    assert "RemoteRegistry" in s
    assert "File and Printer Sharing" in s
    assert "Windows Management Instrumentation (WMI)" in s
    # installs + starts the agent pointed at the share
    assert "networkdoctor-agent.ps1" in s
    assert r"\\RAKESH-IT\LeakLog" in s
    assert 'schtasks /Create /TN "%s"' % D.TASK_BG in s
    assert 'schtasks /Run /TN "%s"' % D.TASK_BG in s
    # /TR inner quotes are escaped for cmd.exe
    assert '-File \\"C:\\ProgramData\\NetworkDoctor\\networkdoctor-agent.ps1\\"' in s


def test_enabler_script_handles_bare_share():
    import nd_deploy as D
    s = D.enabler_script("")
    assert "central.txt" in s   # still writes the config file even if empty


def test_enabler_hardens_against_tampering():
    """Boot task, watchdog task + script, and folder lock-down make the agent survive a user deleting it."""
    import nd_deploy as D
    s = D.enabler_script(r"\\RAKESH-IT\LeakLog")
    # a second task that also restarts the agent at system start (so a killed logon task still comes back)
    assert 'schtasks /Create /TN "%s Boot"' % D.TASK_BG in s
    assert "ONSTART" in s
    # a watchdog that re-creates the task + re-runs the agent, scheduled every few minutes
    assert "watchdog.cmd" in s
    assert 'schtasks /Create /TN "%s Watchdog"' % D.TASK_BG in s
    assert "/SC MINUTE" in s
    # standard users get read+execute only on the install folder
    assert "icacls" in s
    assert "Users:(OI)(CI)RX" in s
    assert "SYSTEM:(OI)(CI)F" in s


def test_enabler_writes_secret_as_central_second_line():
    """The IT-only tamper-off secret goes on central.txt line 2, and only when a secret is supplied."""
    import nd_deploy as D
    s = D.enabler_script(r"\\RAKESH-IT\LeakLog", secret="topsecret42")
    assert "topsecret42" in s
    assert "central.txt" in s
    # no secret -> no second echo into central.txt
    s0 = D.enabler_script(r"\\RAKESH-IT\LeakLog")
    assert "topsecret42" not in s0


def test_agent_source_has_it_controlled_uninstall():
    """The agent only removes itself on a valid IT token; otherwise it self-heals. Checked in the ps1 source."""
    import os
    ps1 = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "..", "endpoint", "networkdoctor-agent.ps1")
    src = open(ps1, encoding="utf-8").read()
    assert "function Self-Heal" in src
    assert "function Uninstall-Allowed" in src
    assert "function Do-Uninstall" in src
    # the loop checks the IT token and only uninstalls when allowed, else heals
    assert "if (Uninstall-Allowed) { Do-Uninstall }" in src
    assert "else { Self-Heal }" in src
    # token lives in the IT share, keyed to this PC or ALL, guarded by the secret
    assert "agent-remove" in src
    assert '"$pc.txt", "ALL.txt"' in src


def test_single_file_enabler_is_self_contained_and_roundtrips():
    """The 1-file setup carries the agent inside it (base64) and decodes it on the PC - no sidecar files to copy,
    so one file per PC is enough (Rakesh, 28 Nov: 0/23 installed, wants the easiest way onto every PC)."""
    import base64
    import nd_deploy as D
    agent = "PS1-AGENT-CONTENT\nline2\n"
    fix = "@echo fix\n"
    central = r"\\RAKESH-IT\LeakLog"
    txt = D.single_file_enabler(central, agent, fix, secret="topsecret42")
    # it must NOT copy sidecars from %~dp0 any more - everything is embedded/decoded
    assert "%~dp0networkdoctor-agent.ps1" not in txt
    assert "call :decode AGENT" in txt
    assert "certutil -decode" in txt
    assert central in txt and "topsecret42" in txt
    # simulate the batch decode: lines "#AGENT#<b64>" / "#FIX#<b64>", strip prefix, concat, base64-decode
    for tag, orig in (("AGENT", agent), ("FIX", fix)):
        chunks = []
        for line in txt.split("\r\n"):
            parts = line.split("#")
            if len(parts) >= 3 and parts[0] == "" and parts[1] == tag:
                chunks.append(parts[2])
        assert chunks, "no payload for " + tag
        assert base64.b64decode("".join(chunks)).decode("utf-8") == orig


def test_single_file_enabler_without_fix():
    """With no fix-launch file, there is no FIX payload and no FIX decode call, but the agent still embeds."""
    import nd_deploy as D
    txt = D.single_file_enabler(r"\\IT\share", "AGENT", fix_cmd="", secret="")
    assert "#AGENT#" in txt
    assert "#FIX#" not in txt
    assert "call :decode FIX" not in txt


def test_push_enabler_to_startup_writes_each_reachable_pc():
    """Queue the 1-file setup into each PC's Startup folder; only PCs we can connect to get it, and the copy
    uses the injected place stub (no real filesystem)."""
    import nd_deploy as D
    placed = []

    def fake_run(argv, timeout=40):
        # net use to .5 fails (offline), everything else connects
        if argv[:2] == ["net", "use"] and "/user:" in " ".join(argv):
            return (1, "system error 53") if "192.168.0.5" in argv[2] else (0, "")
        return (0, "")

    def fake_place(ip, text, run):
        placed.append(ip)
        return True, "queued"

    targets = [{"ip": "192.168.0.3", "name": "A"}, {"ip": "192.168.0.5", "name": "B"}]
    creds = [("office", "Administrator", "pw")]
    res = D.push_enabler_to_startup(targets, creds, "ENABLER", run=fake_run, place=fake_place, workers=2)
    by_ip = {r["ip"]: r for r in res}
    assert by_ip["192.168.0.3"]["ok"] and by_ip["192.168.0.3"]["step"] == "startup"
    assert not by_ip["192.168.0.5"]["ok"]            # offline PC never received the file
    assert placed == ["192.168.0.3"]


def test_push_enabler_startup_dir_is_all_users():
    """It targets the All-Users Startup folder so the agent installs regardless of who logs in."""
    import nd_deploy as D
    assert D.STARTUP_DIR.endswith(r"StartUp")
    assert "ProgramData" in D.STARTUP_DIR


def test_enabler_removes_previous_agent_before_install():
    """A re-run must REPLACE the agent, not stack a second one: stop the running agent, delete every known task
    (current + legacy names), unlock + clear the old files, then install fresh (Rakesh, 28 Nov)."""
    import nd_deploy as D
    s = D.enabler_script(r"\\IT\share", secret="x")
    # stops the running agent process by its command line
    assert "networkdoctor-agent.ps1" in s and "Stop-Process" in s
    # deletes all four task names + the legacy Cleanup task
    for t in (D.TASK_BG, D.TASK_BG + " Boot", D.TASK_BG + " Watchdog", D.TASK_FIX, "NetworkDoctor Cleanup"):
        assert t in s
    assert "schtasks /Delete /TN %%~T /F" in s
    # removal happens BEFORE the fresh install writes the agent
    assert s.index("Removing any previous agent") < s.index("Installing the Network Doctor agent")
    # unlocks the folder so old files can be overwritten
    assert "/reset" in s


def test_single_file_enabler_also_removes_previous_agent():
    """The 1-file build carries the same clean-replace, so copying it again never leaves duplicates."""
    import nd_deploy as D
    t = D.single_file_enabler(r"\\IT\share", "AGENT", "FIX", secret="x")
    assert "Removing any previous agent" in t
    assert "schtasks /Delete /TN %%~T /F" in t
