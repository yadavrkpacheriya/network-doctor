# -*- coding: utf-8 -*-
r"""Remote deployment of the PC agent from the Network Doctor PC.

Lets you save Windows admin credentials (encrypted) once, then push-install the agent to every office PC
without visiting them - so even the FIRST install is hands-off. After that, the agent self-updates from the
share within ~2 minutes, so this is only needed to onboard a PC (or revive one whose agent was removed).

Mechanism uses only built-in Windows tools (no PsExec, no extra software):
  1. net use \\IP\C$  - authenticate to the admin share with the saved credential
  2. copy the agent files + central.txt into C:\ProgramData\NetworkDoctor\
  3. schtasks /S \\IP /U /P  - register the background + fix tasks (SYSTEM, highest) and run the agent now
Prerequisites on each PC: File & Printer Sharing on, admin shares (C$) reachable, and for workgroup PCs
LocalAccountTokenFilterPolicy=1 (remote admin over a local account). The sweep reports per-PC success/why.

Credentials are stored encrypted (nd_routeros.protect) in settings['admin_logins'] - the same scheme used for
camera logins. They never leave this PC except as the /U /P of a schtasks call to the target you choose.
"""
import subprocess
import time


# ------------------------------------------------------------------ credential store (encrypted)
def admin_set(store, label, user, pw):
    """Save/replace an admin credential under a short label. Password kept encrypted. `store` is a list."""
    import nd_routeros as RO
    label = (label or user or "admin").strip()
    entry = {"label": label, "user": user, "pw": RO.protect(pw),
             "time": time.strftime("%Y-%m-%d %H:%M")}
    for i, e in enumerate(store):
        if e.get("label") == label:
            store[i] = entry
            return
    store.append(entry)


def admin_list(store):
    """[(label, user)] for display - never the password."""
    return [(e.get("label", ""), e.get("user", "")) for e in (store or []) if e.get("user")]


def admin_creds(store):
    """[(label, user, password)] decrypted, for use by the sweep. Skips anything that won't decrypt."""
    import nd_routeros as RO
    out = []
    for e in store or []:
        if not e.get("user"):
            continue
        pw = RO.unprotect(e.get("pw", ""))
        if pw is not None:
            out.append((e.get("label", ""), e["user"], pw))
    return out


def admin_del(store, label):
    store[:] = [e for e in (store or []) if e.get("label") != label]


# ------------------------------------------------------------------ which PCs to deploy to
def windows_targets(devices):
    """Online computers (not cameras/NVR/router/printers) with an IP - the PCs worth deploying to."""
    out = []
    for d in devices or []:
        if not d.get("online") or not d.get("ip"):
            continue
        if "omputer" not in str(d.get("category", "")):
            continue
        out.append({"ip": d["ip"], "name": d.get("name") or d["ip"], "mac": d.get("mac", "")})
    return out


# ------------------------------------------------------------------ command builders (pure - unit tested)
REMOTE_DIR = r"C:\ProgramData\NetworkDoctor"
TASK_BG = "NetworkDoctor Agent"
TASK_FIX = "NetworkDoctor Fix"
_PS = r"powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File"


def _tr_escape(cmd):
    r"""Escape a command for use inside schtasks /TR "..." written in a .cmd file: the inner double quotes
    around the .ps1 path must become \" so cmd.exe keeps them as part of the one /TR argument."""
    return cmd.replace('"', '\\"')


def enabler_script(central, secret=""):
    r"""A self-contained, self-elevating one-time setup a PC runs LOCALLY (double-click, GPO startup script, or
    pushed once). It does two jobs so a workgroup PC becomes fully remote-manageable AND gets the agent:
      1. opens the doors Windows shuts by default - admin shares, Remote Registry, File & Printer Sharing +
         WMI firewall rules, and LocalAccountTokenFilterPolicy=1 - so Network Doctor's remote push works forever
         after;
      2. installs the Network Doctor agent (copies it to ProgramData, registers the logon + fix tasks, starts
         it) pointed at the IT share, so this PC starts reporting full details immediately.
    After this runs once per PC, the agent self-updates from the share with no further per-PC visit. `central` is
    the IT share path written to central.txt. Returns the .cmd text. The agent .ps1 is expected next to this
    script as networkdoctor-agent.ps1 (the caller writes both into the same folder)."""
    share = (central or "").replace("^", "^^").replace("&", "^&")
    return (
        "@echo off\r\n"
        "setlocal EnableExtensions\r\n"
        "title Network Doctor - one-time setup\r\n"
        ":: self-elevate to admin\r\n"
        'net session >nul 2>&1\r\n'
        "if %errorlevel% NEQ 0 (\r\n"
        '  powershell -NoProfile -Command "Start-Process \'%~f0\' -Verb RunAs"\r\n'
        "  exit /b\r\n"
        ")\r\n"
        "echo(\r\n"
        "echo   Setting up this PC for Network Doctor... please wait.\r\n"
        "echo(\r\n"
        ":: 1) open the doors Windows closes by default (so remote management works from now on)\r\n"
        'echo   - Admin shares + remote UAC token\r\n'
        'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f >nul 2>&1\r\n'
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v AutoShareWks /t REG_DWORD /d 1 /f >nul 2>&1\r\n'
        'echo   - Remote Registry service\r\n'
        'sc config RemoteRegistry start= auto >nul 2>&1 & sc start RemoteRegistry >nul 2>&1\r\n'
        'echo   - File ^& Printer Sharing + WMI through the firewall\r\n'
        'netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes >nul 2>&1\r\n'
        'netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=Yes >nul 2>&1\r\n'
        'netsh advfirewall firewall set rule group="Remote Administration" new enable=Yes >nul 2>&1\r\n'
        ":: 1b) REMOVE any previous Network Doctor agent first, so a re-run REPLACES it and never leaves a second\r\n"
        "::     copy running (Rakesh, 28 Nov). Stop the running agent, delete every known task (old names too),\r\n"
        "::     and clear an install left in an old location. The new agent is written fresh below.\r\n"
        'echo   - Removing any previous agent (clean replace)\r\n'
        'set "ND=%ProgramData%\\NetworkDoctor"\r\n'
        ':: stop the running agent process(es): powershell loops whose command line points at our agent .ps1\r\n'
        'powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \\"Name=\'powershell.exe\'\\" | '
        'Where-Object { $_.CommandLine -match \'networkdoctor-agent.ps1\' } | '
        'ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>&1\r\n'
        ':: delete every scheduled task this agent has ever created (current + legacy names)\r\n'
        'for %%T in ("' + TASK_BG + '" "' + TASK_BG + ' Boot" "' + TASK_BG + ' Watchdog" "' + TASK_FIX + '" '
        '"NetworkDoctor Cleanup") do schtasks /Delete /TN %%~T /F >nul 2>&1\r\n'
        ':: drop the folder lock so the old files can be overwritten, then clear stale agent files\r\n'
        'icacls "%ND%" /reset /t /c >nul 2>&1\r\n'
        'if exist "%ND%\\networkdoctor-agent.ps1" del /f /q "%ND%\\networkdoctor-agent.ps1" >nul 2>&1\r\n'
        'if exist "%ND%\\watchdog.cmd" del /f /q "%ND%\\watchdog.cmd" >nul 2>&1\r\n'
        ":: 2) install the Network Doctor agent locally and point it at the IT share\r\n"
        'echo   - Installing the Network Doctor agent\r\n'
        'if not exist "%ND%" md "%ND%" >nul 2>&1\r\n'
        'copy /y "%~dp0networkdoctor-agent.ps1" "%ND%\\networkdoctor-agent.ps1" >nul 2>&1\r\n'
        'if exist "%~dp0fix-launch.cmd" copy /y "%~dp0fix-launch.cmd" "%ND%\\fix-launch.cmd" >nul 2>&1\r\n'
        '> "%ND%\\central.txt" echo ' + share + "\r\n"
        # line 2 = the tamper secret: the agent only uninstalls when IT writes a removal token carrying this
        # secret, so a user (even a local admin) can't forge an uninstall.
        + ('>> "%ND%\\central.txt" echo ' + secret.replace("^", "^^").replace("&", "^&") + "\r\n" if secret else "")
        + ':: Background agent: run at logon AND at system start, so it comes up before anyone logs in.\r\n'
        'schtasks /Create /TN "' + TASK_BG + '" /TR "' + _tr_escape(agent_run_cmd("background")) + '" '
        '/RU SYSTEM /RL HIGHEST /F /SC ONLOGON >nul 2>&1\r\n'
        'schtasks /Create /TN "' + TASK_BG + ' Boot" /TR "' + _tr_escape(agent_run_cmd("background")) + '" '
        '/RU SYSTEM /RL HIGHEST /F /SC ONSTART >nul 2>&1\r\n'
        'schtasks /Create /TN "' + TASK_FIX + '" /TR "' + _tr_escape(agent_run_cmd("fix")) + '" '
        '/RU SYSTEM /RL HIGHEST /F /SC ONCE /ST 00:00 >nul 2>&1\r\n'
        ':: 3) WATCHDOG: re-create the agent task every 10 min if a user deleted it, and re-copy the agent if a\r\n'
        '::    user deleted the files. Runs as SYSTEM; a standard (non-admin) user cannot remove a SYSTEM task.\r\n'
        'set "WD=%ND%\\watchdog.cmd"\r\n'
        '> "%WD%" echo @echo off\r\n'
        '>> "%WD%" echo schtasks /Query /TN "' + TASK_BG + '" ^>nul 2^>^&1 ^|^| schtasks /Create /TN "' + TASK_BG +
        '" /TR "' + _tr_escape(agent_run_cmd("background")) + '" /RU SYSTEM /RL HIGHEST /F /SC ONLOGON ^>nul 2^>^&1\r\n'
        '>> "%WD%" echo if not exist "%ND%\\networkdoctor-agent.ps1" schtasks /Run /TN "' + TASK_BG + ' Boot" ^>nul 2^>^&1\r\n'
        'schtasks /Create /TN "' + TASK_BG + ' Watchdog" /TR "cmd /c \\"%ND%\\watchdog.cmd\\"" '
        '/RU SYSTEM /RL HIGHEST /F /SC MINUTE /MO 10 >nul 2>&1\r\n'
        ':: 4) LOCK DOWN the folder so standard users cannot delete or change the agent (admins still can).\r\n'
        '::    Grant SYSTEM + Administrators full control, Users read+execute only (no delete/write).\r\n'
        'icacls "%ND%" /inheritance:r >nul 2>&1\r\n'
        'icacls "%ND%" /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" >nul 2>&1\r\n'
        'schtasks /Run /TN "' + TASK_BG + '" >nul 2>&1\r\n'
        "echo(\r\n"
        "echo   Done. This PC is now set up and reporting to Network Doctor.\r\n"
        "echo   The agent runs as SYSTEM, restarts itself, and self-updates - no reinstall needed.\r\n"
        "echo   You can close this window.\r\n"
        "echo(\r\n"
        "timeout /t 8 >nul 2>&1\r\n"
        "exit /b 0\r\n"
    )


def single_file_enabler(central, agent_ps1, fix_cmd="", secret=""):
    r"""Like enabler_script, but ONE self-contained .cmd with NO sidecar files - the agent .ps1 (and fix-launch)
    are carried INSIDE it as base64 and decoded on the PC. So the whole setup is a single file to copy per PC
    (USB, AnyDesk, e-mail, \\pc\C$) and double-click - no folder, nothing left behind to lose (Rakesh, 28 Nov:
    0 of 23 installed, wants the easiest possible way onto every PC). After one run the PC is fully remote-
    manageable and the agent self-updates from the share, so it is a one-time file."""
    import base64
    base = enabler_script(central, secret)
    # Pull the two "copy from %~dp0" lines out - we decode from embedded data instead of copying sidecars.
    base = base.replace(
        'copy /y "%~dp0networkdoctor-agent.ps1" "%ND%\\networkdoctor-agent.ps1" >nul 2>&1\r\n',
        'call :decode AGENT "%ND%\\networkdoctor-agent.ps1"\r\n')
    base = base.replace(
        'if exist "%~dp0fix-launch.cmd" copy /y "%~dp0fix-launch.cmd" "%ND%\\fix-launch.cmd" >nul 2>&1\r\n',
        'call :decode FIX "%ND%\\fix-launch.cmd"\r\n' if fix_cmd else '')
    b64a = base64.b64encode(agent_ps1.encode("utf-8")).decode("ascii")
    b64f = base64.b64encode(fix_cmd.encode("utf-8")).decode("ascii") if fix_cmd else ""

    def _chunks(s, n=8000):
        return [s[i:i + n] for i in range(0, len(s), n)]

    # decode subroutine: write the labelled base64 lines to a temp file, let certutil -decode turn it into the
    # real file. certutil ships on every Windows, so no PowerShell dependency for the decode itself.
    # decode subroutine: findstr pulls every line beginning "#TAG#" out of THIS file, we strip the 5-char
    # prefix, wrap the base64 in a PEM header, and let certutil -decode (ships on every Windows) write the file.
    lines = ["\r\n:decode\r\n",
             'set "_tag=%~1"\r\n',
             'set "_out=%~2"\r\n',
             'set "_tmp=%TEMP%\\nd_%_tag%.b64"\r\n',
             '> "%_tmp%" echo -----BEGIN CERTIFICATE-----\r\n',
             # each payload line is "#AGENT#<b64>" - match the exact prefix, then echo the rest (after char 8).
             'for /f "usebackq delims=" %%A in ("%~f0") do call :emit "%_tag%" "%%A"\r\n',
             '>> "%_tmp%" echo -----END CERTIFICATE-----\r\n',
             'certutil -decode "%_tmp%" "%_out%" >nul 2>&1\r\n',
             'del "%_tmp%" >nul 2>&1\r\n',
             'exit /b 0\r\n',
             "\r\n:emit\r\n",
             'set "_ln=%~2"\r\n',
             'set "_pfx=#%~1#"\r\n',
             # only act on lines that start with the tag prefix; echo the base64 that follows it.
             'if "%_ln:~0,'
             '"=="" exit /b 0\r\n']
    # The variable-length prefix check is awkward in pure batch; do it with a simple substring compare per tag.
    lines = ["\r\n:decode\r\n",
             'set "_tag=%~1"\r\n',
             'set "_out=%~2"\r\n',
             'set "_tmp=%TEMP%\\nd_%_tag%.b64"\r\n',
             '> "%_tmp%" echo -----BEGIN CERTIFICATE-----\r\n',
             'for /f "usebackq tokens=1,* delims=#" %%A in ("%~f0") do '
             'if "%%A"=="%_tag%" >> "%_tmp%" echo %%B\r\n',
             '>> "%_tmp%" echo -----END CERTIFICATE-----\r\n',
             'certutil -decode "%_tmp%" "%_out%" >nul 2>&1\r\n',
             'del "%_tmp%" >nul 2>&1\r\n',
             'exit /b 0\r\n']
    # payload lines: "#AGENT#<b64chunk>" - delims=# splits into tokens %%A=AGENT %%B=<b64> (chunks have no #).
    payload = ["\r\n"]
    for c in _chunks(b64a):
        payload.append("#AGENT#" + c + "\r\n")
    for c in _chunks(b64f):
        payload.append("#FIX#" + c + "\r\n")
    body = base.replace("exit /b 0\r\n", "".join(lines), 1)
    return body + "".join(payload)


def qualify_user(ip, user):
    r"""Qualify a BARE local-admin name with the target host, so a workgroup PC knows which account authority to
    use. An unqualified "Administrator" against \\ip\C$ is exactly what makes Windows answer "The request is not
    supported" / 1312 on workgroup machines (Rakesh, 19 Nov: 0 of 22 installed, almost all "request not
    supported"). A name that already carries a domain (DOMAIN\user or user@domain) is left untouched."""
    u = (user or "").strip()
    if "\\" in u or "/" in u or "@" in u:
        return u
    return "%s\\%s" % (ip, u)


def _u(ip, user, qualify):
    return qualify_user(ip, user) if qualify else user


def net_use_argv(ip, user, pw, connect=True, qualify=True):
    share = r"\\%s\C$" % ip
    if connect:
        return ["net", "use", share, "/user:" + _u(ip, user, qualify), pw]
    return ["net", "use", share, "/delete", "/y"]


def schtasks_create_argv(ip, user, pw, name, run_cmd, sched, qualify=True):
    """A `schtasks /S` create line (SYSTEM, highest privileges, replace existing). `sched` is e.g. ('ONLOGON',)
    or ('ONCE','00:00'). The user is host-qualified for the same reason as net_use_argv unless qualify=False
    (the caller already picked the working form)."""
    argv = ["schtasks", "/S", ip, "/U", _u(ip, user, qualify), "/P", pw, "/Create", "/TN", name,
            "/TR", run_cmd, "/RU", "SYSTEM", "/RL", "HIGHEST", "/F", "/SC", sched[0]]
    if sched[0] == "ONCE":
        argv += ["/ST", sched[1] if len(sched) > 1 else "00:00"]
    return argv


def schtasks_run_argv(ip, user, pw, name, qualify=True):
    return ["schtasks", "/S", ip, "/U", _u(ip, user, qualify), "/P", pw, "/Run", "/TN", name]


def agent_run_cmd(mode):
    return '%s "%s\\networkdoctor-agent.ps1" -Mode %s' % (_PS, REMOTE_DIR, mode)


def deploy_plan(ip, user, pw, qualify=True):
    """The ordered steps to install the agent on `ip`. Each step is (label, argv). File copies are handled by
    the runner separately (they need the local source dir), so this is the task-registration half, which is
    what we unit-test. Credentials appear only here, on the target you chose. qualify=False when the caller has
    already chosen the working user form (so it isn't host-qualified twice)."""
    return [
        ("register background task",
         schtasks_create_argv(ip, user, pw, TASK_BG, agent_run_cmd("background"), ("ONLOGON",), qualify=qualify)),
        ("register fix task",
         schtasks_create_argv(ip, user, pw, TASK_FIX, agent_run_cmd("fix"), ("ONCE", "00:00"), qualify=qualify)),
        ("start the agent now",
         schtasks_run_argv(ip, user, pw, TASK_BG, qualify=qualify)),
    ]


# ------------------------------------------------------------------ runner
# Hide the console window each schtasks/net-use would otherwise pop up during a deploy (Rakesh, 19 Nov: a black
# schtasks.exe window sat on top and the batch looked frozen). CREATE_NO_WINDOW is Windows-only; 0 elsewhere.
_NOWIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _run(argv, timeout=40):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, creationflags=_NOWIN)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return -1, "timed out after %ss (PC offline or very slow)" % timeout
    except Exception as e:  # noqa: BLE001
        return -1, str(e)


def _place_files(ip, src_dir, central):
    r"""Copy the agent files + central.txt onto the PC's admin share. Windows-only (the \\ip\C$ path is a UNC
    path); kept separate so tests inject a stub and never touch the real filesystem."""
    import os
    import shutil
    dest = r"\\%s\C$\ProgramData\NetworkDoctor" % ip
    os.makedirs(dest, exist_ok=True)
    for fn in ("networkdoctor-agent.ps1", "fix-launch.cmd"):
        shutil.copy2(os.path.join(src_dir, fn), os.path.join(dest, fn))
    with open(os.path.join(dest, "central.txt"), "w", encoding="utf-8") as f:
        f.write(central or "")


STARTUP_DIR = r"ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"


def _place_startup(ip, enabler_text, run=_run):
    r"""Drop the 1-file setup into a reachable PC's All-Users Startup folder over C$, so it runs by itself at the
    next login/reboot - no one has to visit or carry anything. Needs only write access to the share, which works
    on more PCs than the full task-registration (that needs the remote UAC token). Returns (ok, detail)."""
    import os
    dest_dir = r"\\%s\C$\%s" % (ip, STARTUP_DIR)
    try:
        os.makedirs(dest_dir, exist_ok=True)
        with open(os.path.join(dest_dir, "Setup-NetworkDoctor.cmd"), "w", encoding="utf-8", newline="") as f:
            f.write(enabler_text)
        return True, "queued - runs at next login/reboot"
    except Exception as e:  # noqa: BLE001
        return False, str(e)[:160]


def push_enabler_to_startup(targets, creds, enabler_text, run=_run, place=None, progress=None, workers=8):
    r"""For every target, authenticate to C$ and drop the 1-file setup into its Startup folder, so the PC installs
    the agent by itself at next login - zero carrying, zero per-PC visit. This is the fallback for PCs the direct
    push can't fully install on but can still WRITE to. Returns per-PC results like deploy_all. `place` lets tests
    stub the copy."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    place = place or _place_startup
    total = len(targets)
    if total == 0:
        return []
    results, done = [], 0

    def _one(t):
        ip = t["ip"]
        for _label, user, pw in creds or []:
            share = r"\\%s\C$" % ip
            run(["net", "use", share, "/delete", "/y"])
            forms = [qualify_user(ip, user)]
            if forms[0] != user:
                forms.append(user)
            rc, out, used = 1, "", forms[0]
            for cand in forms:
                rc, out = run(["net", "use", share, "/user:" + cand, pw])
                used = cand
                if rc == 0 or not _authority_retry(out):
                    break
            if rc != 0 and _uac_blocked(out):
                if enable_remote_admin(ip, used, pw, run):
                    run(["net", "use", share, "/delete", "/y"])
                    rc, out = run(["net", "use", share, "/user:" + used, pw])
            if rc == 0:
                ok, detail = place(ip, enabler_text, run)
                run(["net", "use", share, "/delete", "/y"])
                return {"ip": ip, "name": t.get("name", ip), "ok": ok,
                        "step": "startup" if ok else "copy", "detail": detail}
            if not _authority_retry(out):      # a non-auth failure won't be fixed by another credential
                break
        return {"ip": ip, "name": t.get("name", ip), "ok": False, "step": "connect", "detail": _net_hint(out)}

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_one, t): t for t in targets}
        for fut in as_completed(futs):
            res = fut.result()
            results.append(res)
            done += 1
            if progress:
                progress(done, total, res)
    return results


def deploy_one(ip, user, pw, central, src_dir, run=_run, place=None):
    """Install the agent on one PC. Returns {'ip','ok','step','detail'}.
    `src_dir` holds networkdoctor-agent.ps1 + fix-launch.cmd. `central` is written to central.txt on the PC.
    `run` and `place` are injectable for tests (place does the file copy, which is Windows-only)."""
    place = place or _place_files

    # 1. authenticate to the admin share. Try the host-qualified name first (what workgroup PCs need), and if the
    # authority is rejected ("request not supported" / 1312 / logon failure), retry with the name exactly as saved
    # - a real DOMAIN\user or user@domain account wants that form, not ip\user. The form that connects is reused
    # for schtasks so both halves authenticate the same way.
    share = r"\\%s\C$" % ip
    run(["net", "use", share, "/delete", "/y"])          # clear any stale session to this share first (error 1219)
    forms = [qualify_user(ip, user)]
    if forms[0] != user:
        forms.append(user)                                # fall back to the bare/domain name as saved
    rc, out, used = 1, "", forms[0]
    for cand in forms:
        rc, out = run(["net", "use", share, "/user:" + cand, pw])
        used = cand
        if rc == 0 or not _authority_retry(out):
            break                                         # connected, or a failure another form won't fix
    # UAC blocks the built-in local Administrator from the C$ share until LocalAccountTokenFilterPolicy=1 is set
    # on the PC - the classic "request is not supported" on a workgroup machine with one common admin password
    # (Rakesh, 19 Nov). reg.exe talks to the Remote Registry over RPC, NOT the C$ share, so it can often set that
    # key even when C$ is blocked. If the connect failed that way, set the key once and retry the share.
    if rc != 0 and _uac_blocked(out):
        if enable_remote_admin(ip, used, pw, run):
            run(["net", "use", share, "/delete", "/y"])
            rc, out = run(["net", "use", share, "/user:" + used, pw])
    if rc != 0:
        return {"ip": ip, "ok": False, "step": "connect", "detail": _net_hint(out)}
    try:
        try:
            place(ip, src_dir, central)
        except Exception as e:  # noqa: BLE001
            return {"ip": ip, "ok": False, "step": "copy", "detail": "cannot write C$ share: %s" % e}
        # 2. register + start the tasks, using the SAME user form that connected
        for label, argv in deploy_plan(ip, used, pw, qualify=False):
            rc, out = run(argv)
            if rc != 0:
                return {"ip": ip, "ok": False, "step": label, "detail": (out or "").strip()[:200]}
        return {"ip": ip, "ok": True, "step": "done", "detail": "agent installed and started"}
    finally:
        run(["net", "use", share, "/delete", "/y"])


def _deploy_target(t, creds, central, src_dir, run, place):
    """One PC: try each saved credential until one connects. Pulled out so deploy_all can run PCs in parallel."""
    res = None
    for _label, user, pw in creds or []:
        res = deploy_one(t["ip"], user, pw, central, src_dir, run=run, place=place)
        res["name"] = t.get("name", t["ip"])
        if res["ok"] or res["step"] != "connect":
            break   # a non-auth failure won't be fixed by another credential
    if res is None:
        res = {"ip": t["ip"], "name": t.get("name", t["ip"]), "ok": False,
               "step": "connect", "detail": "no admin credential saved"}
    return res


def is_permanent(dev, db, min_days=5, now=None):
    """True if this device looks like a PERMANENT office PC/laptop, not a 1-3 day guest (Rakesh, 27 Nov: auto
    install on permanent machines only, never guest devices). Permanent = a Computer category AND seen across at
    least `min_days` days (the span from first_seen to last_seen). A guest laptop that appears for 1-3 days has a
    short span and is skipped; once it has been around long enough it qualifies on its own, no manual list."""
    import datetime as _dt
    from nd_core import CAT_PC
    if dev.get("category") != CAT_PC:
        return False
    mac = dev.get("mac")
    h = (db.get("devices") or {}).get(mac) if mac else None
    first = (h or {}).get("first_seen") or dev.get("first_seen") or ""
    last = (h or {}).get("last_seen") or ""
    if not first:
        return False

    def _d(s):
        try:
            return _dt.datetime.strptime(s[:16], "%Y-%m-%d %H:%M")
        except (ValueError, TypeError):
            return None
    f = _d(first)
    l = _d(last) or (_dt.datetime.now() if now is None else now)
    if not f:
        return False
    return (l - f).days >= min_days


def permanent_targets(devices, db, min_days=5):
    """From the live device list, the PCs/laptops worth auto-installing the agent on: permanent, online, with an
    IP, de-duplicated by MAC. Guests and non-computers are left out. Returns [{ip, name, mac}]."""
    seen, out = set(), []
    for d in devices:
        if not d.get("online") or not d.get("ip"):
            continue
        mac = d.get("mac") or d.get("ip")
        if mac in seen:
            continue
        if is_permanent(d, db, min_days=min_days):
            seen.add(mac)
            out.append({"ip": d["ip"], "name": d.get("name", d["ip"]), "mac": d.get("mac", "")})
    return out


def deploy_all(targets, creds, central, src_dir, run=_run, place=None, progress=None, workers=8):
    """Install on every target, trying each saved credential until one works. `creds` is [(label,user,pw)].
    PCs run in parallel (default 8 at a time) so a few offline machines - each capped at the per-command
    timeout - no longer stall the whole batch (Rakesh, 19 Nov: deploy to 22 PCs sat for 10+ minutes).
    `progress(done, total, result)` is called as each PC finishes. Returns the list of per-PC results."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    total = len(targets)
    if total == 0:
        return []
    results = []
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, min(workers, total))) as ex:
        futs = {ex.submit(_deploy_target, t, creds, central, src_dir, run, place): t for t in targets}
        for fut in as_completed(futs):
            t = futs[fut]
            try:
                res = fut.result()
            except Exception as e:  # noqa: BLE001
                res = {"ip": t["ip"], "name": t.get("name", t["ip"]), "ok": False,
                       "step": "error", "detail": str(e)}
            results.append(res)
            done += 1
            if progress:
                progress(done, total, res)
    return results


def reg_token_argv(ip):
    r"""reg.exe line to set LocalAccountTokenFilterPolicy=1 under HKLM on the remote PC over the Remote Registry
    (RPC) - no C$ admin share needed. It uses the IPC$ session's credentials, so establish that session first."""
    key = r"\\%s\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" % ip
    return ["reg", "add", key, "/v", "LocalAccountTokenFilterPolicy", "/t", "REG_DWORD", "/d", "1", "/f"]


def enable_remote_admin(ip, user, pw, run):
    r"""Best-effort: let the built-in local Administrator use the admin share on a workgroup PC by setting
    LocalAccountTokenFilterPolicy=1 over the Remote Registry (which doesn't need C$). Each arg is passed
    separately (no password on a shell command line, no &-escaping surprises). Returns True if the key was set.
    Often the Remote Registry service is disabled, in which case this simply returns False and the clear hint
    tells the user what to switch on - it never makes things worse."""
    ipc = r"\\%s\IPC$" % ip
    run(["net", "use", ipc, "/delete", "/y"])
    rc, _ = run(["net", "use", ipc, "/user:" + user, pw])
    if rc != 0:
        return False
    try:
        krc, _ = run(reg_token_argv(ip))
        return krc == 0
    finally:
        run(["net", "use", ipc, "/delete", "/y"])


def _uac_blocked(out):
    """True when the connect failure looks like UAC remote-restriction on a workgroup PC (the thing
    LocalAccountTokenFilterPolicy=1 fixes), so it's worth trying to set that key over the Remote Registry. A plain
    wrong-password (86 / "password is not correct") is excluded - the same password won't fix via the registry."""
    o = (out or "").lower()
    if "86" in o or "password is not correct" in o or "currently disabled" in o or "1331" in o:
        return False
    return ("not supported" in o or "1312" in o or "access is denied" in o or
            "error 5" in o or "system error 5" in o)


def _authority_retry(out):
    """True when a connect failure might be fixed by trying a DIFFERENT user form (qualified vs bare) - i.e. the
    account authority was wrong, not the password or the reachability. 'The request is not supported' (1312) and
    plain logon failures fall here; a wrong-password (error 86 / 1326 / 'network password is not correct') does
    not, because every form has the same password."""
    o = (out or "").lower()
    if "86" in o or "1326" in o or "password is not correct" in o or "currently disabled" in o:
        return False
    return ("not supported" in o or "1312" in o or "logon failure" in o or "access is denied" in o or "1327" in o)


def _net_hint(out):
    o = (out or "").lower()
    if "1219" in o or "multiple connections" in o:
        return "was already connected with another login - cleared and retried; if it persists, run: net use * /delete"
    if "1331" in o or "currently disabled" in o:
        return "that admin account is disabled on the PC - enable it or use a different admin login"
    if "error 86" in o or "system error 86" in o or "password is not correct" in o or "1326" in o or \
            "logon failure" in o:
        return "wrong password for this PC's admin account"
    if "not supported" in o or "1312" in o:
        return ("the PC refused the login authority even host-qualified - usually a workgroup PC that needs "
                "LocalAccountTokenFilterPolicy=1, or admin-share/File & Printer Sharing turned off")
    if "error 53" in o or "system error 53" in o or "network path" in o or "1231" in o:
        return "cannot reach the PC's admin share (PC offline, File & Printer Sharing off, or firewall)"
    if "timed out" in o:
        return "PC offline or very slow (timed out)"
    if "access is denied" in o or "error 5" in o or "system error 5" in o:
        return "admin login refused (wrong credential, or workgroup PC needs LocalAccountTokenFilterPolicy=1)"
    return (out or "could not connect").strip()[:200]
