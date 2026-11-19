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
