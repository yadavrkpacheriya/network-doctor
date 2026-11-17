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


def net_use_argv(ip, user, pw, connect=True):
    share = r"\\%s\C$" % ip
    if connect:
        return ["net", "use", share, "/user:" + user, pw]
    return ["net", "use", share, "/delete", "/y"]


def schtasks_create_argv(ip, user, pw, name, run_cmd, sched):
    """A `schtasks /S` create line (SYSTEM, highest privileges, replace existing). `sched` is e.g. ('ONLOGON',)
    or ('ONCE','00:00')."""
    argv = ["schtasks", "/S", ip, "/U", user, "/P", pw, "/Create", "/TN", name,
            "/TR", run_cmd, "/RU", "SYSTEM", "/RL", "HIGHEST", "/F", "/SC", sched[0]]
    if sched[0] == "ONCE":
        argv += ["/ST", sched[1] if len(sched) > 1 else "00:00"]
    return argv


def schtasks_run_argv(ip, user, pw, name):
    return ["schtasks", "/S", ip, "/U", user, "/P", pw, "/Run", "/TN", name]


def agent_run_cmd(mode):
    return '%s "%s\\networkdoctor-agent.ps1" -Mode %s' % (_PS, REMOTE_DIR, mode)


def deploy_plan(ip, user, pw):
    """The ordered steps to install the agent on `ip`. Each step is (label, argv). File copies are handled by
    the runner separately (they need the local source dir), so this is the task-registration half, which is
    what we unit-test. Credentials appear only here, on the target you chose."""
    return [
        ("register background task",
         schtasks_create_argv(ip, user, pw, TASK_BG, agent_run_cmd("background"), ("ONLOGON",))),
        ("register fix task",
         schtasks_create_argv(ip, user, pw, TASK_FIX, agent_run_cmd("fix"), ("ONCE", "00:00"))),
        ("start the agent now",
         schtasks_run_argv(ip, user, pw, TASK_BG)),
    ]


# ------------------------------------------------------------------ runner
def _run(argv, timeout=40):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:  # noqa: BLE001
        return -1, str(e)


def deploy_one(ip, user, pw, central, src_dir, run=_run, copy=None):
    """Install the agent on one PC. Returns {'ip','ok','step','detail'}.
    `src_dir` holds networkdoctor-agent.ps1 + fix-launch.cmd. `central` is the share path to write to
    central.txt. `run`/`copy` are injectable for tests."""
    import os
    import shutil
    copy = copy or (lambda s, d: shutil.copy2(s, d))

    # 1. authenticate to the admin share
    rc, out = run(net_use_argv(ip, user, pw, True))
    if rc != 0:
        return {"ip": ip, "ok": False, "step": "connect", "detail": _net_hint(out)}
    try:
        dest = r"\\%s\C$\ProgramData\NetworkDoctor" % ip
        try:
            os.makedirs(dest, exist_ok=True)
            for fn in ("networkdoctor-agent.ps1", "fix-launch.cmd"):
                copy(os.path.join(src_dir, fn), os.path.join(dest, fn))
            with open(os.path.join(dest, "central.txt"), "w", encoding="utf-8") as f:
                f.write(central or "")
        except Exception as e:  # noqa: BLE001
            return {"ip": ip, "ok": False, "step": "copy", "detail": "cannot write C$ share: %s" % e}
        # 2. register + start the tasks
        for label, argv in deploy_plan(ip, user, pw):
            rc, out = run(argv)
            if rc != 0:
                return {"ip": ip, "ok": False, "step": label, "detail": (out or "").strip()[:200]}
        return {"ip": ip, "ok": True, "step": "done", "detail": "agent installed and started"}
    finally:
        run(net_use_argv(ip, user, pw, False))


def deploy_all(targets, creds, central, src_dir, run=_run, copy=None, progress=None):
    """Install on every target, trying each saved credential until one works. `creds` is [(label,user,pw)].
    `progress(done, total, result)` is called after each PC. Returns the list of per-PC results."""
    results = []
    total = len(targets)
    for i, t in enumerate(targets, 1):
        res = None
        for _label, user, pw in creds or []:
            res = deploy_one(t["ip"], user, pw, central, src_dir, run=run, copy=copy)
            res["name"] = t.get("name", t["ip"])
            if res["ok"] or res["step"] != "connect":
                break   # a non-auth failure won't be fixed by another credential
        if res is None:
            res = {"ip": t["ip"], "name": t.get("name", t["ip"]), "ok": False,
                   "step": "connect", "detail": "no admin credential saved"}
        results.append(res)
        if progress:
            progress(i, total, res)
    return results


def _net_hint(out):
    o = (out or "").lower()
    if "1219" in o or "multiple connections" in o:
        return "already connected with other credentials - run: net use * /delete"
    if "53" in o or "network path" in o:
        return "cannot reach the PC's admin share (File & Printer Sharing off, or firewall)"
    if "5" in o or "access is denied" in o or "1326" in o or "logon failure" in o:
        return "admin login refused (wrong credential, or workgroup PC needs LocalAccountTokenFilterPolicy=1)"
    return (out or "could not connect").strip()[:200]
