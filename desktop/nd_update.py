# -*- coding: utf-8 -*-
"""
Network Doctor - online updates from GitHub Releases (no server needed).

How it works
  * GitHub builds NetworkDoctor.exe for every new version and publishes it as a Release,
    together with NetworkDoctor.exe.sha256.
  * The app asks the public GitHub API once a day: "what is the latest release?"
  * If it is newer, the user is asked. The new exe is downloaded next to the old one, its SHA-256
    checksum is verified, then a tiny helper waits for the app to close, swaps the files and
    starts the new version. Nothing is installed and no server is involved.
  * When running from the .py source files instead of the exe, the source files are updated.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request

REPO = "yadavrkpacheriya/network-doctor"
API_LATEST = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPO}/releases/latest"
SOURCE_FILES = ["NetworkDoctor.py", "nd_core.py", "nd_monitor.py", "nd_update.py", "nd_share.py", "nd_tools.py", "nd_tabs.py", "nd_net.py", "nd_toolstab.py", "nd_snmp.py", "nd_plugins.py", "nd_linux.py", "nd_dnsfilter.py", "nd_routeros.py", "nd_usage.py", "nd_home.py", "nd_slow.py", "nd_smbinfo.py", "nd_alerts.py", "nd_auth.py", "nd_defense.py", "nd_vuln.py", "nd_capture.py", "nd_expose.py", "nd_protab.py"]
UA = {"User-Agent": "NetworkDoctor-updater", "Accept": "application/vnd.github+json"}
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")
# the file each kind of computer downloads from a release
ASSET = "NetworkDoctor-macOS.zip" if IS_MAC else ("NetworkDoctor-Linux" if IS_LINUX else "NetworkDoctor.exe")


class UpdateError(Exception):
    pass


def parse_version(v):
    nums = re.findall(r"\d+", v or "")
    return tuple(int(x) for x in nums[:4]) or (0,)


DAILY_HOUR = 15  # automatic update check every day at 15:00 (local time)


def last_daily(now=None, hour=DAILY_HOUR):
    """Epoch seconds of the most recent hh:00 that has already passed (today or yesterday)."""
    now = time.time() if now is None else now
    lt = time.localtime(now)
    t = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, hour, 0, 0, 0, 0, -1))
    if t > now:
        t = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday - 1, hour, 0, 0, 0, 0, -1))
    return t


def daily_due(last_check, now=None, hour=DAILY_HOUR):
    """True when no check happened since the most recent 15:00 (also catches a PC that was off at 15:00)."""
    return (last_check or 0) < last_daily(now, hour)


def is_frozen():
    return bool(getattr(sys, "frozen", False))


def check(current_version, timeout=15):
    """Returns info dict if a newer release exists, None if up to date. Raises UpdateError on problems."""
    try:
        req = urllib.request.Request(API_LATEST, headers=UA)
        data = json.loads(urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise UpdateError("No version has been published on GitHub yet.")
        if e.code == 403:
            raise UpdateError("GitHub is limiting requests right now - try again in an hour.")
        raise UpdateError(f"GitHub answered {e.code}.")
    except Exception as e:
        if "getaddrinfo" in str(e) or "11001" in str(e) or "Name or service" in str(e):
            raise UpdateError("Could not reach GitHub: this PC cannot look up internet names (DNS), and the public "
                              "DNS servers 1.1.1.1 / 8.8.8.8 did not answer either. Check that this PC has internet "
                              "and that its DNS server (ipconfig /all) is the office router - a second Wi-Fi router "
                              "handing out its own DNS causes this. Network Doctor tries again in 6 hours.")
        raise UpdateError(f"Could not reach GitHub ({e}).")
    tag = data.get("tag_name", "")
    if parse_version(tag) <= parse_version(current_version):
        return None
    assets = {a.get("name"): a for a in data.get("assets", [])}
    exe = assets.get(ASSET)
    sha = assets.get(ASSET + ".sha256")
    return {"version": tag.lstrip("v"), "tag": tag, "notes": (data.get("body") or "").strip(),
            "page": data.get("html_url") or RELEASES_PAGE,
            "exe_url": exe and exe.get("browser_download_url"), "exe_size": exe and exe.get("size"),
            "sha_url": sha and sha.get("browser_download_url"), "published": data.get("published_at", "")}


def _get(url, timeout=60):
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA["User-Agent"]}), timeout=timeout)


def download_exe(info, progress=lambda done, total: None):
    """Downloads and verifies the new exe. Returns the path of the verified file."""
    if not info.get("exe_url") or not info.get("sha_url"):
        raise UpdateError(f"This release has no {ASSET} yet (it may still be building - try in a few minutes).")
    try:
        expected = _get(info["sha_url"], 30).read().decode("ascii", "replace").strip().split()[0].lower()
    except Exception as e:
        raise UpdateError(f"Could not download the checksum ({e}).")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise UpdateError("The published checksum is not valid - update cancelled for safety.")
    if IS_MAC:
        folder = tempfile.gettempdir()
        dest = os.path.join(folder, "NetworkDoctor-update.zip")
    else:
        folder = os.path.dirname(sys.executable) if is_frozen() else tempfile.gettempdir()
        dest = os.path.join(folder, "NetworkDoctor.new" if IS_LINUX else "NetworkDoctor.new.exe")
    h = hashlib.sha256()
    total = info.get("exe_size") or 0
    done = 0
    try:
        with _get(info["exe_url"], 60) as r, open(dest, "wb") as f:
            while True:
                chunk = r.read(256 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                h.update(chunk)
                done += len(chunk)
                progress(done, total)
    except Exception as e:
        _rm(dest)
        raise UpdateError(f"Download failed ({e}).")
    if total and done != total:
        _rm(dest)
        raise UpdateError("Download was incomplete - update cancelled.")
    if h.hexdigest() != expected:
        _rm(dest)
        raise UpdateError("Downloaded file does not match the published checksum - update cancelled for safety.")
    return dest


def mac_bundle():
    """/Applications/Network Doctor.app when running from a built Mac app, else None."""
    p = os.path.abspath(sys.executable)
    for _ in range(4):
        p = os.path.dirname(p)
        if p.endswith(".app"):
            return p
    return None


def apply_mac(zip_path, args=()):
    """Unpacks the verified zip and starts a helper that swaps the .app after this process exits."""
    import zipfile
    bundle = mac_bundle()
    if not bundle:
        raise UpdateError("Could not find the Network Doctor app bundle to replace.")
    work = tempfile.mkdtemp(prefix="nd_update_")
    # ditto keeps the app's permissions and code-signature layout; zipfile is the fallback
    try:
        unpacked = subprocess.call(["ditto", "-x", "-k", zip_path, work]) == 0
    except OSError:
        unpacked = False
    if not unpacked:
        with zipfile.ZipFile(zip_path) as z:
            z.extractall(work)
        for root, _, files in os.walk(work):  # zipfile loses the 'executable' bit
            if os.sep + "MacOS" in root:
                for f in files:
                    os.chmod(os.path.join(root, f), 0o755)
    apps = [os.path.join(work, x) for x in os.listdir(work) if x.endswith(".app")]
    if not apps:
        raise UpdateError("The downloaded update does not contain the app.")
    new_app = apps[0]
    script = os.path.join(work, "swap.sh")
    with open(script, "w") as f:
        f.write(f"""#!/bin/sh
while kill -0 {os.getpid()} 2>/dev/null; do sleep 1; done
rm -rf "{bundle}.old"
mv "{bundle}" "{bundle}.old" && mv "{new_app}" "{bundle}" && rm -rf "{bundle}.old"
[ -d "{bundle}" ] || mv "{bundle}.old" "{bundle}"
open "{bundle}"{(" --args " + " ".join(args)) if args else ""}
rm -rf "{work}" "{zip_path}"
""")
    os.chmod(script, 0o755)
    subprocess.Popen(["/bin/sh", script], start_new_session=True, close_fds=True, env=clean_env())


def clean_env():
    """Environment for starting a NEW copy of Network Doctor. A PyInstaller one-file exe passes private _PYI_* /
    _MEIPASS* variables to the copy it unpacks; a fresh start that inherits them takes itself for that copy, looks
    for its parent process - which has already closed - and stops with "Security validation failure: invalid
    originating onefile parent process (PID not found)". Remove them and tell PyInstaller to start fresh."""
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("_PYI", "_MEIPASS"))}
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    return env


def apply_update(path, args=()):
    """Platform-independent: replace the running app with the verified download and start it again with <args>.
    Caller must exit."""
    if IS_MAC:
        apply_mac(path, args)
    elif IS_LINUX:
        apply_linux(path, args)
    else:
        apply_exe(path, args)


def apply_linux(new_path, args=()):
    """Linux lets a running program's file be replaced: swap it in, then start the new one. Caller must exit."""
    exe = sys.executable
    try:
        os.chmod(new_path, 0o755)
        os.replace(new_path, exe)
    except OSError as e:
        _rm(new_path)
        raise UpdateError(f"Could not replace {exe} ({e}). Move Network Doctor to a folder you can write to.")
    subprocess.Popen([exe, *args], start_new_session=True, close_fds=True, env=clean_env())


def apply_exe(new_path, args=()):
    """Starts a helper that swaps the exe after this process exits, then restarts it. Caller must exit."""
    exe = sys.executable
    bat = os.path.join(tempfile.gettempdir(), f"nd_update_{int(time.time())}.cmd")
    script = f"""@echo off
set n=0
:wait
ping -n 2 127.0.0.1 >nul
move /y "{new_path}" "{exe}" >nul 2>&1 && goto done
set /a n+=1
if %n% lss 40 goto wait
echo Network Doctor could not replace "{exe}" - it may still be open. > "%TEMP%\\NetworkDoctor_update_failed.txt"
goto end
:done
set PYINSTALLER_RESET_ENVIRONMENT=1
start "" "{exe}" {" ".join(args)}
:end
del "%~f0"
"""
    with open(bat, "w", encoding="ascii", errors="replace") as f:
        f.write(script)
    flags = 0x08000000 | 0x00000008  # CREATE_NO_WINDOW | DETACHED_PROCESS
    subprocess.Popen(["cmd", "/c", bat], creationflags=flags, close_fds=True, env=clean_env())


def update_sources(info, folder):
    """Source (.py) install: downloads the files of the new version tag, keeping .bak copies."""
    new = {}
    names = list(SOURCE_FILES)
    try:  # newer versions list their own files, so files added later are fetched too
        lst = _get(f"https://raw.githubusercontent.com/{REPO}/{info['tag']}/desktop/SOURCE_FILES.txt", 20).read()
        extra = [x.strip() for x in lst.decode("utf-8", "replace").splitlines()
                 if x.strip().endswith(".py") and "/" not in x and "\\" not in x]
        names = list(dict.fromkeys(names + extra))
    except Exception:
        pass
    for name in names:
        url = f"https://raw.githubusercontent.com/{REPO}/{info['tag']}/desktop/{name}"
        try:
            new[name] = _get(url, 30).read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue  # file not part of that version
            raise UpdateError(f"Could not download {name} ({e}).")
        except Exception as e:
            raise UpdateError(f"Could not download {name} ({e}).")
        if not new[name].startswith((b"#", b"\xef\xbb\xbf#", b'"""', b"# -*-")) or b"\x00" in new[name]:
            raise UpdateError(f"{name} from GitHub does not look like a Python file - update cancelled.")
    if "NetworkDoctor.py" not in new:
        raise UpdateError("The new version's files were not found on GitHub.")
    for name, data in new.items():
        path = os.path.join(folder, name)
        if os.path.exists(path):
            try:
                os.replace(path, path + ".bak")
            except OSError:
                pass
        with open(path, "wb") as f:
            f.write(data)


def restart_sources(folder, args=()):
    subprocess.Popen([sys.executable, os.path.join(folder, "NetworkDoctor.py"), *args], cwd=folder, close_fds=True,
                     env=clean_env())


def cleanup_leftovers():
    """Removes a half-downloaded update file left from an earlier attempt."""
    if is_frozen():
        _rm(os.path.join(os.path.dirname(sys.executable), "NetworkDoctor.new" if IS_LINUX else "NetworkDoctor.new.exe"))


def _rm(p):
    try:
        os.remove(p)
    except OSError:
        pass
