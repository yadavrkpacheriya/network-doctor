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
SOURCE_FILES = ["NetworkDoctor.py", "nd_core.py", "nd_monitor.py", "nd_update.py", "nd_share.py"]
UA = {"User-Agent": "NetworkDoctor-updater", "Accept": "application/vnd.github+json"}


class UpdateError(Exception):
    pass


def parse_version(v):
    nums = re.findall(r"\d+", v or "")
    return tuple(int(x) for x in nums[:4]) or (0,)


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
        raise UpdateError(f"Could not reach GitHub ({e}).")
    tag = data.get("tag_name", "")
    if parse_version(tag) <= parse_version(current_version):
        return None
    assets = {a.get("name"): a for a in data.get("assets", [])}
    exe = assets.get("NetworkDoctor.exe")
    sha = assets.get("NetworkDoctor.exe.sha256")
    return {"version": tag.lstrip("v"), "tag": tag, "notes": (data.get("body") or "").strip(),
            "page": data.get("html_url") or RELEASES_PAGE,
            "exe_url": exe and exe.get("browser_download_url"), "exe_size": exe and exe.get("size"),
            "sha_url": sha and sha.get("browser_download_url"), "published": data.get("published_at", "")}


def _get(url, timeout=60):
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA["User-Agent"]}), timeout=timeout)


def download_exe(info, progress=lambda done, total: None):
    """Downloads and verifies the new exe. Returns the path of the verified file."""
    if not info.get("exe_url") or not info.get("sha_url"):
        raise UpdateError("This release has no NetworkDoctor.exe yet (it may still be building - try in a few minutes).")
    try:
        expected = _get(info["sha_url"], 30).read().decode("ascii", "replace").strip().split()[0].lower()
    except Exception as e:
        raise UpdateError(f"Could not download the checksum ({e}).")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise UpdateError("The published checksum is not valid - update cancelled for safety.")
    folder = os.path.dirname(sys.executable) if is_frozen() else tempfile.gettempdir()
    dest = os.path.join(folder, "NetworkDoctor.new.exe")
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


def apply_exe(new_path):
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
start "" "{exe}"
:end
del "%~f0"
"""
    with open(bat, "w", encoding="ascii", errors="replace") as f:
        f.write(script)
    flags = 0x08000000 | 0x00000008  # CREATE_NO_WINDOW | DETACHED_PROCESS
    subprocess.Popen(["cmd", "/c", bat], creationflags=flags, close_fds=True)


def update_sources(info, folder):
    """Source (.py) install: downloads the files of the new version tag, keeping .bak copies."""
    new = {}
    for name in SOURCE_FILES:
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


def restart_sources(folder):
    subprocess.Popen([sys.executable, os.path.join(folder, "NetworkDoctor.py")], cwd=folder, close_fds=True)


def cleanup_leftovers():
    """Removes a half-downloaded update file left from an earlier attempt."""
    if is_frozen():
        _rm(os.path.join(os.path.dirname(sys.executable), "NetworkDoctor.new.exe"))


def _rm(p):
    try:
        os.remove(p)
    except OSError:
        pass
