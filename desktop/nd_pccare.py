# -*- coding: utf-8 -*-
"""
Network Doctor - page "PC Care" (This PC & Wi-Fi): repair, clean-up and health checks for THIS Windows PC -
slow / hanging PC, blue screens, C: drive clean-up, Windows + driver updates, printer sharing, RAM, security.

It never touches the router or any other device: every action runs on this PC only, as one PowerShell run of
the script in nd_pcengine.py. Each run makes a Windows restore point first and logs every setting it changes
in an undo folder (<drive>:\\PCCare_Backup). Nothing here asks questions while it runs; the two options are
tick-boxes. Windows only, and it needs Administrator.
"""
import os
import queue
import subprocess
import tempfile
import threading

try:  # the rules below are tested without a screen
    import tkinter as tk
    from tkinter import ttk
except ImportError:  # pragma: no cover
    tk = ttk = None

import nd_core as core
import nd_pcengine

# (choice the engine understands, button text, what it does)
ACTIONS = (
    ("A", "RUN ALL repairs", "Scan, updates, clean-up, crash repair, speed fix, PC network, printer, RAM, security. "
                             "30-120 minutes."),
    ("1", "Scan and report", "Read-only. Finds why this PC is slow, hangs or crashes."),
    ("2", "Blue screen and crash repair", "Repairs Windows system files, checks the disk, restarts broken devices."),
    ("3", "Slow PC and hang fix", "Startup apps, power plan, Fast Startup, page file, failed services."),
    ("4", "C: drive clean-up", "Temp files, caches, old Windows files; writes a storage report."),
    ("5", "Apps and drivers", "Windows and driver updates, broken Store apps, old driver versions."),
    ("6", "This PC's network repair", "Tests gateway / internet / DNS from this PC and repairs what failed."),
    ("7", "Printer and sharing repair", "Print spooler, stuck jobs, sharing services and firewall rules."),
    ("8", "RAM check", "Installed memory, free slots, biggest memory users, leaks."),
    ("8.1", "Schedule a RAM hardware test", "Windows Memory Diagnostic runs at the next restart."),
    ("10", "Security check", "Antivirus state, Defender, firewall. Quick scan when Defender is the antivirus."),
    ("9.2", "Files by category (all drives)", "Report only: what kind of files fill each drive."),
)
CHOICES = tuple(a[0] for a in ACTIONS)
# engine colour name -> text tag
COLOURS = {"Red": "fail", "Yellow": "warn", "Green": "pass", "Cyan": "head", "White": "bold", "DarkGray": "dim"}
REPORTS_DIR = "PCCare_Reports"  # on the Desktop, written by the engine


def powershell_exe():
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0",
                        "powershell.exe")


def build_command(script, choice, startup=True, winget=False):
    """The one PowerShell run for an action. Raises ValueError for a choice this page does not offer."""
    if choice not in CHOICES:
        raise ValueError(f"unknown PC Care action: {choice!r}")
    return [powershell_exe(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script,
            "-Choice", choice, "-OptStartup", "1" if startup else "0", "-OptWinget", "1" if winget else "0"]


def parse_line(raw):
    """One engine output line -> (tag, text). Engine lines look like '@@Colour@@text'; anything else (output of
    DISM, sfc, winget...) is shown as it is. A progress line redrawn with \\r keeps only its last state."""
    line = raw.rstrip("\r\n").lstrip("\ufeff")
    if "\r" in line:
        line = line.rsplit("\r", 1)[1]
    if line.startswith("@@"):
        end = line.find("@@", 2)
        if end != -1:
            return COLOURS.get(line[2:end], ""), line[end + 2:]
    return "", line


def lock_down(folder):
    """Only Administrators and SYSTEM may touch the folder the script is written to: it runs elevated, so a
    program without admin rights must not be able to swap it between writing and running."""
    r = subprocess.run(["icacls", folder, "/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F",
                        "*S-1-5-18:(OI)(CI)F"], capture_output=True, stdin=subprocess.DEVNULL,
                       creationflags=0x08000000)
    if r.returncode != 0:
        raise OSError("could not protect the working folder: " + (r.stdout or r.stderr or b"").decode(errors="replace"))


def write_engine(folder=None, lock=True):
    """Write the engine script into a new private folder and return (folder, script path)."""
    folder = folder or tempfile.mkdtemp(prefix="nd_pccare_")
    if lock and core.IS_WIN:
        lock_down(folder)
    path = os.path.join(folder, "pccare_engine.ps1")
    with open(path, "w", encoding="ascii", newline="\r\n") as f:
        f.write(nd_pcengine.ENGINE)
    return folder, path


def desktop_folder():
    """The user's Desktop as Windows reports it (it can be redirected, e.g. into OneDrive)."""
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(260)
        if ctypes.windll.shell32.SHGetFolderPathW(None, 0x10, None, 0, buf) == 0 and buf.value:
            return buf.value
    except Exception:
        pass
    return os.path.join(os.path.expanduser("~"), "Desktop")


def reports_folder():
    return os.path.join(desktop_folder(), REPORTS_DIR)


class PCCarePage:
    def __init__(self, app, parent):
        self.app = app
        self.proc = None
        self.q = queue.Queue()
        self.buttons = []

        if not core.IS_WIN:
            ttk.Label(parent, text="PC Care repairs a Windows PC, so it is only available on Windows.",
                      padding=20).pack(anchor="w")
            return

        ttk.Label(parent, text="Repairs and cleans THIS PC only - the router and other devices are never touched. "
                               "Every repair makes a Windows restore point first and logs each setting it changes "
                               "in <drive>:\\PCCare_Backup (UNDO_SETTINGS.bat inside). Actions start at once and "
                               "ask no questions.", wraplength=1100, foreground="#344054",
                  justify="left").pack(anchor="w", pady=(0, 6))

        self.var_admin = tk.StringVar()
        top = ttk.Frame(parent)
        top.pack(fill="x", pady=(0, 6))
        self.l_admin = ttk.Label(top, textvariable=self.var_admin, foreground="#b42318")
        self.l_admin.pack(side="left")
        self.b_admin = ttk.Button(top, text="Restart as Administrator", command=self.app.elevate)

        body = ttk.Frame(parent)
        body.pack(fill="both", expand=True)
        left = ttk.Frame(body)
        left.pack(side="left", fill="y", padx=(0, 10))

        opt = ttk.LabelFrame(left, text="Options (RUN ALL, Slow PC fix, Apps and drivers)", padding=6)
        opt.pack(fill="x", pady=(0, 6))
        self.var_startup = tk.BooleanVar(value=True)
        self.var_winget = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt, text="Switch off common non-essential startup apps",
                        variable=self.var_startup).pack(anchor="w")
        ttk.Checkbutton(opt, text="Update ALL apps with winget (not on ERP / fixed-version PCs)",
                        variable=self.var_winget).pack(anchor="w")

        for choice, text, tip in ACTIONS:
            b = ttk.Button(left, text=text, width=40, command=lambda c=choice, t=text: self.start(c, t))
            b.pack(fill="x", pady=1)
            self.buttons.append(b)
            if choice == "A":
                ttk.Label(left, text=tip, foreground="#667085", wraplength=300, justify="left").pack(anchor="w",
                                                                                                    pady=(0, 6))
        low = ttk.Frame(left)
        low.pack(fill="x", pady=(8, 0))
        self.b_stop = ttk.Button(low, text="Stop", command=self.stop, state="disabled")
        self.b_stop.pack(side="left")
        ttk.Button(low, text="Open reports folder", command=self.open_reports).pack(side="left", padx=6)

        right = ttk.Frame(body)
        right.pack(side="left", fill="both", expand=True)
        self.var_state = tk.StringVar(value="Ready. Scan and report is the best first step - it changes nothing.")
        ttk.Label(right, textvariable=self.var_state, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        sb = ttk.Scrollbar(right)
        sb.pack(side="right", fill="y")
        self.txt = tk.Text(right, wrap="none", height=20, font=("Consolas", 10), state="disabled",
                           background="#101828", foreground="#e4e7ec", yscrollcommand=sb.set)
        self.txt.pack(fill="both", expand=True)
        sb.configure(command=self.txt.yview)
        for tag, col in (("fail", "#f97066"), ("warn", "#fdb022"), ("pass", "#6ce9a6"), ("head", "#53b1fd"),
                         ("bold", "#ffffff"), ("dim", "#98a2b3")):
            self.txt.tag_configure(tag, foreground=col)
        self._admin_state()

    # ------------------------------------------------------------------ state
    def _admin_state(self):
        admin = core.is_admin()
        if admin:
            self.var_admin.set("")
            self.b_admin.pack_forget()
        else:
            self.var_admin.set("PC Care needs Administrator rights to scan and repair this PC.")
            self.b_admin.pack(side="left", padx=8)
        self._buttons(admin and self.proc is None)
        return admin

    def _buttons(self, on):
        for b in self.buttons:
            b.configure(state="normal" if on else "disabled")
        self.b_stop.configure(state="normal" if self.proc is not None else "disabled")

    def _append(self, tag, text):
        self.txt.configure(state="normal")
        self.txt.insert("end", text + "\n", (tag,) if tag else ())
        self.txt.see("end")
        self.txt.configure(state="disabled")

    # ------------------------------------------------------------------ run one action
    def start(self, choice, text):
        if self.proc is not None or not self._admin_state():
            return
        try:
            folder, script = write_engine()
            cmd = build_command(script, choice, self.var_startup.get(), self.var_winget.get())
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                         stdin=subprocess.DEVNULL, creationflags=0x08000000)
        except Exception as e:
            self.proc = None
            self._append("fail", f"Could not start: {e}")
            return
        self._append("bold", f"--- {text} ---")
        self.var_state.set(f"Running: {text} ...   (the other buttons unlock when it finishes)")
        self._buttons(False)
        threading.Thread(target=self._reader, args=(self.proc, folder), daemon=True).start()
        self.txt.after(150, self._pump)

    def _reader(self, proc, folder):
        try:
            for raw in iter(proc.stdout.readline, b""):
                self.q.put(parse_line(raw.decode("utf-8", errors="replace")))
        except Exception as e:  # the pipe closed under us (Stop)
            self.q.put(("dim", f"(output ended: {e})"))
        code = proc.wait()
        try:
            for name in os.listdir(folder):
                os.remove(os.path.join(folder, name))
            os.rmdir(folder)
        except OSError:
            pass
        self.q.put(("done", code))

    def _pump(self):
        done = None
        try:
            for _ in range(400):
                tag, text = self.q.get_nowait()
                if tag == "done":
                    done = text
                    break
                self._append(tag, text)
        except queue.Empty:
            pass
        if done is None:
            self.txt.after(150, self._pump)
            return
        self.proc = None
        if done == 0:
            self.var_state.set("Finished. Restart the PC after repairs so every fix takes effect.")
        else:
            self._append("warn", f"The action ended early (code {done}).")
            self.var_state.set("Stopped or failed - see the log.")
        self._admin_state()

    def stop(self):
        p = self.proc
        if p is None:
            return
        self._append("warn", "Stopping...")
        try:  # /T: also the tool it started (DISM, sfc, winget...)
            subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True,
                           stdin=subprocess.DEVNULL, creationflags=0x08000000)
        except Exception:
            p.kill()

    def open_reports(self):
        path = reports_folder()
        os.makedirs(path, exist_ok=True)
        try:
            os.startfile(path)
        except Exception as e:
            self._append("warn", f"Could not open {path}: {e}")

    def refresh(self):
        if core.IS_WIN:
            self._admin_state()
