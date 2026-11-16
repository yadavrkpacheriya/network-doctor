# Network Doctor — Audit & Repairs Log (brain's long-term memory of bugs → fixes)

Append-only. Every bug found in a line-by-line audit is recorded here with its **symptom → root
cause → permanent repair → version**, so a fix is never lost and the next audit starts from here
instead of re-discovering the same thing. Newest first.

Format per entry:
- **Symptom** — what the user/app saw.
- **Root cause** — the real reason.
- **Repair** — the permanent fix (not a patch).
- **Prevents** — the recurring class it kills.

---

## 2026-11-16 — Full Windows audit (v3.77.0 – v3.79.0)

### R-005 · License file written non-atomically
- **Symptom:** (latent) a crash/collision while saving the Pro license could leave a torn file,
  silently dropping the user's activation back to free.
- **Root cause:** `nd_license.save_license` wrote the license with a plain `open(...,"w")`.
- **Repair:** Atomic write (temp + `os.replace`), same as every other persistent file.
- **Prevents:** The "lost Pro license for no reason" case.

### Audit pass — classes checked across all 40 modules (33k lines), result
- **Thread-safety (UI/settings off the main thread):** CLEAN. Only the `firewall` startup race
  (R-002) existed; fixed. All tab-module worker threads marshal UI via `q.put`/`after`.
- **File-corruption (non-atomic writes):** every non-regenerable persistent file (device DB, auth,
  alert log, config backups, settings, license) is now atomic. Two regenerable caches (threat feeds,
  DNS blocklist) left as plain writes on purpose — a torn file there just re-downloads, harmless.
- **RouterOS command paths:** full-path commands, no WinBox-context (bare-verb) syntax that fails
  over the API. Bare-verb strings found were D-Link switch-console CLI / a Windows batch `set`, not
  RouterOS.
- **Static:** 0 compile failures, pyflakes clean (cosmetic f-strings only), no broken
  `command=self.X` handlers, no undefined names, no mutable default arguments.



### R-004 · IP conflict kept re-appearing; user expected the brain to auto-fix it
- **Symptom:** "Two devices use the same IP" alert recurred; user thought it should already be
  auto-fixed and auto-marked done.
- **Root cause:** NOT a bug — a real live conflict (two physical cameras both set to the same IP).
  The auto-fix (`_auto_fix_ip_conflict`) and the auto-clear-on-resolve (`_evaluate`) both already
  exist, but the auto-fix only runs when exactly one conflicting device is tagged "Default device
  for its IP" (it must never guess which device to keep, to avoid dropping a camera off the NVR).
  The dialog never told the user that tagging one device unlocks the automatic fix — a discoverability
  gap, not a logic bug.
- **Repair:** The IP-conflict troubleshoot text and steps now explicitly tell the user to tag the
  keeper device as "Default device for its IP" so every future repeat fixes itself and clears its
  own alert.
- **Prevents:** User confusion + manual re-fixing of a conflict the app can handle once told the
  keeper. The never-guess safety rule stays intact.

### R-003 · Settings wiped themselves overnight ("a new bug every day with no update")
- **Symptom:** Tags, camera logins, whitelist, ignored problems, SNMP community occasionally all
  gone after a restart, with no new version installed. Problems/alerts reappeared as if nothing was
  ever fixed.
- **Root cause:** Two faults compounding. (1) `settings.json` was written with a plain
  `open(...,"w")` + `json.dump` — not atomic, so a crash or a colliding writer could leave a
  truncated/half-written file. (2) The loader caught *all* errors and fell back to an empty dict
  `{}`, silently wiping every saved setting instead of recovering.
- **Repair:** Atomic save — dump to `settings.json.tmp`, `fsync`, rotate the old file to
  `settings.json.bak`, then `os.replace()` the temp in (atomic on Windows + POSIX). Loader now
  recovers from `.bak` before ever falling back to `{}`, and rejects non-dict JSON.
- **Prevents:** The entire "state silently resets itself" class — no reader or writer can ever see a
  torn file again, and a bad file self-heals from backup.

### R-002 · settings.json write race from a background thread
- **Symptom:** Rare, hard-to-reproduce settings corruption (feeds into R-003).
- **Root cause:** `firewall(quiet=True)` runs on a start-up background thread (NetworkDoctor.py
  ~line 1360) and called `_save_settings()` directly. `_save_settings` has no lock, so it could
  collide with a main-thread save.
- **Repair:** New `_save_persist()` helper marshals the save onto the main thread via the UI queue
  when called off-thread; `firewall()` now uses it. Pattern to reuse for any off-thread save.
- **Prevents:** Background/main-thread save collisions.

### R-001 · Scan stuck at "Waiting for the last answers…"
- **Symptom:** Scan hung forever in its final phase; "Devices online: -", never finished.
- **Root cause:** The finalization loop (`nd_core.py`) joined every background check (conflict
  rounds, packet tests, name lookups) with `t.join(0.3)` in a loop and **no overall deadline**, so
  one unresponsive device (camera/recorder that never answers) froze the whole scan.
- **Repair:** 75-second cap on that phase; move on with partial results and record the slow check's
  name (`tests["final_wait_timeout"]`). Background threads are daemon, so leftovers die with the
  process.
- **Prevents:** Any single hung network probe freezing a scan.

---

## Audit coverage note
Automated sweep across all 40 modules (33k lines): `py_compile` 0 failures; `pyflakes` clean except
cosmetic f-strings; no broken `command=self.X` button handlers; no undefined-name references (the 5
attrcheck flags + the nd_tabs `W/H` flag are confirmed false positives — class attributes / harmless
re-imports). Remaining audit focus: off-main-thread UI mutations in the other worker methods
(`_access_poll`, `_poe_poll`, `_check_worker`, `_quick_worker`, `_watch_loop`, etc.).
