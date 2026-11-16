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

## 2026-11-16 — Full Windows audit (v3.77.0)

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
