# Network Doctor — HANDOFF

_Last updated: 2026-11-23 (v4.43)_

## Done (v4.40–4.43, latest session)
- **Watch for drops** (v4.43) `nd_slow.watch_probe()` + `summarize_watch()`, wired into SlowTab
  (`nd_tabs.py` `toggle_watch`/`_watch_tick`/`_watch_result`). Catches INTERMITTENT site drops the
  one-shot test misses — checks the site every 20s in the background, logs each failure by cause
  (dns/connect/tls/slow/http), shows by-cause + by-hour + most-likely-fix. For the Google Sheets
  "disconnects many times a day, everyone but not same time" problem.
- **Power/UPS report** (v4.42) `nd_power.py` + PowerReportWindow in `nd_tabs.py`. ≥4 fixed devices
  dropping in one scan = power cut; survivors = on UPS. Coverage split + daily downtime + monthly avg
  + CSV. `power_log` recorded each scan in `nd_core._update_db` (45d/20000 cap).
- **IP-changed PC no longer stuck offline** (v4.42) `nd_core._update_db`: MAC-less online devices matched
  to history by IP/name before the offline pass.
- **NVR code-607 fallback** (v4.42) `nd_dvrip.py` + `mobile/lib/net/dvrip.dart`: CONFIG_GET→CONFIG_GETALL
  (1046) fallback + name-enrichment + 60% coverage gate so cameras show IPs where readable.
- **DHCP 150/100 split** (v4.40) `nd_bandwidth.py`: 150 IPs mobile/pc, 100 fixed; `reserved_ips` (.70 = PC only).
- Mobile build fix: `default_login_test.dart` List.contains-by-identity bug (broke every APK since Batch 1).

_Older history below is pre-v4.40 and may be stale._

---
_(archived) Last updated: 2026-11-17 (v3.83.0)_

## Goal
Office network + CCTV manager (Python/Tkinter desktop `desktop/NetworkDoctor.py` + ~50 `nd_*.py` modules;
Flutter Android in `mobile/`). Offline-first, syncs to phone, self-healing "fixer brain", auto-update.

## Done (this session)
- **Simulation sandbox** `desktop/tests/sim/` — fake MikroTik (real RouterOS API wire protocol) + fake
  XMeye/DVRIP, Hikvision, Dahua, ONVIF cameras. Exercises leases/arp/binding, `run_cli` (ROS6 + ROS7),
  camera read_info/set_dhcp/recorder_update/reboot. 16 tests. **This is the "test like a real device before
  release" rule, now real.**
- **Permanent fixed-IP conflict fix** `desktop/nd_ipfix.py` — reserve (make-static) the IP for the current
  lease holder when untagged (was: did nothing → daily recurrence), + static→DHCP switch recipe for a known
  camera with a saved login. Wired into `NetworkDoctor._auto_fix_ip_conflict` (strictly additive; tagged
  path unchanged). 9 tests.
- **Brain upgrade** `desktop/nd_brain.py` — `RECIPES` catalog (fix + auto-safe flag per kind), curriculum for
  ip_conflict/dhcp_conflict/bogus_mac/random_mac, `recipe()`, `recurring_report()` pattern-finder,
  window-aware `recur_count()` (SEED_VERSION→4). 6 tests.
- R-009 (v3.82.0): saved camera logins now used by restart/picture-check.
- Repo slimmed (history rewrite, 203MB→~10MB); release binaries gitignored.

## Version / tests
- VERSION **3.83.0** (`desktop/NetworkDoctor.py:73`). `core.VERSION` mirrors it.
- `cd desktop && python3 -m pytest tests -q` → **849 passed, 6 skipped**.
- `python3 /tmp/attrcheck2.py NetworkDoctor.py` → always "5 genuine" = known false positives.

## In progress / next
- Camera static→DHCP auto-apply in the live GUI untagged path is **planned but not auto-run** (needs real
  hardware to validate safely). The recipe is produced; apply it via Line-up / sweep flow for now.
- Feature-verification doc (`docs/FEATURE_VERIFICATION.md`) — still to write: confirm each feature in
  `docs/FEATURES_AND_ISSUES.md` Part A against unit/sandbox tests.
- Surface `recurring_report()` in the Alerts tab (escalation list) — not yet wired to UI.

## Key decisions
- Sandbox is **test-only**, never imported by the app (`desktop/tests/sim/`).
- Fixer brain never auto-applies block/expose/reboot/quarantine/DNS (AUTO_SAFE excludes them); only
  ip_conflict + dhcp_conflict self-heal.
- Verify-before-release: suite must be green + router/camera changes proven in the sandbox before shipping.

## File map (new/changed)
- `desktop/nd_ipfix.py` (new), `desktop/nd_brain.py` (recipes/pattern-finder),
  `desktop/NetworkDoctor.py` (untagged IP-conflict fallback, v3.83.0),
  `desktop/tests/sim/*` (new), `desktop/tests/test_sim_sandbox.py`, `test_ipfix.py`,
  `test_brain_master.py` (new), `desktop/nd_update.py` + `SOURCE_FILES.txt` (added nd_ipfix.py).

## Known bugs / limits
- `attrcheck2.py` reports 5 missing-attribute refs — verified false positives (dynamic Tk attrs).
- Backup bundle (180MB, 7 parts) delivered to chat on 2026-11-17; user to drag into Google Drive folder
  `1FowCyFAhvTBUTnpexgKU2hbhuQFwqfVr` (agent can't push binaries to Drive by reference from here).

## Last commit
See `git log -1`. Latest release: **3.83.0**.
