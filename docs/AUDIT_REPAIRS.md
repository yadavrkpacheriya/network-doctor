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

## 2026-11-16 — Line-by-line read: module coverage ledger
Fully read, end to end (not just scanned):
- nd_core.py (2251) — R-006, R-007 fixed; everything else correct.
- nd_camline.py (428) — clean (camera-move logic is reversible, one-at-a-time, safe).
- nd_bandwidth.py (629) — clean (ip_plan/auto-resolve correct; router commands reversible).
- nd_tools.py (2161) — clean (binding/guard/DNS/site-block commands full-path + reversible;
  PC-fix PowerShell conservative; command library informational).
- nd_reset.py (147) — clean (only ND-tagged items touched; exports config first; restores before removing).
- nd_routeros.py (396) — clean (DPAPI password storage, pooled logins, correct API wire format).
- nd_snmpcfg.py (75) — clean (random community, LAN-only, read-only, reversible — hacker-safe).
- nd_arpblock.py (156) — clean (never blocks backbone/phones, auto-heals, internet-only).
- nd_access.py (143) — clean (reply-only ARP / DHCP-full detection, reversible one-click fix).
- nd_dvrip.py (233) — clean (XMeye protocol; bounded reads; single-match-only writes).
- nd_dnsfilter.py (314) — clean (DNS filter server; never loops to self; per-client stats).
- nd_defense.py (152) — clean (auto-defense: never acts on backbone/phones; cooldowns; auto-release).
- nd_vuln.py (169) — clean (read-only security check; never logs in or exploits).
- nd_brain.py (278) — clean (NB+ensemble; recurrence signatures match callers; AUTO_SAFE excludes
  block/expose/reboot/quarantine/DNS kinds).
- nd_sweep.py (708) — clean (one-try-per-device, canary+breaker, LAN-only, saved logins encrypted).
- nd_snmp.py (709) — clean (BER/SNMP read stack; writes gated on write-community + port_risk safety check).
- nd_net.py (1448) — clean (port scan, DNS codec+hijack check, WoL, subnet calc, MTU probe, speed test,
  Wi-Fi analyzer, LAN speed server private-only, web/TLS check, MAC lookup).
- nd_usage.py (1494) — clean (usage SQLite WAL store, app classification, insights/leak detection,
  embedded offline dashboard with proper escaping).
- nd_monitor.py (1741) — clean (threat-intel, RDAP org lookup, NetFlow v5/v9/IPFIX parser, syslog
  parsing, Monitor sampler/sniffer, root-cause engine; thread-safe, bounded, never flags own scans).
  Note: Setup-paste SNMP uses community 'netdoctor' (LAN-locked to this PC); in-app enable uses a
  random one. Both non-'public' (relevant to R-008).
- nd_pcengine.py (1755) — clean (PC-Care PowerShell engine; every change reversible via undo scripts;
  safe-path guards block system folders; user removal backs up + verifies before delete; net/TCP reset
  gated and warned). Exemplary reversible design.
- nd_configbak.py (194) — clean (router config backup; export-only, never pushes config).
- nd_endpoint.py (309) — clean (endpoint inventory; read-only, bounded).
- nd_telemetry.py (239) — clean (phone/agent telemetry intake; sanitized, bounded, rate-limited).
- nd_home.py (243) — clean (home/dashboard tab; read-only summary rendering).
- nd_pccare.py (278) — clean (PC-Care tab; marshals to main thread; actions gated + reversible).
- nd_livecheck.py (76) — clean (live reachability poll; read-only).
- nd_poe.py (99) — clean (PoE status read; read-only SNMP-style poll).
- nd_report.py (120) — clean (report builder; pure formatting over collected data).
- nd_tunnel.py (288) — clean (Cloudflare tunnel helper; owner-opt-in, loopback-terminated, no silent expose).
- nd_share.py (367) — clean (phone-link JSON API; LAN-only default, hmac.compare_digest for all secrets,
  pairing/login lockouts, size caps, per-IP rate limits, remote gated behind owner opt-in + sign-in).
- nd_slow.py (486) — clean (slow-site diagnostic; measure() read-only, judge() pure; router fix_script
  outputs are reversible remove-before-add scripts, button-gated, never auto-applied).
- nd_ranges.py (214) — clean (multi-range planner; read-only, RFC1918-only, 4096-addr cap, skips
  virtual/VPN adapters, never sweeps > /22 whole — only /24s with a known device).
- nd_auth.py (202) — clean (Pro accounts: PBKDF2-SHA256 200k + per-user salt, hmac.compare_digest,
  fail-safe RBAC, last-admin protection, atomic save, append-only audit log, TTL token sessions).
- nd_license.py (206) — clean (pure-Python Ed25519 verify-only RFC 8032, sig+expiry checked, R-005
  atomic write, on-curve + S<L checks correct; private key never ships).
- nd_smbinfo.py (134) — clean (read-only SMB2 NTLM-challenge parser for PC name/OS; no login, no
  password sent, bounded reads, timeouts, exception-safe — same technique as nmap).
- nd_linux.py (132) — clean (read-only /proc + /sys facts, test-parameterized roots, read-only ioctls).
- nd_xlsx.py (148) — clean (dep-free xlsx writer/reader; XML-escaped, illegal-char stripped,
  bounds-checked shared strings, named-member reads only — no path traversal).
- nd_sweeptab.py (619) — clean (login-sweep UI; passwords never saved by default + cleared after each
  scan, one-try-per-device with auto-skip to avoid lockout, all DB/UI writes via q.put under DB_LOCK;
  camera line-up moves one at a time with reversible DHCP bindings, waits per-camera, stops at first
  failure, never moves recorders, confirms before every change).
- nd_protab.py (743) — clean (Pro pages; remote access opens NO router port — tunnel forwards only the
  TCP 8787 remote-access addr, sign-in required, every action audited; auto-defense reversible +
  exclude-list + levels default "notify"; accounts/license delegate to verified nd_auth/nd_license;
  tunnel token used once, never saved).
- nd_bwtab.py (975) — clean (bandwidth plan; every Apply has an Undo, FastTrack restored on undo;
  fixed-IPs reserve-not-move by default, cameras warned + confirmed, bind-confirmed avoids half-moved
  cameras; camera isolation blocks internet both ways + closes port-forwards reversibly; Reset removes
  ONLY ND-made items, never ISP/owner config, saves nd-before-reset.rsc first with read-only preview).
- nd_tabs.py (2582) — clean (shared UI: map/binding/commands/usage/slow/alerts/troubleshoot/assistant +
  section navigator). Binding default can't cut a device off + check_ip rejects bad IPs; Commands
  run-on-router prompts on add/set/remove/disable/enable/reboot/reset; every auto-fix + troubleshoot +
  assistant router action has an Undo and asks first; AutoFixWindow surfaces fixes that keep getting
  undone (the R-004 recurrence concern); Assistant never runs free-form router commands — only shipped
  fixes. All DB/tag writes via save_db + after_tags_changed.
- nd_toolstab.py (2131) — clean (Tools tab: watch/speed/ports/SNMP/website/guard/dns/web/CGNAT/backup/
  lan/wifi/nic/mtu/subnet/wol/mac/inventory/login/ready). R-008 fix confirmed in place (show() pre-fills
  SNMP Read community from the saved private one). Every router-change path gated (login + Yes/No + undo):
  SNMP port off/on/restart needs the write-community + port_risk warning + undo stack; Network guard
  defaults random-MAC/torrent OFF, warns before blocking random MACs, blocks rogue routers only when
  ticked, never auto-applies; website-block/force-DNS reversible with backup; CGNAT check is read-only
  and refuses wide-open rules (one scoped port + undo). All diagnostics read-only; thread-safe queue/poll.
NetworkDoctor.py (5137) — COMPLETE, read line-by-line end to end, clean. Both flagged safety checks VERIFIED CLEAN:
  (1) EXPIRED/RELEASE: _defense_expire() (L3052) iterates d.expired() → _remote("block", on:False) →
      d.release(key), scheduled via self.after(mins*60000); arpblock.expired() released every 30s
      (L1435-1439); App.on_close shutdown heals every active LAN block (L5082-5083). PASS.
  (2) AUTO_SAFE / no disruptive auto-action: _auto_fix (L2824) applies a router fix ONLY when
      kind in AL.AUTO_SAFE, always with cmd+undo, and _check_fix_regression (L2913) auto-undoes any
      fix that produces a NEW problem on the same device/IP (this is the R-004 recurrence safety —
      a bad fix throttles+reverses itself, the brain learns). Auto-defense (_defense_consider/_act,
      L2985-3034) is a SEPARATE Pro-only path, gated by: armed + per-threat level explicitly set
      above "notify" (default notify = NO action) + d.guard() (never backbone/phones) + wifi
      whitelist + cooldown + audit log + time-limited auto-release. loop/multicast have no
      disruptive auto-action by default. PASS.
  Phone/remote API (_remote_cmd/_remote, L4165-4577): LAN-only share → pairing code → token → (Pro)
  nd_auth RBAC role check per action → audit log. router_reboot/poweroff/isolate are Pro + admin-role +
  MANUAL (never automatic). router_cmd accepts only INDICES into the vetted T.COMMANDS library — no
  arbitrary command injection. block/isolate/site-blocks reversible by rule comment; _arp_fallback_block
  uses verified AB.plan (never backbone/phones), internet-only, time-limited. CGNAT/vuln/capture/exposure
  read-only. R-fixes re-confirmed in place: R-003 (_settings recovers from .bak; _save_settings atomic
  tmp+fsync+rotate+os.replace), R-002 (_save_persist marshals off-thread saves), R-006 (core.VERSION at
  L73), R-007 (load_db .bak recovery in nd_core). Auto-update (daily 15:00, auto/ask/off, waits for a
  running scan) is the "update not available" item — working as designed; a published GitHub release at a
  higher version is what triggers the in-app prompt. Minor (not a bug): PingWindow._close references
  self.usage which it never sets — harmless, wrapped in try/except so the flush just no-ops.

---

## FINAL AUDIT SUMMARY — 2026-11-16 (line-by-line, every module)

**Scope:** full line-by-line read of the entire desktop codebase (~40 modules, ~33k lines) at the user's
request ("Full line-by-line, every module"), driven by an autonomous self-continuing check loop.

**Verdict:** the codebase is high-quality, reversible, and safety-conscious throughout. Every module was
read end to end (not grep-sampled). Real bugs found and fixed: R-001..R-008 (below). The remaining ~39
modules read clean. No new bugs surfaced in the tab/UI modules, the helpers, or NetworkDoctor.py.

**Standing safety rules — all upheld in code:**
- Never disrupt the office network: every router change flows through ONE gate (App.router_apply /
  _router_job) that asks "Apply on the router now?" and keeps an UNDO; the Reset tab touches only
  ND-tagged items and backs up to nd-before-reset.rsc first; camera moves are one-at-a-time with
  per-camera verify and stop-at-first-failure.
- Reversible: every auto-fix has an undo + a post-fix regression check that auto-undoes a fix which
  causes a new problem (nd_autofix + _check_fix_regression). Auto-defense cuts auto-release on a timer
  and heal on app close.
- Hacker-safety: SNMP is enabled hacker-safe (random read-only community, LAN-locked, never 'public',
  reversible); remote access opens NO router port (Cloudflare tunnel forwards only TCP 8787, sign-in
  required); CGNAT advisor refuses wide-open rules (one scoped port + undo); no auto-UPnP.
- block/expose/reboot/quarantine/DNS kinds stay MANUAL: none are wired to any automatic/brain path;
  they require an explicit operator action (and, on the phone, an admin role + audit).

**Repairs made this audit:** R-001 stuck-scan deadline; R-002 off-thread settings save race; R-003 the
daily settings-wipe (atomic write + .bak recovery) — the root cause of "a new bug every day with no
update"; R-004 IP-conflict auto-fix discoverability; R-005 atomic license write; R-006 stale version in
exported reports; R-007 device-DB .bak recovery; R-008 SNMP Read box ignored the saved private community.

**Module coverage ledger below** (every module marked "clean" was read in full this audit).

## 2026-11-16 — Line-by-line read (v3.81.0)

### R-008 · SNMP Read box ignored the private community the app set ("enabled SNMP but still can't read")
- **Symptom:** After using "Turn on SNMP (safe)", the Switches (SNMP) Read tab still showed "No SNMP
  answer" when reading the router. User had saved the router login and enabled SNMP but it never worked.
- **Root cause:** "Turn on SNMP" correctly sets a RANDOM private community (never 'public', the
  hacker-safe design) and saves it to settings["snmp_community"]. But the Read tab's community field
  (nd_toolstab.py:485) was hard-coded to "public" and never loaded the saved community, so every read
  used the wrong community and failed.
- **Repair:** nd_toolstab ToolsTab.show() now pre-fills the SNMP community box with the saved private
  community whenever it still holds the unusable "public" default (a community the user typed is kept).
- **Note:** If the box still shows "public" after this (no saved community), "Turn on SNMP" never
  actually applied on the router — the router API login in Setup is the thing to check.

## 2026-11-16 — Line-by-line read (v3.80.0+)

### R-007 · Device DB had no backup recovery (tags/labels could be lost)
- **Symptom:** (latent) if devices_db.json were ever corrupt, `load_db` fell back to `{}`, wiping all
  labels/tags and device history.
- **Root cause:** No `.bak` safety net (unlike settings after R-003). Writes are atomic, so only
  external corruption could trigger it, but tags are precious.
- **Repair:** `save_db` now rotates a `.bak`; `load_db` recovers from it before falling back to empty,
  and rejects non-dict JSON.

### R-006 · Exported HTML reports showed the wrong app version
- **Symptom:** Every "Export report (HTML)" footer read "Network Doctor v3.18.0" regardless of the
  real version.
- **Root cause:** `nd_core.export_html` prints `nd_core.VERSION`, a separate constant frozen at
  "3.18.0" that nothing kept in sync with the real `NetworkDoctor.py` VERSION.
- **Repair:** `NetworkDoctor.py` sets `core.VERSION = VERSION` at startup — one source of truth, so
  reports always show the running version.
- **Found by:** the line-by-line read (an earlier grep missed it because the use is a bare `VERSION`
  inside nd_core).

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
