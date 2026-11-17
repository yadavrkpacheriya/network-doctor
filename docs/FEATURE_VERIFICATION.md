# Network Doctor — Feature Verification (v3.83.0, 2026-11-17)

Every feature area from `FEATURES_AND_ISSUES.md` Part A, checked against the automated test suite
(**849 passed, 6 skipped**) and the new simulation sandbox. Status key:

- ✅ **Tested** — logic covered by unit tests (listed), passing.
- 🧪 **Sandbox** — exercised against the fake router / fake cameras (real protocols) in `tests/sim/`.
- 🔌 **Needs real hardware** — logic is unit/sandbox-tested, but final confirmation needs a real device on your network. These can't be proven in CI.

> How to re-run: `cd desktop && python3 -m pytest tests -q`

---

## 1. Scanning & device discovery — ✅
Tests: `test_device_changes`, `test_recent_mark`, `test_mentioned_devices`, `test_mac_find`, `test_quick_filter`, `test_tree_sort`, `test_wifi`, `test_mass_disconnect`.
Scan **speed** on your /24 is 🔌 (never timed on the real network — the ~1 min target is a design estimate).

## 2. Cameras & CCTV — ✅ 🧪
Tests: `test_sweep` (38), `test_camline` (27), `test_dvrip` (12), `test_sweeptab`, `test_saved_logins` (incl. R-009 regression), `test_poe`, `test_livecheck`.
🧪 New: login/read_info/set_dhcp/recorder-update/reboot now run against fake XMeye/Hikvision/Dahua/ONVIF in `test_sim_sandbox`.
🔌 Real-camera confirm still wise for: picture-check freeze/black detection thresholds, PoE watt budget on your switch.

## 3. IP, binding & conflicts — ✅ 🧪
Tests: `test_ranges` (16), `test_arpblock` (12), `test_priority_device`, `test_ipfix` (9, new), `test_routeros`.
🧪 The new permanent fixed-IP fix (`nd_ipfix.reserve_recipe`) is proven to make a lease static against the fake router.
🔌 End-to-end "camera takes the reserved IP after switch to DHCP" needs a real camera (the wait-and-confirm step).

## 4. Bandwidth, usage & internet — ✅
Tests: `test_bandwidth` (43), `test_bwtab` (19), `test_usage_tidy`, `test_traffic_broadcast`, `test_slow` (18), `test_outage`, `test_snmp` (21), `test_latency_streak`.
🔌 Real NetFlow/DNS-log naming accuracy depends on your router's data.

## 5. Security & defence — ✅
Tests: `test_pro` (16), `test_dnsfilter` + `test_dnsfilter_persist`, `test_gw_flap`, `test_vpn_detect`, `test_warning_fixes` (19), `test_snmp`, `test_switchbw`.
🔌 Shodan/Censys exposure + threat-intel feeds hit live services; auto-defense actions (cut/isolate/power-off) are reviewed one-click by design.

## 6. Fixer brain & auto-fix — ✅
Tests: `test_brain` (10), `test_brain_master` (6, new), `test_autofix_brain` (13), `test_alerts` (10).
🧪/✅ New master-brain recipes, window-aware recurrence, and the recurring-issue pattern finder are unit-tested. ip_conflict + dhcp_conflict self-heal; block/expose/reboot/quarantine/DNS stay manual.

## 7. Reports, alerts & inventory — ✅
Tests: `test_inventory_excel`, `test_asset_history_names`, `test_configbak` (19), `test_alerts`, `test_reset`.

## 8. PC Care & endpoint agent — ✅
Tests: `test_pccare` (13), `test_endpoint` (12), `test_telemetry` (27), `test_telemetry_endpoint`.
🔌 Actual BSOD/driver/printer repair outcomes depend on the real Windows PC (each makes a restore point + UNDO first).

## 9. Phone app & remote access — ✅
Tests: `test_tunnel` (27), `test_license`, `test_auto_sweep`.
🔌 Cloudflare tunnel + Tailscale advertise paths need your real internet/accounts to confirm reachability.

## 10. Platform, packaging & UI — ✅
Tests: `test_update` (12), `test_linux_packaging` (14), `test_linux`, `test_v311`/`test_v314`/`test_v315`.
Note: the in-app "update available" prompt fires when a GitHub **release** is published (the app polls the latest release daily) — bumping VERSION alone does not trigger it.

---

## Summary
- **10/10 feature areas have passing automated coverage.**
- **Newly sandbox-backed** (was previously only mockable): router API conversations, XMeye/Hik/Dahua/ONVIF camera config, IP-reserve.
- **🔌 Real-hardware confirmation list** (safe to ship, but verify on a real device when convenient):
  1. Scan speed on the live /24.
  2. Camera takes its reserved IP after the static→DHCP switch (end-to-end).
  3. Picture-check freeze/black thresholds on real streams.
  4. PoE watt-budget warning point on your switch.
  5. Remote-access reachability (Cloudflare/Tailscale) from outside the office.
