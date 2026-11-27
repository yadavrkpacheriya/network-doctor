# Network Doctor — HANDOFF

_Last updated: 2026-11-27 (v4.74)_

## Done (mobile 1.38.0+48 — update check names the real cause when GitHub is unreachable)
- Rakesh (27 Nov): phone app "Could not reach GitHub" on Wi-Fi. SAME root cause as the banking app - this Wi-Fi's
  DNS failing (works on mobile data). checkForUpdate now: retries via the releases page host, and if that fails,
  calls `_hasInternet()` (gstatic/generate_204 AND 1.1.1.1 by IP - the IP one needs no DNS). If the phone is
  online but GitHub isn't reachable → error says it's this network's DNS and to apply the router DNS fix; else the
  old "is the phone online?". So the message points at the fix instead of dead-ending.

## Done (v4.79 — DNS fix now ISP-first, so banking/UPI apps work on Wi-Fi too)
- Rakesh (27 Nov): app opens on MOBILE data but NOT on office Wi-Fi, no VPN. Root cause: our v4.68 DNS fix made
  the router answer with public DNS (1.1.1.1/8.8.8.8); some Indian banking/UPI apps reject a Wi-Fi whose DNS
  isn't a normal ISP path ("Unsecured Network") — mobile works because it uses the telecom's own DNS.
- Changed AL.DNS_FIX to ISP-FIRST: reads the ISP DNS the PPPoE/DHCP link pushed (/ip dns dynamic-servers, DHCP
  lease), sets servers=<isp>,1.1.1.1,8.8.8.8 (public only as fallback), and sets use-peer-dns=yes on the
  dhcp-client/pppoe-client so the link keeps supplying ISP DNS. Falls back to public-only if no ISP DNS found.
  Still caches (speed) and still blocks port 53 from the WAN (not an open resolver). This keeps browsing fast AND
  removes the foreign-DNS signal the apps dislike.
- test_dns_isp_first (3). Suite 1116. NOTE if it still fails on Wi-Fi after this, cause is the office public IP
  being on an app blocklist, or MSS/MTU — next diagnostics, not a DNS issue.

## Done (v4.78 — detect DNS redirect / proxy that breaks genuine apps ("Unsecured Network"))
- Rakesh (27 Nov): a banking/UPI app showed "Unsecured Network Detected" on the office network; wants genuine
  apps to work. Honest scope: the banner is the APP's own fraud check (VPN/proxy on the phone, or non-trusted
  network) — we must NOT defeat it. But the NETWORK-side causes that trip it, and that are also leak vectors, we
  can detect + advise removing.
- nd_lanhealth.diagnose() now also checks the router for: (1) a transparent DNS redirect (dst-nat/redirect on
  port 53 to a non-router address, not ND-tagged) → critical "Something is redirecting DNS (breaks banking/UPI)";
  (2) /ip proxy enabled → warning "web proxy is ON". Our own ND DNS rules are skipped. Advice: remove the
  redirect / proxy + turn off phone VPN; we do not auto-change these (could be intentional) — flag only.
- Confirmed our v4.68 DNS fix does NOT force a transparent redirect (only sets the resolver), so it is not the
  direct cause; the phone banner is most likely a VPN/proxy on that phone or the app's strict Wi-Fi check.
- test_lanhealth +4 (redirect flagged, ND rule not flagged, proxy flagged, clean router no false alarm). Suite 1113.

## Done (v4.77 — per-site productivity + occasional heavy-download (movie/game) detection & block)
- Rakesh (27 Nov): want real time + data per site per user (how many times he opened Instagram/YouTube/Sheets/
  Gmail, how long, how much data); and find the occasional movie/game DOWNLOAD sites (rare use, huge data) to
  measure productivity and BLOCK them.
- `UsageStore.site_activity(days, dev)`: per (device, site) → opens (visits), down, up, bytes, active hours,
  days seen. Answers the per-site time/data question. (Time = active hours with traffic; no second-level dwell,
  stated honestly.)
- `UsageStore.heavy_downloads(days, min_mb, max_active_hours)`: the detector. Signature = lots of DOWNLOAD bytes
  in FEW active hours (a work site spreads over many hours; a movie/game grab dumps GBs in 1-2 sittings). Returns
  per site: down_mb, hours, days, mb_per_hour, suggest_block (true for personal/Games/Video/file-sharing, or 2GB+
  in ≤2 days). Steady work sites (Sheets over 8h) are NOT flagged — verified by test.
- Dashboard: new "Heavy downloads to review" card (t_heavy) listing user/site/category/downloaded/hours/days/
  action, with a "Copy block list" button → paste into Security > Website firewall (existing nd_dnsfilter). Added
  `heavy` to dashboard_data. Respects device/dept filter.
- test_heavy_downloads (3). Suite 1109 passed.
- NEXT idea (not done): a one-click "Block" straight from the card wired to the live dnsfilter (now it copies the
  list for paste); and a per-site time breakdown table in the dashboard using site_activity().

## Done (v4.76 — read REAL site names from TLS SNI, no guessing, no decryption)
- Rakesh (27 Nov): name every real site/app from actual connection data, don't assume from CDN/IP owner.
- Reality: HTTPS is encrypted — cannot see page content/uploads without a MITM cert (declined, invasive). BUT the
  TLS ClientHello's SNI field carries the real domain in PLAIN TEXT before encryption. New `nd_sni.parse_sni()`
  (pure, bounds-checked, never raises, fuzz-tested) extracts it. Wired into the sniffer: BPF filter extended with
  "or (tcp dst port 443)", on each ClientHello to :443 it calls `on_sni(client_ip, dst_ip, host)` →
  `UsageStore.dns_seen(client, host, (dst,))` which learns name→IP AND counts the visit. `mon.sni_rx` counts hits.
  So a site is named from what the connection declares — even when DNS is cached or the router's DNS log dropped.
  Needs the optional sniffer (Npcap+Scapy); when absent, DNS-log naming (v4.75 self-heal) still applies.
- nd_sni.py in SOURCE_FILES(.txt). test_sni (5: real names, junk→empty, no IP-as-name, fuzz never-raises, feeds
  usage). Suite 1106 passed.
- NOTE: names fill going FORWARD as devices browse; already-recorded "CDN" rows don't rename retroactively.

## Done (v4.75 — dashboard: 4 top-10 charts + keep DNS naming on so sites stay clear)
- Rakesh (27 Nov): dashboard still missing the top-10 charts he asked for, and site names still vague.
- Added 4 charts to usage-dashboard (nd_usage.dashboard_html): Top 10 users, Top 10 websites, Top 10 productive
  apps/sites, Top 10 unproductive apps/sites. New generic `hbar(boxId,rows,empty)` SVG bar helper + draw fns
  (drawTopUsers/Sites/Prod/Unprod, topByCat merges named sites+apps by category). Wired into draw(). All
  client-side from existing D.apps/D.sites/D.act — no new data. test_usage asserts all 4 present.
- Site clarity: names come from the router DNS log; vague buckets ("CDN (various)"/"Unnamed servers") dominate
  when DNS logging isn't arriving. `_auto_name_traffic()` changed from ONCE-per-run to a 30-min RE-CHECK (new
  `_name_dns_t` throttle, called from the tick): if blindness ≥25% and dns_log_rx==0 and a router login is saved,
  it re-applies the naming fix. This matters because the office router reboots on power cuts and loses the logging
  setting — now it self-restores. Still guarded by auto_name_dns setting, logs only on first apply.
- Suite 1101 passed.

## Done (v4.74 — DHCP-full PERMANENT cure: reclaim stale IPs, then auto-grow the pool)
- Rakesh (27 Nov): fix DHCP pooling permanently through the brain so it never repeats; if more IPs are needed add
  20 more, itself; and free the OLD IP a rotated-MAC phone left behind BEFORE adding new ones.
- `AL.DHCP_GROW` (router script) does, in order: (1) RECLAIM — remove every dynamic lease not `status=bound`
  (ghosts of moved/rotated-MAC phones free instantly); (2) recount FREE in the pool; (3) GROW — only if <20 free,
  push the pool's last address up by 20, capped at .254 (never .255). Self-guarding + idempotent; logs "ND: grew
  DHCP pool to .X" when it acts. `nd_bandwidth.grow_pool_script(net)` / `grow_pool_script_generic()` mirror it
  (reclaim-first too); empty for non-/24.
- Wired two ways: (a) appended to the existing dhcp_full AUTO_SAFE fix (so reserve-fixed + 30m-lease + reclaim +
  grow all run together on the alert); (b) PROACTIVE `NetworkDoctor._dhcp_headroom_check()` every 15 min
  (`_dhcpgrow_t`, setting `dhcp_auto_grow` default on) runs DHCP_GROW via run_script and logs a health line if the
  range actually changed — so the pool keeps headroom before anyone ever gets "no address".
- If it reaches .254 and is still full, that's a true /24 subnet-size limit (needs /23) — logged, not silently looped.
- Tests: test_dhcp_grow (5: grow guards, builder subnet guard, full fix has all 3 cures + grow, reclaim-before-grow).
  Suite 1100 passed.

## Done (v4.65 — agent tamper protection, Sophos-style IT-only off switch)
- Agent (`endpoint/networkdoctor-agent.ps1` → `$AgentVersion=1.3.0`, regenerated into `desktop/nd_agent.py`):
  added `Self-Heal` (re-creates BG/Boot/Watchdog tasks + re-applies icacls lockdown), `Uninstall-Allowed`
  (true only on a valid IT token in `<share>/agent-remove/<PC>.txt` or `ALL.txt`, matched against the secret on
  central.txt line 2), `Do-Uninstall` (deletes tasks, icacls /reset, schedules one-shot "NetworkDoctor Cleanup"
  to rd /s /q the folder, exits). Background loop: every ~60s `if (Uninstall-Allowed) { Do-Uninstall } else { Self-Heal }`.
  Agent will NOT uninstall on a user's command — only when IT writes the token from Network Doctor.
- Enabler (`nd_deploy.enabler_script(central, secret="")`): added "NetworkDoctor Agent Boot" (ONSTART task),
  `watchdog.cmd` + "NetworkDoctor Agent Watchdog" (SC MINUTE /MO 10), icacls folder lock-down
  (Users:(OI)(CI)RX, SYSTEM/Admins full), writes secret as central.txt line 2.
- Desktop (`NetworkDoctor.py`): `_agent_secret()`, `_allow_agent_removal()` + "Allow agent removal (tamper-off)"
  button (writes the token to the share). `_make_enabler()` passes the secret into the enabler.
- Honest limit: true kernel-level tamper protection needs a signed driver (not feasible here). This is the strong
  practical equivalent: SYSTEM tasks + watchdog self-heal + IT-only token uninstall + folder lockdown.
- Tests: test_deploy +3 (hardening, secret line, agent uninstall logic). Suite 1041 passed, 15 skipped.

## Done (v4.73 — Recorders: usage history keeps filling while the Network Doctor PC is off)
- This delivers the "phase 2" listed under v4.71 (always-on collection), built in `nd_collect.py` with raw-file
  recorders and 10-second-slice dedup. `nd_collector.py` (v4.71 core) is left in place but is not wired in.
- Cause of blank days (e.g. 22 and 25 Nov): the router sends NetFlow (UDP 2055) and the DNS log (syslog) ONLY to
  the IT PC; nothing stores it, so hours when that PC/app is off are lost. Those past days cannot be recovered.
- Recorder = an office PC with the PC agent (v1.4.0, `-Mode recorder`). IT switches it on from Setup >
  "Recorders" (writes `<share>/collect/on/<PC>.txt` with the agent secret + router: second traffic-flow target
  `<pcip>:2056` v9 and log action `ndrec-<ip>` topics dns,!packet → `<pcip>:5516`). The app's own 2055 target and
  `netdoctor` action are never touched. Agent remembers the switch locally (recorder.txt) so it keeps recording
  while the share is off; starts at boot (ONSTART task), opens UDP 2056/5516 for localsubnet only.
- Agent writes raw datagrams (no parsing in PS) to 10-min files `flow-YYYYMMDD-HHMM.ndf` / `dns-...txt` (UTC) +
  `arp-YYYYMMDD.csv`, copies finished files to `<share>/collect/<PC>/` via .tmp+rename, status.txt every minute,
  keeps 14 days locally, 2 GB cap; share probe backs off 5 min when the IT PC is off.
- App (`nd_collect.py`): every 2 min imports new files through the SAME path as live (TrafficStore NAT/LAN
  matching → UsageStore.add_flow with a separate `_Acc` tally, DNS lines → dns_log) so names/categories match.
  Dedup: 10 s slices; router export clock (v5/v9/IPFIX header) used when within a day of arrival (PC clock skew
  safe), else arrival. Slices the app received live (Coverage.note from Monitor.on_flow_raw / DNS lines) are never
  imported; among recorders the fullest slice wins; imported slices + files remembered (cover / collect_files in
  usage.db), templates persisted. Late/duplicate files never double count.
- Reset: nd_reset "limits" removes flow targets on port 2056 + `ndrec-*` log actions; classify lists them.
- Also fixed: the main app now flushes the last minute of usage at close.
- Tests: test_collect (20 + 2 Windows-only: PS parse + a real recorder end-to-end on the CI runner). Suite 938 OK on
  Linux. Import speed ~23 s for 540k flow records (6 h of 25 PCs).
- Waiting on Rakesh: which PC(s) stay on; merge = release; then "Make recorder" applies the router change.

## Done (mobile 1.37.0+47 — phone speedtest now has UPLOAD too)
- Phone app showed download only. Added `SpeedTest.uploadMbps()` (mobile/lib/net/speedtest.dart): streams
  generated bytes to rotating upload endpoints (cloudflare __up, httpbin, postman-echo), live progress + avg
  Mbps, 0 on failure, same rotate-on-block design as download. scan_screen._runSpeed now runs download then
  upload (skips upload only on cancel or no-internet), shows "Download X · Upload Y", adds an orange upload line
  to the chart. No Flutter in this env (CI builds APK); brace-balanced + matches ChartSeries signature. CI
  publishes mobile-v1.37.0 APK.

## Done (v4.72 — Slow check: "too many heavy tabs" = browser, not network)
- Real case: 8-10 Google Sheets tabs open, everything loads slowly, but speedtest is a full 100 Mbps. That is the
  browser/PC overloaded, not the line. nd_slow.judge() now adds a finding when the agent reports memory ≥85% full
  AND the browser (chrome/msedge/firefox/…) is the top memory user ≥1.5 GB: titled "Too many heavy tabs ... the
  browser is the slow part, not the network", with real fixes (close sheets, Chrome Memory Saver, split big sheets,
  8 GB RAM min). Uses data the agent already sends (hw.mem_used_pct, hw.top_procs) — no agent change. test_slow +2.
  Suite 1076.

## Done (v4.71 — SMB-leak auto-block + always-on collector core)
TWO items this batch.
1) SMB-to-internet block (open item: PC 192.168.0.27 sent SMB/445 to the internet).
   - `nd_bandwidth.block_smb_to_internet(wan)` → drops outbound 445/139 (TCP) + 137/138 (UDP) on the WAN and
     inbound on the router; tagged "ND: block SMB to internet" (Reset removes it); returns (script, undo). LAN
     file sharing untouched (only WAN-bound traffic dropped).
   - New alert recipe `smb_leak` in nd_alerts (matches "file sharing ... internet / worm / ransomware"), prio 1,
     with a SELF-DETECTING-WAN auto script `AL.SMB_FIX`/`SMB_UNDO` (finds WAN from default route like DNS_FIX).
     Added to AUTO_SAFE → the brain auto-blocks it on detection (nd_monitor already flags 445 outbound critical).
   - test_smb_leak (4). Safe because SMB to the internet is always leak or malware.
2) Always-on collector CORE (new feature, phase 1 — decided: runs on PC AGENTS not the router; main PC primary,
   other agent PCs as backup; full app/site granularity).
   - Problem: router streams NetFlow (UDP 2055) to ONE PC IP; when that PC is off, flows are lost = usage gap.
   - `nd_collector.py`: each agent buffers received flows in its own SQLite (`CollectorBuffer`), deduped by a
     DETERMINISTIC `flow_id = sha1(exporter,start_bucket,src,dst,sport,dport,proto)` so two agents that saw the
     SAME NetFlow row compute the SAME id. `MergeState` merges all agents' buffers keeping each flow_id once
     (NO double count) and tracks a per-agent watermark (last bucket merged) so a re-pull after a drop ingests
     only new rows (resumable). `gaps(covered_sets=...)` reports minutes no agent covered (sees holes inside a run).
   - test_collector (9): proves same-flow-across-two-agents = counted once (9000 not 18000), re-pull adds nothing,
     agents cover each other's gaps, real gap reported. In SOURCE_FILES(.txt). Suite 1074 passed.
   - NEXT (phase 2, not yet done): wire CollectorBuffer into the agent (receive NetFlow + buffer); make the
     router send NetFlow to ALL agent IPs (multi-target); app pulls each agent's buffer on startup via the share
     and feeds merged rows into UsageStore.add_flow; show a "coverage / gaps" line in Internet & Usage. Must map
     collector rows → add_flow(lan, remote, port, proto, bytes, up, org) and ensure add_flow isn't double-fed
     for buckets already received live (watermark covers the agent buffers; live NetFlow is the main PC's own path).

## Done (v4.70 — device classifier: a Windows PC on port 554 is no longer mis-filed as a camera)
- Real bug (screenshot 26 Nov): "SAURABH" laptop (Windows RPC/NetBIOS/file-sharing, Intel vendor) showed under
  CCTV cameras because RTSP port 554 was open. categorize() ran the camera branch before PC and treated any
  554/37777/34567 as a camera.
- Fix in nd_core.categorize(): compute win_strong (SMB/RPC/RDP ports 135/139/445/3389 OR a NetBIOS/SMB computer
  name) and cam_strong (camera-only ports 34567/37777, camera brand, or camera web/UPnP). If win_strong and NOT
  cam_strong → PC, even with 554 open (reason notes "port 554 is open but this is a Windows PC"). Cameras keep
  winning on a camera-only port / brand / web page, so real Hikvision/Dahua/NVRs are unaffected.
- Self-correcting memory ALREADY exists: a manual Tag (kind) is saved by MAC in db labels/tags and overrides the
  guess permanently (nd_tools.apply_tags) — so a corrected device never reverts. This fix stops the wrong auto-
  guess at the source so no manual fix is needed for this class.
- New test_pc_not_camera (6 cases incl. the SAURABH case + real-camera guards). Suite 1061 passed.

## Done (v4.69 — Slow tab: "Copy PC command" button)
- The curl compare-command in the result box wasn't selectable → user couldn't tell what to paste / run order.
  Added a "Copy PC command" button (SlowTab) that copies the single curl timing line to the clipboard; enabled
  only after a per-site "Find the cause" run (a LAN check has no url, stays disabled). Text label clarified to
  "ONE command ... paste this single line". Suite 1055.

## Done (v4.68 — DNS auto-fix hardened + now AUTO (safe on a public-IP line))
- User wants ALL experience-killing network faults fixed automatically. DNS (the top "everything wakes up
  slowly" cause) was deliberately kept MANUAL before, because the fix sets allow-remote-requests=yes =
  open-resolver risk on this office's PUBLIC IP. Fixed properly rather than forced:
  - `AL.DNS_FIX` now, in ONE step: sets 1.1.1.1/8.8.8.8 + cache, AND blocks port 53 inbound on the WAN —
    finding the WAN itself from the default route (`/ip route get [find dst-address=0.0.0.0/0 active]`), so it
    is correct for PPPoE/VLAN/ether (confirmed this office is PPPoE `pppoe-out` over ether1, vlan3818). Else-branch
    fallback drops 53 from any non-192.168/16 source. Rules tagged "ND: block DNS from WAN" → Reset removes them.
  - `AL.DNS_UNDO` removes the WAN block; `_auto_fix_dns()` captures the router's CURRENT dns servers +
    allow-remote-requests BEFORE applying and builds the full undo (restore ISP DNS + remove block), so it is
    exactly reversible — if the old value can't be read, it does NOT auto-change (stays a manual alert).
  - `dns` added to AUTO_SAFE; dispatched via `_auto_fix_dns` like ip_conflict. Test `test_v315` updated:
    DNS now hardened+auto, `exposed`/rogue-DHCP still manual (real "might break something intended" trade-off).
  - Observed in the screenshot: ether1 MTU 1500 but pppoe-out MTU 1480 → the MSS-clamp auto-fix (already AUTO)
    handles the "some sites hang" side.
- Suite 1055 passed. What now auto-heals regularly through the brain: IP conflict, DHCP full/conflict,
  broadcast/multicast storm (IGMP), switching loop (storm-block), MTU/MSS, and DNS (hardened). Still manual by
  design: close exposed camera port, block rogue DHCP, slow/half-duplex cable (physical).

## Done (v4.67 — LAN-health runs AUTOMATICALLY through the brain, every ~10 min)
- User's follow-up: "make it automatic and regular through brain AI so the same issues don't recur."
- `NetworkDoctor._lan_health_check()` now runs off-thread every 10 min from the main tick (guard `_lanhealth_t`,
  setting `lan_health_auto` default on). It reads the router via nd_lanhealth.diagnose(), raises each
  critical/warning finding as an alert (deduped in alerts_active under "lan_health:<title>"), which flows through
  `_record_alert` → `_auto_fix` → the brain. Auto-clears a LAN alert when its fault is gone (`_clear_lan_alert`,
  sets status=fixed) — same self-healing behaviour as reconnect clearing a disconnect alert.
- KEY: the finding TITLES already map to existing alert kinds, so NO new recipe was needed and the brain
  auto-applies the SAFE reversible fixes on recurrence:
    • "Broadcast flood on X (… pps)" → kind=multicast (AUTO_SAFE) → auto IGMP-snooping router fix.
    • "Possible switching loop: … MAC on N ports" → kind=loop (AUTO_SAFE) → storm block + "pull the cable".
    • "eth3 runs at 100 Mbps HALF-duplex" → kind=cable (NOT auto) → stays a human alert (software can't fix a cable).
  Verified by test_lanhealth.BrainPipeline. So storms/loops get caught + fixed regularly without a button press;
  cable faults get flagged loudly for a person. Suite 1054 passed.

## Done (v4.66 — LAN-health: "100 Mbps line but everything feels like 10")
- User's real symptom: speedtest shows 90–100 Mbps, but Sheets/Gmail/sites/printers all "wake up slowly, like
  asleep" — on CABLED PCs. That is LATENCY, not a bandwidth cap: DNS delay + layer-2 flooding, not the line.
- New `nd_lanhealth.py` reads the live MikroTik (RouterOS API) with TWO samples ~1s apart to measure packet
  RATES, and flags: broadcast/multicast STORM per port (BCAST_PPS_WARN=400/BAD=1500), switching LOOP (same MAC on
  >1 bridge port), slow/HALF-duplex links (≤100 Mbps or half), ARP bloat (≥400), proxy-ARP left on. Each finding
  carries plain evidence + fixes. `fix_script()` gives idempotent RouterOS fixes: igmp_snoop, no_proxy_arp,
  storm_control, mac_winbox_find_loop (read-only loop finder). diagnose() never raises.
- Wired into the Slow tab (`nd_tabs.SlowTab`): new "Check the whole LAN" button → runs diagnose() in a thread,
  renders in the same findings tree, fixes routed via `lan:` action prefix to the LAN fixer. mac_winbox_find_loop
  shows the read-only command instead of applying.
- Added to SOURCE_FILES + SOURCE_FILES.txt (auto-updates). Tests: test_lanhealth (11). Suite 1052 passed.
- NOTE the DNS angle is ALREADY covered by nd_slow.judge() (slow-DNS → dns_public fix). Tell user: run
  "Check the whole LAN" (loop/storm/cable) AND the per-site Slow check (DNS/line). On this network DNS is the
  likeliest "wakes up slowly" cause — the dns_public fix points the router at 1.1.1.1/8.8.8.8 with caching.
- TODO mobile parity: phone app also has a router client; mirror a lan-health read there next.

## Done (v4.40–4.57, latest session)
- **NVR camera coverage via saved channel map** (v4.57): NVR .74's web API is FULLY ENCRYPTED (RSA key +
  per-request AES; crypto-js) - confirmed in browser, every getconfig body is a base64 blob, so no plaintext
  Python read is viable. Instead: read the 32 channel IPs ONCE from the web UI (did it live via Chrome, cycling
  the IP Channels dropdown) and bake them in. New `nd_nvrmap.py` (per-recorder channel->IP map in db["nvr_map"],
  coverage() = live online/offline per channel vs scanned IPs, orphan_cameras()), `nd_nvrseed.py` (built-in map
  for .74 FAN-AIR 32ch, apply() seeds only if user has none - never overwrites a live read/refresh). list_channels
  in _nvr_cameras now SAVES any live read to the map and FALLS BACK to the saved map (with live online state)
  when the read is empty. All 3 files in SOURCE_FILES. nd_nvrcgi.py (v4.56) stays as a best-effort path but won't
  work on fully-encrypted firmwares. Tests: test_nvrmap (3), test_nvrcgi (4). Suite 1031.
  Mirror map+seed into mobile (TODO).
- **2nd recorder seeded + cross-NVR dup found** (v4.58): added NVR .22 (11 cameras, CH12-32 empty) to
  nd_nvrseed.SEED, read live via browser. Now 2 recorders mapped = 43 camera bindings total (matches the "43
  cameras" count). Seed caught a REAL cross-recorder duplicate: camera 192.168.0.157 is on BOTH .74 (CH23) and
  .22 (CH03). DVR .73 is the OLD model - only opens in IE mode (ActiveX), can't read via Chrome; likely analog
  (BNC) cameras with no per-channel IPs to map, so coverage doesn't apply. If .73 has IP cameras, user reads it
  once in Edge/IE and sends IPs to add to SEED. Suite 1031.
- **NVR camera read via WEB CGI - THE REAL FIX** (v4.56): proven in Rakesh's Chrome that NVR .74's DVRIP API
  (34567) is locked (every config node empty) but its WEB interface reads channels fine via
  POST /cgi-bin/login.cgi + /cgi-bin/getconfig.cgi (saw CH01=192.168.0.143, CH16=192.168.0.146). New
  nd_nvrcgi.py: login()+read_config()+channels() over HTTP:80, parses NetWork.NetDigital/Digital/etc, handles
  dotted + little-endian-hex IPs, never raises. Wired as the final fallback in nd_dvrip.list_channels when
  DVRIP yields no IPs. nd_nvrcgi.py in both SOURCE_FILES. Tests: test_nvrcgi (4). Suite 1028.
  VERIFY on real .74: the getconfig.cgi/login.cgi body is my reconstruction of the NetSurveillance CGI; if
  login returns no SessionID, the login body (EncryptType/PassWord hashing) needs adjusting. Mirror into mobile next.
- **More aggressive auto-fix + auto-delete connect/disconnect alerts** (v4.52): _auto_fix now fires on FIRST
  sight (need=1) for any AUTO_SAFE kind that has a router fix AND a saved router login (removed the backwards
  recurring+2 penalty). resolve_matching gained delete=True - connect/disconnect ("answering"/"offline"/
  "responding") alerts are now REMOVED from the log (not just marked fixed) when the device returns. Watch
  "Back up" path matches by NAME + MAC + IP so an IP-change-then-reconnect still clears the stale alert
  (old-IP text wouldn't match the new IP). Tests: delete mode, IP-change-by-MAC, resolve-by-name.
- **Camera count consistency** (v4.55): Home card showed a different CCTV count than the top bar (44 vs 43)
  and didn't drop live when a camera went offline. Two fixes: (1) core.category_counts now splits DVR/NVR out
  of CCTV cameras exactly like the top summary bar, so Home and top bar agree everywhere it's used; (2) the
  quick-check liveness pass (every ~2 min, marks devices on/offline via ARP) now also refreshes the Home card
  when on the Home tab, so the camera count updates between full scans instead of only on tab switch. Tests:
  test_counts (NVR split). Suite 1024.
- **Background push via ntfy** (v4.54, mobile 1.36.0): FULL background push (buzzes phone when app closed),
  no Firebase. New `nd_push.py` (ntfy.sh client: new_topic/send/approval_push, injectable opener, never
  raises, ascii-safe). PC: _flush_alerts -> _maybe_push_approvals pushes when the pending-approval count GOES
  UP (debounced via _pushed_approvals); settings push_topic/push_enabled; snapshot sends push_topic; new
  remote actions push_setup (makes a secret topic, optional test push). Phone: _PushSetupCard in pc_more
  SummaryTab - "Turn on background push" -> push_setup, shows topic, "Subscribe in ntfy app" (ntfy:// deep
  link, Play Store fallback io.heckel.ntfy), Send test. Delivery is by the ntfy app (survives app-closed);
  our app just sets the topic + deep-links. nd_push.py in both SOURCE_FILES. Tests: test_push (7). Suite 1022.
- **Approval queue on phone** (v4.53, mobile 1.35.0): snapshot now sends `pending_approval` = open alerts that
  HAVE a router fix but are NOT auto-safe (need a human yes) and aren't rejected. Phone AlertsTab shows a
  "Needs your approval" block with Approve (runs alert_fix), Reject (new `approve_reject` action sets
  alert.approval=rejected so it stops being offered), and "Ask Claude" (copies the alert+fix to share). NOTE:
  this surfaces via the phone's existing 6s poll (seen when the app is open); TRUE background push (phone
  asleep) would need FCM/Firebase - not built, told the user.
- **PC app "stops responding" fix** (v4.51): two main-thread UI freezes. (1) `_poll` drained the WHOLE queue
  every 100ms tick with no cap - a burst (event storm, many job results) froze the window. Now capped at
  POLL_BUDGET=40 msgs/tick, reschedules in 10ms when more remain. (2) AlertsTab.refresh inserted up to 1500
  Tk tree rows on the UI thread each refresh as the alert log grew - capped render to 300 (sorted so open/
  high-prio/recent come first) with a "showing first 300 of N" note. Scans/router calls were already threaded;
  alerts flush already debounced (400ms). Suite 1012.
- **Phone router fixes parity** (mobile 1.34.0): new `mobile/lib/net/router_fixes.dart` with (apply,undo) RouterOS
  scripts mirroring desktop nd_tools: "Fix website & app names" (DNS-log+redirect+DoH-block, ND-DOH list),
  "Fix DHCP-full permanently" (reserve fixed gear + 30m lease), "Block torrents", "Block rogue DHCP". Added a
  "Fix problems (on the router)" section to router_screen with Apply/Undo per fix, run via r.runScript() over
  the direct MikroTik API (no PC needed). `$L/$m/$n` escaped as `\$` so RouterOS gets literal vars.
- **Phone router login "dropped the connection"** (mobile 1.33.3): RouterOs.connect split into connect (retries
  the handshake once, 500ms apart) + _connectOnce. A reset DURING login (not a !trap) is now caught and turned
  into a specific message: check IP>Services>api "Available From" includes this phone's /24, and that the phone
  is on the office Wi-Fi not a guest VLAN - the usual cause when the PC connects but the phone can't. A
  'login refused' (wrong user/pass) still fails fast without retry.
- **Alerts now auto-close when the device returns** (v4.50) — "stopped answering" / "not answering" alerts
  stayed open forever after the device came back. Two gaps: (1) _missing_devices raised them via _record_alert
  (not tracked in alerts_active), so the resolve loop never saw them; (2) the device-watch "Back up" path only
  popped alerts_active, never closed the LOG entry. Added `AlertLog.resolve_matching(must, also)` (both
  substrings, case-insensitive on 2nd). _missing_devices now closes stopped-answering alerts for any MAC/IP
  online now; the watch "Back up" path resolves the log entry by IP/MAC too. Tests: resolve_matching (2).
  NOTE: screenshot still shows pre-v4.46 dhcp_full text + all open -> those are OLD log lines; verify the
  v4.46 brain self-heal actually fires on a FRESH dhcp_full after v4.50 installs (needs saved router login).
- **Phone↔PC stability + parity** (v4.49, mobile 1.33.0):
  - Disconnects: pc_screen._load tolerates `_failsBeforeErr`=3 consecutive failed polls before showing the
    "disconnected" screen, keeping the last good data meanwhile (one Wi-Fi blip no longer = disconnect).
    pc_link._send now does one quick retry (600ms) on transient failure, 6s timeout (was 8s, no retry).
  - Parity: audited all 31 PC remote actions vs phone. Added missing ones to phone Pc Tools > Checks:
    "Fix website & app names" (new PC action `name_traffic` = v4.48 DNS-log+redirect+DoH-block) and
    "Hardening commands" (existing PC `hardening`, now shown via new `_showCommands` copyable dialog).
    runOnPc now renders a `{commands:[...]}` result instead of dropping it.
- **Keep-alive ping** (mobile 1.33.1): pc_screen runs a cheap `/api/hello` every 3s (PcLink.keepAlive, never
  throws) between the 6s data polls, so the phone↔PC link never idles out; on success it clears the fail
  count and, if it had been showing an error, reloads data immediately (fast recovery instead of waiting ≤6s).
- **Stuck "connecting" spinner fix** (mobile 1.33.2): the screen could sit on a bare spinner with no error
  (first connect slow, or a PcError swallowed while `!mounted`). Now: an 8s `_slowTimer` replaces the bare
  spinner with "Still connecting… + hint + Retry now" (Retry clears any stuck `_loading` guard); and
  `_send` fails fast on SocketException/ClientException (connection refused = nothing listening, don't retry;
  only a timeout gets the one retry), so first-load resolves in seconds instead of ~20s.
- **Website/app naming fix + verify** (v4.48) — root cause of "finding/verifying website & app still an issue":
  usage names depend on the router's DNS log, but DoH (port 443) and devices using their own DNS hide names,
  so traffic shows as 'other'/CDN. Added `nd_tools.block_doh_commands` (drops 443 to public DoH/DoT resolver
  IPs → devices fall back to router DNS) + `name_traffic_commands` (one apply/undo: DNS-log on + redirect 53 +
  block DoH). New Assistant intent "naming": `_apply_naming` applies then VERIFIES by watching usage.dns_log_rx
  climb (~70s) and reports whether names started arriving. List named `ND-DOH` (reset-contract convention).
  Tests: test_assistant NamingFixTests (3). Full suite 1010.
- **Ask-the-brain questions** (v4.47) — NEW `nd_ask.py`: answers plain-English questions from data the app
  already stores. "which website/app/device uses the most data" (nd_usage.summary), "which device
  disconnects the most" / "not on UPS" (nd_power.summarize over db.power_log), "which site is dropping"
  (SlowTab watch events). Keyword intent-routing over STRUCTURED data (offline, exact, testable - not an LLM),
  handles most/least + day ranges. Wired into AssistantTab: when a typed line isn't a fix request but looks
  like a question, it answers with text + a small table. Intro/examples updated. nd_ask.py added to both
  SOURCE_FILES lists. Tests: new test_ask.py (9).
- **Brain now SELF-HEALS recurring permanent issues** (v4.46) — root cause the app "couldn't fix on its own":
  (1) recurrence always added +2 to the auto-fix threshold (more recurrence = HARDER to fire), and alert
  `count` is always 1 ("same alert within an hour counted, not repeated"), so count(1) < need(3+) → never fired;
  (2) `dhcp_full` was missing from `nd_brain.AUTO_SAFE` (separate set from nd_alerts.AUTO_SAFE). Fix: `decide()`
  now returns `apply_now=True` when the recipe is `permanent`+`auto`+AUTO_SAFE and the issue is recurring
  (conf≥0.5); `_auto_fix` sets need=1 on apply_now (acts on sight). Added dhcp_full to nd_brain.AUTO_SAFE.
  When apply_now but no router login saved, it now notes that ON the alert instead of silently re-logging.
  Tests: test_brain (apply_now recurring / not one-off).
- **DHCP-full PERMANENT fix** (v4.45) — root cause: 150-wide phone pool + rotating private MACs + fixed gear
  (cams/NVR/PCs/printers) still sitting on dynamic leases. The old 30m-lease patch kept recurring (brain
  logged 30x, auto was False so it never self-applied). Now: `dhcp_full` auto fix = one RouterOS script that
  (1) make-static every bound DYNAMIC lease whose MAC is NOT locally-administered (fixed gear reserved out of
  the pool), (2) removes ghost/expired dynamic leases, (3) sets lease-time=30m on the dynamic pool. Reversible
  undo. Flipped `nd_brain.RECIPES["dhcp_full"]` auto=True + added to `nd_alerts.AUTO_SAFE` so it self-applies.
  Tests: test_assistant (make-static/30m/dynamic=yes/undo), test_brain (auto+permanent+AUTO_SAFE).
- **NVR empty-config PERMANENT fix** (v4.44, mobile 1.32.1) — raw dump showed every named channel node
  null/[] (not 607). Added `DvrIp.get_all_tree()` (CONFIG_GETALL 1046, empty Name = whole config) +
  `_harvest_channels()` that walks the WHOLE tree for any channel-ish list carrying camera IPs
  (hex-decoded) / names / enable. Wired as fallback in `list_channels` when named nodes are empty;
  `raw_config` now also prints the whole-tree keys + harvest result. Mirrored into `mobile/.../dvrip.dart`.
  No more node-name whack-a-mole. Tests: test_dvrip.py +2 (buried tree, longest-list).
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
