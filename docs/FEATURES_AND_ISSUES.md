# Network Doctor — Features & Issues (full history)

Compiled from all 117 released versions (v3.5.0 → v3.81.0) in RELEASE_NOTES.md.
Two parts: **A. Features built** (by area) and **B. Issues you found & how they were fixed**.

---

# A. FEATURES BUILT (by area)

## 1. Scanning & device discovery
- Full network scan: finds every device, names it, categorises it (camera, PC, phone, router, switch, printer, unknown).
- Parallel scan engine — device-finding, then conflict rounds, packet tests, names, UPnP, DNS, services, web pages all run side-by-side (target ~1 min on a /24 vs ~140 s before).
- 75-second cap on the final phase so one hung device can't freeze the scan.
- Quick loop/conflict check every few minutes between full scans; updates who's online from its ARP sweep.
- "Online only" default view; offline/known devices still available in the Show box (nothing deleted).
- Best-guess typing for devices with weak clues ("likely" phone/appliance/managed gear); remembers a learned type.
- Second-chance ARP retry for devices asleep on Wi-Fi (phones/cameras) — Windows, Linux, Mac.
- New/changed devices stay marked for 7 days ("new since…", "was under Unknown until…"), green highlight, per-category breakdown ("8 new: 6 cameras, 2 phones").
- Devices that stopped answering since last scan are flagged too.
- Search by MAC in any format; sort by any column; "one list by IP (no groups)" option.

## 2. Cameras & CCTV
- Separate **Cameras** and **Computers** menus (recorders told apart from cameras automatically).
- DVR/NVR auto-detected (web page, name, model, channel count, DVR port) and counted separately.
- **Login sweep** — one admin login tried once per device across PCs / cameras-NVR / routers-switches; auto-skips after refusals to avoid lockout; remembers the working login (encrypted on Windows).
- Reads model, serial, firmware, device's own stored name (Hikvision ISAPI, Dahua, XMeye/DVRIP port 34567, ONVIF).
- "Use the device's own name as its tag" (one click).
- **Line up cameras** — one fixed IP each in a camera block; can move Hikvision/Dahua/XMeye/ONVIF cameras itself (reserve IP → switch to DHCP → wait for it to answer), one at a time, stops at first failure; points the NVR channel at the new IP.
- Restart cameras across brands (Hikvision ISAPI, Dahua/CP-Plus HTTP, XMeye) — asks once for a login if none saved.
- Camera picture check — two snapshots a few seconds apart, flags frozen or blacked-out/covered cameras a ping can't see.
- PoE power watch — warns before the evening night-vision spike browns out cameras (set watt budget in Setup).
- Camera isolation — blocks cameras from the internet (both directions) while the NVR keeps working; reversible.

## 3. IP, binding & conflicts
- IP-MAC binding — one-click "Bind all devices to their current IP"; advanced strict/block-random-MAC behind a tick box; `check_ip` rejects bad IPs.
- IP conflict auto-fix — keeps the IP on the device the router can't move, moves the other to a free IP; needs one device tagged "Default device for its IP" (never guesses).
- "Show free IPs" — lists addresses no device uses, as ranges + full list, Copy all.
- Fixed-IP plan by device type (PCs / cameras / recorders blocks); restart → settle → "Bind confirmed (already in range)".
- Locally-administered MACs on cameras/printers/switches recognised as fixed (reservable), not "randomized".
- Single live IP kept when a device changed DHCP address (stale router IP moved to a note).

## 4. Bandwidth, usage & internet
- Bandwidth plan — groups, VIP/Boost (full speed, uncapped — fixed from the old 5 Mbps cap), per-user fair share, every Apply has an Undo.
- Live monitor — broadcast/multicast rate, router ping stability, link up/down, top talkers, graph.
- Usage tab — per-device/app/site history (SQLite), real app & website names (from the router DNS log + the PC agent), category tagging, insights/leak detection, dashboard HTML export.
- Data-leak watch — large uploads leaving the office by person/place/day (cloud, email, file-sharing, AnyDesk, Telegram, torrents); trusted apps excluded.
- NVR/DVR bandwidth calculator; camera chart.
- SNMP switch-port counters as a bandwidth fallback for devices NetFlow can't see (local camera↔NVR traffic).
- "Slow website?" diagnostic — where the connection stalls, with reversible router fixes.
- "Is it down for everyone or just us?" web check (DNS/connect/TLS/response stage + public status pages).

## 5. Security & defence
- Auto-defense (Pro) — 24/7, per-threat levels (notify / cut internet / isolate / power off), night-only option, exclude list, auto-release on a timer. Never cuts your own PC, the router, or the backbone.
- Network guard — block rogue DHCP, force all DNS through the router, block torrents, block randomized MACs; defaults safe, warns before disruptive options, reversible.
- Brute-force / password-guessing alert (Windows Event 4625) with inside-vs-outside/internet source marking.
- Vulnerability check (read-only, never logs in or exploits); packet capture & analysis; internet exposure (Shodan/Censys).
- Threat-intel feeds (Spamhaus DROP, FireHOL) correctly classified to the malware fix recipe.
- "Router keeps dropping for a few seconds" — correlates short gateway losses with ARP spoofing/storms/loops into one alert, names the MAC, PC-shield (lock gateway MAC) + reviewed fix.
- Fake/cloned camera MAC detection (A0:00:00:xx) as the real cause of gateway flap; duplicate-MAC detection.
- SNMP turned on automatically but safely — random private community (never "public"), LAN-locked, read-only, reversible.
- CGNAT / remote-access readiness check (read-only; refuses wide-open UPnP; suggests one scoped port + undo).
- Device whitelist — ticked devices always get internet, never blocked/quarantined.
- "Let blocked devices connect" — finds LAN interface set to ARP reply-only (blocks unbound phones), one-click fix with router backup + undo.

## 6. Fixer brain & auto-fix
- Learning brain — Naive-Bayes text model + ensemble vote (keyword rule + learned model + success history) with confidence; learns per-situation (trust a fix for cameras but not PCs; never when the attempt is from the internet).
- Ships pre-trained with an office-network curriculum (loops, storms, PoE, bandwidth, CCTV, data-leak, self-healing).
- Every auto-fix has an Undo + a post-fix regression check that auto-undoes a fix that causes a new problem; a fix-kind that keeps getting undone is tried more cautiously.
- Auto-fixes act on the first occurrence (not after 5 repeats) now that every fix is reversible.
- AUTO_SAFE kinds only (dhcp_conflict, multicast, loop, ip_conflict, MTU/MSS clamp); block/expose/reboot/quarantine/DNS kinds stay manual one-click.
- Read-only auto-diagnosis for alerts with no safe fix (e.g. router CPU busy).
- Teach-the-brain — paste Claude's `TEACH kind=…` lines; the next daily report shows what it newly recognised.

## 7. Reports, alerts & inventory
- Daily report (what broke, what was fixed/rolled back, what's open, what it couldn't work out, what's missing) — shareable, feeds the brain.
- Health log (CSV per month), alert history & trends page (14/30/90 days), export to CSV.
- Alert mute (1 hour everything / 1-3-7 days serious-only), remembered across restart; "Clear all alerts".
- Mark a problem "known" to hide it permanently (count-independent key); restore any.
- Inventory / asset register — real .xlsx export (frozen header, filters) + import edited sheet back (by MAC); owner, serial, purchase date, warranty, last-seen.
- PC details auto-collected per PC (maker, model, serial, Windows, CPU, RAM, disk, user, printers, antivirus).
- Router config backup & diff — read-only, section-by-section, passwords never stored, auto every 6 h, alerts on a real change.

## 8. PC Care & endpoint agent
- PC Care (This PC) — scan & report, BSOD/crash repair, slow-PC fix, C: cleanup, apps/drivers, network repair, printer/sharing repair, RAM check, security check — each makes a restore point + logs an UNDO.
- One PC agent — "Fix my PC" one-click cleaner for staff (temp/caches/Recycle Bin, flush DNS, restart Explorer — never touches real files); background USB/data-leak watch + per-app network naming + 30-min detail refresh.
- LeakWatch — USB drive plug/copy watch (path + size, never contents), alerts by user/PC/department.

## 9. Phone app & remote access
- Phone link (LAN-only by default) — pairing code, token auth; mirrors the PC (devices, alerts, map, usage, troubleshoot, actions: ping/trace, WOL, block, isolate, bind, guard, config backup, router commands).
- Remote access from outside the office — opens NO router port; Cloudflare tunnel forwards only the remote-access port; Tailscale permanent address advertised so the phone address stops going dead; sign-in required (Pro).
- Users & sign-in (accounts) + audit log of every change (Pro).

## 10. Platform, packaging & UI
- Windows portable .exe + installer + Microsoft Store package; auto-update (daily 15:00 check, silent download, "update available" prompt, waits for a running scan).
- Linux .deb (app menu + icon, scans without sudo via setcap, self-update via pkexec) + portable binary; Mac login-item autostart.
- Coloured section headers across every page; menu reorganised so each tab does one job (≤5 sub-items).
- Network map (matrix/rows), Fix Assistant tab (plain-language → shipped fixes only, never raw commands).

---

# B. ISSUES YOU FOUND & HOW THEY WERE FIXED

## Recent line-by-line audit (R-001 → R-008, this round)
| Issue | Cause | Fix | Ver |
|---|---|---|---|
| Scan stuck at "Waiting for the last answers…" | Finalisation loop had no overall deadline — one hung device froze it | 75 s cap, move on with partial results | 3.76 |
| **Settings wiped overnight ("a new bug every day, no update")** | Non-atomic settings write + loader fell back to blank `{}` on corruption | Atomic write (tmp+fsync+rotate .bak+replace) + recover from .bak | 3.77 |
| Background settings-save race | `firewall()` saved settings off-thread, no lock | `_save_persist()` marshals off-thread saves to main thread | 3.77 |
| IP conflict kept re-appearing | Real conflict; auto-fix needs a tagged "keeper", dialog never said so | Troubleshoot text now explains the tag | 3.78 |
| Pro license could be lost on a crash | License written non-atomically | Atomic write | 3.79 |
| Reports showed wrong version (v3.18.0) | Stale duplicate VERSION constant in nd_core | `core.VERSION = VERSION` at startup | 3.80 |
| Device DB (tags) had no backup recovery | No .bak net | `save_db` rotates .bak, `load_db` recovers | 3.80 |
| **SNMP on but switch read still fails** | App sets a random private community; Read box defaulted to "public" | Read box pre-fills the saved private community | 3.81 |

## Earlier real bugs found & fixed
- **Quick check raised NameError on every run** (silently "check failed" in the health log) — referenced an undefined variable; fixed + regression test (3.28.1).
- **Port scanner did nothing since 3.43.0** — a new `_ports` method clashed with the scanner's own; renamed (3.52.0).
- **Camera-check could corrupt settings** — wrote from a background thread; now gathers in background, writes once on main thread (3.65.0).
- **Router config backup didn't work (3.28.0–3.28.3)** — used `/export` (can't read >4 KB over API on ROS6, date line made every backup look "changed", printed passwords); now read section-by-section, passwords never stored (3.28.4).
- **IP-MAC binding silently did nothing over the API** — commands written in WinBox terminal style (bare `add`); now full-path `/ip dhcp-server lease add …` (3.69.0).
- **App's own scan raised "broadcast storm" / "router not answering"** — monitor now stays quiet during/after the app's own scan; multicast flood told apart from a broadcast storm (3.36.1).
- **PC agent data never showed** — app read the wrong folder + the CSV UTF-8 BOM skipped every row (3.39.1).
- **Crash on startup "Item already exists"** — two alerts in the same millisecond got the same id; ids now unique + table tolerates duplicates (3.21.3).
- **Devices shown twice (two IPs)** — stale router ARP/lease kept as a second IP; live IP now wins (3.70.0).
- **Cameras falsely flagged "randomized MAC — cannot be reserved"** — locally-administered MAC treated like a phone's privacy MAC; now recognised as fixed (3.72.0).
- **"Fake/cloned MAC" warned for every placeholder-MAC camera** — now just an INFO note unless two devices truly share one MAC (3.74.0).
- **False IP clashes from phones** — randomized-MAC phones briefly reusing a DHCP address no longer counted (3.75.0).
- **CGNAT false reading with a VPN active** — Tailscale rerouted the check; now detects an active tunnel + reads two providers (3.27.1).
- **VIP/Boost ran slower** — put the device in a 5 Mbps pool; now top-priority and uncapped (3.22.0).
- **NVR blocked with the cameras** — recorder now recognised by model/channel-count/port even without "NVR" in the name (3.22.0).
- **Auto-defense could cut your own PC / router / switch** — now a permanent "alert only, never cut" list (3.22.0).
- **Phone address kept going dead** — Cloudflare quick-tunnel address changes on restart; Tailscale permanent address now advertised (3.22.0 / 3.28.x).
- **Auto-fix list stayed empty** — old "5 repeats of the exact same alert" rule rarely fired; now acts on first occurrence (3.24.2).
- **Threat-list hits had no fix** — Spamhaus/FireHOL alerts didn't contain the word "malware" so matched no recipe; now classified correctly (3.24.2).
- **Blocked sites didn't reach phones** — phones on their own DNS ignored the block; "force DNS" option added, reversible (3.64.0).
- **Blocked sites also handled MSS/MTU nag** — MTU warning no longer repeats after the clamp is applied (3.18.x).
- **Remote-tunnel error dialog itself crashed** — a queued callback closed over a deleted `except … as e` variable; captured to a plain var (3.28.1).
- **Two devices on one IP (a phone shown as the DVR)** cut phones off — phone check now catches the exact mix-up (3.19.1 / 3.20.0).

## Linux / packaging saga (3.23.0 → 3.23.11) — the .deb wouldn't open
A chain of "builds fine, never runs" bugs, each caught and fixed: `/proc` crash from setcap (3.23.1), missing `libtk8.6.so` (3.23.2), CI only checked compile not run (3.23.3), build machine's own Tk masked the gap (3.23.4), GitHub's `LD_LIBRARY_PATH` papered over it for the whole job (3.23.5), stray Tcl/Tk survived purge (3.23.6), Tk libs bundled in the wrong folder vs `_tkinter` (3.23.7), the verify step gave a false alarm (3.23.8), and finally **setcap puts the binary in secure-execution mode where glibc ignores `LD_LIBRARY_PATH`** — fixed by baking the library path in with patchelf RPATH (3.23.9). Then Linux feature-parity gaps filled (3.23.10) and .deb self-update via pkexec (3.23.11).

## Release-pipeline issues
- 3.37.0 / 3.37.1 / 3.38.0 never reached you — a test imported pytest the Windows build check lacked; rewritten as unittest (3.38.1).
- 3.30.0 / 3.30.1 never released — a test couldn't delete its own temp folder (3.30.2).

---

# C. PENDING / UNCONFIRMED / KNOWN LIMITS (the "at-risk" list)

These were built or promised but **never confirmed on your real hardware**, or explicitly left as "next". Worth verifying on the office network — they're the items most likely to be forgotten.

## Built but NOT yet tested on real devices (tested only against simulated ones)
- **Line up cameras / move to fixed IP** — move ONE camera first and check its picture before the rest (3.29 / 3.31).
- **XMeye / NetSurveillance cameras & recorders** (port 34567) — not tested on a real XMeye device (3.31).
- **ONVIF camera move** — not tested on a real ONVIF camera (3.31.1).
- **NVR/DVR auto-update of a moved camera's IP** (Hikvision/Dahua) — not tested on a real recorder (3.30.1).
- **Usage real-name DNS log line** — not confirmed on a real router (log format taken from RouterOS docs) (3.30).
- **Gateway ARP protection (reply-only) guard** — not tested on a real router; apply at a quiet time with Undo ready (3.40).

## Scan speed never measured on your network
- The parallel-scan work (3.33 / 3.34) targets ~1 min on a /24 vs the ~140 s you last saw — **actual time was never measured on your network**. Worth timing a real scan.

## Explicitly "next" / not built yet
- **One-click filter to show only recorders** (DVR/NVR) — promised as "next" in 3.62, not confirmed shipped.
- **PC Care — not included yet:** remove user accounts, duplicate finder, folder organizer, and the small tools (bulk rename, resize pictures) — they need typed answers the page doesn't take (3.36).

## Known limits (by design — may still bite you)
- **Force-DNS site block:** a phone using Private DNS over DNS-over-HTTPS can still slip through — turn Private DNS off on the phone, or ask to block the providers' IPs (3.64).
- **LeakWatch / endpoint:** a PC without the agent installed is not watched; can't catch a leak by screenshot or printing; per-process byte totals not collected (3.38 / 3.39).

## Stated requests NOT fully delivered (recovered from cross-session memory)
These came from your chats (including ones since deleted) and were filed in memory. Checked against what actually shipped — these three are **incomplete**, and none were flagged as pending in the release notes:
- **Per-app bandwidth (MB) breakdown on each PC**, like Windows Settings → Data usage. Only PARTIAL: the agent names *which app* opened each connection, but release note 3.39 states **per-process byte totals are not collected** — so the exact "this app used X MB" number you wanted does not exist yet. **Real gap.**
- **Low-latency remote access that does NOT depend on the PC being on.** Current remote access (Tailscale / Cloudflare tunnel) needs the office PC switched on. An always-available path (a small always-on device, or a cloud relay) was never built. **Open — unsolved.**
- **Full feature parity: every Windows function also in Android + Ubuntu.** Linux got a parity pass (3.23.10) and the phone app mirrors many actions, but complete 1:1 parity was never confirmed. **Verify / likely partial.**

## From your saved notes / standing goals (verify these are fully met)
- **Directors' + your own PC "faster internet sometimes"** (e.g. backup uploads) — VIP/Boost exists (uncapped, 3.22); confirm it's set up for the right PCs.
- **Cameras on local network only, remote viewing via NVR app** — camera-isolation exists; confirm it's applied.
- **"MNC-level testing so disruptions never repeat"** — the line-by-line audit (R-001…R-008) is the first pass; a real-hardware test round on the untested items above is the natural next step.

> Note: I searched your chat history for anything missed, but the chat index returned the ERP (FanAir) project thread, not the Network Doctor conversation, so this at-risk list is drawn from the release notes' own "not yet tested / next / limit" notes plus your saved Network Doctor notes — not from re-reading the Network Doctor chat. If you paste the Network Doctor chat link, I can scan it directly for anything these sources don't cover.

---

# D. ONE-TRY vs REPEATED — combined analysis

Every issue and feature classified by whether it landed working on the first attempt, or needed multiple versions / kept coming back.

## Combined totals
| Category | ✅ Clean in 1 try | 🔁 Iterated / repeated | Total |
|---|---|---|---|
| Issues (bugs) | 23 | 9 | 32 |
| Features | 29 | 13 | 42 |
| **Combined** | **52 (70%)** | **22 (30%)** | **74** |

**The one pattern across all 22 hard ones:** they only break, or stay unconfirmed, against **real hardware / a real network** — the MikroTik router, real XMeye cameras, a clean Linux install, the live office. The 52 clean ones were app-internal logic/UI that the test suite fully covers.

## 🔁 Issues that needed multiple tries or repeated (9)
| Problem | Versions | Why it was hard |
|---|---|---|
| Linux .deb wouldn't open | 3.23.0→3.23.11 (~11) | Failed on real machines 3× running; CI masked it each time |
| Settings wiped overnight | R-002+R-003+R-007 (3) | "A new bug every day"; took 3 fixes to kill the class |
| Config backup didn't work | 3.28.0→3.28.4 (4) | Only broke on a real RouterOS router |
| SNMP read still fails | 3.63→3.81 (2) | Read box kept defaulting to "public" |
| IP conflict kept re-appearing | R-004 + 3.61 (2+) | Real recurring conflict; flagged "why again" |
| WiFi cut off after binding | 3.42/3.60/3.69 (3) | Three causes: fake MAC, reply-only ARP, binding not applying |
| Camera move / XMeye / ONVIF / NVR | 3.29/3.30.1/3.31/3.31.1 (4) | Still untested on real cameras |
| Phone remote address goes dead | 3.22 + 3.28.x (2) | Cloudflare tunnel address kept changing |
| Versions never reached you | 3.30.x, 3.37/3.38.x (2) | Build/test pipeline blocked the release |

## 🔁 Features that needed rework (13)
Line up cameras (6 versions, unconfirmed) · Login sweep (4) · Usage real names (4) · IP-MAC binding (3) · SNMP (3) · Remote access/phone link (5+) · Menu/UI reorg (6+) · PC Care/agent (5) · Auto-fix brain (5) · Linux .deb (11) · Config backup (5) · Data-leak/LeakWatch (3) · Restart cameras (2).

## ✅ Clean in one try — issues (23)
Stuck scan · License atomic-write · Report wrong version · Quick-check NameError · Port-scanner name clash · Camera-check settings race · Startup "Item already exists" crash · Devices shown twice · Cameras false "randomized MAC" · "Fake/cloned MAC" false warning · False IP clashes from phones · CGNAT false reading with VPN · VIP/Boost ran slower · NVR blocked with cameras · Auto-defense cut own PC · Auto-fix list stayed empty · Threat-list misclassified · Blocked sites not reaching phones · Remote-tunnel error-dialog crash · Phone shown as DVR · PC-agent data not showing · Own-scan false "broadcast storm" · MTU nag after clamp.

## ✅ Clean in one try — features (29)
Full scan · Quick check · New/changed 7-day marking · Online-only default · Best-guess typing · Sort/filter/MAC search · Cameras & Computers menus · DVR/NVR auto-detect · Show free IPs · IP-conflict auto-fix · Fixed-IP plan · Bandwidth plan/VIP · Live monitor · SNMP bandwidth fallback · Slow-website check · Down-for-everyone check · Brute-force alert · Vuln/capture/exposure · Router-drop diagnosis · Fake-MAC detection · CGNAT check · Whitelist · Let-blocked-connect · Daily report · Alert mute · Mark known/Clear all · History & trends · Inventory Excel · Fix Assistant · Network map.

*Counts are by distinct issue / major feature; sub-features would run higher.*

---

*Source: RELEASE_NOTES.md (117 versions) + /areas/network-doctor.md. Bug-detail reference for the recent audit: docs/AUDIT_REPAIRS.md.*
