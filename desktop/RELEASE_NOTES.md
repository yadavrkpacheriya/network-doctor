## Network Doctor 3.49.0

### Setup page: colour-headed sections, easy to scan
The Setup page was a wall of same-looking boxes. Every section now has a small coloured title bar, so you can
spot the one you want at a glance:
- Quick actions (slate), App updates (teal), Automatic checks 24/7 (green), Phone app link (blue),
  Website names & filtering (indigo), Router login (purple), Help improve (grey).
Nothing moved or changed - only the look. The same coloured-section style can be applied to any other page.

## Network Doctor 3.48.0

### Simpler pages: one main action, the rest under "Advanced"
Same clean-up as the binding page, now on the busiest pages:
- Network guard: one "Turn on protection (apply on router)" button; UNDO, make/copy/save commands moved under
  Advanced.
- Inventory: "Export to Excel" + "Refresh" stay; Tag, Import, Get PC details, Collect-from-all-PCs moved under
  Advanced.
Every option is still there - just hidden until you tick "Advanced", so the normal view is compact and clear.

## Network Doctor 3.47.0

### Simpler IP-MAC binding: one button
- The binding page now opens with a single big button - "Bind all devices to their current IP" - which ticks
  every bindable device, keeps each on the IP it already has, and reserves them all on the router in one go.
  No strict mode, no manual IPs, nothing that can cut a device off.
- All the old controls (strict mode, block randomized MACs, moved-device re-bind, bridge name, set-IP, forget,
  show/copy/save commands, PC fix script) are still there - tucked behind an "Advanced" tick box, so the normal
  view stays clean.

## Network Doctor 3.46.0

### Clearer, better-categorised menus
The top menu is reorganised so each section does one job:
- Scan & Devices (IP scan: all devices, network map, login sweep)
- Inventory (asset register, IP-MAC binding)
- Network Issues (alerts, problems, root cause, health checks, history)
- Fixer (commands, PC Care repair & clean-up)
- Internet & Usage (live monitor, usage, bandwidth plan, slow website)
- Advanced Network (switches, port scanner, MAC lookup, Wake-on-LAN, remote access, DNS/website/speed tests)
- This PC & Wi-Fi (LAN speed, Wi-Fi analyzer, adapters, MTU, subnet)
- Security (login attempts / brute force, critical devices)
- Firewall (network guard, website firewall)
- Setup
Nothing was removed - every page is the same, just grouped where you would look for it.

## Network Doctor 3.45.0

### New page: Login attempts (brute force) - with logs, history and inside-vs-outside
- Network Tools > "Login attempts": shows failed logins from every PC running the agent - the account tried,
  how many times, the logon kind, and the time - over the last 7 days.
- Each source is checked against your whole network and marked clearly: [inside network] (with the device name),
  [OUTSIDE/internet] (a public IP), or [this PC]. Outside-IP attempts are listed first and in red.
- An attempt from an outside IP still raises its own alert (critical), so you are told even without opening the
  page. Uses Windows' built-in failed-logon log (Event ID 4625) - no third-party tool.

## Network Doctor 3.44.0

### Brute-force / password-guessing alert (Windows Event ID 4625)
- The PC agent now reads the Windows Security log for failed logons (Event ID 4625) and reports the account
  tried and where it came from. Network Doctor raises an alert when the tries pile up on a PC - "N failed
  logins on PC: account 'Administrator' from 203.0.113.45", with the source IP.
- An attempt coming from the internet (a public IP) or over Remote Desktop is marked critical, with the advice
  to close RDP to the internet and change the password. Inside-the-network attempts are flagged too.
- Uses only built-in Windows logging - no third-party tool. Reading the Security log needs admin, which the
  agent already has (it runs as SYSTEM).

## Network Doctor 3.43.0

### See how many devices are on each router port (find the camera switch)
- Network Tools > MAC lookup > new "Router ports (devices on each)" button: asks the router (read-only) and
  lists every router port with how many devices sit on it, which known devices they are, and how many carry a
  fake / cloned MAC. A port with many devices has a switch on it; a port full of fake-MAC devices is the
  camera segment - so you can find the one cable to fix or isolate.

## Network Doctor 3.42.0

### Detects the real cause of the gateway flap: fake / duplicate camera MACs
On a flat network (cameras on the same switch as the PCs), the router "dropping for a few seconds" is usually
caused by cheap CCTV cameras shipped with cloned, non-real MAC addresses (A0:00:00:xx and the like). Several
near-identical addresses confuse the ARP tables and flap the gateway.
- New problems, found on every scan: "Devices with a fake / cloned MAC address" and "The same MAC address on two
  or more devices", each listing the cameras and IPs.
- The fixer brain explains the fix: give every camera a unique fixed IP (line-up), optionally set a real MAC in
  the camera's web page, and ideally move cameras to their own switch. It also explains why IP-MAC binding kept
  cutting devices off - the router cannot tell duplicated MACs apart - so it tells you NOT to bind these.

## Network Doctor 3.41.0

### Powered-off / disconnected devices drop off the active device list
- All devices now opens on "Online only" by default, so a PC that is switched off or unplugged is not shown in
  the active list. Pick "All devices" in the Show box to see offline/known devices again (nothing is deleted).
- The quick loop/conflict check (every few minutes) now also updates who is online from its ARP sweep, so a
  device that stops answering leaves the list within minutes - not only after the next full scan.

## Network Doctor 3.40.1

### Router-drop fix now leads with a shield that needs no binding
Since IP/MAC binding takes time (and MAC/IP changes can drop users offline), the "router keeps dropping" fix now
leads with locking the router's real MAC on each PC - the PC then ignores fake ARP for the gateway. No router
change, no binding, affects no one else.
- The "Fix my PC" agent does this automatically on every click: it pins the gateway's MAC, but only when the
  internet is working at that moment, so it can never pin a spoofed address. A reboot clears it.
- The fixer-brain steps were reordered: shield the PCs now -> find and unplug the offender -> (later, when
  ready) bind devices + reply-only.

## Network Doctor 3.40.0

### "Router keeps dropping for a few seconds" is now diagnosed and fixed
Your router vanishing for 5-10 seconds many times a day is almost never the internet or a cable - it is a
device faking addresses (ARP spoofing / a wrong static IP), a loop, or a broadcast storm flapping the router's
address. Network Doctor now tells these apart from a real outage.

- The live monitor correlates repeated short gateway losses with ARP conflicts, storms and loops in the same
  window and raises ONE clear alert: "Router keeps dropping for a few seconds (N times) - this is NOT the
  internet going down. Cause: ... Devices: ...", naming the MAC(s) behind it.
- The fixer brain has a new permanent fix for it: find and unplug the offender (MAC lookup > Find on the
  network), bind every device to its IP, then turn on "only the router answers ARP" (reply-only) so a faked
  gateway address is simply ignored. An immediate PC shield (lock the router's MAC) is included.
- New router guard option: gateway ARP protection (static ARP for the gateway + reply-only), fully reversible,
  with a built-in warning to bind all devices first so nothing loses the network. It is never auto-applied -
  it can cut a mis-set device off, so it stays a reviewed, one-click action.

## Network Doctor 3.39.1

### Fix: the app now actually reads the PC agent's data
- The agent writes to C:\ProgramData\NetworkDoctor\agent; Network Doctor was looking in a different folder, so
  nothing showed up. It now reads that folder (and the shared folder set in Settings, and the old one) together.
- The agent's CSV files carry a UTF-8 BOM (Windows PowerShell): the reader skipped every row because of it.
  Fixed - connections and USB events are read correctly now.
- Verified on a real PC: details, resource use and 136 live connections read in; AnyDesk named from its process.

## Network Doctor 3.39.0

### One PC agent: users get a single "Fix my PC" button; Network Doctor gets everything
Replaces the separate USB and cleanup scripts with one agent (repo `endpoint/` folder, install per PC with
`install-agent.cmd` as administrator). Users see only a "Fix my PC" shortcut on the Desktop; everything else is
background.

- **Fix my PC (one click):** cleans junk (temp, caches, Windows Update leftovers when admin, Recycle Bin),
  flushes DNS, restarts Explorer, shows space freed - never touches real files - and then sends this PC's
  fresh details, resource use and connections to Network Doctor. So the inventory and usage update the moment
  a user clicks.
- **Background (from logon):** watches USB drives (plug in / out, files copied - the leak alerts from 3.38),
  every minute records which app (process) is using the network, every 30 min refreshes details + CPU/RAM.
- **No more per-PC detail script:** each PC lists itself into the inventory automatically (maker, model,
  serial, Windows, CPU, RAM, disk, user, printers, antivirus).

### Usage names get accurate from the PCs
- The network alone sees only address-to-address, so it guessed "CDN" / "service not known". The agent reports
  which app opened each connection, so a **native app owns its traffic**: WhatsApp, Telegram, Acronis, AnyDesk,
  OneDrive, Teams, Steam, torrents and more are named exactly. Browser traffic keeps its website name (better
  than "chrome.exe").
- Resource monitor per PC: CPU %, memory % and the heaviest apps.

Honest limit: the agent must be installed on each PC; per-process byte totals are not collected (Network Doctor
already has the bytes per address from the router and uses the agent only to put the right app name on them).

## Network Doctor 3.38.1

### Fix: the Windows release build failed on 3.37.1 / 3.38.0
- A new test file imported pytest, which the Windows "code loads" check (plain unittest) does not have, so the
  build stopped before publishing. Rewritten with unittest; the whole suite runs under both now. This is why
  3.37.0, 3.37.1 and 3.38.0 did not reach you - their contents ship in this build.

### One-click "Clean my PC" for users (bundled with LeakWatch, in endpoint/)
- A safe cleaner any staff member can double-click: clears temp files, browser/app caches, Windows Update
  leftovers (when run as admin), the Recycle Bin, flushes DNS and restarts Explorer, then shows the space
  freed. It never touches Documents, Desktop, Downloads or any real file.
- `install-cleanup-shortcut.cmd` drops a "Clean my PC" shortcut on the Desktop. For a deep repair, the in-app
  PC Care page (admin) is unchanged.

## Network Doctor 3.38.0

### USB / data-leak watch on the PCs (LeakWatch endpoint agent)
- The office network can never see a file copied to a USB pen drive, phone or external disk - it never touches
  the network. A tiny agent (in the repo's `endpoint/` folder) now runs on each PC and reports it.
- It records a removable drive plugged in or removed, and any file copied / created / renamed on it (path and
  size, never contents), with the PC and the logged-in user. It reads nothing else and sends nothing to the
  internet - it only appends CSV lines to a shared folder on the IT PC.
- Network Doctor reads that folder every 5 minutes and raises an alert when files are copied to USB, named by
  user, PC and department (critical over 20 MB). Point it at the share in Settings > endpoint_dir.
- Install per PC with `endpoint/install-leakwatch.cmd` (run as administrator); `uninstall-leakwatch.cmd`
  removes it. See `endpoint/README.md`. Honest limit: a PC without the agent is not watched, and it cannot
  catch a leak by screenshot or printing.

## Network Doctor 3.37.1

### Data-leak watch: large uploads leaving the office
- Usage insights now list every large upload of the last 7 days by person (name - department - IP), place and
  day: over 300 MB in a day to cloud storage, e-mail, messaging, AI tools or photos, and over 100 MB to file
  sharing (WeTransfer, MEGA, Dropbox), Telegram, remote control (AnyDesk, TeamViewer), VPN, torrents or a
  server with no name. File-sharing / remote-control / unnamed places are marked critical.
- Apps marked as trusted (a backup) are left out. It shows size and place only: the network cannot see which
  file was sent.

## Network Doctor 3.37.0

### Usage: clear app names instead of company / whois texts (old days are renamed too)
- **Acronis Cloud Backup is one line.** It was split over "acronis.com", "Acronis Asia Pte Ltd administrator",
  "CDN (various)" and "Microsoft (other)" because backups travel through Akamai / Azure addresses.
- A real site name always wins over a company bucket (CDN, Amazon cloud, Microsoft other...).
- Server host names and whois texts are no longer shown as apps: Meta servers go to Facebook / Instagram /
  WhatsApp, rented servers (Linode, Vultr, Alibaba...) to one line, Indian ISP addresses to one line, and what
  has only an owner ("netutils-mnt", a person's name) to "Unnamed servers" with the owner kept as the site.
- New apps: Certificate checks, Website analytics / trackers, DNS look-ups (Google DNS).
- The stored history is renamed once at start, so the dashboard of past days is clear as well.
- New warning in Usage insights: "N% of the traffic has no website name", with the reason (router DNS log not
  arriving / devices asking Google DNS directly) and the two settings that fix it. Nothing on the router is
  changed automatically.

### All devices: sorting works, and a device can be found by its MAC alone
- Clicking a column title (IP, name, MAC...) now sorts the devices inside every group, ascending then
  descending, and the order stays after a rescan. Before, only the group headings were sorted.
- New tick box "One list by IP (no groups)": every device in one list in IP order.
- The search box takes a MAC in any form (00-22-46-53-F7-89, 0022.4653.f789, 00224653F789).
- Network Tools > MAC lookup > "Find it on the network (asks the router)": for a MAC no scan has found
  (a "top sender" in an alert): the router's ARP table, DHCP lease and port, the history, and whether it is
  this PC. Read-only.

### Usage alerts tell two people with the same name apart
- "Hitesh - Accounts (192.168.0.57) used 1.5 GB ..." : department (when set) and IP are always shown.

## Network Doctor 3.36.1

### No more "Broadcast storm" / "Router not answering" alerts caused by the app's own scan
- While Network Doctor scans, runs the quick check or the login sweep (and for 25 s after), the live monitor
  no longer raises a storm or a "router not answering" alert: the burst of ARP questions and probes is the
  app's own work. A real storm or a router that is really down is still there afterwards and is reported
  then.
- A burst where most broadcasts come from this PC is never reported, and this PC is never listed as a
  "top sender".
- When the rate is mostly multicast (the counter is far above the broadcasts actually seen) the alert now
  says "Multicast flood" - a camera / recorder / TV box streaming to every port - with the IGMP-snooping
  fix, instead of "Broadcast storm: find the looped cable".
- The sweep of empty addresses is a little gentler again (128 at a time instead of 192 / 256).

## Network Doctor 3.36.0

### New page: This PC & Wi-Fi > PC Care (repair and clean-up for this Windows PC)
- FastClean is now part of Network Doctor, so there is one app and it updates through the built-in updater.
- One button per job: Scan and report (read-only), Blue screen and crash repair, Slow PC and hang fix,
  C: drive clean-up, Apps and drivers, This PC's network repair, Printer and sharing repair, RAM check,
  Security check, Files by category - and RUN ALL.
- It works on THIS PC only. It never logs in to, or changes, the router or any other device.
- Actions start at once and ask no questions. Two tick-boxes replace the old questions: switch off common
  non-essential startup apps (on) and update all apps with winget (off - leave it off on ERP PCs).
- Every repair makes a Windows restore point first and logs each setting it changes in
  <drive>:\PCCare_Backup, with UNDO_SETTINGS.bat inside. Reports go to Desktop\PCCare_Reports.
- Needs Administrator (the page offers "Restart as Administrator"). Windows only.
- Not included yet: remove user accounts, duplicate finder, folder organizer and the small tools
  (bulk rename, resize pictures...) - they need answers typed in, which this page does not do yet.
- Tested by the automatic checks on a clean Windows machine (script syntax + a full read-only scan).
  The repair actions themselves have run on one real PC so far - tell me what you see on others.
## Network Doctor 3.35.1

### All devices: cameras the Login sweep has never read are shown in blue
- A camera / recorder that is online but has no login check yet (while others have one) is listed first in
  blue with "(not read by the Login sweep yet)", and the group header counts them. This is how a device
  that joined the camera group before 3.35.0 - too early for the "new / changed" mark - still stands out.
- Run the Login sweep once and they turn normal (or show under "Needs attention" there).

## Network Doctor 3.35.0

### All devices: what is new or changed stays visible for a week
- The "(new)" mark only compared with the scan just before, so it was gone after the next hourly scan - a
  count going from 40 to 42 cameras could not be traced to the two devices behind it.
- A device first seen in the last 7 days now shows "(new since 13-Nov 22:49)" beside its name, in green.
- A device that moved to another group (for example out of "Unknown devices" when the app learned what it
  is) shows "(was under 'Unknown devices' until 13-Nov 23:10)" - a higher count is often this, not a new
  device.
- The group header says how many: "CCTV cameras / DVR / NVR (42) - 2 new / changed this week", and those
  rows are listed first. "Show: New / changed in the last 7 days" lists only them.
- The marks start from this version on: a change that happened before the update cannot be shown.

## Network Doctor 3.34.1

### The router log is no longer filled with "logged in / logged out via api"
- Every reading the app takes from the router (DNS names each minute, leases, bandwidth, backups...) used
  to log in and out again - hundreds of lines an hour in the router's log, hiding the lines that matter.
- The app now keeps ONE login open and reuses it. You will see a single "logged in ... via api" when the app
  starts (and again only if the router restarts or the connection drops).
- If the router login is changed in Setup, the kept login is closed at once.

## Network Doctor 3.34.0

### Scan: everything after "finding devices" now runs side by side
- Once the devices are found, the IP-conflict rounds, the packet tests (all-replies ARP, rogue-DHCP listen,
  loop echo), the duplicate-reply test, computer names, UPnP, reverse DNS, open services and device web
  pages no longer wait for each other. Every check is still done; only the waiting overlaps.
- The conflict rounds (which empty this PC's ARP cache) start only after the short service probes, so they
  cannot hide an open service.
- A device that answers only late (it slept through the first sweep) is still identified, in a short extra
  pass at the end.
- The Health log now says where the time went: "Scan took N s: finding devices X s, identifying + tests Y s".
- Aim: about a minute on an office /24 instead of about 140 s. Not measured on a real network yet.

## Network Doctor 3.33.1

### Faster scan
- The scan asked its questions one after the other, and most of each step is waiting for devices that never
  answer. Computer names, UPnP, reverse DNS and the rogue-DHCP check now run at the same time as the port
  check; file-sharing names run beside the web pages. Nothing was removed from the scan.
- Empty addresses are swept in fewer waves (each empty address costs seconds of waiting, not CPU).
- Not measured on a real network yet - the last scan there took about 140 s; tell me the new time.

## Network Doctor 3.33.0

### Login check runs by itself after every scan
- After each scan (also the one at start-up) every device that has a remembered login is asked once, with
  exactly that login - nothing typed, nothing guessed. Turn "Remember the login that works for each device"
  off to stop this.
- What was read goes to the Inventory: model, serial number, firmware, the name stored on the device, and a
  new "Login check" column (OK / LOGIN REFUSED / NOT REACHABLE with the time). The Excel export has them too.
- The Login sweep page now shows only what needs a person ("Needs attention"): new devices without a login,
  refused logins, devices that did not answer. Choose "All" to see everything.

### New alerts (pop-up at once, then in Alerts)
- "A device's password was changed": the remembered login of a camera / recorder / PC is refused. The login
  is forgotten at once, so it is never sent again.
- "A camera / recorder stopped responding": it is on the network but its login service does not answer, or
  a camera / recorder with a remembered login is gone from the network.
- The same problem pops up once, not after every scan; it is counted in Alerts until it is fixed.
- These are found only for devices whose login was remembered by a sweep with 3.32.0 or later - run the
  Login sweep once with the logins typed.

## Network Doctor 3.32.0

### Login sweep remembers the login that works for each device
- New tick box "Remember the login that works for each device" (on by default). After a sweep, the login
  that worked is kept per device; the next sweep tries that one first, so nothing needs typing for those
  devices - "Start scan" works with the login boxes empty.
- If a remembered login is refused (the password was changed), it is forgotten at once and the typed logins
  get their normal single try each. A remembered login never counts towards the "stop to avoid locking the
  account" rule, and the same refused login is never sent twice to a device.
- "Line up cameras" uses the remembered logins too, for cameras and recorders.
- Passwords are stored encrypted for this Windows user (the same protection as the router login). On Linux
  they are only encoded in your own settings file, not encrypted. "Forget saved logins" removes them all.

## Network Doctor 3.31.1

### Line up cameras: any camera that answers ONVIF can now be moved
- In a real sweep 37 of 40 cameras were read through ONVIF, not through a brand's own page - and the mover
  only knew Hikvision / Dahua / XMeye pages, so all of them would have been "by hand". ONVIF cameras are now
  switched to automatic IP (DHCP) through ONVIF itself and restarted only when the camera asks for it.
- Login sweep: a camera read through ONVIF now also shows the name stored on it (when the camera gives one).
- A camera that answers ONVIF keeps being read that way; its own XMeye login (port 34567) is tried only when
  ONVIF gives nothing, so a login that works today is not refused through another door.
- Recorders: only Hikvision, Dahua and XMeye recorders are updated automatically (ONVIF has no standard way
  to change a recorder's camera list) - for others type the new IP by hand.
- NOT yet tested on a real camera - move ONE camera first and check its picture.

## Network Doctor 3.31.0

### XMeye / NetSurveillance cameras and recorders (port 34567)
- Login sweep: XMeye devices are now really logged in to (before: "not supported"). The sweep shows whether
  the login works, model, serial number, firmware and the name stored on the camera - so "Use device's own
  name as its tag" works for them too.
- Line up cameras: XMeye cameras can be switched to automatic IP (DHCP) and moved into the camera block like
  Hikvision and Dahua ones, and an XMeye recorder's channel is pointed at the camera's new IP afterwards.
- The same safety rules apply: every login is tried once per device, one camera is moved at a time, and the
  run stops at the first camera that does not come back.
- NOT yet tested on a real XMeye camera or recorder (only against a simulated one). Many of these cameras
  fall back to 192.168.1.10 when they get no IP - move ONE camera first and check its picture.

## Network Doctor 3.30.2

- 3.30.0 and 3.30.1 were never released: a new test failed on the Windows build machine (the test could not
  delete its own temporary folder). Fixed; this is the first release with everything listed under them.

## Network Doctor 3.30.1

### Line up cameras: the recorder gets the new IP automatically (Hikvision and Dahua NVR / DVR)
- Right after a camera has moved, each recorder that accepted a login in the Login sweep is asked for its
  camera list; the one channel that pointed at the camera's old IP is pointed at the new one. Nothing else
  on the recorder is changed. On Hikvision the app then waits for the recorder to show that channel online
  and says so in the Note column (or says it is still offline).
- Include the recorders in the Login sweep and keep their login filled in when you press Move.
- Other recorder brands, or a recorder whose login was refused: type the new IP there by hand as before.
- NOT yet tested on a real recorder (only against simulated ones) - move ONE camera first and check its
  picture before moving the rest.

## Network Doctor 3.30.0

### Inventory: real Excel sheet, and edits come back
- Inventory > "Export to Excel" now writes a real .xlsx (bold frozen header, filter buttons) with every
  detail plus new columns: Owner, Purchase date, Warranty until, Last seen.
- "Import edited Excel sheet": change Name, Department, Location, Owner, Serial no., Purchase date,
  Warranty until, Router port or Notes in Excel, save, import. Only changed cells of known devices (by MAC)
  are taken. A serial number can now be typed for devices that cannot report one (cameras, switches).

### Usage: the app / website instead of "Google server", "Meta", "CDN"
- Many apps share the same Google / Meta / CDN addresses, so traffic alone cannot say which app it was.
  The router can say which device asked for which website name: its DNS log is now read, and a shared
  address is named after what that device actually opened.
- This needs one more line on the router. Press Setup > Apply router settings now once (it is added to the
  same router-log settings as before, and removed by the same Undo). Until then usage works as before.
- Not yet confirmed on a real router - the log line format is taken from RouterOS documentation.

### Fewer "Unknown devices"
- A device with no strong clue now gets a best guess with the reason starting "likely": managed equipment
  (answers on SSH / Telnet / SNMP), an appliance with its own web page, or a phone / tablet (answers like
  Android / iOS with nothing open, or only the router sees it).
- A device recognised in an earlier scan keeps that type when it gives no clues today.
- A device that answers nothing at all and has an unknown maker still shows as Unknown - name it once
  (right-click > Set label) and it stays named.

## Network Doctor 3.29.0

### New: Line up cameras - one fixed IP each, in one block (Network Tools > Login sweep)
- "Line up cameras (fixed IPs in one block)..." lists every camera with the IP it would get, in order, inside
  the camera block. The default blocks are now: .2 - .25 free for router / switches, .26 - .70 PCs and
  laptops, .71 - .140 cameras, .141 - .150 recorders (edit them as before; saved choices are kept).
- For Hikvision and Dahua cameras that accepted a login in the sweep, the app can do the move itself: the
  router reserves the new IP, the camera is switched to automatic (DHCP), and the app waits until it answers
  on the new IP. One camera at a time; the run stops at the first camera that does not come back.
- "Move ONE camera (test first)" exists on purpose: the NVR / DVR stores each camera's IP, so a moved camera
  shows no picture until its new IP is typed on the recorder. "Save old -> new list" is for that.
- Other brands, or cameras without a working login, are marked "by hand". Recorders are never moved.
- NOT yet tested on real cameras (only against simulated ones) - start with one camera.

## Network Doctor 3.28.5

### Second re-check pass
- Remote access (VPN) check: a VPN adapter that is only installed (Windows shows it as "Media disconnected")
  no longer counts as an active tunnel - only a connected one does.
- Login sweep: a very long name read from a camera is cut to 60 characters, like names typed on the phone.
- Phone app 1.16.1 - speed test: five servers are tried instead of three, the first request is 25 MB instead
  of 100 MB, and the clock starts when data arrives (connect time no longer makes a fast line read low).

## Network Doctor 3.28.4

### Fixed: Router config backup (3.28.0 - 3.28.3) did not work properly
Found while re-checking this feature against a real RouterOS 6 router:
- It read the config with "/export". On RouterOS 6 that text can only come back through a file, and files
  over 4 KB cannot be read through the API - so "Backup now" ended in "no output in 15 seconds".
- "/export" starts with a date/time line, so on RouterOS 7 every backup looked different from the last one:
  the 6-hourly check would have raised "Router configuration changed" every time.
- RouterOS 6 "/export" also prints passwords (PPPoE, Wi-Fi, PPP secrets), which were then kept on disk.
Now the settings are read section by section (print only, RouterOS 6 and 7 alike): counters and other values
that change by themselves are ignored, passwords and keys are never stored, and rules Network Doctor added
itself are left out (they have their own Undo list). The history moved out of settings.json into its own
file; old "/export" copies are dropped. "Save last backup to file" now writes a readable record (.txt) and
says plainly that it is not a restore file - use WinBox > Files > Backup for that.

### Phone app: Router config backup (same feature as the PC, run from the phone)
- New phone action "config_backup": the Office PC tab on the phone gets a "Router config backup" card.
  The PC does the work and the phone shows the result and what changed. Needs the phone app 1.16.0.

## Network Doctor 3.28.3

### Learning brain: the "find" half, not just "fix"
- Some alerts (so far: "The router's CPU is very busy") have a one-click read-only diagnostic button but
  no safe auto-fix (there's nothing to change). The brain now runs that diagnostic by itself once the
  alert repeats, the same way it auto-applies a real fix for AUTO_SAFE kinds - except this never changes
  anything on the router (query-only), so it's safe for any kind, not just the AUTO_SAFE list.
- Result shows up right in Troubleshoot as "Auto-diagnosed (read-only, no change made)" - by the time you
  open the alert, the extra context (e.g. the router's actual CPU/memory numbers) is already there.

## Network Doctor 3.28.2

### Config backup now runs itself every 6h, and a real change raises an alert
- The config backup added in 3.28.0 was manual-only (had to press "Backup now"). It now also runs itself
  in the background every 6 hours (read-only `/export compact`, same as the button).
- If that auto-backup finds a real change since the last one, it now raises a normal "Router configuration
  changed" alert - P3, informational, links straight to Setup > Config backup & diff to see what changed.
  Not auto-fixed (nothing to "fix" - it's a record of a change someone already made, not a problem).
- A first-ever backup never raises an alert (nothing to compare it against yet).

## Network Doctor 3.28.1

### Code audit (pyflakes pass + manual review) - one real bug fixed, several latent ones fixed before they bit
- **Real, live bug**: `quick_check()` (the fast loop/conflict/rogue-DHCP/stability check that runs between
  full scans) referenced a variable it never defined - it has been raising `NameError` on every single run,
  silently logged in the health log as "check failed". Fixed: it now runs as intended. Added a regression
  test that calls the real function (the old tests only exercised a hand-built fixture, which is why this
  was never caught).
- **Latent bug, 3 spots** (remote tunnel quick-start/setup/remove in Setup > Remote access): on failure, the
  error dialog would itself crash with a second, unrelated `NameError` instead of showing the real error -
  Python deletes an `except ... as e:` variable when the block ends, so a queued callback that closes over
  `e` directly blows up when it finally runs. Fixed by capturing the message into a plain variable first.
- Minor cleanup: removed several dead/unused variables and imports found by a pyflakes pass (no behaviour
  change) - keeps the codebase easier to read and reduces noise around future real findings.

## Network Doctor 3.28.0

### New: Router config backup & diff (Setup)
- Closes a real gap: nothing in the app recorded what changed in the ROUTER'S OWN SETTINGS over time -
  a firewall rule, port forward, or static lease someone added by hand in Winbox left no trace anywhere.
- "Backup now" reads the router's config (read-only `/export compact`) and compares it with the last saved
  copy, showing exactly what was added/removed. Unchanged backups aren't re-saved (no pointless duplicates).
  Keeps the last 30 backups. "Save last backup to file" exports a `.rsc` you can keep outside the app too.

## Network Doctor 3.27.3

### Menu reorganization, part 2: "Fix & Commands" split out "This PC & Wi-Fi"
- "Fix & Commands" (6 sub-pages, 7 on Pro) is now two tabs: **Fix & Commands** (Commands, and Packet capture
  on Pro) and **This PC & Wi-Fi** (LAN speed, Wi-Fi analyzer, Network adapters, MTU finder, Subnet calculator).
- Every top-level tab is now 5 sub-items or fewer. Navigation-only change, same as part 1 (3.27.0).

## Network Doctor 3.27.2

### Auto-fix brain widened by one kind: MTU/MSS clamp now self-applies
- "Large packets do not pass the line (MTU/MSS)" now auto-fixes like the other safe kinds (dhcp_conflict,
  multicast, loop, ip_conflict): it only adds a passthrough firewall rule that lets big sites load properly -
  it never blocks, exposes, or changes anything a user would notice - and it now has a real Undo, so a bad
  outcome reverts itself through the same regression check as the others.
- Deliberately still manual: anything that blocks a device's internet (torrent, malware), closes/opens
  internet exposure, or touches DNS (changing the router's own resolver settings is a real open-resolver
  risk if it were ever reachable from the WAN) - these can affect a real user or loosen what reaches the
  network from outside, so they stay one-click-confirm, not silent.

## Network Doctor 3.27.1

### Fix: "Remote access (VPN)" check could give a false CGNAT reading with Tailscale/a VPN active
- Real-world case: the check reported a different "seen from the internet" address than the router's own
  IP Cloud address, suggesting CGNAT - but an independent browser check (whatismyip.com) agreed with the
  router, not with the app's reading. Cause: a VPN/tunnel (Tailscale) was active on the PC at the time and
  rerouted that one outbound check through its own exit path.
- The check now: (1) detects an active VPN/tunnel on this PC (Tailscale, WireGuard, ZeroTier, OpenVPN,
  a 100.64.0.0/10 tunnel IP...) and warns up front if one looks active; (2) reads the public IP from two
  independent providers, not one, and compares both against the router's own address; a mixed result (one
  matches, one doesn't) is now reported as "inconclusive - recheck with the VPN off" instead of a confident
  CGNAT verdict. Still fully read-only.

## Network Doctor 3.27.0

### Menu reorganization - fewer items per tab, clearer categories
- "Devices" (9 pages) is now two tabs: **Devices** (All devices, Inventory, Network map, IP-MAC binding) and
  **Network Tools** (Login sweep, Switches SNMP, Port scanner, MAC lookup, Wake-on-LAN).
- "Internet & Usage" (8 pages) is now two tabs: **Internet & Usage** (Live monitor, Usage, Bandwidth plan,
  Slow website?) and **Diagnostics** (Speed test, Website check, DNS test, Remote access/VPN).
- Navigation-only change - no page was moved, renamed, or had functionality altered; this just stops two
  tabs from being crowded with 8-9 sub-items each.

## Network Doctor 3.26.1

### New: "Remote access (VPN)" readiness check (Internet & Usage) - is it even possible to fix the latency?
- Before changing any router setting to speed up a VPN (Tailscale, WireGuard, etc.), this answers the
  question that decides whether that's even possible: does this office have its own public IP, or does
  the ISP share one address between many customers (CGNAT)? If it's CGNAT, no router setting can ever
  give a direct connection - only the ISP can fix that (a static/public IP, often a paid add-on).
- **Read-only, by design** - it only asks the router what it already knows (IP Cloud) and compares it to
  what the internet sees; it never opens a port, enables UPnP, or changes anything. If you're NOT behind
  CGNAT, it deliberately does not offer a one-click "enable UPnP" - UPnP lets any device on the LAN open
  its own port automatically, which this app treats as a security issue everywhere else (the "exposed
  DVR" alert kind), so it won't quietly recommend the same risk here. The safe next step it does suggest:
  one scoped port-forward to one named trusted device, with an Undo - never a blanket auto-forward rule.

## Network Doctor 3.26.0

### "Is it down for everyone, or just us?" (Tools > Web check)
- When Outlook/Teams/some site stops working, the first question is always "is this us or them" -
  now answered in one line. Pick a known service from the new dropdown (or type any address) and
  it shows which stage the connection got stuck on (DNS / connect / secure handshake / the server's
  actual response) - that failure point IS the diagnosis: reaching the server and getting no answer
  points at THEIR service; failing at DNS points at THIS network.
- For services that publish a public status page (GitHub, Cloudflare, Slack, Zoom, Dropbox, Atlassian,
  OpenAI, Discord), the official status is fetched too, so you see both signals together.
- Microsoft 365/Outlook does not publish an unauthenticated public status API (needs a work/school
  sign-in) - rather than guess or fake one, that case shows the network-reachability verdict only, plus
  a link to check manually (portal.office.com or Downdetector).

## Network Doctor 3.25.1

### Blank "Bandwidth now" for cameras - a real fallback, not just an explanation
- Root cause (confirmed in code): the Devices list's bandwidth comes from NetFlow, which only sees
  traffic that crosses the router. A camera that only ever talks to a local NVR on the same switch never
  crosses the router, so it showed blank - correctly, but not usefully.
- **New fallback: SNMP switch port counters.** Go to Devices > Switches (SNMP), read your switch once,
  then press "Save for bandwidth fallback". Network Doctor then asks that switch for its port counters
  every ~25 seconds in the background and uses them to fill in the Devices list's bandwidth for any
  device that NetFlow has nothing for - marked "(switch)" so it's clear where the number came from.
- Only applied where a port has **exactly one** device on it - a port with 2+ devices (an unmanaged
  switch or hub cascading off this one) is left blank rather than guessing how to split the total between
  them, same as before.
- Read-only: no port is ever turned off, renamed, or changed by this - same community string you'd use to
  just "Read" a switch.

## Network Doctor 3.25.0

### Asset records, alert history, and camera names fetched from the camera itself
- **Device tags now hold asset-register fields**: Owner / handled by, Serial number, Purchase date,
  Warranty until - alongside the existing Name/Department/Location. Shows in "Tag" on any device, and in
  the tag CSV export/import.
- **New "History & trends" page** (Alerts section): one row per day for the last 14/30/90 days - total
  alerts and the busiest kind that day - so you can see at a glance whether things are improving, not
  just the raw 3000-row log. Exports to CSV.
- **Audit log now exports to CSV** (Users & sign-in > Audit log > "Export (CSV)") for compliance/handover.
- **Login sweep (Devices > Login sweep) can now fetch the camera/NVR's own configured name** and apply
  it as the device's tag with one click ("Use device's own name as its tag") - no more opening each
  camera's web page by hand to find out what it's labelled. Works for Hikvision (ISAPI) and now also
  Dahua (added the missing `getConfig&name=General` call that carries the MachineName).
- Reminder: moving cameras/NVRs into their planned IP block (e.g. .150-.199 for cameras) by device type is
  already built - Internet & Usage > Bandwidth plan > fixed-IP plan - this release just makes it easier to
  name them correctly first.

## Network Doctor 3.24.2

### Auto-fix was staying blank, and malware alerts weren't naming the real threat
- **Auto-fixes now act on the first occurrence**, not after 5 repeats of the exact same alert. On a
  network where every alert is for a different device (one DHCP conflict today on camera A, a different
  one tomorrow on camera B) the old 5-repeat rule meant it practically never fired - the Auto-fixes list
  stayed empty even with fixable alerts sitting there. Now that every auto-fix has an Undo and a post-fix
  recheck (3.24.0), it is safe to act immediately; a fix-kind that turns out wrong needs MORE repeats
  next time (the "learning" part), not fewer.
- **Fixed a real classification bug**: the public threat-list hits Network Doctor actually raises -
  "Hijacked criminal network (Spamhaus DROP)", "Known attacker (FireHOL level 1)", "Compromised /
  attacking host" - never matched the "malware" fix recipe at all (none of them contain the literal word
  "malware"), so they fell through to a generic message with no fix, no Undo, and no way to find the
  program responsible. They're now classified correctly.
- **Malware alerts now point at the actual remote address** to search for (Resource Monitor's Network
  tab / `netstat -ano | findstr <remote IP>`) instead of only showing the device's own IP, so you can
  actually find which program on that PC made the connection.
- The port-forward/UPnP "exposed device" fix now has an Undo too - it stays a manual, one-click-confirm
  fix (closing it can break a camera's remote-viewing feature someone set up on purpose), but once you
  apply it you can revert it from Auto-fixes if it turns out to be needed.

## Network Doctor 3.24.1

### New devices now stand out in the Devices tab itself
3.23.12 added a breakdown and two filters ("New since last scan" / "Stopped answering since last scan"),
but the main "All devices" list still looked the same for a brand-new device as for one you've had for
months - you had to switch the filter to see which was which. A device that is new this scan is now
marked "(new)" and highlighted green right in the normal list, so it stands out without changing filters.

## Network Doctor 3.24.0

### A proper Windows installer, trusted services, and a "learning" auto-fix
- **Windows installer**: NetworkDoctor-Setup.exe (alongside the existing portable .exe on the Releases
  page) - installs to Program Files-style location, adds a Start Menu entry and optional Desktop
  shortcut, and a real uninstaller in "Add or remove programs". The portable .exe is unaffected; the
  installed copy keeps self-updating exactly as before.
- **Trusted services**: mark an app as trusted (Usage tab > App list > "Trusted (ignore usage
  spikes)"). A deliberate high-traffic service you run on purpose - a backup, say - stops showing up as
  a "used Nx its usual daily traffic" problem in alerts.
- **IP-conflict auto-fix with a priority device**: tag a device "Default device for its IP" (Devices
  tab > tag editor). When two devices fight over one IP, the auto-fix now binds that IP permanently to
  the tagged one - and leaves the alert for you to resolve by hand if nobody (or more than one device)
  is tagged, since it must not guess.
- **Auto-fixes now have an Undo, and the app learns from its own fixes**: Alerts tab > "Auto-fixes..."
  lists every fix Network Doctor applied by itself with a one-click Undo, plus a per-fix-kind
  confidence score. After every applied fix the app re-checks a short while later whether a NEW problem
  appeared on the same device - if so it undoes the fix itself and remembers that outcome, so a fix-kind
  that keeps needing an Undo is tried more cautiously next time, and one with a clean record is tried
  sooner.

## Network Doctor 3.23.12

### "32 cameras yesterday, 40 today, but I can't find the difference" - now you can
Scans already noted new devices, but only a flat count buried among other alerts, and there was no way to
see what had dropped OFF the network at all - so a day-to-day count change (more cameras, fewer cameras)
had no explanation anywhere.
- Every new/missing-device alert, the Home tab's Devices card, and the Problems-tab issue now break the
  count down by category: "8 new device(s) (6 CCTV cameras, 2 Phones)" instead of a bare "8".
- New: devices that answered the previous scan and don't answer this one are now flagged too ("3 device(s)
  stopped answering since the last scan (3 CCTV cameras)") - with a note, a health-log entry and (if alerts
  are on) a pop-up, the same way a new device always has been.
- Devices tab: two new filters, "New since last scan" and "Stopped answering since last scan", to jump
  straight to exactly the devices that changed instead of re-reading the whole list.
- Setup > Alerts: the "Alert when a new device joins" checkbox now also covers a device dropping off,
  renamed to match.

## Network Doctor 3.23.11

### The .deb install can now update itself automatically
Until now, the .deb-packaged copy always refused to self-update (it's managed by `apt`, which the app must
never silently overwrite) and could only tell you to run `sudo apt install` by hand. It now does that step
for you:
- Checks GitHub for a new version the same way the Windows/Mac builds already do, and (per your "New
  versions" setting on the Setup tab) can download and install it automatically.
- Installs the new `.deb` with `pkexec`, which pops your desktop's own native password prompt - Network
  Doctor itself never sees, asks for, or stores your password. This needs `pkexec` (part of
  `policykit-1`), which ships by default with GNOME/KDE/XFCE desktop sessions on Ubuntu.
- If `pkexec` isn't available, automatic updates are turned off and the Setup tab goes back to pointing you
  at the manual `sudo apt install ./NetworkDoctor_*_amd64.deb` command, exactly as before.
- After installing, it restarts itself automatically - no separate relaunch needed.

## Network Doctor 3.23.10

### Linux had been getting a second-class version of several features
With the `.deb` finally launching reliably, a round of real usage on Ubuntu surfaced a batch of
feature gaps where Linux was quietly getting less than Windows and Mac:
- **Unknown devices with no MAC/vendor (e.g. two phones on Devices tab)**: the "second chance" ARP retry
  for devices that miss the first round (phones/cameras asleep on Wi-Fi) only ran on Windows. Linux and Mac
  now get the same retry via `scapy`, so a device that answers late no longer stays stuck as an unlabeled
  "Unknown device" with MAC `-`.
- **Fix & Commands > Commands tab had nothing for Linux**: "This PC" commands were Windows/Mac only. Added
  a full set of Linux equivalents (IP/MAC/gateway info, renew DHCP lease, flush DNS, ARP/neighbour table,
  ping, traceroute, Wi-Fi details, switch to DHCP, lock the router's MAC, restart networking, test a TCP
  port, cable speed/duplex, DNS lookup, firewall status, sync clock, and more) - also fixed a bug that could
  incorrectly enable a Windows/Mac command's Run button on Linux.
- **"Need administrator" shown on a correctly-installed `.deb`**: the `.deb` install never needs `sudo` -
  it gets network capabilities (`setcap`) instead of root - but the app's admin check only recognized
  literal root, so it always showed the "need administrator" label and skipped some extra scanning it
  already had everything needed for. It now recognizes those capabilities too.
- **Slow website? > "compare on your own PC" only worked on Windows**: the suggested `curl` command and
  its label ("Command Prompt") are now OS-aware, so the comparison step actually works on Ubuntu and Mac.
- **Website check gave an unhelpful raw error**: a TLS handshake failure other than a bad certificate (e.g.
  "Connection reset by peer") used to show only Python's bare exception text. It now explains what that
  specific failure usually means (a content/DNS filter, proxy, or firewall cutting the connection; a
  timeout; or a server-side TLS rejection) instead of leaving the user with nothing to act on.
- **Wi-Fi analyzer said "works on Windows and Mac" and did nothing on Linux**: it now scans and ranks
  nearby Wi-Fi networks on Linux too, using NetworkManager's `nmcli` (installed by default on Ubuntu).

### Usage tab blank - not a bug
If Internet & Usage > Usage shows no traffic, check Setup > "What is missing": this tab needs the router
to be sending it NetFlow data (or, for some routers, API/log access) - it's the same on every platform and
just means that hasn't been turned on yet for this router.

## Network Doctor 3.23.9

### Found the final cause: setcap itself breaks how the bundle finds its own libraries
- 3.23.8's CI run got further than ever - every static check passed, and the *portable* binary genuinely
  launched clean in its own smoke test - but the real, installed `.deb` still crashed with the same
  `libtk8.6.so` error. The difference between the two finally explains the whole saga: the installed copy
  gets `setcap`'d (so scans work without `sudo`), and Linux puts a `setcap`'d binary into a stricter
  "secure execution" mode - in which `glibc` **ignores `LD_LIBRARY_PATH` entirely**, for security reasons.
  That's exactly the mechanism PyInstaller's own packaging normally relies on to find bundled libraries, so
  it silently stopped working the moment `setcap` was added, on every version since 3.23.0's `.deb`.
- Fixed by baking the library location directly into the binary itself (via `patchelf`, an `RPATH` entry),
  instead of relying on an environment variable - which is unaffected by secure-execution mode and is how
  the portable (never-`setcap`'d) build was finding things correctly all along.
- This is also why the CI pipeline itself took several small, visible steps to land on: each one closed a
  real gap in a different part of the chain (bundling, a masked test machine, a directory mismatch, a
  verification blind spot) until the checks and the real `.deb` finally agreed.

## Network Doctor 3.23.8

### CI fix: the library check itself was giving a false alarm
- 3.23.7 fixed the real bundling problem but still didn't publish: the `ldd`-based verification step checks
  each bundled file in isolation, with none of the environment the app itself gets at real startup -
  specifically, PyInstaller's own `onedir` build points `LD_LIBRARY_PATH` at its `_internal/` folder right
  before the real app runs, which is how a nested module finds a sibling library placed at the top level.
  The check didn't set that, so it reported Tcl/Tk as "not found" even after 3.23.7 genuinely fixed where
  they live - a false alarm, not a real bug.
- Fixed by setting `LD_LIBRARY_PATH` the same way before running the check, so it now matches what actually
  happens when the app starts for real.

## Network Doctor 3.23.7

### Found the actual, final cause of the libtk8.6.so crash
- 3.23.6's CI run never published either - but this time because its new, honest checks finally caught the
  real bug instead of a masked one: `libtk8.6.so`/`libtcl8.6.so` were genuinely bundled inside the `.deb`'s
  files, but not in the same folder as `_tkinter`, the Python module that actually needs them. PyInstaller's
  `--onedir` layout can nest `_tkinter` below the top level of the bundle, while the two Tcl/Tk libraries
  were being force-added to the top level - two directories that never met, so the app looked for them in
  the one place they weren't, on every real machine, every time.
- Fixed by finding wherever `_tkinter`'s own file actually ends up in each build and copying Tcl/Tk's
  libraries directly into that same folder, instead of guessing a fixed destination.

## Network Doctor 3.23.6

### CI fix: 3.23.5 never actually published (the new safety check caught something real)
- 3.23.5 was meant to fix the `libtk8.6.so` saga for good, but its own build never finished: the CI job's
  new check (`ldconfig` should show nothing after removing the build machine's Tcl/Tk) found that
  `libtcl8.6.so`/`libtk8.6.so` were *still* resolvable even after `apt purge` reported them removed - a
  stray copy outside the package manager's own tracking survived the purge. The job correctly refused to
  continue rather than risk testing against that leftover copy, so no 3.23.5 release was ever published.
- This version deletes those files directly (not just via `apt purge`) and re-confirms they're gone before
  any verification or smoke-test step is allowed to run, closing that gap.

## Network Doctor 3.23.5

### Fix: found the actual reason CI kept saying "fine" when the .deb wasn't
- 3.23.4's CI run reported every check green - the libraries were confirmed bundled, `ldd` said every
  dependency resolved, both the portable binary and the actually-installed `.deb` passed their self-test -
  and it still failed on a real machine with the same `libtk8.6.so` error.
- The real cause: GitHub's own Python setup step sets `LD_LIBRARY_PATH` to its own Python install's library
  folder **for the whole CI job**, not just while it builds. That folder ships its own private copy of
  Tcl/Tk's libraries. `apt purge` (3.23.4's fix) only removes Debian packages, so it never touched that
  folder - every check in that job kept quietly succeeding against GitHub's copy, never the actual package.
- Fixed by clearing `LD_LIBRARY_PATH` for the rest of the job right after both builds finish, so every
  verification and smoke-test step from then on can only pass using what's genuinely inside the `.deb`/the
  portable binary - nothing else on the build machine is left that could paper over a real gap.

## Network Doctor 3.23.4

### Fix: the .deb still would not open on a clean machine (libtk8.6.so, for real this time)
- 3.23.3's CI run passed its new smoke tests, but the installed app still failed on a clean Ubuntu machine
  with the same `ImportError: libtk8.6.so: cannot open shared object file`. Root cause: the CI build machine
  has `python3-tk` installed (needed to build the app at all), so the smoke test could still find
  `libtk8.6.so` on the *system*, even when PyInstaller had failed to actually bundle it into the package -
  the test was accidentally checking the build machine, not the package.
- Fixed two ways: the build now explicitly force-bundles Tcl/Tk's shared libraries into both the portable
  binary and the `.deb` payload (`pyinstaller --add-binary`), instead of relying on PyInstaller's automatic
  detection, which was silently skipping them. And CI now **removes `python3-tk`/`tcl8.6`/`tk8.6` from the
  build machine** right after building, before running any of the verification or smoke-test steps, so
  nothing can pass by quietly falling back to a system copy that a real user's machine won't have.
- Sorry for the back-and-forth on this one - thanks for testing and reporting exactly what broke each time.

## Network Doctor 3.23.3

### Fix: the release pipeline now actually proves the Linux build runs before publishing it
- 3.23.0, 3.23.1 and 3.23.2 each shipped a Linux build that looked fine in CI but failed to launch for real
  users, three times in a row - the pipeline only checked that the build *compiled*, never that it *ran*.
- The CI build now launches both Linux outputs for real, headless (via a virtual display), using the app's
  own built-in self-test: the portable `NetworkDoctor-Linux` binary, and the actual installed `.deb` -
  including its real `postinst` and the real `setcap` grant, exactly as it lands on a user's machine. Either
  one failing to start now fails the build instead of reaching the Releases page.
- This is also the first release where that installed-`.deb` self-test runs for real, which is what the
  previous two fixes (the `/proc` crash and the missing Tk library) were only ever checked against by hand.

## Network Doctor 3.23.2

### Fix: the .deb package still would not open (this time: missing Tk library)
- 3.23.1 fixed the `/proc` crash but the app still failed to start, now with `ImportError: libtk8.6.so:
  cannot open shared object file`. The Linux build machine never had the Tk GUI toolkit's system libraries
  installed, so PyInstaller silently built a binary without them - nothing failed at build time, only at
  startup, on every machine. Fixed by installing `python3-tk` on the build machine before building.
- The CI build now also verifies every bundled binary resolves its shared libraries (`ldd ... | grep "not
  found"`) before packaging the `.deb`, specifically so this class of "builds fine, never runs" bug fails
  the build instead of shipping.

## Network Doctor 3.23.1

### Fix: the .deb package would not open at all
- 3.23.0's `.deb` package failed on every launch with `Security validation failure: could not access /proc
  entry...`. Cause: granting the raw-socket capability directly to the installed binary (`setcap`, so scans
  work without `sudo`) makes Linux treat it like a setuid program - which blocks PyInstaller's single-file
  bootloader from reading its own process entry at startup. Fixed by building the `.deb`'s payload as a
  plain folder (PyInstaller `--onedir`) instead of a self-extracting single file, which needs no such
  self-check. The portable `NetworkDoctor-Linux` download is unaffected (it was never `setcap`'d).
- Also: the Linux build never actually included Scapy, so the ARP-based device block (3.22.9) silently
  could not run on Linux at all, on either the `.deb` or the portable binary. Both now bundle it.

## Network Doctor 3.23.0

### New: a real install on Linux (Ubuntu/Debian)
- Linux went from "download a raw file, `chmod +x`, run it from a terminal with `sudo`" to a proper
  **`NetworkDoctor_*_amd64.deb`** package: `sudo apt install ./NetworkDoctor_*_amd64.deb` puts **Network
  Doctor** in your app menu / Activities search with its own icon, so it can be pinned to the taskbar or
  favourites like any other installed app.
- The raw-socket scans and the ARP-based device block (3.22.9) now work **without `sudo`** - the package
  grants the installed binary the specific network capability it needs (`setcap`), not full root.
- **Setup > "Start at login"** now actually works on Linux (an XDG autostart entry, honoured by every
  desktop environment) - previously it was Windows/Mac only, so Linux had no way to keep the 24/7 checks
  running in the background after a reboot.
- The portable **NetworkDoctor-Linux** binary is still published on every release for non-Debian distros or
  anyone who prefers a no-install file; it keeps self-updating in place as before. The new `.deb` is managed
  by `apt` instead (download the newest `.deb` and reinstall it over the old one to update).

## Network Doctor 3.22.0

### New: the Fix Assistant (Assistant tab)
- A new **Assistant** tab (next to Home). Type a network problem in plain words - "block YouTube on the Wi-Fi",
  "internet is slow and pages hang", "a camera is open to the internet", "check my network for problems" - and
  Network Doctor routes it to the right built-in, tested fix and applies it, with **Undo** on every fix. It never
  invents raw router commands; it only runs fixes the app already ships and has tested.

### Fixes
- **Remote access from the phone now uses a stable address automatically.** A Cloudflare quick-tunnel address
  changes every time it restarts, so the one saved on the phone kept going dead ("address not available"). When
  Tailscale is running on the PC, Network Doctor now advertises its permanent Tailscale address to the phone, and
  the phone adopts it by itself while on the office Wi-Fi - so reaching the PC from home keeps working without
  pasting a new address each time.
- **VIP / Boost now means FULL SPEED, not a 5 Mbps cap.** Marking a device VIP, or pressing Boost, used to put it in
  a small 5 Mbps pool - so a "boosted" PC actually ran slower. A VIP / boosted device is now top priority and
  uncapped: it can use the whole internet line, so Windows updates and large downloads finish fast. Everyone else
  still keeps their fair share, and the VIP's guaranteed floor is unchanged.
- **Your NVR / DVR is no longer blocked with the cameras.** The camera-isolation feature now recognises a recorder
  even when its name doesn't contain "NVR"/"DVR" - it also reads the model (e.g. Hikvision DS-7xxx), the channel
  count ("16 CH") and the DVR port label - so the recorder keeps its internet (and your remote NVR viewing keeps
  working) while only the individual cameras are blocked. You can still mark any device by hand on the Bandwidth
  page, and a manual choice always wins.
- **Auto-defense never cuts your own PC, the router, or a switch / AP.** The PC running Network Doctor, the
  gateway, and the network backbone are now on a permanent "alert only, never cut" list - so a fix can no longer
  take the Network Doctor PC (e.g. .70) or the network itself off the internet.

### Reminder
Close and reopen Network Doctor once to let the auto-update install.

## Network Doctor 3.21.3

### Fix in this version
- **Crash on startup: "Failed to execute script NetworkDoctor ... Item ... already exists".** If two alerts were
  recorded in the very same millisecond they were given the same internal id, and the Alerts table then refused to
  show two rows with the same id - which crashed the whole app before it could even open. Alert ids are now always
  unique, and the Alerts table tolerates any duplicate ids already saved from before, so the app opens normally again.

### If your app is currently crashing on open
The fix installs through the normal auto-update, but a crash on startup stops the app before it can update itself. To
get going immediately, either download and run the latest installer from the GitHub releases page, or delete the saved
alerts file so the app can open (it then auto-updates): press Win+R, paste **%APPDATA%\\NetworkDoctor**, press Enter,
and delete **alerts.json** (only your alert history is cleared - devices, settings and your licence are untouched).

### Reminder
Close and reopen Network Doctor once to let the auto-update install.

## Network Doctor 3.20.0

### New in this version
- **Login sweep (Devices > Login sweep).** Give the SAME admin user name and password you already use (up to 3
  logins), tick PCs / cameras-NVR-DVR / routers-switches, and press **Start scan** - no need to run anything by hand
  on each device any more. It reads every PC's make, model, serial, CPU, RAM and disk (the existing Windows PC
  check), every MikroTik router/switch's identity, model and RouterOS version, and every Dahua / Hikvision / ONVIF
  camera, NVR or DVR's model, serial and firmware. Every login is tried **only once per device**: if the first couple
  of devices of a kind all refuse it, the rest of that kind are skipped automatically so an account cannot get
  locked ("Keep trying anyway" overrides this if you are sure of the password). Devices that refused the login,
  could not be reached, or answered with data missing are listed with the reason, plus one button to copy the
  "login refused" list and one to export everything to CSV. Passwords are kept in memory only for the run and are
  cleared the moment it finishes - never saved to settings, the database or a log.
- **Phone check (same page).** Checks every phone/tablet WITHOUT logging in to it: an IP it shares with another
  device, an IP inside the camera/NVR/infra block, a hand-typed (static) IP, camera/recorder ports open on something
  tagged as a phone, a leftover app block still keyed to that phone's MAC, and phones the router has but the scan
  missed. This is the exact mix-up (an IP showing as "Dahua NVR" on a phone) that cut phones off before 3.19.1 - this
  catches it before it happens again.

## Network Doctor 3.19.1

### Fixed
- **Auto-defense no longer cuts phones.** A phone changes its IP and uses a private Wi-Fi address, so a block made for
  "the device at that IP" landed on the wrong phone and many phones lost internet. Phones and tablets are now only
  alerted on, never cut automatically.
- **"Open to the internet" no longer cuts the wrong device.** That alert is about a router port-forward, so only a
  camera / recorder may be cut for it; every other device is just alerted (fix the port-forward instead).
- **Automatic internet cuts end by themselves** after 60 minutes (setting `release_min`, 0 = never), so a wrong
  guess cannot last. The app log says when a device was NOT cut and why.
- **Reset (Bandwidth plan > 5. Reset (safety)).** *Show what the app changed* lists, read only, everything Network Doctor
  made on the router. *Reset blocks, limits and rules*, *Reset fixed-IP reservations* and *Reset EVERYTHING* remove only
  items named or commented "ND ..." and switch on again what the app had switched off (port-forwards, FastTrack). The ISP
  and owner configuration is never matched. A copy of the router configuration is saved first (nd-before-reset.rsc).
  Single settings (DNS servers, UPnP, loop protection ...) cannot be reversed blindly and are listed for a manual check.
- **Safety tests.** The build now fails if any new router rule, queue or list the app creates is not covered by the
  reset, or if code could wipe the router, delete without a condition or change router users.
- Already-made blocks: Bandwidth plan > 4. Cameras and chart > *Release auto-defense blocks* (Undo included).

## Network Doctor 3.19.0

### New in this version
- **Bandwidth plan (Internet & Usage > Bandwidth plan).** Splits the internet line into parts and caps every user inside
  its part, so one heavy user can no longer slow the others. Default for a 100 Mbps line: 5% kept free, NVR / DVR remote
  viewing 10 Mbps, mobiles 20 Mbps (4 Mbps each), VIP PCs 5 Mbps guaranteed (up to 20 each), everything else (office
  PCs) 60 Mbps with 5 Mbps each. Unused bandwidth is lent to whoever needs it. The page checks the numbers, shows what
  each office PC gets when everyone is busy, and applies the plan on the router itself (or shows the commands to
  paste). **Remove the plan** takes it all away again, FastTrack included.
- **Two devices on one IP (a phone shown as the DVR).** The page shows a red *IP CLASH* line and leaves that IP out of
  every rule. *Change IP of selected...* (page 3) moves the wrong device to a free IP and reserves it. Page 4 has
  *Check port-forwards* (marks forwards that now point at the wrong device), *Release auto-defense blocks* and
  *Undo the release*; the camera block also closes forwards by CCTV port. Every action has an Undo.
- **Boost for directors / backups.** Select a device and press *Boost now* (1 hour, 4 hours, 8 hours or until you stop
  it): it becomes a VIP with a higher limit and priority. When the time ends Network Doctor removes the boost on the
  router (Network Doctor must be running at that moment).
- **Fixed IPs that survive a power cut.** *3. Fixed IPs* reserves every device's IP on the router by MAC address, so
  after a power cut the PCs, NVR / DVR and cameras come back with the same IPs. Nothing is moved by default; you can
  optionally move groups into IP blocks (NVR / DVR, VIP, PCs, mobiles). Cameras are never moved unless you confirm,
  because the NVR stores each camera's IP. Hand-typed IPs are marked "also change on the device". Saves the IP list as
  an Excel CSV.
- **Cameras without internet.** *4. Cameras and chart* stops every camera from reaching the internet **on the router**
  (many cameras have no setting for it), blocks new connections from the internet to cameras and NVR / DVR, and
  switches off the router's port-forwards to them (the Dahua DVR on port 37777 case). The NVR / DVR keeps its own
  outbound link to the maker's cloud, so the phone app (DMSS, Hik-Connect, XMeye) works from anywhere, with live view,
  playback and clip download, and no open port. One Undo puts everything back.
- **NVR / DVR bandwidth calculator.** Cameras, NVRs, people viewing and clip download -> how many Mbps to reserve.
  Example for 50 cameras and 2 NVR / DVR with 3 people watching 9 cameras each on the sub-stream: about 25 Mbps live,
  about 35 Mbps while one clip is also being downloaded.
- **Camera chart.** A drawing of cameras, PoE switches, NVR / DVR, router and the app, with the blocked path in red,
  using your real device counts. Save it as `.svg` (also in `docs/camera-network-chart.svg`).
- The Root cause advice for "device uses most of the internet" and "reachable from the internet" now points to this page.

### Good to know
- Per-user limits use MikroTik *simple queues with PCQ*. FastTrack skips queues, so the plan switches the router's
  FastTrack rules off as its last step (marked, and switched on again by Undo). Watch the router's CPU after applying.
- Not tested on a real router yet: apply it at a quiet time, with the Undo commands at hand.

## Network Doctor 3.18.7

### Fix in this version
- **Phone link no longer drops to "This phone is no longer paired" after you turn on Pro sign-in.** Once an account
  was created on the PC, a paired phone on the office Wi-Fi was being blocked from even viewing the network and the
  app showed it as un-paired. A phone on the local network can now always view the network again; signing in is only
  required for remote (outside-the-office) access, and each action is still checked against the signed-in user's
  role, so Pro stays locked to you. If your phone still shows "Pair again", re-pair it once with the code on the PC's
  Setup tab - that issues a fresh link.

### Reminder
Close and reopen Network Doctor once to let the auto-update install.

## Network Doctor 3.18.6

### New in this version
- **Every router fix now has an "Undo this fix" button.** Open any alert's Troubleshoot window: next to
  "Show commands" there is now "Undo this fix (on the router)". It removes exactly what Network Doctor added
  for that fix - by the "ND ..." tag it put on each rule - and puts the router back as it was (re-enabling
  UPnP or a port-forward where the fix had turned them off). You get a preview and a Yes/No before anything
  changes.
- **"Show commands" now also lists the UNDO commands.** The command window shows the fix and, below it, a clearly
  marked UNDO block you can copy and paste in WinBox if you ever need to roll the fix back by hand.
- **Automatic re-check after a fix (and after an undo).** When a fix is applied, Network Doctor immediately
  re-checks the network and tells you in the same window whether the problem is **Resolved** or **Still showing** -
  no need to press "Re-check" yourself. For checks that only run in a full scan (such as "device exposed to the
  internet"), it says so plainly and asks you to confirm once the device can no longer be reached, instead of
  guessing.

### Reminder
Close and reopen Network Doctor once to let the auto-update install - that is how you move up to the latest
version.

## Network Doctor 3.18.5

### The fix in this version
- **Google Sheets / big sites that spin on "Loading…" even though the internet works.** This is the classic
  large-packet (MTU) blackhole on PPPoE and some fibre lines: the page connects but then hangs because full-size
  packets are silently dropped. The MSS-clamp fix is now **two rules** instead of one - the usual
  `clamp-to-pmtu` rule plus a hard ceiling (line MTU − 40, e.g. 1440 on a 1480 line) so it still works even when
  the router never learns the path MTU. The ceiling is computed from the MTU actually measured on your line.
- **The MTU warning no longer keeps nagging after the clamp is applied.** Once the "ND: MSS clamp" rule is on the
  router, the Slow-website check detects it and shows a green "Large packets handled - MSS clamp active" note
  instead of flagging the same problem again. A PPPoE/fibre line will always read an MTU below 1500; that is the
  real line limit, not a fault, and the app now says so.

### Also included since the last store build (3.18.0 → 3.18.5)
- **3.18.1 - Updater no longer flashes a black command window.** Auto-updates now run fully hidden.
- **3.18.2 - Alert pop-up could hang and stop responding.** Alerts are now drained in small batches on the main
  thread, so a burst of events can never freeze the window.
- **3.18.3 - "Stop a device's internet" now actually sticks for printers/IoT.** Blocks keep the device fully usable
  on the local network (printing, scanning) while cutting only its internet, in both directions.
- **3.18.4 - Block distracting sites for the whole Wi-Fi** (Instagram, Facebook, WhatsApp, YouTube, shopping, …)
  straight from the PC or the phone; **cameras can be cut off from the internet while the NVR stays reachable from
  outside** (bi-directional block that keeps the LAN), so single cameras can't be reached by attackers from the
  internet; and the first version of the **MSS-clamp / MTU** fix.

### Reminder
Close and reopen Network Doctor once to let any pending auto-update install - that is how you move up to the
latest version.

## Network Doctor 3.18.0

**Standard app:** no visible change - this version adds a separate private "Pro" edition for the owner.

### Network Doctor Pro (private build - auto-defense, remote, security tools)

A separate `NetworkDoctor-Pro.exe` (built privately, never in the public download, Play or the Microsoft Store)
adds, behind a sign-in and an audit log:

- **Users & sign-in + audit log.** Add admin / operator / viewer users. The phone and remote access must sign in;
  every change (block, isolate, router fix, auto-defense action, setting) is written to an audit log you can read
  on the PC or the phone. The PC console itself is always trusted (physical access) and logged as "console".
- **Auto-defense (24/7, even at night).** Arm it and Network Doctor contains an attacker by itself: cut a device's
  internet, fully quarantine it on the router, or (with the PC agent) power it off / make it disconnect. You choose
  how far it may go for each kind of attack, exclude your servers and admin PC, and optionally limit automatic
  action to night hours. Everything is reversible and logged, and your phone is notified. It reacts to: a device
  open to the internet, malware contact, ARP spoofing, a rogue DHCP server, a torrent, and a device suddenly
  scanning the LAN or spreading to many PCs.
- **Security check (Nessus / Nuclei, made safe).** Reads only: finds devices reachable from the internet, default
  passwords, Telnet / FTP, old SMBv1, weak HTTPS, and a credential poisoner (Responder) - each with a plain fix,
  plus one-click Windows hardening commands. It never logs in or attacks anything.
- **Packet capture & analysis (Wireshark + Zeek, readable).** A few seconds of capture, explained: protocols,
  who talked to whom, the websites looked up, and anything suspicious (clear-text passwords, a port scan, a flood).
- **Internet exposure (Shodan + Censys).** Looks up your office's public IP and lists what the outside world can
  reach (add your free API keys).
- **Remote access from outside the office.** With remote access turned on and a free Cloudflare Tunnel / Tailscale
  on the PC, a signed-in user can check and fix the network from their phone over the internet - block or quarantine
  a device, reboot the router, run a security check - at any time, from anywhere. Outside connections can do nothing
  until they sign in, and everything is audited.
- **On the phone:** sign-in, the Auto-defense & checks tab, and Quarantine / Power-off / Reboot on any device - so
  a 3 a.m. breach can be stopped from your phone.

The Pro features never appear in the public app: the public exe, Play app and Store app have none of them, and the
phone shows them only when it is connected to your signed-in Pro PC.

## Network Doctor 3.17.1

- **Microsoft Store package.** Every release now also has `NetworkDoctor-Store.msix`, the package type the Microsoft Store accepts, with Network Doctor's Store identity (Pacheriya.NetworkDoctor) and its logos.
- **Same logo as the phone app** on the Windows program, its window and taskbar, and in the Microsoft Store.
- **The Store copy behaves the way the Store requires.** It starts as a normal user (press "Restart as Administrator" for the full tests) and it never updates itself; the Microsoft Store installs new versions. The normal download (`NetworkDoctor.exe`) keeps updating itself at 15:00 as before.

## Network Doctor 3.17.0

**A new, easier layout: seven coloured sections with their own pages.** Phone app 1.7.0 uses the same sections.

- **The tabs are now grouped by what they are for.** Before there were 15 tabs plus a Tools list of 16 more items. Now there are seven sections, each with its own colour and its own row of pages:
  - **Home** (grey): the overview.
  - **Alerts** (orange): Alerts, Problems, Root cause, Health checks.
  - **Devices** (blue): All devices, Inventory, Network map, IP-MAC binding, Switches (SNMP), Port scanner, MAC lookup, Wake-on-LAN.
  - **Internet & Usage** (green): Live monitor, Usage, Slow website?, Speed test, Website check, DNS test.
  - **Security** (purple): Network guard, Website firewall, Critical devices.
  - **Fix & Commands** (amber): Commands, LAN speed (PC to PC), Wi-Fi analyzer, Network adapters, MTU finder, Subnet calculator.
  - **Setup** (grey): Setup, What is missing.
- Each section remembers the page you used last. The Alerts section shows how many alerts are open.
- The Home buttons carry the colour of the section they open.
- **Phone app 1.7.0**: the Office PC screen has the same coloured sections (Home, Alerts, Devices, Internet & Usage, Security, Fix & Commands). The top bar takes the section's colour, and the pages of a section are chips under it.
- **Checked live before release.**
  - The Windows .exe now runs a self-test on a real Windows machine: it opens every section and page, checks the phone link, and screenshots every page.
  - The phone app is opened screen by screen on an Android emulator.

## Network Doctor 3.16.0

**The phone app can now do what the PC does.** Phone app 1.6.0 with PC 3.16.0:

- **Alerts** on the phone: open / all, priority, time, how often. Tap one for **Troubleshoot**: what it means, the fix, **Fix it automatically** (the PC applies it on the router), tick-off steps, Re-check and Mark fixed.
- **Network map**: router → ports / switches / access points → devices, problems in red / orange; many devices on one port as a compact grid.
- **Health**: the PC's health checks, watched devices and **Check now**.
- **Tools & commands**:
  - **Slow website?** Pick the user (type a name, IP or MAC) and the website; the PC finds the cause.
  - **Ping / traceroute from the PC.**
  - **Network guard**: block torrents, all DNS through the router, block rogue DHCP, block randomized MACs.
  - **Router commands**: run any library command on the router; the phone asks for the IP / port / speed it needs and asks before changing anything.
  - **Other brands, antivirus, drivers**: the whole command library to copy.
- **Device page → Office PC actions**: Tag (name, department, location), Ping and Traceroute from the PC, **Bind IP**, **Block internet** / Unblock, **Wake (WOL)**.
- Safe by design: only a phone paired with the PC's 6-digit code can act, only on the office LAN; the router login never leaves the PC; every change on the router asks first on the phone and is written to the PC's health log.

## Network Doctor 3.15.0

**Every device has a name, readable website names, filters in Usage, a map in rows, and repeated alerts fix themselves.**

- **Names for every device.** Devices that tell no name now show what they are: "Hikvision Camera .105", "XMeye Camera .69", "HP PC .57", "Phone .101". Tag a device to give it its real name. Windows PCs are also asked for their exact Windows version and domain over file sharing.
- **PC details for all PCs.**
  - Inventory > **Collect from all PCs (admin login)** reads RAM, SSD / HDD, printers, antivirus and more from every Windows PC with one administrator login. Nothing is installed and the password is not saved.
  - The PC details script now installs a small daily report: run it once on a PC (Inventory only) and its details stay up to date by themselves.
- **Network map as a matrix.** Many devices on one switch or port are laid out in rows across the window instead of one long column.
- **Repeated alerts fix themselves.** When the same alert comes 5 times, Network Doctor applies its safe fix on the router by itself: it reserves the IP for a device with a hand-typed IP (the repeating "conflict by ARP response"), or turns on IGMP snooping or loop protection. It never closes port forwards or blocks users on its own. You can switch this off in the Alerts tab.
- **Fewer false warnings.** Router debug lines such as "lease bound, init-reboot, extending" no longer show as warnings.
- **Readable website names.**
  - Server names like "lcdelw-in-f113.1e100.net Google LLC" or "a23-55-245-233.deploy.static.akamaitechnologies.com" now read "Google server (service not named)", "Akamai CDN", "WhatsApp media", "Instagram media" and so on.
  - The router's DNS cache is read every minute and followed back to the name people typed (docs.google.com, not googlehosted.l.googleusercontent.com).
  - The Live monitor's Main app uses the same names.
  - **Get exact website names...** (Usage tab): Chrome / Edge "secure DNS" hides every site name from the router. Network guard > "All DNS through the router" now also blocks that bypass, so Usage shows docs.google.com, mail.google.com, youtube.com per user.
- **Usage tab filters.** Find (user, app or website), Category (Productive / Neutral / Unproductive) and Department. Click any column title to sort, e.g. Traffic for the biggest users or sites first.
- **Slow website?** Type part of a name, IP or MAC and the matching devices drop down. The internet plan starts at 100 Mbps.
- **IP-MAC binding in one click.** "Bind on the router now" sends the reservations to the router directly. No WinBox, no copy / paste. The commands are still there under "Only show commands".
- **Commands tab:** type part of a device name to pick it.
- **Phone app 1.5.0:**
  - Usage has a search box.
  - Website names are readable.
  - Google Play: once the Play Console key is added to the project, each new phone version is uploaded to Play by itself.

## Network Doctor 3.14.0

**Alerts with priority, fixes and one-click Troubleshoot; Inventory tab with full PC details, torrent blocking, real website names, commands for other brands, and updates every day at 15:00.**

- **New tab: Alerts** (right after Home) - no more screenshots of the alert window.
  - Every warning and problem is kept with its time, **priority** (P1 fix now, P2 fix today, P3 this week, P4 information), the device and the **fix**. The same alert within 15 minutes is counted instead of repeated.
  - **Troubleshoot** (also on the alert pop-up): explains the alert, fixes it with one click where commands can (on the router after asking, or on this PC), and gives numbered steps with tick boxes for what needs hands on a cable, a switch or a device. Re-check and Mark fixed buttons.
  - Examples: "conflict by ARP response" reserves that IP for the device on the router; a torrent alert blocks torrents; a DVR reachable from the internet closes its port forward and UPnP; a loop turns on loop protection; a rogue DHCP server is blocked.
  - Alerts close by themselves when a later check finds the problem gone.
  - **Export** to Excel (CSV) or a report (HTML) with the fixes and steps; Copy puts the selected alerts and fixes on the clipboard.
  - The alert pop-up now shows the priority and the fix under each line.
  - The phone app shows the open alerts with priority, fix and steps.
- **New tab: Inventory** (right after Devices).
  - Every device and PC: IP, MAC, maker, host name, user, department, status.
  - For each PC: RAM (and the RAM sticks), SSD / HDD, CPU, graphics, monitors, keyboard, mouse, printers, antivirus (on / off, up to date), Windows Firewall, driver problems, last Windows update, BIOS and the installed programs.
  - **Needs attention** column and filters: driver problems, 4 GB RAM or less, HDD without SSD, disk almost full, antivirus off or out of date, no Windows update for 60+ days.
  - Click a PC to see all its details. Buttons: **Driver download page** (Dell / Lenovo / HP ... using the serial no.), Copy serial no., Copy details, Driver commands.
  - The Network Doctor PC adds its own details by itself (once a day). Other PCs: **Get PC details (script) > Inventory only (changes nothing)**, run it once on each PC.
- **PC names for Windows PCs** that hide them (for example a PC asking for a user name and password when you open its shared folders). The scan reads the computer name, domain and Windows version from the file-sharing service, without logging in.
- **Torrents.**
  - When a torrent download is found, the alert has a **Block torrents...** button.
  - Network guard has a new option: block torrent traffic and torrent websites on the MikroTik (rules placed above FastTrack so they really work; Undo removes everything).
  - The website firewall has a "Torrent sites" category.
- **Main website column** in the Live monitor (and on the phone): youtube.com, web.whatsapp.com, sheets.google.com ... instead of "Google services" or "UDP 20115", so you can judge work or not.
- **Commands for other brands** (Commands tab, choose the brand / type at the top, or search):
  - Switches and routers: Cisco IOS, TP-Link JetStream / Omada, D-Link, HP / Aruba, Ubiquiti UniFi / EdgeRouter, Netgear, Huawei.
  - Firewalls: FortiGate, Sophos, pfSense / OPNsense, Seqrite UTM.
  - Find a MAC's port, port speed and errors, loop protection, VLANs, DHCP snooping (stops rogue DHCP), and syslog / SNMP / NetFlow to Network Doctor.
  - Antivirus: Windows Defender (status, update, scan, threats), Quick Heal / Seqrite, K7, ESET and others.
  - Windows Firewall: on / off, allow a port, allow ping, file sharing, block rules, reset.
  - Drivers and updates: devices with driver problems, winget update of all programs, Dell Command Update, Lenovo System Update, HP Support Assistant, Windows Update repair, system file repair.
  - Printers: list, clear a stuck queue, add a printer by IP.
- **Automatic updates every day at 15:00.** The PC app checks at 15:00 (or at start-up if the PC was off at 15:00) and installs by itself (Setup > New versions). If there is no internet at 15:00 it tries again every 30 minutes.
- **Phone app 1.4.0.**
  - Checks for an update every day at 15:00 and shows an Update button. Android asks you to tap Install.
  - Inventory shows the new PC details and a "Needs attention" filter.
  - Top bandwidth users show the main website and app.
  - Open alerts with priority, fix and steps on the Summary page.
- **Faster and light on the network.**
  - Usage history has extra indexes, so the Usage tab stays fast with months of data.
  - Monitoring only reads what the router already sends (NetFlow / syslog / its DNS cache every 3 minutes); nothing is added to the internet line.
  - The speed test and the "busy line" test in Slow website? run only when you press them.

## Network Doctor 3.13.0

**New Home screen, "Slow website?" check, phone names, and a phone app with usage and inventory.**

- **Home screen (first tab).**
  - Your network at a glance: devices online, problems, internet used today, router connection.
  - Big buttons for the everyday jobs.
  - A setup checklist with a Fix button on every line that is not green yet.
- **New tab: Slow website?** Someone says Google Sheets (or Gmail, a portal...) is slow:
  1. Choose their device and the website, then press **Find the cause**.
  2. In about a minute Network Doctor tests their Wi-Fi / cable, the office network, the router (and its CPU), the internet line, DNS, packet size (MTU), the website itself against a reference site, whether the line is full and who fills it, what their PC is downloading, and their PC's RAM / disk.
  3. Optionally it also measures the delay while the line is busy.
  4. You get the causes, most likely first, each with the measurements, the fix steps and - where it can - a **Fix this on the router** button (fast public DNS, MSS clamp, limit the biggest user, fair queue). A command to compare the same timings on the user's own PC is included.
- **Phone and device names.** With the router login, the scan reads the router's DHCP list and ARP table, so phones show their names (Galaxy-S23, Redmi-Note-12, iPhone...) and devices that sleep are still listed. Health checks show how many devices got a name.
- **Updates & drivers in the app list.** Windows Update, Office and Defender updates, Dell / Lenovo / HP / Intel / NVIDIA / AMD / Realtek / Asus / Acer drivers, printer drivers, Chrome / Edge / Firefox updates and more - 146 apps, 871 website addresses in all. The advisor warns when updates run in office hours.
- **Phone app 1.3.0.**
  - Office PC now has Summary, Problems, Devices, **Usage** (apps, websites, productivity per person, advice), **Inventory** and Monitor.
  - **Check for updates** in About, plus a once-a-day automatic check with an Update button.
- Privacy policy updated (usage history, router login, phone update check).

## Network Doctor 3.12.0

**Apps told apart: WhatsApp, Instagram, Facebook, YouTube, Google Drive, Gmail and 126 more.**

- **New app catalogue: 133 apps, 776 website addresses.** Each address goes to its own app - WhatsApp (whatsapp.net), Instagram (cdninstagram.com), Facebook, Messenger, YouTube (googlevideo.com), Google Drive, Gmail, Google Meet, Teams, Outlook, OneDrive, Indian OTT, games, shopping, GST / income tax / GeM portals, banks, Tally, Zoho, AI tools and more. Before, everything on Meta's servers showed as "Facebook".
- **Usage > App list**: every app with its group (Social media, Messaging, Video, Office...), its category and its website addresses. Search, change the category, export to Excel.
- **Category per department.** Example: WhatsApp *Productive* for Sales, *Neutral* for everyone else. Choose the department in "for" before pressing Productive / Neutral / Unproductive.
- **Honest when unsure.** Google and Meta use some addresses for several apps (login and page servers). When the router cannot say which app a device used there, the traffic shows as "Google (shared address)" / "Meta (shared address)" instead of a guess. The big traffic (video, WhatsApp media, Instagram pictures) uses app-own addresses and is always named correctly. For exact per-user app names on every address, send all DNS through this PC: Tools > Network guard > "All DNS through this PC" with the website firewall running.
- The Live monitor's "Main app" column uses the same catalogue.

### Also in this version (first prepared as 3.11.1)

- **Fixed: "Security validation failure: invalid originating onefile parent process (PID not found)" after an update.** The update itself was installed, but the restarted app stopped with this message; it had to be started by hand. The new copy is now started with a clean environment. The same applies to "Restart as Administrator".
- **Fixed: "Apply router settings now" failed on RouterOS 6 with "expected end of command (line 10 column 118)".** A fallback for very old RouterOS used a word that 6.43+ and 7 do not know, and the router refuses a whole script when one word is unknown. If the router ever refuses a script again, the message shows the exact line.

## Network Doctor 3.11.0

**Usage and productivity, inventory, network guard, and direct router control.**

- **New Usage tab + dashboard.** Which device used which app and website, how much and when, with history for 120 days.
  - Every app / site is Productive, Neutral or Unproductive. Common ones are built in (YouTube, Instagram, OTT, games, shopping vs Microsoft 365, Google Workspace, Tally, GST / government portals, banking...). Change any of them with one click; the history follows.
  - Productivity per device / user = productive active time compared with unproductive active time.
  - **Open dashboard** makes an interactive page: traffic per day / hour, apps, websites, busy hours per weekday, devices and users, filters for period, department and device.
  - **The advisor learns this office's pattern**: the busiest hours and which apps fill them day after day, devices far above their normal, one device eating the line, updates / backups during office hours - each with what to do.
  - Website names come from the router's DNS cache (router login in Setup) or the website firewall. Bandwidth comes from NetFlow.
- **Router login (optional, Setup).** With a MikroTik user saved (password encrypted for this Windows user), Network Doctor can:
  - **Apply on router** for IP-MAC binding, the network guard and the router settings - no more copy / paste or .rsc files.
  - **Run on router** in the Commands tab and show the output.
  - read the DHCP host names and the DNS cache.
- **IP-MAC binding: choose the IP.** Double-click a device (or *Set IP of selected...*) and type the IP you want. It is checked: same network, not the router, not used or reserved by another device.
- **New tool: Network guard.** Stops a second router from giving out its own IP / DNS, sends all DNS through the office router (or the website firewall), and blocks randomized MACs so every phone keeps one identity and one history. With UNDO.
- **New tool: Inventory.** Every device ever seen, with IP, MAC, maker, host name, type, department, location, first / last seen - plus model, serial number, CPU, RAM, disk, Windows version and user from the PC script. Tag from the list, export to Excel.
- **More devices found.**
  - Several networks can be scanned at once, e.g. `192.168.0.0/24, 192.168.1.0/24` for cameras on their own range.
  - A second ARP round catches sleeping phones.
  - The router's own device list is read over SNMP; the router commands now switch this on, read-only and only for this PC.
- **Update error "getaddrinfo failed" fixed.** When this PC's DNS does not answer, Network Doctor asks public DNS servers itself.
- **Commands fixed.** Reserve IP (failed when a dynamic lease existed), Block / Unblock a device (failed with an empty firewall), Limit speed (named by IP now; new *Turn off FastTrack* command because FastTrack skips speed limits).
- **.rsc files.** Plain ASCII, with progress messages and a separate undo file. The message says how to import them: WinBox > Files, then `/import file-name=... verbose=yes`. Double-clicking a .rsc on the PC does nothing.
- **Live monitor.** It can be stopped and started again at once; before, the restart could not receive NetFlow / the router log ("UDP 2055 busy"). Devices on all scanned networks count as office devices.

### Also in this version (first prepared as 3.10.1)

**Warnings that did not go away after following their advice are fixed.**

- **Broadcast storm / loop warnings caused by cameras.** Windows' counter added broadcast and multicast together, so CCTV / NVR streams, mDNS and IPv6 traffic were reported as a "broadcast storm (probable loop)" - and unplugging cables never fixed it. Network Doctor now counts broadcasts and multicast separately. A loop is only suspected for real broadcasts; heavy multicast gets its own warning with the fix that works (IGMP snooping, cameras on unicast).
- **"Router log / NetFlow is not arriving".**
  - The router commands can now be pasted again safely (before, a second paste failed and the router kept sending to the old PC IP). They end with a test message, so the Live monitor shows "receiving" within seconds.
  - If this PC's IP changed, the note now says so and what to do.
  - A router that is set up but has had nothing to log is no longer reported as missing.
  - **Allow in Windows Firewall** also removes the hidden rules Windows adds when "Cancel" is clicked in its "allow this app" prompt - those blocked the router data even with the allow rule in place.
- **"Bound device ... is on IP X instead of Y".** The IP-MAC binding tab shows which devices moved and keeps their reserved IP when you make the commands again. New: **Moved devices: bind their NEW IP** and **Forget binding of selected**. The warning shows the device name instead of only its MAC.
- **"IP address now used by a different device"** no longer counts phones that changed their private (randomized) MAC.

## Network Doctor 3.10.0

**Updates now install by themselves.**

- Network Doctor checks GitHub when it starts and then every 6 hours (before, it checked only once a day).
- When a new version is found, it downloads in the background. A small window then says **"Restarting in 60 seconds"**, with **Restart now** and **Later (tomorrow)** buttons. If nobody is at the PC, it installs and starts again by itself, minimised, with monitoring and automatic checks running.
- It waits for a running scan or check to finish before updating.
- The **Updates** button at the top is always there. It shows your version, turns into **Update to x.y.z** when a new version is waiting, and installs it with one click.
- **Setup → New versions** lets you choose **Install automatically** (the default), **Ask me first**, or **Never check**.
- After an update, the status line and the health log show which version it updated from.
## Network Doctor 3.9.0

**New: website firewall for the whole network, switch control, and a map of all switches with ring / loop check.**

- **Tools -> Website firewall.** Blocks ads and trackers, adult sites, gambling, social media, video streaming or online games, plus your own list, for every phone, PC and TV on the network. Nothing is installed on them: set the router's DHCP DNS server to this PC's IP. It also has:
  - **Safe search** for Google, Bing, YouTube and DuckDuckGo
  - an always-allow list
  - a live report of which device tried to open what, and the most blocked sites

  The lists update weekly, and built-in names keep it working offline.
- **Switch control (any brand, SNMP).** In Switch / router details, after **Read**, choose a port. You can:
  - **Turn it off / on**
  - **Restart** it (reboots a hung camera or AP)
  - **Rename** it
  - **Undo** the last change

  It needs the switch's read-write community. Every change asks first and warns when the port carries this PC or a whole group of devices.
- **Map all switches.** Starting from one switch, Network Doctor follows the LLDP neighbours to every switch that shares the community. It shows which port connects to which switch. It also finds **rings** (more than one path) and checks that spanning tree blocks one port in each. A ring with nothing blocked is a network loop, and it names the cables.

## Network Doctor 3.8.0

**New: Linux version, switch and router details for any brand, a loop finder, and device filters.**

- **Linux app.** Download `NetworkDoctor-Linux` from this release, make it runnable once (`chmod +x NetworkDoctor-Linux`) and start it. It works without the old `arp` / `ifconfig` tools and updates itself like the Windows and Mac versions. Run it with `sudo` for the full IP-conflict tests.
- **Tools -> Switch / router details (SNMP, any brand).** Pick a managed switch or router (Cisco, TP-Link, MikroTik, Ubiquiti, HP, D-Link, Netgear and others) and its SNMP community. It shows:
  - the model, uptime and location
  - every port with its speed, traffic and errors, with warnings for 10/100 Mbps links and ports with errors
  - LLDP neighbours (which switch, AP or phone is on which port)
  - **which device is plugged into which port**, using the names Network Doctor already knows
  It is read-only and never changes anything on the switch.
- **Live traffic + loop check** (same tool, new button). Every 5 seconds: each port's in / out speed, how busy it is and broadcasts per second, with the device on it. It warns about:
  - **network loops**: a broadcast storm on a port, or devices jumping between the same two ports. It names the port, or both ports, so you know which cable to unplug. Loops are also written to the health log.
  - ports over 80% busy, errors and dropped packets.
- **Devices tab filters.**
  - Department and Location lists, filled from your tags.
  - A Show list: online only, *not tagged yet* (makes tagging everything easy), or *watched*.
  - Search now needs every word to match, and understands `dept:accounts`, `port:ether3`, `loc:"2nd floor"`, `vendor:hikvision` and `type:printer`.

## Network Doctor 3.7.0

**New: a Tools tab with the everyday network-engineer tools, and alerts when a critical device goes down.**

- **Critical devices (alert if down).** Tick *Watch* for the router, servers, ERP PC, DVR and switches (in **Tag...**, by right-click, or **Watch router + all network equipment**). They are pinged every 30 seconds; if one stops answering for about 1.5 minutes you get a pop-up and sound, it turns red on the map, and the health log records when it went down and came back. If several devices behind the same switch go down together, the alert names that switch. Shows 24-hour uptime per device.
- **New-device alert.** A pop-up when a MAC address that was never seen before joins the network (for example someone plugging in their own router). You can turn it off in Setup.
- **Tools tab:**
  - **Internet speed and quality:** public IP and ISP, ping / jitter / loss to the router and the internet (tells you whether the problem is inside the office or at the ISP), download and upload speed, and latency while the line is busy (bufferbloat). Results go into the health log.
  - **Port scanner:** open ports with what each service is, server banners, and the risky ones marked (Telnet, SMB, Remote Desktop, WinBox...).
  - **DNS lookup and DNS server test:** any record type on any server; compares this PC's, the router's and public DNS for speed, failures and DNS hijacking.
  - **Website / server check:** DNS, connect, TLS and answer times, and when the certificate expires. Useful for the ERP server, router pages, cameras and your websites.
  - **LAN speed test (PC to PC):** the real speed through the cables and switches between two PCs running Network Doctor. Finds 100 Mbps cables and slow switches.
  - **Wi-Fi analyzer:** nearby networks, channels, signal and security, and the best free channel.
  - **This PC's network adapters:** link speed (1 Gbps / 100 Mbps), duplex, packet errors, APIPA (169.254) addresses, cable + Wi-Fi bridging.
  - **MTU finder** (PPPoE / VPN problems where some websites hang), **subnet calculator**, **Wake-on-LAN** (also for PCs that are off now), **MAC address lookup**.
  - **Setup check - what is missing:** administrator rights, firewall rule, Npcap, router feeds, threat lists, start with Windows, watched devices, how many devices are tagged, PC fix script coverage. Each item says how to fix it.
- **PC fix script now also reports cable speed, duplex and errors** of every PC. A PC whose cable runs at 100 Mbps, in half duplex or with errors appears in Problems.
- **30 more ready commands** in the Commands tab: TCP port test, cable speed, routing table, Wi-Fi drop report, MikroTik cable test, torch, speed limit per device, MSS clamp, DHCP pool use, router services and logins, router backup, and more.
- **Fixes:**
  - The scan network now follows this PC's real subnet mask, instead of always using /24.
  - The automatic scan retries if a scan fails.
  - The firewall rule now also opens the phone link / PC report / LAN speed-test ports, for the office network only.
  - Wake-on-LAN is sent through the office network card, to every broadcast address.

## Network Doctor 3.6.0

**New: network map, tags, IP-MAC binding, a PC fix script and a command library.**

- **Tags.** Give any device a name, department, location, type and where it is connected (which switch / AP, router port, switch port). Select several devices in **Devices** and press **Tag...** to tag them all at once. Tags can be exported to and imported from Excel (CSV).
- **Network map tab.** Router → router ports → switches / APs → PCs, built from your tags and from MikroTik switches that announce themselves (MNDP). Problem devices and their whole path to the router light up red or orange, so you can see which port, switch and department a loop or flood comes from. **Only problem paths** hides everything else. Click a device for details, Ping, Analyse, Open in browser or its commands.
- **IP-MAC binding tab.** Tick devices and press **Make router commands**: the router then always gives each device the same IP (DHCP reservation), so two devices can no longer end up with the same address.
  - Optional **strict mode**: a device with a hand-typed IP cannot use the network.
  - Optional **block randomized MACs** on the router bridge.
  - An **UNDO** set of commands is always made too. The app still never logs in to the router; you paste the commands in WinBox → New Terminal.
  - The tab warns when a bound device appears on a different IP, or when another device uses a reserved IP.
- **PC fix script** (in IP-MAC binding and Commands). One `.cmd` file to run on every office PC (by hand, from a shared folder or as a login script). It:
  - turns off Wi-Fi random (private) MAC addresses, so each PC keeps one MAC;
  - can switch hand-typed IPs back to automatic (ask / yes / no);
  - renews the IP and can lock the router's MAC on the PC (stops ARP spoofing);
  - reports the PC name, user and MACs back to Network Doctor, which tags the device automatically.
  An undo script is made alongside it.
- **Commands tab.** About 40 ready Windows, MikroTik and Mac commands, each with a short line on what it does. Pick a device and its IP / MAC are filled in. **Copy** or **Run on this PC**, and add your own commands.

## Network Doctor 3.5.0

**New: automatic loop and network-problem checks, 24/7.**

- **Loop / conflict check every 5 minutes** (choose 2–15 minutes, or off). It is fast, takes about 20 seconds, and does not interrupt the network. It checks:
  - broadcast storms (loops)
  - duplicate replies from the router
  - IP conflicts on all known devices
  - router stability
  - rogue DHCP servers (every 30 minutes)
- **Full scan every 30 minutes** (choose 15–120 minutes, or off).
- **Alerts:** a pop-up with a sound appears when a **new** problem is found, or when the live monitor sees one:
  - a port going down (for example ether2)
  - a storm or loop
  - the router not answering
  - an IP conflict
  - ARP spoofing
  - a malware connection

  You get one alert per problem, not one every 5 minutes. When the problem goes away, a "Resolved" note is logged. Use **Mute 1 hour** if you are working on it.
- **Health log:** every check and every problem is written to `Documents\NetworkDoctor Reports\health-log-YYYY-MM.csv`, which opens in Excel. It is a record of when the network had trouble.
- **Start with Windows:** tick it in **Setup → Automatic checks**. The app then starts minimised at login with full administrator tests and no prompt, so the checks keep running after a restart.
- The phone app sees the open problems and the latest check result.

All settings are in **Setup → Automatic checks (24/7)**. The status line at the top shows the last check, for example *09:05 OK*.

**Windows first start:** if Windows says *"Windows protected your PC"*, click **More info → Run anyway**. This appears because the app is not code-signed.
