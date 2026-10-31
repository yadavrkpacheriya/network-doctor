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
