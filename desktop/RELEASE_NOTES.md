## Network Doctor 3.8.0

**New: Linux version, switch and router details for any brand, and device filters.**

- **Linux app.** Download `NetworkDoctor-Linux` from this release, make it runnable once (`chmod +x NetworkDoctor-Linux`) and start it. It works without the old `arp` / `ifconfig` tools and updates itself like the Windows and Mac versions. Run it with `sudo` for the full IP-conflict tests.
- **Tools -> Switch / router details (SNMP, any brand).** Pick a managed switch or router (Cisco, TP-Link, MikroTik, Ubiquiti, HP, D-Link, Netgear and others) and its SNMP community. It shows:
  - the model, uptime and location
  - every port with its speed, traffic and errors, with warnings for 10/100 Mbps links and ports with errors
  - LLDP neighbours (which switch, AP or phone is on which port)
  - **which device is plugged into which port**, using the names Network Doctor already knows
  It is read-only and never changes anything on the switch.
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
