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
