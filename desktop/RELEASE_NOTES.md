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
