## Network Doctor 3.4.0

**New: Mac version.**
Download **NetworkDoctor-macOS.zip** below. It is for Macs with Apple silicon (M1 or newer).

1. Unzip it and move **NetworkDoctor** to *Applications*.
2. The first time, **right-click → Open**.
3. If macOS still blocks it, go to **System Settings → Privacy & Security → Open Anyway**. This appears because the app is not yet signed with an Apple Developer certificate.

On the Mac:
- The router log arrives on port **5514**. The *Copy router commands* button already uses it.
- The IP-conflict rounds need administrator rights.
- Mac copies update themselves the same way as Windows copies.

**Also fixed:**
- MAC addresses printed without leading zeros (macOS style) are now read correctly.
- Devices that block ping are found from the ARP table on Mac and Linux.
- Pings on Mac now use the right timeout, so there are no false "router not answering" alarms.

**Windows first start:** if Windows says *"Windows protected your PC"*, click **More info → Run anyway**. This appears because the app is not code-signed.
