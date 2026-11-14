# Network Doctor — PC agent (one button for users)

One small agent per office PC. **Users see a single "Fix my PC" button on the Desktop.** Everything else runs
quietly in the background and feeds Network Doctor.

## What it does
**When a user clicks "Fix my PC":**
- Cleans junk (temp, caches, prefetch, Delivery-Optimisation cache, Windows Update leftovers, old Windows
  component files via DISM), empties the Recycle Bin, flushes DNS, restarts Explorer, shows space freed.
  **It never touches Documents, Desktop, Downloads or any real file.**
- Runs a quick Windows health check (DISM CheckHealth, a few seconds). Only **if** it finds repairable damage
  does it run the full repair (DISM RestoreHealth + sfc /scannow, several minutes) - healthy PCs stay fast.
- Sends this PC's fresh **details** (maker, model, serial, Windows, CPU, RAM, disk, logged-in user, printers,
  antivirus) and **resource use** (CPU %, memory %, top memory apps) to Network Doctor.
- Sends the current **network connections** — which app (process) is talking to which internet address — so
  Network Doctor can name site/app usage correctly instead of "unknown".

**Quietly in the background (starts at logon):**
- Watches USB drives: plugged in / removed, and any file copied to one (name, size, user) — never contents.
- Every minute writes which app is using the network; every 30 minutes refreshes details + CPU/RAM.

It writes only to a shared folder on the IT PC. It never uses the internet.

## Install (per PC, 2 minutes)
1. Make a shared folder on the IT PC, e.g. `\\RAKESH-IT\LeakLog`, that staff PCs can write to.
2. Open `networkdoctor-agent.ps1`, set the first line `$Central` to that share.
3. Copy the `endpoint` folder to the PC and **right-click `install-agent.cmd` → Run as administrator**.

`uninstall-agent.cmd` removes it. Network Doctor reads the shared folder automatically (set it in
**Settings → endpoint_dir** if it is not the default).

## Why this improves Network Doctor
- **App/site usage**: the network alone sees only IP↔IP (so it guessed "CDN", "Google service not known").
  The agent maps each connection to the real app on the PC (Chrome, WhatsApp, a backup tool…), so usage names
  get accurate.
- **Inventory**: every PC lists itself — you don't run a details script on each PC any more.
- **Resource monitor**: CPU %, memory % and the heaviest apps per PC.
- **Data-leak control**: USB copies the network can never see.

## Honest limits
- Must be installed on each PC; a PC without it is not covered.
- A user with local-admin rights can stop any agent — don't give staff admin rights.
- It reads no file contents and can't catch a leak by screenshot, printing or phone photo.
- Per-process **byte** totals are not collected (Windows does not expose them without heavier tooling);
  Network Doctor already has the bytes per address from the router and uses the agent only to put the right
  **app name** on them.
