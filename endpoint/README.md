# Network Doctor — LeakWatch endpoint agent

The office network (and Network Doctor's Usage page) can see which **website or app** each PC used and how much
it uploaded. It can **never** see a file copied to a **USB pen drive, phone or external disk** — that never
touches the network. LeakWatch is a tiny agent that runs on each PC and reports exactly that.

## What it records
- A removable drive (USB stick, phone, external disk) **plugged in or removed**, with the PC and the logged-in user.
- A file **created, copied or renamed on** such a drive — the file's path and size (not its contents).

It reads nothing else, opens no file's contents, and sends nothing to the internet. It only appends CSV lines
to a shared folder on your IT PC.

## Install (per PC, 2 minutes)
1. Make a shared folder on your IT PC, e.g. `\\RAKESH-IT\LeakLog`, that staff PCs can write to.
2. Open `leakwatch-agent.ps1` and set the first line `$Central` to that share (leave `""` for local-only).
3. Copy the `endpoint` folder to the PC and **right-click `install-leakwatch.cmd` → Run as administrator**.

It installs a hidden scheduled task that starts at every logon. `uninstall-leakwatch.cmd` removes it.

## Seeing the data
Network Doctor reads the collected folder automatically and raises an alert when files are copied to USB
(name, user, PC, department, size). Point it at the share in **Settings → endpoint_dir** if it is not the
default `…\NetworkDoctor\leakwatch`.

## Honest limits
- It needs to be installed on each PC; a PC without it is not watched.
- A savvy user with local-admin rights can stop any agent. For staff PCs, do not give users admin rights.
- It does not read file contents and cannot catch a leak by screenshot, printing or typing.
