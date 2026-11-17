# Camera firmware — safe update & brick recovery

Network Doctor **tracks** camera firmware (Cameras → "Firmware & versions") but never flashes it, because a
wrong or interrupted flash **bricks** a no-name camera and no software can un-brick it remotely. This is the
safe procedure to update firmware yourself, and how to recover a camera that does brick.

## Before you flash anything
1. **Record what you have.** Cameras → "Camera health report" (online), then "Firmware & versions". Note each
   camera's exact **model** and current **firmware**.
2. **Get the RIGHT file.** Download firmware **only** for that exact model, from the seller/manufacturer who
   supplied the camera. A file for a different model/board is the #1 cause of bricking. If you are not sure it
   matches, do not flash.
3. **Back up the config** of every camera you will touch: Cameras → "Restart & fix camera IPs" → config
   backup (or the camera's own export). You will need it if settings are wiped.
4. **Power must be stable.** Flash over a wired/PoE link the camera will not lose. Never flash during a power
   cut or on a flaky PoE port. One camera at a time.

## Assisted update (the safe flow)
1. **Test on ONE spare camera first** — never the whole fleet. Flash it, confirm it boots, keeps its IP, and
   the picture is fine.
2. Apply the firmware through the camera's **own** mechanism (its web page, or the XMeye/CMS "upgrade"), which
   is the tested path for that model.
3. After it reboots, re-run **Camera health report** → the registry records the new version and confirms the
   camera is reachable and the login still works. Restore the config backup if any setting was lost.
4. Only once the spare is proven, repeat model-by-model, a few at a time, checking the health report each
   round.

## If a camera bricks (no boot, no ping after a flash)
A bricked camera needs **physical** recovery — software cannot reach it:
1. **Power-cycle** once (pull PoE 10 s, replug). Some cameras finish a half-done flash on the next boot.
2. **TFTP recovery** (most XMeye/Dahua-style boards): set your PC to the camera's recovery IP range (often
   `192.168.1.x`), run a TFTP server with the correct recovery firmware named as the board expects
   (e.g. a brand-specific `.bin`), power the camera while it requests the file over the wire. The exact IP and
   filename are board-specific — get them from the seller.
3. **Serial / UART** console (3-pin TX/RX/GND on the board, USB-TTL adapter, 115200 baud) to re-flash from the
   bootloader — advanced, and only with the vendor's recovery image.
4. If none of that works, it is an **RMA / replacement**. This is why we flash one spare first.

## What the app does and does not do
- **Does:** store model/firmware per camera, track version changes, flag cameras off a target version you set,
  back up config, and verify each camera after you update it.
- **Does not:** download firmware for local/no-name brands (there is no reliable per-model source), and does
  not flash firmware automatically — by design, to protect the cameras.
