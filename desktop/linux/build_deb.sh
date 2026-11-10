#!/bin/sh
# Builds NetworkDoctor_<version>_amd64.deb: a real Ubuntu/Debian package, not just a loose binary.
#
# What it fixes over the old "download a file, chmod +x, run it from a terminal" install:
#   - `apt install ./NetworkDoctor_*.deb` puts the binary where it belongs (/opt/networkdoctor), registers
#     it with the desktop (a .desktop entry + icon under /usr/share/applications and
#     /usr/share/icons/hicolor), and adds a plain `networkdoctor` command to PATH - so it shows up in the
#     app menu / Activities search like any other installed app, and can be pinned to a launcher or
#     taskbar from there, the same as Windows/Mac users get for free.
#   - The postinst script grants the installed binary CAP_NET_RAW/CAP_NET_ADMIN directly (`setcap`), so the
#     raw-socket scans and the ARP-based device block (nd_arpblock.py) work without `sudo` every launch -
#     the Linux equivalent of the admin checkbox Windows/Mac already have.
#   - Setup > "Start at login" (NetworkDoctor.py's toggle_autostart()) then has somewhere sane to point an
#     XDG autostart entry at, so the app can actually run in the background across reboots.
#
# Takes a PyInstaller --onedir build (a folder: NetworkDoctor + its _internal/ support files), not a
# --onefile binary. A file with capabilities set (setcap, just above) becomes a "secure-exec" process to
# the kernel - the same treatment as a setuid binary - which makes /proc/<pid>/exe unreadable by other
# processes including its own children. PyInstaller's --onefile bootloader forks a child that re-reads its
# own parent's /proc/<ppid>/exe to confirm it wasn't hijacked, so a setcap'd onefile binary fails to start
# with "Security validation failure: could not access /proc entry...". --onedir runs the real executable
# directly - no self-extracting fork, so that check never happens. The portable NetworkDoctor-Linux
# download stays --onefile (see the workflow) since it is never setcap'd.
#
# Usage: build_deb.sh <path-to-onedir-folder> <version e.g. 3.23.0> <path-to-icon.png> <output .deb path>
set -eu

BINDIR="$1"
VERSION="$2"
ICON="$3"
OUT="$4"

if [ ! -f "$BINDIR/NetworkDoctor" ]; then echo "build_deb.sh: $BINDIR/NetworkDoctor not found (expected a PyInstaller --onedir folder)" >&2; exit 1; fi
if [ ! -f "$ICON" ]; then echo "build_deb.sh: icon not found: $ICON" >&2; exit 1; fi

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
PKG="$WORK/pkgroot"

mkdir -p "$PKG/DEBIAN" "$PKG/opt/networkdoctor" "$PKG/usr/bin" \
         "$PKG/usr/share/applications" "$PKG/usr/share/icons/hicolor/192x192/apps"

# Copy the whole onedir folder's contents (the NetworkDoctor executable plus its _internal/ support files
# as siblings) - not just the executable, or it can't find its bundled libraries at runtime.
cp -r "$BINDIR"/. "$PKG/opt/networkdoctor/"
chmod 755 "$PKG/opt/networkdoctor/NetworkDoctor"
# 192x192: the real size of the shared source icon (mobile/.../ic_launcher.png) - placed under the matching
# hicolor size bucket rather than upscaled into a larger one.
cp "$ICON" "$PKG/usr/share/icons/hicolor/192x192/apps/networkdoctor.png"
cp "$HERE/networkdoctor.desktop" "$PKG/usr/share/applications/networkdoctor.desktop"
ln -s /opt/networkdoctor/NetworkDoctor "$PKG/usr/bin/networkdoctor"

SIZE_KB="$(du -sk "$PKG/opt" "$PKG/usr" | awk '{sum+=$1} END {print sum}')"

cat > "$PKG/DEBIAN/control" <<EOF
Package: networkdoctor
Version: $VERSION
Section: net
Priority: optional
Architecture: amd64
Installed-Size: $SIZE_KB
Maintainer: Network Doctor <noreply@github.com>
Recommends: libcap2-bin
Homepage: https://github.com/yadavrkpacheriya/network-doctor
Description: Network scanner, live monitor and root-cause tool for office LANs
 Finds every device on the LAN, sorts each one into a category, and explains
 why the network misbehaves: IP conflicts, loops, ports dropping, rogue DHCP
 servers, bandwidth hogs and devices talking to dangerous servers.
EOF

# libcap2-bin provides setcap; it is a Recommends (not a hard Depends) so the package still installs
# without it - the app just falls back to needing sudo for raw-socket tests, same as before this package
# existed. update-desktop-database / gtk-update-icon-cache are best-effort refreshes of caches that may not
# exist on a minimal system; their absence is not an install failure.
cat > "$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin+eip /opt/networkdoctor/NetworkDoctor || true
fi
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -qf /usr/share/icons/hicolor || true
exit 0
EOF
chmod 755 "$PKG/DEBIAN/postinst"

cat > "$PKG/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -qf /usr/share/icons/hicolor || true
exit 0
EOF
chmod 755 "$PKG/DEBIAN/postrm"

mkdir -p "$(dirname "$OUT")"
dpkg-deb --build --root-owner-group "$PKG" "$OUT"
rm -rf "$WORK"
echo "Built $OUT"
