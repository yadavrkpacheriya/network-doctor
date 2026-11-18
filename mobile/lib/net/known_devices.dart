import 'package:shared_preferences/shared_preferences.dart';

import 'model.dart';

/// Remembers which devices (by MAC) have been seen on each network, so a scan can flag a freshly connected
/// one - e.g. a new camera just plugged into the LAN - with a clear "NEW" highlight. Per-network, so moving
/// to a different Wi-Fi/office doesn't mark everything new; keyed by the scanned network (e.g. 192.168.0.0/24).
class KnownDevices {
  static String _key(String network) => 'known_macs::$network';

  /// Mark devices whose MAC was not seen on this network before as new, then remember the current set.
  /// Returns the number newly seen. The very first scan of a network marks nothing new (nothing to compare).
  static Future<int> markAndRemember(String network, List<Device> devices) async {
    if (network.isEmpty) return 0;
    final p = await SharedPreferences.getInstance();
    final key = _key(network);
    final known = (p.getStringList(key) ?? const <String>[]).toSet();
    final firstEver = known.isEmpty;
    final now = <String>{};
    var count = 0;
    for (final d in devices) {
      final mac = d.mac.trim().toUpperCase();
      if (mac.isEmpty) continue;
      now.add(mac);
      if (!firstEver && !known.contains(mac)) {
        d.isNew = true;
        count++;
      }
    }
    // keep anything seen before plus what is online now, so a device that is off today isn't "new" tomorrow
    await p.setStringList(key, {...known, ...now}.toList());
    return count;
  }

  /// Forget the baseline for a network, so the next scan's devices are all treated as already known
  /// (used by a "mark all as known" action).
  static Future<void> reset(String network, List<Device> devices) async {
    if (network.isEmpty) return;
    final p = await SharedPreferences.getInstance();
    final macs = devices.map((d) => d.mac.trim().toUpperCase()).where((m) => m.isNotEmpty).toSet();
    await p.setStringList(_key(network), macs.toList());
    for (final d in devices) {
      d.isNew = false;
    }
  }
}
