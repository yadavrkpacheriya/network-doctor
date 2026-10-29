import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

/// Result of trying one TCP port. A refused connection still proves the device is there.
class Probe {
  const Probe(this.alive, this.open, this.ms);
  final bool alive;
  final bool open;
  final int ms;
}

const _refusedCodes = {111, 61, 10061}; // Linux/Android, iOS/macOS, Windows

Future<Probe> tcpProbe(String ip, int port, {Duration timeout = const Duration(milliseconds: 450)}) async {
  final sw = Stopwatch()..start();
  try {
    final s = await Socket.connect(ip, port, timeout: timeout);
    final ms = sw.elapsedMilliseconds;
    s.destroy();
    return Probe(true, true, ms);
  } on SocketException catch (e) {
    final code = e.osError?.errorCode;
    final msg = '${e.osError?.message ?? ''} ${e.message}'.toLowerCase();
    if ((code != null && _refusedCodes.contains(code)) || msg.contains('refused')) {
      return Probe(true, false, sw.elapsedMilliseconds);
    }
    return const Probe(false, false, 0);
  } catch (_) {
    return const Probe(false, false, 0);
  }
}

/// "Ping" that works on every phone without special permissions: time to get any TCP answer.
Future<int?> tcpPing(String ip, List<int> ports, {Duration timeout = const Duration(milliseconds: 1500)}) async {
  for (final p in ports) {
    final r = await tcpProbe(ip, p, timeout: timeout);
    if (r.alive) return max(r.ms, 1);
  }
  return null;
}

/// Runs [fn] over [items] with at most [n] running at the same time.
Future<void> pool<T>(List<T> items, int n, Future<void> Function(T) fn, {bool Function()? cancelled}) async {
  var i = 0;
  Future<void> worker() async {
    while (true) {
      if (cancelled != null && cancelled()) return;
      if (i >= items.length) return;
      final item = items[i++];
      await fn(item);
    }
  }

  await Future.wait(List.generate(min(n, max(items.length, 1)), (_) => worker()));
}

// ---------------------------------------------------------------- IPv4 helpers
int ipToInt(String ip) {
  final p = ip.split('.').map(int.parse).toList();
  return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

String intToIp(int n) => '${(n >> 24) & 255}.${(n >> 16) & 255}.${(n >> 8) & 255}.${n & 255}';

int maskToPrefix(String? mask) {
  if (mask == null || !RegExp(r'^\d+\.\d+\.\d+\.\d+$').hasMatch(mask)) return 24;
  var n = ipToInt(mask);
  var bits = 0;
  while (n & 0x80000000 != 0) {
    bits++;
    n = (n << 1) & 0xFFFFFFFF;
  }
  return bits == 0 ? 24 : bits;
}

/// Host addresses of the network [ip]/[prefix]; never more than 1024 (a /22).
List<String> hostsOf(String ip, int prefix) {
  final pre = min(30, max(22, prefix));
  final mask = (0xFFFFFFFF << (32 - pre)) & 0xFFFFFFFF;
  final net = ipToInt(ip) & mask;
  final bcast = net | (~mask & 0xFFFFFFFF);
  return [for (var n = net + 1; n < bcast; n++) intToIp(n)];
}

String broadcastOf(String ip, int prefix) {
  final pre = min(30, max(8, prefix));
  final mask = (0xFFFFFFFF << (32 - pre)) & 0xFFFFFFFF;
  return intToIp((ipToInt(ip) & mask) | (~mask & 0xFFFFFFFF));
}

int sortKey(String ip) {
  try {
    return ipToInt(ip);
  } catch (_) {
    return 0x7FFFFFFF;
  }
}

// ---------------------------------------------------------------- NetBIOS computer names
Uint8List buildNbstat(int tid) {
  final b = BytesBuilder();
  b.add([tid >> 8 & 255, tid & 255, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20]);
  final name = [0x2A] + List.filled(15, 0); // '*' padded
  for (final c in name) {
    b.add([0x41 + (c >> 4), 0x41 + (c & 0x0F)]);
  }
  b.add([0, 0, 0x21, 0, 1]);
  return b.toBytes();
}

/// Returns the computer name from a NetBIOS node-status answer, or null.
String? parseNbstat(Uint8List d) {
  try {
    var off = 12;
    if (d[off] & 0xC0 == 0xC0) {
      off += 2;
    } else {
      while (d[off] != 0) {
        off += d[off] + 1;
      }
      off += 1;
    }
    off += 10; // type, class, ttl, length
    final n = d[off];
    off += 1;
    for (var i = 0; i < n; i++) {
      final e = d.sublist(off + i * 18, off + i * 18 + 18);
      final nm = String.fromCharCodes(e.sublist(0, 15)).trim();
      final suffix = e[15];
      final group = (e[16] & 0x80) != 0;
      if (suffix == 0 && !group && nm.isNotEmpty) return nm;
    }
  } catch (_) {}
  return null;
}

Future<Map<String, String>> netbiosNames(List<String> ips, {Duration wait = const Duration(seconds: 2)}) async {
  final out = <String, String>{};
  RawDatagramSocket? sock;
  try {
    final s = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
    sock = s;
    s.listen((ev) {
      if (ev == RawSocketEvent.read) {
        final dg = s.receive();
        if (dg != null) {
          final n = parseNbstat(dg.data);
          if (n != null) out[dg.address.address] = n;
        }
      }
    });
    final pkt = buildNbstat(Random().nextInt(0xFFFF));
    for (final ip in ips) {
      try {
        s.send(pkt, InternetAddress(ip), 137);
      } catch (_) {}
      await Future.delayed(const Duration(milliseconds: 4));
    }
    await Future.delayed(wait);
  } catch (_) {
  } finally {
    sock?.close();
  }
  return out;
}

Future<String> reverseName(String ip) async {
  try {
    final r = await InternetAddress(ip).reverse().timeout(const Duration(milliseconds: 1500));
    return r.host == ip ? '' : r.host;
  } catch (_) {
    return '';
  }
}
