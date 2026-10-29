import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;

import 'model.dart';
import 'probe.dart';

/// Ports tried to see if a device is there at all (any answer, even "refused", counts).
const alivePorts = [80, 443, 445, 22, 62078, 139, 554, 8080, 53, 7547, 8000, 5000];

/// Ports tried on devices that answered, to work out what they are.
final fullPorts = portNames.keys.toList();

class ScanResult {
  ScanResult(this.devices, this.network, this.gateway, this.myIp, this.seconds);
  final List<Device> devices;
  final String network;
  final String? gateway;
  final String myIp;
  final int seconds;
}

class Scanner {
  bool _cancel = false;
  void cancel() => _cancel = true;
  bool get cancelled => _cancel;

  Future<ScanResult> run({
    required String myIp,
    required String? gateway,
    required int prefix,
    required void Function(double pct, String text) onProgress,
  }) async {
    final sw = Stopwatch()..start();
    final hosts = hostsOf(myIp, prefix);
    final found = <String, Device>{};
    var done = 0;

    onProgress(0.02, 'Looking for devices on ${hosts.length} addresses...');
    await pool<String>(hosts, 24, (ip) async {
      if (ip == myIp) return;
      final results = await Future.wait(alivePorts.map((p) => tcpProbe(ip, p)));
      Device? d;
      for (var i = 0; i < results.length; i++) {
        final r = results[i];
        if (r.alive) {
          d ??= Device(ip);
          if (r.open) d.ports.add(alivePorts[i]);
          if (d.rttMs == null || r.ms < d.rttMs!) d.rttMs = r.ms;
        }
      }
      if (d != null) found[ip] = d;
      done++;
      if (done % 8 == 0) onProgress(0.02 + 0.5 * done / hosts.length, 'Looking for devices... $done/${hosts.length} (${found.length} found)');
    }, cancelled: () => _cancel);
    if (_cancel) throw const ScanCancelled();

    if (gateway != null && !found.containsKey(gateway)) {
      found[gateway] = Device(gateway);
    }
    final me = Device(myIp)..isSelf = true;
    found[myIp] = me;
    final alive = found.keys.where((ip) => ip != myIp).toList();

    onProgress(0.55, 'Checking services of ${alive.length} devices...');
    var n = 0;
    await pool<String>(alive, 12, (ip) async {
      final d = found[ip]!;
      final todo = fullPorts.where((p) => !alivePorts.contains(p)).toList();
      final res = await Future.wait(todo.map((p) => tcpProbe(ip, p, timeout: const Duration(milliseconds: 600))));
      for (var i = 0; i < res.length; i++) {
        if (res[i].open) d.ports.add(todo[i]);
      }
      n++;
      onProgress(0.55 + 0.25 * n / alive.length, 'Checking services... $n/${alive.length}');
    }, cancelled: () => _cancel);
    if (_cancel) throw const ScanCancelled();

    onProgress(0.82, 'Reading computer names...');
    final names = await netbiosNames(alive);
    names.forEach((ip, name) => found[ip]?.netbios = name);

    onProgress(0.88, 'Asking routers, cameras and TVs to describe themselves (UPnP)...');
    final upnp = await ssdpDiscover();
    upnp.forEach((ip, info) {
      final d = found[ip];
      if (d == null) return;
      d.upnpName = info['friendlyName'] ?? '';
      d.upnpModel = info['modelName'] ?? '';
      d.upnpMaker = info['manufacturer'] ?? '';
      d.upnpType = '${info['deviceType'] ?? ''} ${info['st'] ?? ''}';
      d.server = info['server'] ?? '';
    });

    onProgress(0.94, 'Looking up names...');
    await pool<String>(alive, 16, (ip) async {
      found[ip]!.dns = await reverseName(ip);
    });

    for (final d in found.values) {
      d.isGateway = d.ip == gateway;
      d.name = d.netbios.isNotEmpty ? d.netbios : (d.upnpName.isNotEmpty ? d.upnpName : d.dns.split('.').first);
      final (c, why) = categorize(d, gateway);
      d.category = c;
      d.reason = why;
    }
    final list = found.values.toList()
      ..sort((a, b) {
        final c = Cat.order.indexOf(a.category).compareTo(Cat.order.indexOf(b.category));
        return c != 0 ? c : sortKey(a.ip).compareTo(sortKey(b.ip));
      });
    onProgress(1, 'Done');
    final pre = prefix < 22 ? 22 : prefix;
    return ScanResult(list, '${intToIp(ipToInt(myIp) & ((0xFFFFFFFF << (32 - pre)) & 0xFFFFFFFF))}/$pre', gateway, myIp,
        sw.elapsed.inSeconds);
  }
}

class ScanCancelled implements Exception {
  const ScanCancelled();
}

/// UPnP / SSDP: routers, NVRs, smart TVs and printers answer with a description of themselves.
Future<Map<String, Map<String, String>>> ssdpDiscover({Duration wait = const Duration(seconds: 3)}) async {
  final found = <String, Map<String, String>>{};
  RawDatagramSocket? sock;
  try {
    final s = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
    sock = s;
    s.listen((ev) {
      if (ev != RawSocketEvent.read) return;
      final dg = s.receive();
      if (dg == null) return;
      final text = latin1.decode(dg.data, allowInvalid: true);
      final m = found.putIfAbsent(dg.address.address, () => {});
      for (final line in const LineSplitter().convert(text)) {
        final i = line.indexOf(':');
        if (i <= 0) continue;
        final k = line.substring(0, i).trim().toLowerCase();
        final v = line.substring(i + 1).trim();
        if (k == 'server') m['server'] ??= v;
        if (k == 'location') m['location'] ??= v;
        if (k == 'st') m['st'] = '${m['st'] ?? ''} $v'.trim();
      }
    });
    final msg = utf8.encode('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
        'MX: 2\r\nST: ssdp:all\r\n\r\n');
    for (var i = 0; i < 2; i++) {
      try {
        s.send(msg, InternetAddress('239.255.255.250'), 1900);
      } catch (_) {}
      await Future.delayed(const Duration(milliseconds: 300));
    }
    await Future.delayed(wait);
  } catch (_) {
  } finally {
    sock?.close();
  }
  final tag = RegExp(r'<(friendlyName|manufacturer|modelName|deviceType)>([^<]{1,120})</', caseSensitive: false);
  await Future.wait(found.values.where((m) => m['location'] != null).map((m) async {
    try {
      final r = await http.get(Uri.parse(m['location']!)).timeout(const Duration(seconds: 3));
      for (final t in tag.allMatches(r.body)) {
        const canon = {
          'friendlyname': 'friendlyName',
          'manufacturer': 'manufacturer',
          'modelname': 'modelName',
          'devicetype': 'deviceType',
        };
        final key = canon[t.group(1)!.toLowerCase()];
        if (key != null) m[key] ??= t.group(2)!.trim();
      }
    } catch (_) {}
  }));
  return found;
}
