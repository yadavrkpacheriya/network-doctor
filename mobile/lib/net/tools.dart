// Everyday network tools that work on any phone without special permissions.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'model.dart';
import 'probe.dart';

// ---------------------------------------------------------------- Wake-on-LAN
List<int>? parseMac(String s) {
  final hex = s.replaceAll(RegExp(r'[^0-9A-Fa-f]'), '');
  if (hex.length != 12) return null;
  return [for (var i = 0; i < 12; i += 2) int.parse(hex.substring(i, i + 2), radix: 16)];
}

Uint8List magicPacket(List<int> mac) =>
    Uint8List.fromList([...List.filled(6, 0xFF), for (var i = 0; i < 16; i++) ...mac]);

/// Sends the magic packet to the broadcast address on ports 9 and 7.
Future<void> wakeOnLan(String mac, {String broadcast = '255.255.255.255'}) async {
  final m = parseMac(mac);
  if (m == null) throw const FormatException('A MAC address has 12 hex digits, like AA:BB:CC:11:22:33');
  final s = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
  s.broadcastEnabled = true;
  try {
    for (final port in [9, 7]) {
      s.send(magicPacket(m), InternetAddress(broadcast), port);
    }
  } finally {
    s.close();
  }
}

// ---------------------------------------------------------------- subnet calculator
class Subnet {
  Subnet(this.network, this.prefix, this.mask, this.broadcast, this.first, this.last, this.hosts, this.wildcard);
  final String network, mask, broadcast, first, last, wildcard;
  final int prefix, hosts;
}

/// "192.168.1.77/24", "192.168.1.77 255.255.255.0" or just an IP (/24).
Subnet? subnetOf(String input) {
  final m = RegExp(r'^\s*(\d+\.\d+\.\d+\.\d+)\s*(?:/\s*(\d+)|\s+(\d+\.\d+\.\d+\.\d+))?\s*$').firstMatch(input);
  if (m == null) return null;
  final ip = m.group(1)!;
  if (ip.split('.').any((x) => int.parse(x) > 255)) return null;
  final prefix = m.group(2) != null ? int.parse(m.group(2)!) : (m.group(3) != null ? maskToPrefix(m.group(3)) : 24);
  if (prefix < 0 || prefix > 32) return null;
  final maskInt = prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF;
  final net = ipToInt(ip) & maskInt;
  final bc = net | (~maskInt & 0xFFFFFFFF);
  final hosts = prefix >= 31 ? (prefix == 32 ? 1 : 2) : bc - net - 1;
  final first = prefix >= 31 ? net : net + 1;
  final last = prefix >= 31 ? bc : bc - 1;
  return Subnet(intToIp(net), prefix, intToIp(maskInt), intToIp(bc), intToIp(first), intToIp(last), hosts,
      intToIp(~maskInt & 0xFFFFFFFF));
}

// ---------------------------------------------------------------- DNS
class DnsResult {
  DnsResult(this.addresses, this.ms, [this.error = '']);
  final List<String> addresses;
  final int ms;
  final String error;
}

Future<DnsResult> dnsLookup(String name) async {
  final sw = Stopwatch()..start();
  try {
    final r = await InternetAddress.lookup(name.trim()).timeout(const Duration(seconds: 5));
    return DnsResult(r.map((a) => a.address).toList(), sw.elapsedMilliseconds);
  } on SocketException catch (e) {
    return DnsResult([], sw.elapsedMilliseconds, 'not found (${e.osError?.message ?? e.message})');
  } on TimeoutException {
    return DnsResult([], sw.elapsedMilliseconds, 'no answer in 5 s');
  }
}

// ---------------------------------------------------------------- port scan
const commonPorts = [
  21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 515, 554, 631, 993, 1433, 1723, 1883, 3306, 3389, 4370,
  5000, 5060, 5432, 5900, 7547, 8000, 8080, 8081, 8291, 8443, 8728, 9100, 34567, 37777, 62078,
];
const riskyPorts = {
  23: 'Telnet sends passwords in plain text',
  445: 'Windows file sharing - keep it off the internet',
  3389: 'Remote Desktop - a common way in for attackers',
  5900: 'VNC remote control - often has a weak password',
  8291: 'MikroTik WinBox - limit who can reach it',
  7547: 'TR-069 remote management by the ISP',
  21: 'FTP sends passwords in plain text',
};

Future<List<int>> portScan(String host, {List<int> ports = commonPorts, bool Function()? cancelled,
    void Function(int done)? progress}) async {
  final open = <int>[];
  var done = 0;
  await pool(ports, 32, (p) async {
    final r = await tcpProbe(host, p, timeout: const Duration(milliseconds: 800));
    if (r.open) open.add(p);
    progress?.call(++done);
  }, cancelled: cancelled);
  return open..sort();
}

String portName(int p) => portNames[p] ?? '';

// ---------------------------------------------------------------- internet speed
class SpeedResult {
  SpeedResult({this.pingMs, this.downMbps, this.upMbps, this.error = ''});
  final int? pingMs;
  final double? downMbps;
  final double? upMbps;
  final String error;
}

/// Ping to Cloudflare, then download and upload speed (Cloudflare speed-test servers, like the PC app).
Future<SpeedResult> speedTest({void Function(String)? status}) async {
  status?.call('Measuring reply time ...');
  final pings = <int>[];
  for (var i = 0; i < 5; i++) {
    final ms = await tcpPing('speed.cloudflare.com', [443]);
    if (ms != null) pings.add(ms);
  }
  if (pings.isEmpty) return SpeedResult(error: 'No internet: speed.cloudflare.com does not answer.');
  pings.sort();
  final client = http.Client();
  try {
    status?.call('Measuring download ...');
    var bytes = 0;
    final sw = Stopwatch()..start();
    while (sw.elapsedMilliseconds < 8000) {
      final r = await client.get(Uri.parse('https://speed.cloudflare.com/__down?bytes=25000000'))
          .timeout(const Duration(seconds: 20));
      bytes += r.bodyBytes.length;
      status?.call('Download ${(bytes * 8 / sw.elapsedMilliseconds / 1000).toStringAsFixed(1)} Mbit/s ...');
    }
    final down = bytes * 8 / sw.elapsedMilliseconds / 1000;
    status?.call('Measuring upload ...');
    final payload = Uint8List(4000000);
    var up = 0;
    final sw2 = Stopwatch()..start();
    while (sw2.elapsedMilliseconds < 6000) {
      await client.post(Uri.parse('https://speed.cloudflare.com/__up'), body: payload).timeout(const Duration(seconds: 20));
      up += payload.length;
    }
    return SpeedResult(pingMs: pings[pings.length ~/ 2], downMbps: down, upMbps: up * 8 / sw2.elapsedMilliseconds / 1000);
  } catch (e) {
    return SpeedResult(pingMs: pings[pings.length ~/ 2], error: 'Speed test failed: $e');
  } finally {
    client.close();
  }
}
