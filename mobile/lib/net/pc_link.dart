import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

/// Talks to the Network Doctor PC app on the office LAN (see desktop/nd_share.py).
const pcPort = 8787;
const discoveryPort = 8788;

class PcError implements Exception {
  PcError(this.message);
  final String message;
  @override
  String toString() => message;
}

class PairedPc {
  PairedPc({required this.name, required this.host, required this.port, required this.token});
  String name;
  String host;
  int port;
  String token;

  Map<String, dynamic> toJson() => {'name': name, 'host': host, 'port': port, 'token': token};
  factory PairedPc.fromJson(Map<String, dynamic> j) => PairedPc(
      name: (j['name'] ?? 'PC') as String,
      host: (j['host'] ?? '') as String,
      port: (j['port'] ?? pcPort) as int,
      token: (j['token'] ?? '') as String);

  Uri uri(String path) => Uri.parse('http://$host:$port$path');
}

class FoundPc {
  FoundPc(this.name, this.host, this.port, this.version);
  final String name;
  final String host;
  final int port;
  final String version;
}

class PcLink {
  static const _key = 'paired_pcs';

  static Future<List<PairedPc>> load() async {
    final p = await SharedPreferences.getInstance();
    final raw = p.getString(_key);
    if (raw == null) return [];
    try {
      return (jsonDecode(raw) as List).map((e) => PairedPc.fromJson(Map<String, dynamic>.from(e as Map))).toList();
    } catch (_) {
      return [];
    }
  }

  static Future<void> save(List<PairedPc> pcs) async {
    final p = await SharedPreferences.getInstance();
    await p.setString(_key, jsonEncode(pcs.map((e) => e.toJson()).toList()));
  }

  /// Broadcasts on the Wi-Fi and collects every Network Doctor PC that answers.
  static Future<List<FoundPc>> discover({String? broadcast, Duration wait = const Duration(seconds: 2)}) async {
    final out = <String, FoundPc>{};
    RawDatagramSocket? sock;
    try {
      final s = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      sock = s;
      s.broadcastEnabled = true;
      s.listen((ev) {
        if (ev != RawSocketEvent.read) return;
        final dg = s.receive();
        if (dg == null) return;
        try {
          final j = jsonDecode(utf8.decode(dg.data)) as Map<String, dynamic>;
          if (j['app'] == 'network-doctor') {
            out[dg.address.address] = FoundPc((j['name'] ?? 'PC').toString(), dg.address.address,
                (j['port'] ?? pcPort) as int, (j['version'] ?? '').toString());
          }
        } catch (_) {}
      });
      final msg = utf8.encode('NETWORK-DOCTOR-DISCOVER');
      final targets = {'255.255.255.255', if (broadcast != null) broadcast};
      for (var i = 0; i < 2; i++) {
        for (final t in targets) {
          try {
            s.send(msg, InternetAddress(t), discoveryPort);
          } catch (_) {}
        }
        await Future.delayed(const Duration(milliseconds: 400));
      }
      await Future.delayed(wait);
    } catch (_) {
    } finally {
      sock?.close();
    }
    return out.values.toList();
  }

  static Future<Map<String, dynamic>> hello(String host, {int port = pcPort}) async {
    final r = await _send(() => http.get(Uri.parse('http://$host:$port/api/hello')), 'reach the PC');
    return jsonDecode(r.body) as Map<String, dynamic>;
  }

  static Future<PairedPc> pair(String host, String code, String phoneName, {int port = pcPort}) async {
    final r = await _send(
        () => http.post(Uri.parse('http://$host:$port/api/pair'),
            headers: {'Content-Type': 'application/json'}, body: jsonEncode({'code': code, 'phone': phoneName})),
        'pair');
    final j = jsonDecode(r.body) as Map<String, dynamic>;
    if (r.statusCode != 200) throw PcError((j['error'] ?? 'pairing failed').toString());
    return PairedPc(name: (j['name'] ?? host).toString(), host: host, port: port, token: j['token'] as String);
  }

  static Future<Map<String, dynamic>> state(PairedPc pc) async {
    final r = await _send(() => http.get(pc.uri('/api/state'), headers: {'X-ND-Token': pc.token}), 'load data');
    if (r.statusCode == 401) throw PcError('This phone is no longer paired with ${pc.name}. Pair again.');
    if (r.statusCode != 200) throw PcError('PC answered ${r.statusCode}');
    return jsonDecode(utf8.decode(r.bodyBytes)) as Map<String, dynamic>;
  }

  static Future<String> startScan(PairedPc pc) async {
    final r = await _send(() => http.post(pc.uri('/api/scan'), headers: {'X-ND-Token': pc.token}), 'start a scan');
    if (r.statusCode != 200) throw PcError('PC answered ${r.statusCode}');
    return ((jsonDecode(r.body) as Map)['result'] ?? '').toString();
  }

  static Future<http.Response> _send(Future<http.Response> Function() f, String what) async {
    try {
      return await f().timeout(const Duration(seconds: 8));
    } on TimeoutException {
      throw PcError('The PC did not answer. Is the phone on the office Wi-Fi and the PC app open with '
          '"Phone app link" switched on?');
    } on SocketException {
      throw PcError('Could not $what. Check that the phone is on the office Wi-Fi and the PC app is running '
          'with "Phone app link" switched on.');
    } on http.ClientException catch (e) {
      throw PcError('Could not $what (${e.message}).');
    }
  }
}
