// DVRIP / XMeye client for the phone - the same protocol as the PC app's nd_dvrip.py (TCP 34567). Used to read
// which cameras are ALREADY ADDED to an NVR/DVR (its configured channels), so the app can find duplicates
// across and within recorders and show exactly where each one sits (which NVR + which channel).
//
// Read-only here: login + read channel titles and the digital-channel config. No writes, no reboot.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

const int dvripPort = 34567;

// message ids (nd_dvrip.py)
const int _login = 1000;
const int _configGet = 1042;
const int _titles = 1048;
const Set<int> _ok = {100, 515};

const String _chars =
    '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'; // digits + A-Z + a-z (62)

class DvrError implements Exception {
  DvrError(this.message, {this.refused = false});
  final String message;
  final bool refused;
  @override
  String toString() => message;
}

const Map<int, String> _refused = {
  203: 'password refused',
  205: 'user name refused',
  206: 'account locked by the device',
  207: "this phone is on the device's blacklist",
  204: 'login refused',
};

/// The 8-char password form these devices expect, from the MD5 of the password (sofia_hash in nd_dvrip.py).
String sofiaHash(String password) {
  final d = md5.convert(utf8.encode(password)).bytes; // 16 bytes
  final sb = StringBuffer();
  for (var i = 0; i < 16; i += 2) {
    sb.write(_chars[(d[i] + d[i + 1]) % 62]);
  }
  return sb.toString();
}

Uint8List _pack(int session, int seq, int msg, Map<String, dynamic> data) {
  final body = utf8.encode(jsonEncode(data)) + [0x0a, 0x00];
  final b = BytesBuilder();
  final head = ByteData(20);
  head.setUint8(0, 0xFF);
  head.setUint8(1, 0); // version
  // bytes 2-3 pad
  head.setUint32(4, session, Endian.little);
  head.setUint32(8, seq, Endian.little);
  // bytes 12-13 pad
  head.setUint16(14, msg, Endian.little);
  head.setUint32(16, body.length, Endian.little);
  b.add(head.buffer.asUint8List());
  b.add(body);
  return b.toBytes();
}

class _Reader {
  _Reader(Socket s) {
    _sub = s.listen((d) {
      _buf.addAll(d);
      _pump();
    }, onError: (e) => _fail(e), onDone: () {
      _done = true;
      _pump();
    });
  }
  late final StreamSubscription<Uint8List> _sub;
  final List<int> _buf = [];
  Completer<List<int>>? _c;
  int _want = 0;
  bool _done = false;

  void _fail(Object e) {
    final c = _c;
    _c = null;
    c?.completeError(e is Exception ? e : DvrError('$e'));
  }

  void _pump() {
    final c = _c;
    if (c == null) return;
    if (_buf.length >= _want) {
      final out = _buf.sublist(0, _want);
      _buf.removeRange(0, _want);
      _c = null;
      c.complete(out);
    } else if (_done) {
      _c = null;
      c.completeError(DvrError('the device closed the connection'));
    }
  }

  Future<List<int>> read(int n) {
    final c = Completer<List<int>>();
    _c = c;
    _want = n;
    _pump();
    return c.future;
  }

  Future<void> close() => _sub.cancel();
}

class DvrIp {
  DvrIp(this.ip, {this.port = dvripPort, this.timeout = const Duration(seconds: 6)});
  final String ip;
  final int port;
  final Duration timeout;
  Socket? _sock;
  _Reader? _r;
  int _session = 0;
  int _seq = 0;

  Future<void> connect() async {
    _sock = await Socket.connect(ip, port, timeout: timeout);
    _r = _Reader(_sock!);
  }

  Future<Map<String, dynamic>> _call(int msg, Map<String, dynamic> data) async {
    _sock!.add(_pack(_session, _seq, msg, data));
    await _sock!.flush();
    _seq++;
    final head = await _r!.read(20).timeout(timeout);
    if (head.length != 20 || head[0] != 0xFF) {
      throw DvrError('the device did not answer in the XMeye protocol');
    }
    final hv = ByteData.sublistView(Uint8List.fromList(head));
    final size = hv.getUint32(16, Endian.little);
    if (size > 4000000) throw DvrError('the device sent an answer that is too large');
    final body = size > 0 ? await _r!.read(size).timeout(timeout) : <int>[];
    // strip trailing NUL / newline / spaces
    var end = body.length;
    while (end > 0 && (body[end - 1] == 0 || body[end - 1] == 0x0a || body[end - 1] == 0x20 || body[end - 1] == 0x0d)) {
      end--;
    }
    final text = utf8.decode(body.sublist(0, end), allowMalformed: true);
    if (text.isEmpty) return {};
    try {
      return jsonDecode(text) as Map<String, dynamic>;
    } catch (_) {
      throw DvrError("the device's answer could not be read");
    }
  }

  Future<void> login(String user, String pw) async {
    final r = await _call(_login, {
      'EncryptType': 'MD5',
      'LoginType': 'DVRIP-Web',
      'PassWord': sofiaHash(pw),
      'UserName': user,
    });
    final ret = r['Ret'] as int?;
    if (ret == null || !_ok.contains(ret)) {
      throw DvrError(_refused[ret] ?? 'login not accepted (code $ret)', refused: _refused.containsKey(ret));
    }
    _session = int.tryParse((r['SessionID'] ?? '0').toString().replaceFirst('0x', ''), radix: 16) ?? 0;
  }

  String _sid() => '0x${_session.toRadixString(16).toUpperCase().padLeft(8, '0')}';

  Future<dynamic> get(String name) async {
    final r = await _call(_configGet, {'Name': name, 'SessionID': _sid()});
    if (!_ok.contains(r['Ret'])) {
      throw DvrError("the device did not give '$name' (code ${r['Ret']})");
    }
    return r[name];
  }

  Future<dynamic> getTitles() async {
    final r = await _call(_titles, {'Name': 'ChannelTitle', 'SessionID': _sid()});
    if (!_ok.contains(r['Ret'])) return null;
    return r['ChannelTitle'];
  }

  Future<void> close() async {
    try {
      await _r?.close();
      _sock?.destroy();
    } catch (_) {}
    _sock = null;
    _r = null;
  }
}

// ---- channel reading (what cameras are already added to this recorder) ---------------------------------------

List<dynamic> _channelList(dynamic node) {
  if (node is List) return node;
  if (node is Map) {
    for (final v in node.values) {
      if (v is List && v.isNotEmpty) return v;
    }
    for (final v in node.values) {
      final got = _channelList(v);
      if (got.isNotEmpty) return got;
    }
  }
  return const [];
}

dynamic _findKey(dynamic node, Set<String> keys) {
  if (node is Map) {
    for (final e in node.entries) {
      if (keys.contains(e.key)) return e.value;
    }
    for (final v in node.values) {
      final got = _findKey(v, keys);
      if (got != null) return got;
    }
  } else if (node is List) {
    for (final v in node) {
      final got = _findKey(v, keys);
      if (got != null) return got;
    }
  }
  return null;
}

String _hexToIp(String text) {
  var t = text.trim();
  if (t.toLowerCase().startsWith('0x')) t = t.substring(2);
  final v = int.tryParse(t, radix: 16);
  if (v == null) return '';
  return [0, 8, 16, 24].map((s) => ((v >> s) & 0xFF).toString()).join('.');
}

String _asIp(dynamic v) {
  final s = v.toString().trim();
  if (s.isEmpty) return '';
  if (RegExp(r'^(\d{1,3}\.){3}\d{1,3}$').hasMatch(s)) {
    return (s == '0.0.0.0' || s == '255.255.255.255') ? '' : s;
  }
  if (s.toLowerCase().startsWith('0x') || RegExp(r'^[0-9A-Fa-f]{8}$').hasMatch(s)) {
    final ip = _hexToIp(s);
    return (ip.isNotEmpty && ip != '0.0.0.0' && ip != '255.255.255.255') ? ip : '';
  }
  return '';
}

// field names vary by firmware; many XMeye recorders store the camera IP as a little-endian HEX string.
const Set<String> _ipKeys = {'DevIP', 'HostIP', 'IPAddress', 'Address', 'IP', 'ip', 'DeviceIP', 'RemoteIP'};

String _ipIn(dynamic entry) {
  final got = _findKey(entry, _ipKeys);
  if (got != null) {
    final ip = _asIp(got);
    if (ip.isNotEmpty) return ip;
  }
  // fall back: any dotted or hex IPv4 found anywhere in the entry
  if (entry is Map) {
    for (final v in entry.values) {
      final ip = _ipIn(v);
      if (ip.isNotEmpty) return ip;
    }
  } else if (entry is List) {
    for (final v in entry) {
      final ip = _ipIn(v);
      if (ip.isNotEmpty) return ip;
    }
  } else {
    return _asIp(entry);
  }
  return '';
}

/// One camera already configured on a recorder's channel.
class NvrChannel {
  NvrChannel(this.chan, this.name, this.ip, this.online);
  final int chan; // 1-based
  final String name;
  final String ip;
  final bool? online;
  Map<String, dynamic> toKeyMap() => {'chan': chan, 'name': name, 'ip': ip};
}

/// Log in to a recorder and list the cameras added to it. Read-only. Names come straight from the recorder; the
/// per-channel camera IP / online flag are best-effort (config layout varies by firmware).
Future<List<NvrChannel>> listChannels(String ip, String user, String pw,
    {int port = dvripPort, Duration timeout = const Duration(seconds: 6)}) async {
  final c = DvrIp(ip, port: port, timeout: timeout);
  try {
    await c.connect();
    await c.login(user, pw);
    var names = <String>[];
    try {
      final t = await c.getTitles();
      if (t is List) names = [for (final x in t) x.toString().trim()];
    } catch (_) {}
    final ips = <int, String>{};
    final online = <int, bool>{};
    for (final node in const [
      'Digital', 'NetWork.Digital', 'OPDigitalChannel', 'DigitalChannel', 'NetWork.NetDigital',
      'NetWork.NetDigitalChannel', 'Dev', 'ChannelDevInfo'
    ]) {
      dynamic dig;
      try {
        dig = await c.get(node);
      } catch (_) {
        continue;
      }
      final arr = _channelList(dig);
      if (arr.isNotEmpty) {
        for (var i = 0; i < arr.length; i++) {
          final got = _ipIn(arr[i]);
          if (got.isNotEmpty) ips[i] = got;
          final en = _findKey(arr[i], {'Enable', 'enable'});
          if (en != null) online[i] = en == true;
        }
        if (ips.isNotEmpty) break;
      }
    }
    try {
      final st = await c.get('OnlineDigitalChannel');
      if (st is List) {
        for (var i = 0; i < st.length; i++) {
          final e = st[i];
          if (e is Map) online[i] = (e['Online'] ?? e['Status'] ?? online[i]) == true;
        }
      }
    } catch (_) {}
    final n = names.length > ips.length ? names.length : ips.length;
    final out = <NvrChannel>[];
    for (var i = 0; i < n; i++) {
      final nm = (i < names.length && names[i].isNotEmpty) ? names[i] : 'CAM${i + 1}';
      out.add(NvrChannel(i + 1, nm, ips[i] ?? '', online[i]));
    }
    return out;
  } finally {
    await c.close();
  }
}
