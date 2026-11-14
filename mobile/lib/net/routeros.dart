// Talk to a MikroTik router straight from the phone over the office Wi-Fi (API, TCP 8728 / TLS 8729) - no PC
// and no Tailscale needed. Same protocol as the PC app's nd_routeros.py: length-prefixed words, plain login on
// RouterOS 6.43+ / v7, md5 challenge-response on older firmware.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

class RosError implements Exception {
  RosError(this.message);
  final String message;
  @override
  String toString() => message;
}

List<int> _encLen(int n) {
  if (n < 0x80) return [n];
  if (n < 0x4000) return [(n >> 8) | 0x80, n & 0xFF];
  if (n < 0x200000) return [(n >> 16) | 0xC0, (n >> 8) & 0xFF, n & 0xFF];
  if (n < 0x10000000) {
    return [(n >> 24) | 0xE0, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF];
  }
  return [0xF0, (n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF];
}

List<int> _encWord(String w) {
  final b = utf8.encode(w);
  return [..._encLen(b.length), ...b];
}

List<int> _encSentence(List<String> words) => [for (final w in words) ..._encWord(w), 0];

/// Buffers the socket's bytes and hands them out n at a time, waiting when there aren't enough yet.
class _ByteStream {
  _ByteStream(Stream<List<int>> src) {
    _sub = src.listen((d) {
      _buf.addAll(d);
      _pump();
    }, onError: (Object e) {
      _err = e;
      _pump();
    }, onDone: () {
      _done = true;
      _pump();
    });
  }
  late final StreamSubscription<List<int>> _sub;
  final List<int> _buf = [];
  Object? _err;
  bool _done = false;
  int _want = 0;
  Completer<List<int>>? _c;

  void _pump() {
    final c = _c;
    if (c == null) return;
    if (_err != null) {
      _c = null;
      c.completeError(RosError('the router dropped the connection'));
      return;
    }
    if (_buf.length >= _want) {
      final out = _buf.sublist(0, _want);
      _buf.removeRange(0, _want);
      _c = null;
      c.complete(out);
      return;
    }
    if (_done) {
      _c = null;
      c.completeError(RosError('the router closed the connection'));
    }
  }

  Future<List<int>> read(int n) {
    if (n == 0) return Future.value(const []);
    final c = Completer<List<int>>();
    _c = c;
    _want = n;
    _pump();
    return c.future;
  }

  Future<void> close() => _sub.cancel();
}

class RouterOs {
  RouterOs(this.host, this.user, this.password, {this.ssl = false, int? port, this.timeout = const Duration(seconds: 8)})
      : port = port ?? (ssl ? 8729 : 8728);
  final String host;
  final String user;
  final String password;
  final bool ssl;
  final int port;
  final Duration timeout;
  Socket? _sock;
  _ByteStream? _in;

  Future<int> _readLen() async {
    final c = (await _in!.read(1))[0];
    if (c < 0x80) return c;
    if (c < 0xC0) return ((c & 0x3F) << 8) | (await _in!.read(1))[0];
    if (c < 0xE0) {
      final b = await _in!.read(2);
      return ((c & 0x1F) << 16) | (b[0] << 8) | b[1];
    }
    if (c < 0xF0) {
      final b = await _in!.read(3);
      return ((c & 0x0F) << 24) | (b[0] << 16) | (b[1] << 8) | b[2];
    }
    final b = await _in!.read(4);
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
  }

  Future<List<String>> _readSentence() async {
    final words = <String>[];
    while (true) {
      final n = await _readLen();
      if (n == 0) return words;
      words.add(utf8.decode(await _in!.read(n), allowMalformed: true));
    }
  }

  /// Sends one command and returns every reply line up to !done. Throws on !trap when [check].
  Future<List<(String, List<String>)>> talk(List<String> words, {bool check = true}) async {
    _sock!.add(_encSentence(words));
    await _sock!.flush();
    final out = <(String, List<String>)>[];
    while (true) {
      final s = await _readSentence().timeout(timeout,
          onTimeout: () => throw RosError('the router stopped answering (timeout)'));
      if (s.isEmpty) continue;
      out.add((s[0], s.sublist(1)));
      if (s[0] == '!fatal') throw RosError('router: ${s.sublist(1).join(' ')}');
      if (s[0] == '!done') break;
    }
    if (check) {
      for (final (t, w) in out) {
        if (t == '!trap') throw RosError('router: ${_attrs(w)['message'] ?? 'error'}');
      }
    }
    return out;
  }

  static Map<String, String> _attrs(List<String> words) {
    final m = <String, String>{};
    for (final w in words) {
      if (w.startsWith('=')) {
        final i = w.indexOf('=', 1);
        if (i > 0) m[w.substring(1, i)] = w.substring(i + 1);
      }
    }
    return m;
  }

  Future<void> connect() async {
    try {
      _sock = ssl
          ? await SecureSocket.connect(host, port,
              timeout: timeout, onBadCertificate: (_) => true) // routers use self-signed certs
          : await Socket.connect(host, port, timeout: timeout);
    } on SocketException catch (e) {
      throw RosError('cannot reach $host:$port (${e.osError?.message ?? e.message}). '
          'Turn the API on in the router: IP > Services > api (8728).');
    }
    _in = _ByteStream(_sock!);
    var r = await talk(['/login', '=name=$user', '=password=$password'], check: false);
    if (r.any((e) => e.$1 == '!trap')) {
      await close();
      throw RosError("login refused - check the user name and password (the user needs 'api' + read/write).");
    }
    String? ret;
    for (final (t, w) in r) {
      if (t == '!done') ret = _attrs(w)['ret'];
    }
    if (ret != null && ret.isNotEmpty) {
      // RouterOS before 6.43: md5 challenge / response
      final chal = _hex(ret);
      final digest = md5.convert([0, ...utf8.encode(password), ...chal]).toString();
      r = await talk(['/login', '=name=$user', '=response=00$digest'], check: false);
      if (r.any((e) => e.$1 == '!trap')) {
        await close();
        throw RosError('login refused - check the user name and password');
      }
    }
  }

  static List<int> _hex(String s) =>
      [for (var i = 0; i + 1 < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16)];

  /// A print/query command, returns the !re rows as maps.
  Future<List<Map<String, String>>> cmd(String path, {Map<String, String>? params}) async {
    final words = [path, if (params != null) for (final e in params.entries) '=${e.key}=${e.value}'];
    final r = await talk(words);
    return [for (final (t, w) in r) if (t == '!re') _attrs(w)];
  }

  Future<(String name, String version)> identity() async {
    final a = await cmd('/system/identity/print');
    final b = await cmd('/system/resource/print');
    return (a.isNotEmpty ? a[0]['name'] ?? '' : '', b.isNotEmpty ? b[0]['version'] ?? '' : '');
  }

  /// Run a multi-line script the same way WinBox > New Terminal would (for guard / fixes added later).
  Future<void> runScript(String source, {String name = 'ndphone-run'}) async {
    await cmd('/system/script/remove', params: {'numbers': name}).catchError((_) => <Map<String, String>>[]);
    await cmd('/system/script/add', params: {'name': name, 'policy': 'read,write,test', 'source': source});
    await cmd('/system/script/run', params: {'number': name});
    await cmd('/system/script/remove', params: {'numbers': name}).catchError((_) => <Map<String, String>>[]);
  }

  Future<void> close() async {
    try {
      await _in?.close();
      _sock?.destroy();
    } catch (_) {}
    _sock = null;
    _in = null;
  }
}
