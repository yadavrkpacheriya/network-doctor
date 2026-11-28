import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart' show rootBundle;
import 'package:http/http.dart' as http;
import 'package:path_provider/path_provider.dart';
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
  PairedPc({required this.name, required this.host, required this.port, required this.token,
      this.user = '', this.userToken = '', this.role = '', this.remote = ''});
  String name;
  String host;      // LAN host/IP
  int port;
  String token;     // pairing token (identifies this phone)
  String user;      // signed-in user name (Pro)
  String userToken; // sign-in token (Pro)
  String role;      // admin / operator / viewer
  String remote;    // optional remote address (host:port) to reach the PC from outside the office

  Map<String, dynamic> toJson() =>
      {'name': name, 'host': host, 'port': port, 'token': token, 'user': user, 'role': role, 'remote': remote};
  factory PairedPc.fromJson(Map<String, dynamic> j) => PairedPc(
      name: (j['name'] ?? 'PC') as String,
      host: (j['host'] ?? '') as String,
      port: (j['port'] ?? pcPort) as int,
      token: (j['token'] ?? '') as String,
      user: (j['user'] ?? '') as String,
      role: (j['role'] ?? '') as String,
      remote: (j['remote'] ?? '') as String);

  /// The base address to use now: the remote one when set and we're told to use it, else the LAN host.
  Uri uriVia(String path, bool useRemote) {
    if (useRemote && remote.isNotEmpty) return _remoteUri(path);
    return uri(path);
  }

  Uri uri(String path) {
    if (PcLink.viaRemote.contains(host) && remote.isNotEmpty) return _remoteUri(path);
    return Uri.parse('http://$host:$port$path');
  }

  /// A tunnel address (Cloudflare Tunnel, Tailscale ...) is reached over https with no literal port unless one was
  /// typed. A scheme already in the saved address (http:// or https://) is kept as typed.
  Uri _remoteUri(String path) {
    var r = remote;
    if (!r.contains('://')) r = 'https://$r';
    final u = Uri.parse(r);
    return u.replace(path: u.path + path);
  }
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

  /// Hosts we are currently reaching through their remote address (set after the LAN fails, cleared on the LAN).
  static final Set<String> viaRemote = {};
  static void preferRemote(PairedPc pc, bool on) {
    if (on && pc.remote.isNotEmpty) {
      viaRemote.add(pc.host);
    } else {
      viaRemote.remove(pc.host);
    }
  }

  /// Save a remote address for this PC and keep the in-memory copy in step. Used to auto-adopt the stable address
  /// the PC advertises (its Tailscale IP), so the user never has to paste an address that later expires.
  static Future<void> setRemote(PairedPc pc, String remote) async {
    pc.remote = remote;
    final pcs = await load();
    for (final p in pcs) {
      if (p.token == pc.token) p.remote = remote;
    }
    await save(pcs);
  }

  /// Demo / automatic screen test: --dart-define=ND_DEMO=true shows a recorded office PC (no network needed).
  static const demo = bool.fromEnvironment('ND_DEMO');
  static PairedPc demoPc() => PairedPc(name: 'OFFICE-PC (demo)', host: 'demo', port: pcPort, token: 'demo');

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

  /// Owner Pro sign-in: send the owner email + activation secret to the PC's /api/pro_login. On success the PC
  /// turns on Pro + remote access. Works even before remote access was on (that endpoint is allowed pre-auth,
  /// since it only succeeds with the correct owner secret). Returns the PC's {ok, message}.
  static Future<Map<String, dynamic>> proLogin(PairedPc pc, String email, String secret) async {
    final r = await _withFallback(
        (base) => http.post(base,
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({'email': email, 'secret': secret})),
        pc, '/api/pro_login', 'activate Pro');
    Map<String, dynamic> j = {};
    try {
      j = Map<String, dynamic>.from(jsonDecode(utf8.decode(r.bodyBytes)) as Map);
    } catch (_) {}
    if (r.statusCode != 200) {
      throw PcError((j['message'] ?? 'Could not activate Pro (${r.statusCode}).').toString());
    }
    return j;
  }

  /// Sign out of Pro on EVERY device at once (from this phone). Uses the normal action channel while still
  /// authorized; afterwards remote access is off until the owner signs in again.
  static Future<Map<String, dynamic>> proLogout(PairedPc pc) async {
    return action(pc, 'pro_logout');
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

  /// Turn a non-200 reply into the clearest possible message. A 403 carries the PC's real reason in the body
  /// (e.g. "remote access is off on this PC") - show THAT, not a bare "PC answered 403", so the user knows the
  /// exact fix. A 403 about remote access gets a step-by-step hint (Rakesh, 27 Nov: Tailscale connects but
  /// Network Doctor refused because remote access wasn't turned on).
  static Never _raiseHttp(http.Response r, String pcName) {
    if (r.statusCode == 401) throw PcError('This phone is no longer paired with $pcName. Pair again.');
    String reason = '';
    try {
      reason = ((jsonDecode(r.body) as Map)['error'] ?? '').toString();
    } catch (_) {}
    if (r.statusCode == 403) {
      if (reason.toLowerCase().contains('remote access')) {
        throw PcError('Remote access is turned OFF on the PC. On the PC open Network Doctor > Setup > Users & '
            'sign-in, turn ON remote access and create a sign-in account, then connect again and sign in. '
            '(On the office Wi-Fi it works without this.)');
      }
      if (reason.toLowerCase().contains('sign in')) {
        throw PcError('This PC needs you to sign in for remote access. Enter the username and password you set '
            'on the PC (Setup > Users & sign-in).');
      }
      throw PcError(reason.isEmpty ? 'The PC refused the request (403).' : reason);
    }
    throw PcError(reason.isEmpty ? 'PC answered ${r.statusCode}' : reason);
  }

  static Future<Map<String, dynamic>> state(PairedPc pc) async {
    if (pc.host == 'demo') {
      return Map<String, dynamic>.from(jsonDecode(await rootBundle.loadString('assets/demo_state.json')) as Map);
    }
    final r = await _withFallback((base) => http.get(base, headers: _h(pc)), pc, '/api/state', 'load data');
    if (r.statusCode != 200) _raiseHttp(r, pc.name);
    return jsonDecode(utf8.decode(r.bodyBytes)) as Map<String, dynamic>;
  }

  /// Downloads the 1-file agent setup (Setup-NetworkDoctor.cmd) from the PC and saves it on the phone.
  /// Returns the saved file path so the caller can open/share it. Works on the LAN and remotely (same gate
  /// as other calls). The file is a Windows .cmd - meant to be copied to an office PC and run there.
  static Future<String> downloadSetup(PairedPc pc) async {
    if (pc.host == 'demo') {
      throw PcError('Connect to your office PC first - the setup file comes from it.');
    }
    final r = await _withFallback((base) => http.get(base, headers: _h(pc)), pc, '/api/setup-cmd',
        'download the setup file');
    if (r.statusCode == 404) {
      throw PcError('The PC app is too old for this - update Network Doctor on the PC (4.92 or newer).');
    }
    if (r.statusCode != 200) _raiseHttp(r, pc.name);
    Directory dir;
    try {
      dir = await getExternalStorageDirectory() ?? await getApplicationDocumentsDirectory();
    } catch (_) {
      dir = await getApplicationDocumentsDirectory();
    }
    final f = File('${dir.path}/Setup-NetworkDoctor.cmd');
    await f.writeAsBytes(r.bodyBytes, flush: true);
    return f.path;
  }

  static Future<String> startScan(PairedPc pc) async {
    if (pc.host == 'demo') return '(demo) scan started';
    final r = await _withFallback((base) => http.post(base, headers: _h(pc)), pc, '/api/scan', 'start a scan');
    if (r.statusCode != 200) _raiseHttp(r, pc.name);
    return ((jsonDecode(r.body) as Map)['result'] ?? '').toString();
  }

  /// The PC the dashboard is showing (device pages use it for the "Office PC actions").
  static PairedPc? current;
  static int apiLevel = 1;

  /// Runs an action on the PC (tag, bind, block, fix an alert, ping, slow-site check...).
  /// Answers {ok, message} or {ok, job} for long work (see [waitJob]).
  static Future<Map<String, dynamic>> action(PairedPc pc, String action, [Map<String, dynamic> args = const {}]) async {
    if (pc.host == 'demo') {
      return action == 'job'
          ? {'ok': true, 'done': true, 'text': '(demo) the office PC would show the result here'}
          : {'ok': true, 'message': '(demo) $action sent to the office PC'};
    }
    final r = await _withFallback(
        (base) => http.post(base,
            headers: {..._h(pc), 'Content-Type': 'application/json'},
            body: jsonEncode({'action': action, 'args': args})),
        pc,
        '/api/action',
        'reach the PC');
    if (r.statusCode == 404) {
      throw PcError('The PC app is too old for this - update Network Doctor on the PC (3.16 or newer).');
    }
    if (r.statusCode != 200) _raiseHttp(r, pc.name);
    return Map<String, dynamic>.from(jsonDecode(utf8.decode(r.bodyBytes)) as Map);
  }

  /// Polls a background job on the PC until it is finished (or [limit] passes).
  static Future<Map<String, dynamic>> waitJob(PairedPc pc, String id,
      {Duration limit = const Duration(minutes: 3), void Function(Map<String, dynamic>)? onTick}) async {
    final end = DateTime.now().add(limit);
    while (DateTime.now().isBefore(end)) {
      final j = await action(pc, 'job', {'id': id});
      onTick?.call(j);
      if (j['done'] == true || j['ok'] == false && j['message'] != null) return j;
      await Future.delayed(const Duration(seconds: 2));
    }
    return {'done': true, 'ok': false, 'text': 'The PC is still working on it - look again in a minute.'};
  }

  static Map<String, String> _h(PairedPc pc) =>
      {'X-ND-Token': pc.token, if (pc.userToken.isNotEmpty) 'X-ND-User': pc.userToken};

  /// Sign in a user on the PC (Pro). Fills pc.user / userToken / role on success.
  static Future<void> login(PairedPc pc, String user, String password) async {
    final r = await _send(
        () => http.post(pc.uri('/api/login'),
            headers: {'X-ND-Token': pc.token, 'Content-Type': 'application/json'},
            body: jsonEncode({'user': user, 'password': password, 'device': 'phone'})),
        'sign in');
    final j = jsonDecode(r.body) as Map<String, dynamic>;
    if (r.statusCode != 200) throw PcError((j['error'] ?? 'sign-in failed').toString());
    pc.user = (j['user'] ?? user).toString();
    pc.userToken = (j['token'] ?? '').toString();
    pc.role = (j['role'] ?? '').toString();
  }

  static Future<void> logout(PairedPc pc) async {
    try {
      await _send(() => http.post(pc.uri('/api/logout'), headers: _h(pc)), 'sign out');
    } catch (_) {}
    pc.user = '';
    pc.userToken = '';
    pc.role = '';
  }

  /// Lightweight keep-alive: a bare /api/hello against the current best address, no body parsing, never
  /// throws. Returns true if the PC answered. Used on a short timer between data polls so the link does not
  /// idle out and a drop is noticed (and the other address tried) quickly (Rakesh, 24 Nov).
  static Future<bool> keepAlive(PairedPc pc) async {
    final base = viaRemote.contains(pc.host) && pc.remote.isNotEmpty ? pc.uriVia('/api/hello', true) : pc.uri('/api/hello');
    try {
      final r = await http.get(base, headers: _h(pc)).timeout(const Duration(seconds: 4));
      return r.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  /// State fetch that reports whether the PC wants a sign-in (Pro with accounts).
  static Future<Map<String, dynamic>> hello2(PairedPc pc) async {
    final r = await _send(() => http.get(pc.uri('/api/hello')), 'reach the PC');
    return jsonDecode(r.body) as Map<String, dynamic>;
  }

  /// Sends a request to the PC against the best address, and recovers when it can't be reached:
  ///  - tries the LAN first (or the remote address if we last succeeded there);
  ///  - on a connection failure, transparently tries the OTHER address, so remote access kicks in by
  ///    itself when the phone leaves the office Wi-Fi, and the LAN is used again when it comes back;
  ///  - if neither answers, the PC's LAN IP may have changed, so it rediscovers the PC on the Wi-Fi,
  ///    updates the saved address, and retries once.
  /// [build] turns a base URI (already including the path) into the actual GET/POST request.
  static Future<http.Response> _withFallback(
      Future<http.Response> Function(Uri base) build, PairedPc pc, String path, String what) async {
    final lan = Uri.parse('http://${pc.host}:${pc.port}$path');
    final rem = pc.remote.isEmpty ? null : pc.uriVia(path, true);
    final preferRemote = viaRemote.contains(pc.host) && rem != null;
    final tries = <MapEntry<Uri, bool>>[];
    if (preferRemote) {
      tries.add(MapEntry(rem!, true));
      tries.add(MapEntry(lan, false));
    } else {
      tries.add(MapEntry(lan, false));
      if (rem != null) tries.add(MapEntry(rem, true));
    }
    PcError? last;
    for (final t in tries) {
      try {
        final r = await _send(() => build(t.key), what);
        if (t.value) {
          viaRemote.add(pc.host);
        } else {
          viaRemote.remove(pc.host);
        }
        return r;
      } on PcError catch (e) {
        last = e;
      }
    }
    // Neither address connected: the PC's LAN IP may have changed - rediscover it and retry once.
    try {
      final found = await discover();
      FoundPc? pick;
      for (final f in found) {
        if (f.name == pc.name) {
          pick = f;
          break;
        }
      }
      if (pick == null && found.isNotEmpty) pick = found.first;
      if (pick != null) {
        final np = pick;
        pc.host = np.host;
        pc.port = np.port;
        viaRemote.remove(pc.host);
        final pcs = await load();
        for (final p in pcs) {
          if (p.token == pc.token) {
            p.host = np.host;
            p.port = np.port;
          }
        }
        await save(pcs);
        return await _send(() => build(Uri.parse('http://${pc.host}:${pc.port}$path')), what);
      }
    } catch (_) {}
    throw last ?? PcError('Could not $what.');
  }

  static Future<http.Response> _send(Future<http.Response> Function() f, String what) async {
    // One quick retry on a transient failure: Wi-Fi drops the odd packet, and without a retry every blip
    // surfaced as a "disconnected" to the user (Rakesh, 24 Nov). 6s timeout so a blip recovers fast.
    Object? lastErr;
    for (var attempt = 0; attempt < 2; attempt++) {
      if (attempt > 0) await Future.delayed(const Duration(milliseconds: 600));
      try {
        return await f().timeout(const Duration(seconds: 6));
      } on TimeoutException catch (e) {
        lastErr = e;                  // a timeout may be a blip - worth one retry
      } on SocketException catch (e) {
        lastErr = e;
        break;                        // "connection refused": nothing is listening - fail fast, don't retry
      } on http.ClientException catch (e) {
        lastErr = e;
        break;                        // the HTTP client gave up - a retry won't help on this address
      }
    }
    if (lastErr is TimeoutException) {
      throw PcError('The PC did not answer. Is the phone on the office Wi-Fi and the PC app open with '
          '"Phone app link" switched on?');
    } else if (lastErr is http.ClientException) {
      throw PcError('Could not $what (${(lastErr as http.ClientException).message}).');
    }
    throw PcError('Could not $what. Check that the phone is on the office Wi-Fi and the PC app is running '
        'with "Phone app link" switched on.');
  }
}
