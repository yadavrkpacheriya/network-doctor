// Default-password check for cameras, recorders, routers and the like - the phone side of the PC app's
// nd_camline.default_login_http + nd_secscan. It tries a short list of FACTORY logins against a device's web
// API and reports a hit ONLY when one actually authenticates (HTTP 200), so a warning is raised when a default
// password really works, never as a blanket reminder. Read-only GETs; nothing on the device is changed.
//
// SAFETY: only ever run against device kinds that don't lock accounts out (cameras/DVR/NVR, routers, network
// gear, printers, biometric). NEVER a PC/laptop/phone - trying passwords there can lock the real user's Windows
// / AD account. The caller (scanner) enforces this via mayTestDefault(); this module also refuses otherwise.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'model.dart';

/// The common factory logins to try, same list as the PC app's COMMON_DEFAULTS (nd_camhealth.py).
const List<List<String>> commonDefaults = [
  ['admin', ''],
  ['admin', 'admin'],
  ['admin', '12345'],
  ['admin', '123456'],
  ['admin', '888888'],
  ['admin', 'admin12345'],
  ['admin', '9999'],
  ['root', 'root'],
  ['admin', '1111'],
  ['admin', '54321'],
];

// Brand check paths (need auth, answer 200 only when the login is accepted) - Hikvision ISAPI, Dahua/CP-Plus CGI.
const String _hikCheck = '/ISAPI/System/Network/interfaces/1/ipAddress';
const String _dahuaCheck = '/cgi-bin/configManager.cgi?action=getConfig&name=Network';

/// Categories where actively testing a default login is SAFE (no account lockout). PCs/phones are excluded.
const Set<String> _safeDefaultCats = {Cat.cam, Cat.router, Cat.net, Cat.prn, Cat.bio};

/// True only for device kinds that don't lock accounts out when a login is tried.
bool mayTestDefault(String category) => _safeDefaultCats.contains(category);

/// Result of a confirmed default login, or null if none worked / not applicable.
class DefaultLoginHit {
  DefaultLoginHit(this.user, this.password);
  final String user;
  final String password;
}

/// Try the common factory logins against a device's web API on the given ports. Returns the first login that
/// authenticates (HTTP 200), else null. Only runs for safe categories (see mayTestDefault). Each request is
/// short-timeout and read-only. Mirrors nd_camline.default_login_http.
Future<DefaultLoginHit?> probeDefaultLogin(
  String ip,
  String category, {
  List<int> ports = const [80, 8000, 8080],
  Duration timeout = const Duration(milliseconds: 1200),
}) async {
  if (!mayTestDefault(category)) return null;
  final client = HttpClient()
    ..connectionTimeout = timeout
    ..badCertificateCallback = (_, __, ___) => true; // self-signed camera certs are normal
  try {
    for (final port in ports) {
      var reachable = false;
      for (final path in const [_hikCheck, _dahuaCheck]) {
        for (final cred in commonDefaults) {
          int? code;
          try {
            code = await _getStatus(client, ip, port, path, cred[0], cred[1], timeout);
          } catch (_) {
            code = null;
          }
          if (code == null) break; // port not answering HTTP - give up on this path
          reachable = true;
          if (code == 200) return DefaultLoginHit(cred[0], cred[1]);
          if (code == 401 || code == 403) continue; // path needs a login, this one was wrong - try next default
          break; // 404/other on this brand's path - try the other brand
        }
      }
      if (!reachable) break; // this port isn't a web server - stop trying ports
    }
  } finally {
    client.close(force: true);
  }
  return null;
}

/// One read-only GET with HTTP Basic auth; returns the status code, or null if the socket/HTTP failed. Many
/// cameras accept Basic; those that demand Digest answer 401 here and are simply reported as "not default",
/// which is the safe side to err on (we never claim a weak password that we could not actually confirm).
Future<int?> _getStatus(HttpClient client, String ip, int port, String path, String user, String pw,
    Duration timeout) async {
  final uri = Uri.parse('http://$ip:$port$path');
  final req = await client.getUrl(uri).timeout(timeout);
  final basic = base64.encode(utf8.encode('$user:$pw'));
  req.headers.set(HttpHeaders.authorizationHeader, 'Basic $basic');
  final resp = await req.close().timeout(timeout);
  final code = resp.statusCode;
  await resp.drain<void>(); // free the socket; we only need the status
  return code;
}
