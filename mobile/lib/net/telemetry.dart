import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

/// Anonymous usage & crash reports, OFF until switched on in About - the phone side of the same
/// contract as the PC app's nd_telemetry.py / nd_share.py: a random install id, feature-use counts,
/// sanitised crash details. Never anything that identifies a person, a place or a network - no IPs,
/// no Wi-Fi names, no host names, nothing found in a scan. Nothing is sent anywhere until an admin
/// address is also filled in (the developer's own PC, reached through its Remote access tunnel).
///
/// A single app-wide instance (`Telemetry.instance`) so note() can be called from anywhere without
/// passing it around; counts/crashes are kept in shared_preferences so a report is not lost if the
/// app is killed before it gets a chance to send.
class Telemetry {
  Telemetry();
  static final Telemetry instance = Telemetry();

  static const _kEnabled = 'telemetry_enabled';
  static const _kAdminUrl = 'telemetry_admin_url';
  static const _kInstallId = 'telemetry_install_id';
  static const _kPending = 'telemetry_pending';
  static const maxCrashes = 20;

  bool _enabled = false;
  String _adminUrl = '';
  String _installId = '';
  Map<String, int> _counts = {};
  List<Map<String, String>> _crashes = [];
  bool _loaded = false;

  bool get enabled => _enabled;
  String get adminUrl => _adminUrl;
  String get installId => _installId;

  Future<void> load() => _ensureLoaded();

  Future<void> _ensureLoaded() async {
    if (_loaded) return;
    final p = await SharedPreferences.getInstance();
    _enabled = p.getBool(_kEnabled) ?? false;
    _adminUrl = p.getString(_kAdminUrl) ?? '';
    _installId = p.getString(_kInstallId) ?? '';
    if (_installId.isEmpty) {
      _installId = _newId();
      await p.setString(_kInstallId, _installId);
    }
    final pending = p.getString(_kPending);
    if (pending != null && pending.isNotEmpty) {
      try {
        final m = jsonDecode(pending) as Map<String, dynamic>;
        _counts = Map<String, int>.from(m['counts'] as Map? ?? {});
        _crashes = ((m['crashes'] as List?) ?? const [])
            .map((e) => Map<String, String>.from(e as Map))
            .toList();
      } catch (_) {
        // a damaged pending blob is dropped, not something to crash over
      }
    }
    _loaded = true;
  }

  static String _newId() {
    final r = Random.secure();
    return List<int>.generate(8, (_) => r.nextInt(256)).map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  Future<void> setEnabled(bool on) async {
    await _ensureLoaded();
    _enabled = on;
    final p = await SharedPreferences.getInstance();
    await p.setBool(_kEnabled, on);
    if (!on) {
      _counts = {};
      _crashes = [];
      await _savePending(p);
    }
  }

  Future<void> setAdminUrl(String url) async {
    await _ensureLoaded();
    _adminUrl = url.trim();
    final p = await SharedPreferences.getInstance();
    await p.setString(_kAdminUrl, _adminUrl);
  }

  /// Counts a feature being used. A no-op while switched off, so nothing is even held in memory
  /// before the person opts in.
  Future<void> note(String event) async {
    await _ensureLoaded();
    if (!_enabled) return;
    _counts[event] = (_counts[event] ?? 0) + 1;
    await _persist();
  }

  /// Counts + remembers a sanitised crash: the exception type, its message, and which Network Doctor
  /// source line raised it - never a value, never anything about the phone's network.
  Future<void> noteError(String context, Object error, [StackTrace? stack]) async {
    await _ensureLoaded();
    if (!_enabled) return;
    final key = 'error:${_truncate(context, 40)}';
    _counts[key] = (_counts[key] ?? 0) + 1;
    if (_crashes.length < maxCrashes) {
      _crashes.add({
        'context': _truncate(context, 60),
        'type': error.runtimeType.toString(),
        'message': _truncate(error.toString(), 200),
        'where': _where(stack),
      });
    }
    await _persist();
  }

  static String _truncate(String s, int n) => s.length <= n ? s : s.substring(0, n);

  /// The deepest line of our own code in the stack - a file name and line number, never a local path
  /// beyond that, never a variable's value.
  static String _where(StackTrace? st) {
    if (st == null) return '?';
    final lines = st.toString().split('\n');
    final mine = RegExp(r'package:network_doctor/([\w./]+\.dart):(\d+)');
    for (final line in lines) {
      final m = mine.firstMatch(line);
      if (m != null) return '${m.group(1)}:${m.group(2)}';
    }
    return lines.isNotEmpty ? _truncate(lines.first.trim(), 120) : '?';
  }

  Future<void> _persist() async {
    final p = await SharedPreferences.getInstance();
    await _savePending(p);
  }

  Future<void> _savePending(SharedPreferences p) async {
    await p.setString(_kPending, jsonEncode({'counts': _counts, 'crashes': _crashes}));
  }

  /// What would be sent right now - shown to the person as "what gets sent", for transparency.
  Map<String, dynamic> pendingReport({required String appVersion}) => {
        'install_id': _installId,
        'app': 'Network Doctor',
        'kind': 'phone',
        'version': appVersion,
        'platform': '${Platform.operatingSystem} ${Platform.operatingSystemVersion}',
        'sent_at': DateTime.now().toUtc().toIso8601String(),
        'counts': Map<String, int>.from(_counts),
        'crashes': List<Map<String, String>>.from(_crashes),
      };

  /// Posts the pending report to the configured admin address and clears it on success.
  /// Returns (ok, detail). Never throws.
  Future<(bool, String)> sendNow({required String appVersion, http.Client? client}) async {
    await _ensureLoaded();
    if (!_enabled) return (false, 'reports are switched off');
    final url = _adminUrl.trim();
    if (url.isEmpty) return (false, 'no admin address set');
    if (_counts.isEmpty && _crashes.isEmpty) return (true, 'nothing to send yet');
    final body = jsonEncode(pendingReport(appVersion: appVersion));
    final c = client ?? http.Client();
    try {
      final base = url.endsWith('/') ? url.substring(0, url.length - 1) : url;
      final r = await c
          .post(Uri.parse('$base/api/telemetry'), headers: const {'Content-Type': 'application/json'}, body: body)
          .timeout(const Duration(seconds: 12));
      if (r.statusCode ~/ 100 != 2) return (false, 'server said ${r.statusCode}');
    } catch (e) {
      return (false, e.toString());
    } finally {
      if (client == null) c.close();
    }
    _counts = {};
    _crashes = [];
    final p = await SharedPreferences.getInstance();
    await _savePending(p);
    return (true, 'sent');
  }
}
