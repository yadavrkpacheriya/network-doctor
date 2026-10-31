import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

/// Checks GitHub for a newer Android version ("mobile-vX.Y.Z" releases with NetworkDoctor-Android.apk).
const releasesApi = 'https://api.github.com/repos/yadavrkpacheriya/network-doctor/releases?per_page=30';
const releasesPage = 'https://github.com/yadavrkpacheriya/network-doctor/releases?q=mobile&expanded=true';
const apkName = 'NetworkDoctor-Android.apk';

class AppUpdate {
  AppUpdate(this.version, this.apkUrl, this.pageUrl, this.notes);
  final String version;
  final String apkUrl;
  final String pageUrl;
  final String notes;
}

class UpdateError implements Exception {
  UpdateError(this.message);
  final String message;
  @override
  String toString() => message;
}

/// [1, 3, 0] from "mobile-v1.3.0", "v1.3.0" or "1.3.0+5".
List<int> parseVersion(String v) {
  final m = RegExp(r'(\d+)(?:\.(\d+))?(?:\.(\d+))?').firstMatch(v);
  if (m == null) return [0];
  return [for (var i = 1; i <= 3; i++) int.tryParse(m.group(i) ?? '0') ?? 0];
}

bool isNewer(String candidate, String current) {
  final a = parseVersion(candidate), b = parseVersion(current);
  for (var i = 0; i < 3; i++) {
    final x = i < a.length ? a[i] : 0, y = i < b.length ? b[i] : 0;
    if (x != y) return x > y;
  }
  return false;
}

/// The newest Android release in a GitHub releases list, or null.
AppUpdate? newestMobile(List<dynamic> releases) {
  AppUpdate? best;
  for (final r in releases) {
    if (r is! Map) continue;
    final tag = '${r['tag_name'] ?? ''}';
    if (!tag.startsWith('mobile-v') || r['draft'] == true) continue;
    final assets = (r['assets'] as List?) ?? const [];
    final apk = assets.cast<Map>().where((a) => a['name'] == apkName).toList();
    if (apk.isEmpty) continue;
    final u = AppUpdate(tag.substring('mobile-v'.length), '${apk.first['browser_download_url']}',
        '${r['html_url'] ?? releasesPage}', '${r['body'] ?? ''}');
    if (best == null || isNewer(u.version, best.version)) best = u;
  }
  return best;
}

/// Returns the newer version, or null when [current] is the newest. Throws [UpdateError].
Future<AppUpdate?> checkForUpdate(String current) async {
  http.Response r;
  try {
    r = await http
        .get(Uri.parse(releasesApi), headers: {'Accept': 'application/vnd.github+json', 'User-Agent': 'NetworkDoctor-Android'})
        .timeout(const Duration(seconds: 15));
  } catch (e) {
    throw UpdateError('Could not reach GitHub - is the phone online?');
  }
  if (r.statusCode == 403) throw UpdateError('GitHub is limiting requests right now - try again in an hour.');
  if (r.statusCode != 200) throw UpdateError('GitHub answered ${r.statusCode}.');
  final best = newestMobile(jsonDecode(r.body) as List<dynamic>);
  try {
    final p = await SharedPreferences.getInstance();
    await p.setInt('update_checked', DateTime.now().millisecondsSinceEpoch);
  } catch (_) {}
  if (best == null || !isNewer(best.version, current)) return null;
  return best;
}

/// Automatic check at most once a day (the phone app has no other internet traffic).
Future<AppUpdate?> dailyCheck(String current) async {
  try {
    final p = await SharedPreferences.getInstance();
    if (p.getBool('update_auto') == false) return null;
    final last = p.getInt('update_checked') ?? 0;
    if (DateTime.now().millisecondsSinceEpoch - last < 20 * 3600 * 1000) return null;
    return await checkForUpdate(current);
  } catch (_) {
    return null;
  }
}
