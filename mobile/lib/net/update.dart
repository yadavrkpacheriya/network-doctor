import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:open_filex/open_filex.dart';
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Checks GitHub for a newer Android version ("mobile-vX.Y.Z" releases with NetworkDoctor-Android.apk).
const releasesApi = 'https://api.github.com/repos/yadavrkpacheriya/network-doctor/releases?per_page=30';
const releasesPage = 'https://github.com/yadavrkpacheriya/network-doctor/releases?q=mobile&expanded=true';
const apkName = 'NetworkDoctor-Android.apk';

/// The downloaded update always lands at this one fixed name in the app's own cache, overwriting
/// whatever was there before - unlike a browser download (a new numbered file every time), repeated
/// checks and downloads never pile up extra .apk files on the phone's storage.
const _apkCacheName = 'networkdoctor-update.apk';

class AppUpdate {
  AppUpdate(this.version, this.apkUrl, this.pageUrl, this.notes, this.shaUrl);
  final String version;
  final String apkUrl;
  final String pageUrl;
  final String notes;
  final String? shaUrl;
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
    final list = assets.cast<Map>();
    final apk = list.where((a) => a['name'] == apkName).toList();
    if (apk.isEmpty) continue;
    final sha = list.where((a) => a['name'] == '$apkName.sha256').toList();
    final u = AppUpdate(tag.substring('mobile-v'.length), '${apk.first['browser_download_url']}',
        '${r['html_url'] ?? releasesPage}', '${r['body'] ?? ''}',
        sha.isEmpty ? null : '${sha.first['browser_download_url']}');
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

/// The daily check time: 15:00 on the phone's clock (same as the PC app).
const dailyHour = 15;

/// The most recent 15:00 that has already passed (today or yesterday).
DateTime lastDaily(DateTime now) {
  final t = DateTime(now.year, now.month, now.day, dailyHour);
  return t.isAfter(now) ? DateTime(now.year, now.month, now.day - 1, dailyHour) : t;
}

/// True when there was no check since the most recent 15:00 (also when the phone was off at 15:00).
bool dailyDue(int lastCheckMs, DateTime now) =>
    lastCheckMs < lastDaily(now).millisecondsSinceEpoch;

/// Automatic check once a day at 15:00 (the phone app has no other internet traffic).
Future<AppUpdate?> dailyCheck(String current) async {
  try {
    final p = await SharedPreferences.getInstance();
    if (p.getBool('update_auto') == false) return null;
    final last = p.getInt('update_checked') ?? 0;
    if (!dailyDue(last, DateTime.now())) return null;
    return await checkForUpdate(current);
  } catch (_) {
    return null;
  }
}

Future<File> _apkFile() async {
  final dir = await getTemporaryDirectory();
  return File('${dir.path}/$_apkCacheName');
}

/// Removes a previously downloaded update, if any - called before a fresh download starts and once at
/// app launch, so a download that was interrupted (phone locked, app killed) never lingers.
Future<void> cleanupDownloadedApk() async {
  try {
    final f = await _apkFile();
    if (await f.exists()) await f.delete();
  } catch (_) {}
}

/// Downloads the APK for [update] into the app's own cache (overwriting any earlier download) and
/// verifies it against the published checksum when the release has one. [onProgress] reports bytes
/// received and the total (-1 when the server didn't send a length). Throws [UpdateError] on failure.
Future<File> downloadApk(AppUpdate update, {void Function(int received, int total)? onProgress}) async {
  final client = http.Client();
  List<int> bytes;
  try {
    http.StreamedResponse resp;
    try {
      resp = await client.send(http.Request('GET', Uri.parse(update.apkUrl))).timeout(const Duration(seconds: 30));
    } catch (e) {
      throw UpdateError('Could not reach GitHub - is the phone online?');
    }
    if (resp.statusCode != 200) throw UpdateError('Could not download the update (HTTP ${resp.statusCode}).');
    final total = resp.contentLength ?? -1;
    var received = 0;
    final buf = <int>[];
    await for (final chunk in resp.stream) {
      buf.addAll(chunk);
      received += chunk.length;
      onProgress?.call(received, total);
    }
    bytes = buf;
  } finally {
    client.close();
  }
  if (update.shaUrl != null) {
    String expected;
    try {
      final r = await http.get(Uri.parse(update.shaUrl!)).timeout(const Duration(seconds: 15));
      expected = r.body.trim().split(RegExp(r'\s+')).first.toLowerCase();
    } catch (e) {
      throw UpdateError('Could not download the checksum ($e).');
    }
    if (sha256.convert(bytes).toString() != expected) {
      throw UpdateError('The downloaded file did not match the published checksum - update cancelled for safety.');
    }
  }
  final f = await _apkFile();
  await f.writeAsBytes(bytes, flush: true);
  return f;
}

/// Hands the downloaded APK to Android's own package installer (the same system UI a browser download
/// would open, minus the trip through Downloads/Files). Returns null when it looks to have gone
/// through - a successful install normally restarts this app's process, so there is nothing further to
/// observe from here - or a short, actionable message otherwise.
Future<String?> installApk(File apk) async {
  final result = await OpenFilex.open(apk.path, type: 'application/vnd.android.package-archive');
  switch (result.type) {
    case ResultType.done:
      return null;
    case ResultType.permissionDenied:
      return 'Allow "Install unknown apps" for Network Doctor when Android asks, then try again.';
    case ResultType.noAppToOpen:
      return 'No app on this phone can install packages.';
    case ResultType.fileNotFound:
      return 'The downloaded file went missing - try again.';
    case ResultType.error:
      return result.message.isEmpty ? 'Could not start the installer.' : result.message;
  }
}
