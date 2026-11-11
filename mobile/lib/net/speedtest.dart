import 'dart:async';
import 'dart:io';

/// A quick download-throughput test. It is just an HTTPS download, so it works on Wi-Fi AND on mobile
/// data - unlike the device scan, which needs a local network. Reports the running speed as it goes
/// (so the number climbs live) and returns the average Mbps at the end.
class SpeedTest {
  bool _cancel = false;
  void cancel() => _cancel = true;
  bool get cancelled => _cancel;

  /// Set only after a 0 Mbps result: true when a second, unrelated host answered fine, meaning this
  /// network can actually reach the internet - it just couldn't reach (or was blocked from reaching)
  /// Cloudflare's test server specifically. That is a different, more honest explanation than "this
  /// network has no internet" for the caller to show, and this flag is what lets it tell the two apart
  /// instead of reporting every failed download the same way.
  bool otherHostReachable = false;

  // Cloudflare's open speed endpoint, used by speed.cloudflare.com. Public, no key, available worldwide.
  static final Uri _downUrl = Uri.parse('https://speed.cloudflare.com/__down?bytes=100000000');

  // A second, unrelated host used only to probe general connectivity when the download above gets
  // nothing - small and fast on purpose, since it is not measuring speed, only reachability.
  static final Uri _probeUrl = Uri.parse('https://www.gstatic.com/generate_204');

  /// Downloads for up to [budget], calling [onProgress] with the running Mbps and elapsed seconds.
  /// Returns the overall Mbps, or 0 if it could not run (no internet on this network).
  Future<double> downloadMbps({
    Duration budget = const Duration(seconds: 8),
    void Function(double mbps, double seconds)? onProgress,
  }) async {
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 6);
    final sw = Stopwatch()..start();
    var bytes = 0;
    try {
      final req = await client.getUrl(_downUrl).timeout(const Duration(seconds: 6));
      final resp = await req.close().timeout(const Duration(seconds: 6));
      await for (final chunk in resp) {
        if (_cancel) break;
        bytes += chunk.length;
        final secs = sw.elapsedMilliseconds / 1000.0;
        if (secs > 0.25) onProgress?.call((bytes * 8 / 1e6) / secs, secs);
        if (sw.elapsed >= budget) break;
      }
    } catch (_) {
      // network error / no internet on this network - handled by the "too little" check below
    } finally {
      client.close(force: true);
    }
    final secs = sw.elapsedMilliseconds / 1000.0;
    if (bytes < 50000 || secs <= 0.25) {
      // too little downloaded to be meaningful - find out whether that's "no internet" or just
      // "couldn't reach that one server" before reporting 0
      otherHostReachable = !_cancel && await _probeOtherHost();
      return 0;
    }
    return (bytes * 8 / 1e6) / secs;
  }

  Future<bool> _probeOtherHost() async {
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 4);
    try {
      final req = await client.getUrl(_probeUrl).timeout(const Duration(seconds: 4));
      final resp = await req.close().timeout(const Duration(seconds: 4));
      await resp.drain<void>();
      return true;
    } catch (_) {
      return false;
    } finally {
      client.close(force: true);
    }
  }
}
