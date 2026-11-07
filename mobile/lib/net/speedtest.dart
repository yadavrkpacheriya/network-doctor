import 'dart:async';
import 'dart:io';

/// A quick download-throughput test. It is just an HTTPS download, so it works on Wi-Fi AND on mobile
/// data - unlike the device scan, which needs a local network. Reports the running speed as it goes
/// (so the number climbs live) and returns the average Mbps at the end.
class SpeedTest {
  bool _cancel = false;
  void cancel() => _cancel = true;
  bool get cancelled => _cancel;

  // Cloudflare's open speed endpoint, used by speed.cloudflare.com. Public, no key, available worldwide.
  static final Uri _downUrl = Uri.parse('https://speed.cloudflare.com/__down?bytes=100000000');

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
    if (bytes < 50000 || secs <= 0.25) return 0; // too little downloaded to be meaningful
    return (bytes * 8 / 1e6) / secs;
  }
}
