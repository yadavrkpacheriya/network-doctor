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

  /// Which server actually answered, once one does - shown to the person so a repeat "it didn't work"
  /// report says which one, instead of every failure looking identical.
  String? usedHost;

  // Several independent, well-known throughput-test endpoints on different providers, tried in order.
  // A single hardcoded server (the original design) fails every day a network's firewall/DNS filter/
  // transient outage happens to block *that one* host - which is exactly what "doesn't work everyday"
  // reported. Rotating through unrelated providers means one being blocked or slow doesn't take the
  // whole feature down; it just falls through to the next.
  static final List<Uri> _downUrls = [
    // 25 MB, not 100: the PC app has always used a moderate size here, and a fast line simply finishes
    // early (the speed is bytes / time either way)
    Uri.parse('https://speed.cloudflare.com/__down?bytes=25000000'),
    Uri.parse('https://proof.ovh.net/files/100Mb.dat'),
    Uri.parse('https://speedtest.tele2.net/100MB.zip'),
    Uri.parse('https://ash-speed.hetzner.com/100MB.bin'),
    Uri.parse('http://ipv4.download.thinkbroadband.com/100MB.zip'),
  ];

  /// How many servers are tried before giving up (for the message shown to the person).
  static int get serverCount => _downUrls.length;

  // A second, unrelated host used only to probe general connectivity when every download above gets
  // nothing - small and fast on purpose, since it is not measuring speed, only reachability.
  static final Uri _probeUrl = Uri.parse('https://www.gstatic.com/generate_204');

  /// Downloads for up to [budget] (tried against each candidate host in turn until one answers with
  /// enough data), calling [onProgress] with the running Mbps and elapsed seconds. Returns the overall
  /// Mbps, or 0 if none of them could run (this network likely has no usable internet right now).
  Future<double> downloadMbps({
    Duration budget = const Duration(seconds: 8),
    void Function(double mbps, double seconds)? onProgress,
  }) async {
    for (final url in _downUrls) {
      if (_cancel) break;
      // A shorter connect timeout than the original single-server design on purpose: when a host is
      // blocked outright (not just slow), failing fast here is what keeps the total wait for all 3
      // candidates reasonable instead of piling up long connect timeouts before giving up.
      final client = HttpClient()..connectionTimeout = const Duration(seconds: 4);
      // started when the server answers, not before connecting: the connect / TLS time is not download
      // time, and counting it made a short test on a fast line read low
      final sw = Stopwatch();
      var bytes = 0;
      try {
        final req = await client.getUrl(url).timeout(const Duration(seconds: 4));
        final resp = await req.close().timeout(const Duration(seconds: 4));
        if (resp.statusCode != 200) throw const HttpException('not a download');
        sw.start();
        await for (final chunk in resp.timeout(const Duration(seconds: 5))) {
          if (_cancel) break;
          bytes += chunk.length;
          final secs = sw.elapsedMilliseconds / 1000.0;
          if (secs > 0.25) onProgress?.call((bytes * 8 / 1e6) / secs, secs);
          if (sw.elapsed >= budget) break;
        }
      } catch (_) {
        // this host didn't answer (blocked, down, or slow to connect) - try the next one
      } finally {
        client.close(force: true);
      }
      final secs = sw.elapsedMilliseconds / 1000.0;
      if (bytes >= 50000 && secs > 0.25) {
        usedHost = url.host;
        return (bytes * 8 / 1e6) / secs;
      }
      if (_cancel) break;
    }
    // every candidate host failed - find out whether that's "no internet at all" or just "every one of
    // those particular hosts happens to be blocked/down" before reporting 0
    otherHostReachable = !_cancel && await _probeOtherHost();
    return 0;
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
