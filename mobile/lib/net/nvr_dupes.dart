// Find duplicate cameras across and within NVRs/DVRs - pure, no I/O. Port of the PC app's nd_nvrdup.py.
// Two kinds matter:
//   * within one NVR  - the same camera added to two channels, wasting a channel + licence.
//   * across NVRs     - the same camera on two recorders, so it records twice (double storage).
// A camera is identified by its IP (what the recorder stores per channel). Deleting is the caller's job, on
// confirmation. The result says exactly WHERE each duplicate sits (which NVR + which channel) so the user can act.

import 'dvrip.dart';

/// One recorder's configured cameras, as read by listChannels().
class NvrRecorder {
  NvrRecorder(this.ip, this.name, this.channels);
  final String ip; // the NVR's own IP
  final String name; // the NVR's name (falls back to its IP)
  final List<NvrChannel> channels;
}

/// Same camera on 2+ channels of ONE recorder.
class WithinDup {
  WithinDup(this.nvrIp, this.nvrName, this.camera, this.channels);
  final String nvrIp;
  final String nvrName;
  final String camera; // the camera's label (IP or name)
  final List<int> channels; // the channel numbers it sits on
}

/// Where one camera appears (one recorder + channel).
class DupPlace {
  DupPlace(this.nvrIp, this.nvrName, this.chan);
  final String nvrIp;
  final String nvrName;
  final int chan;
}

/// Same camera on 2+ DIFFERENT recorders.
class CrossDup {
  CrossDup(this.camera, this.places);
  final String camera;
  final List<DupPlace> places;
}

/// A camera that is live on the network but is NOT added to any recorder - so it is NOT being recorded.
class OrphanCam {
  OrphanCam(this.ip, this.name);
  final String ip;
  final String name;
}

class DupResult {
  DupResult(this.within, this.cross, [this.orphans = const []]);
  final List<WithinDup> within;
  final List<CrossDup> cross;
  final List<OrphanCam> orphans; // live cameras not in any DVR/NVR
  bool get isEmpty => within.isEmpty && cross.isEmpty && orphans.isEmpty;
}

/// Cameras on the network that no recorder has a channel for - i.e. live but NOT recorded. `liveCameras` is the
/// scanned cameras as (ip, name); any whose IP is not a channel IP on any recorder (and is not a recorder itself)
/// is an orphan. Recorder IPs are excluded so an NVR doesn't flag itself.
List<OrphanCam> findOrphans(List<NvrRecorder> nvrs, List<(String ip, String name)> liveCameras) {
  final inNvr = <String>{};
  final recorderIps = <String>{};
  for (final rec in nvrs) {
    recorderIps.add(rec.ip.trim());
    for (final ch in rec.channels) {
      final ip = ch.ip.trim();
      if (ip.isNotEmpty) inNvr.add(ip);
    }
  }
  final out = <OrphanCam>[];
  final done = <String>{};
  for (final (ip, name) in liveCameras) {
    final t = ip.trim();
    if (t.isEmpty || done.contains(t)) continue;
    if (inNvr.contains(t) || recorderIps.contains(t)) continue;
    done.add(t);
    out.add(OrphanCam(t, name));
  }
  return out;
}

String _key(NvrChannel ch) {
  final ip = ch.ip.trim();
  return ip.isNotEmpty ? 'ip:$ip' : '';
}

/// Find within- and cross-recorder duplicates. A channel with no camera IP is skipped (can't be matched).
DupResult findDuplicates(List<NvrRecorder> nvrs) {
  final within = <WithinDup>[];
  // key -> list of (nvrIp, nvrName, chan, label)
  final seen = <String, List<DupPlace>>{};
  final seenLabel = <String, String>{};

  for (final rec in nvrs) {
    final nname = rec.name.isNotEmpty ? rec.name : rec.ip;
    final byCam = <String, List<int>>{};
    final byCamLabel = <String, String>{};
    for (final ch in rec.channels) {
      final k = _key(ch);
      if (k.isEmpty) continue;
      final label = ch.ip.isNotEmpty ? ch.ip : (ch.name.isNotEmpty ? ch.name : k.split(':').last);
      byCam.putIfAbsent(k, () => []).add(ch.chan);
      byCamLabel[k] = label;
      seen.putIfAbsent(k, () => []).add(DupPlace(rec.ip, nname, ch.chan));
      seenLabel[k] = label;
    }
    byCam.forEach((k, chans) {
      if (chans.length > 1) {
        within.add(WithinDup(rec.ip, nname, byCamLabel[k]!, chans..sort()));
      }
    });
  }

  final cross = <CrossDup>[];
  seen.forEach((k, places) {
    final recs = places.map((p) => p.nvrIp).toSet();
    if (recs.length > 1) {
      cross.add(CrossDup(seenLabel[k]!, places));
    }
  });
  return DupResult(within, cross);
}
