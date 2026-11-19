import 'package:flutter_test/flutter_test.dart';
import 'package:network_doctor/net/dvrip.dart';
import 'package:network_doctor/net/nvr_dupes.dart';

NvrChannel ch(int n, String ip, [String name = '']) => NvrChannel(n, name.isEmpty ? 'CAM$n' : name, ip, null);

void main() {
  group('within-recorder duplicates', () {
    test('same camera IP on two channels of one NVR is flagged', () {
      final nvr = NvrRecorder('192.168.0.22', 'NVR-A', [ch(1, '192.168.0.50'), ch(2, '192.168.0.51'), ch(3, '192.168.0.50')]);
      final r = findDuplicates([nvr]);
      expect(r.within.length, 1);
      expect(r.within.first.camera, '192.168.0.50');
      expect(r.within.first.channels, [1, 3]);
      expect(r.cross, isEmpty);
    });
  });

  group('across-recorder duplicates', () {
    test('same camera on two different recorders is flagged with both locations', () {
      final a = NvrRecorder('192.168.0.22', 'NVR-A', [ch(1, '192.168.0.50')]);
      final b = NvrRecorder('192.168.0.23', 'NVR-B', [ch(5, '192.168.0.50')]);
      final r = findDuplicates([a, b]);
      expect(r.cross.length, 1);
      final places = r.cross.first.places;
      expect(places.length, 2);
      expect(places.map((p) => '${p.nvrName}:${p.chan}').toSet(), {'NVR-A:1', 'NVR-B:5'});
    });

    test('a camera on one recorder only is NOT a cross duplicate', () {
      final a = NvrRecorder('192.168.0.22', 'NVR-A', [ch(1, '192.168.0.50'), ch(2, '192.168.0.60')]);
      expect(findDuplicates([a]).cross, isEmpty);
    });

    test('channels with no IP are ignored (cannot be matched)', () {
      final a = NvrRecorder('192.168.0.22', 'NVR-A', [ch(1, ''), ch(2, '')]);
      final r = findDuplicates([a]);
      expect(r.within, isEmpty);
      expect(r.cross, isEmpty);
    });
  });

  group('orphan cameras (live but in no recorder)', () {
    test('a live camera not on any channel is an orphan; recorder IP and added ones are excluded', () {
      final a = NvrRecorder('192.168.0.22', 'NVR-A', [ch(1, '192.168.0.50')]);
      final live = [
        ('192.168.0.50', 'in NVR'),      // already in NVR-A -> not orphan
        ('192.168.0.22', 'the NVR'),     // the recorder itself -> not orphan
        ('192.168.0.77', 'Gate cam'),    // live, in no recorder -> ORPHAN
      ];
      final o = findOrphans([a], live);
      expect(o.length, 1);
      expect(o.first.ip, '192.168.0.77');
      expect(o.first.name, 'Gate cam');
    });

    test('duplicate live entries are de-duped', () {
      final o = findOrphans([], [('192.168.0.77', 'x'), ('192.168.0.77', 'x')]);
      expect(o.length, 1);
    });
  });
}
