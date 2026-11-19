import 'package:flutter_test/flutter_test.dart';
import 'package:network_doctor/net/default_login.dart';
import 'package:network_doctor/net/model.dart';

void main() {
  group('default-password safety gate', () {
    test('only safe device kinds may be tested (never PCs/phones)', () {
      // safe: these do not lock accounts out
      expect(mayTestDefault(Cat.cam), isTrue);
      expect(mayTestDefault(Cat.router), isTrue);
      expect(mayTestDefault(Cat.net), isTrue);
      expect(mayTestDefault(Cat.prn), isTrue);
      expect(mayTestDefault(Cat.bio), isTrue);
      // unsafe: trying passwords here can lock out the real user's Windows/AD account
      expect(mayTestDefault(Cat.pc), isFalse);
      expect(mayTestDefault(Cat.phone), isFalse);
      expect(mayTestDefault(Cat.iot), isFalse);
      expect(mayTestDefault(Cat.unknown), isFalse);
    });

    test('common defaults list matches the PC app (10 factory logins, admin/blank first)', () {
      expect(commonDefaults.length, 10);
      expect(commonDefaults.first, ['admin', '']);
      // List.contains compares by identity, so match on the values instead
      expect(commonDefaults.any((c) => c[0] == 'root' && c[1] == 'root'), isTrue);
    });
  });

  group('safetyNotes promotion', () {
    test('a confirmed default login shows as a critical, most-severe finding', () {
      final d = Device('192.168.0.50')
        ..category = Cat.cam
        ..defaultLoginUser = 'admin'
        ..ports.add(80)
        ..ports.add(23); // also telnet, which must rank below the password finding
      final notes = d.safetyNotes;
      expect(notes.first, contains('Default / weak password works'));
      expect(notes.first, contains("'admin'"));
      expect(notes.length, 2); // password + telnet
    });

    test('no default hit -> no password finding', () {
      final d = Device('192.168.0.51')
        ..category = Cat.cam
        ..ports.add(80);
      expect(d.safetyNotes.where((n) => n.contains('password')), isEmpty);
    });

    test('a tested camera (web port present) is not also nagged with the blanket tip', () {
      final d = Device('192.168.0.52')
        ..category = Cat.cam
        ..ports.add(80);
      // it was testable (port 80) and came back clean -> no "change it once" reminder
      expect(d.safetyTips, isEmpty);
    });

    test('an untestable camera (no web port) still gets the gentle reminder', () {
      final d = Device('192.168.0.53')
        ..category = Cat.cam
        ..ports.add(554); // RTSP only, no web login to probe
      expect(d.safetyTips.any((t) => t.contains('default password')), isTrue);
    });
  });
}
