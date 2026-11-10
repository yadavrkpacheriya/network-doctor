import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:network_doctor/net/telemetry.dart';
import 'package:network_doctor/net/wifi_security.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  // Telemetry() is a plain constructible class (Telemetry.instance is just the app-wide default), so
  // each test gets its own in-memory state - only the shared_preferences mock store needs resetting.
  setUp(() => SharedPreferences.setMockInitialValues({}));

  group('off by default', () {
    test('disabled until switched on', () async {
      final t = Telemetry();
      await t.load();
      expect(t.enabled, isFalse);
    });

    test('note is a no-op while disabled', () async {
      final t = Telemetry();
      await t.load();
      await t.note('scan');
      expect(t.pendingReport(appVersion: '1.0')['counts'], {});
    });

    test('noteError is a no-op while disabled', () async {
      final t = Telemetry();
      await t.load();
      await t.noteError('ctx', Exception('boom'));
      final rep = t.pendingReport(appVersion: '1.0');
      expect(rep['counts'], {});
      expect(rep['crashes'], []);
    });

    test('sendNow refuses while disabled even with an address', () async {
      final t = Telemetry();
      await t.load();
      await t.setAdminUrl('https://admin.example.com');
      final (ok, detail) = await t.sendNow(appVersion: '1.0');
      expect(ok, isFalse);
      expect(detail, contains('off'));
    });

    test('sendNow refuses without an address even when enabled', () async {
      final t = Telemetry();
      await t.load();
      await t.setEnabled(true);
      final (ok, detail) = await t.sendNow(appVersion: '1.0');
      expect(ok, isFalse);
      expect(detail, contains('address'));
    });
  });

  group('install id', () {
    test('a fresh store gets a random 16-char hex id', () async {
      final t = Telemetry();
      await t.load();
      expect(t.installId.length, 16);
      // Every character is a hex digit - checked this way, not via int.tryParse(id, radix: 16), because a
      // 16-hex-char id covers the full 64-bit range and about half the time (whenever the leading nibble is
      // 8-f) that overflows Dart's signed 64-bit int on the VM, making tryParse return null for a perfectly
      // valid id and failing this test on a coin flip unrelated to anything actually wrong.
      expect(RegExp(r'^[0-9a-f]{16}$').hasMatch(t.installId), isTrue);
    });

    test('the same preferences store keeps its id across instances', () async {
      final a = Telemetry();
      await a.load();
      final b = Telemetry();
      await b.load();
      expect(a.installId, b.installId);
    });
  });

  group('counting', () {
    test('note counts each call', () async {
      final t = Telemetry();
      await t.load();
      await t.setEnabled(true);
      await t.note('scan');
      await t.note('scan');
      await t.note('pc_pair');
      final counts = t.pendingReport(appVersion: '1.0')['counts'] as Map;
      expect(counts['scan'], 2);
      expect(counts['pc_pair'], 1);
    });

    test('noteError counts and remembers a sanitised crash', () async {
      final t = Telemetry();
      await t.load();
      await t.setEnabled(true);
      await t.noteError('quick_check', Exception('bad thing'));
      final rep = t.pendingReport(appVersion: '1.0');
      expect((rep['counts'] as Map)['error:quick_check'], 1);
      final crashes = rep['crashes'] as List;
      expect(crashes.length, 1);
      expect(crashes.first['type'], contains('Exception'));
      expect(crashes.first['message'], contains('bad thing'));
    });

    test('crash list is capped', () async {
      final t = Telemetry();
      await t.load();
      await t.setEnabled(true);
      for (var i = 0; i < Telemetry.maxCrashes + 10; i++) {
        await t.noteError('loop', Exception('x'));
      }
      expect((t.pendingReport(appVersion: '1.0')['crashes'] as List).length, Telemetry.maxCrashes);
    });

    test('turning off clears whatever was pending', () async {
      final t = Telemetry();
      await t.load();
      await t.setEnabled(true);
      await t.note('scan');
      await t.setEnabled(false);
      expect(t.pendingReport(appVersion: '1.0')['counts'], {});
    });

    test('pending state survives a fresh instance over the same preferences store', () async {
      final a = Telemetry();
      await a.load();
      await a.setEnabled(true);
      await a.note('scan');
      final b = Telemetry();
      await b.load();
      expect((b.pendingReport(appVersion: '1.0')['counts'] as Map)['scan'], 1);
    });
  });

  group('sending', () {
    test('nothing to send is reported ok without a network call', () async {
      final t = Telemetry();
      await t.load();
      await t.setEnabled(true);
      await t.setAdminUrl('https://admin.example.com');
      var called = false;
      final client = MockClient((req) async {
        called = true;
        return http.Response('{}', 200);
      });
      final (ok, detail) = await t.sendNow(appVersion: '1.0', client: client);
      expect(ok, isTrue);
      expect(detail, contains('nothing'));
      expect(called, isFalse);
    });

    test('successful send clears pending and posts to the telemetry path', () async {
      final t = Telemetry();
      await t.load();
      await t.setEnabled(true);
      await t.setAdminUrl('https://admin.example.com');
      await t.note('scan');
      Uri? seenUri;
      Map<String, dynamic>? seenBody;
      final client = MockClient((req) async {
        seenUri = req.url;
        seenBody = jsonDecode(req.body) as Map<String, dynamic>;
        return http.Response('{}', 200);
      });
      final (ok, detail) = await t.sendNow(appVersion: '1.0', client: client);
      expect(ok, isTrue);
      expect(detail, 'sent');
      expect(seenUri.toString(), 'https://admin.example.com/api/telemetry');
      expect(seenBody!['kind'], 'phone');
      expect((seenBody!['counts'] as Map)['scan'], 1);
      expect(t.pendingReport(appVersion: '1.0')['counts'], {});
    });

    test('a trailing slash on the admin url is tolerated', () async {
      final t = Telemetry();
      await t.load();
      await t.setEnabled(true);
      await t.setAdminUrl('https://admin.example.com/');
      await t.note('scan');
      Uri? seenUri;
      final client = MockClient((req) async {
        seenUri = req.url;
        return http.Response('{}', 200);
      });
      await t.sendNow(appVersion: '1.0', client: client);
      expect(seenUri.toString(), 'https://admin.example.com/api/telemetry');
    });

    test('a non-2xx response leaves the pending report untouched', () async {
      final t = Telemetry();
      await t.load();
      await t.setEnabled(true);
      await t.setAdminUrl('https://admin.example.com');
      await t.note('scan');
      final client = MockClient((req) async => http.Response('nope', 429));
      final (ok, detail) = await t.sendNow(appVersion: '1.0', client: client);
      expect(ok, isFalse);
      expect(detail, contains('429'));
      expect((t.pendingReport(appVersion: '1.0')['counts'] as Map)['scan'], 1);
    });

    test('a network failure leaves the pending report untouched', () async {
      final t = Telemetry();
      await t.load();
      await t.setEnabled(true);
      await t.setAdminUrl('https://admin.example.com');
      await t.note('scan');
      final client = MockClient((req) async => throw Exception('network down'));
      final (ok, detail) = await t.sendNow(appVersion: '1.0', client: client);
      expect(ok, isFalse);
      expect(detail, contains('network down'));
      expect((t.pendingReport(appVersion: '1.0')['counts'] as Map)['scan'], 1);
    });
  });

  group('WifiSecurityCheck.classify', () {
    test('open and OWE are both "open"', () {
      expect(WifiSecurityCheck.classify(0), WifiSecurity.open);
      expect(WifiSecurityCheck.classify(6), WifiSecurity.open);
    });

    test('WEP is "weak"', () {
      expect(WifiSecurityCheck.classify(1), WifiSecurity.weak);
    });

    test('PSK, EAP, SAE and anything else known are "secured"', () {
      for (final t in [2, 3, 4, 5, 7, 8, 9, 10, 11, 12]) {
        expect(WifiSecurityCheck.classify(t), WifiSecurity.secured);
      }
    });

    test('null or negative is "unknown"', () {
      expect(WifiSecurityCheck.classify(null), WifiSecurity.unknown);
      expect(WifiSecurityCheck.classify(-1), WifiSecurity.unknown);
    });
  });
}
