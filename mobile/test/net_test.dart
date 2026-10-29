import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:network_doctor/net/model.dart';
import 'package:network_doctor/net/probe.dart';
import 'package:network_doctor/net/snmp.dart' as snmp;
import 'package:network_doctor/net/tools.dart';
import 'package:network_doctor/screens/about_screen.dart';

Uint8List fakeNbstatAnswer(String name) {
  final b = BytesBuilder();
  b.add([0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]); // header, 1 answer
  b.add([0x20]);
  b.add(List.filled(32, 0x41));
  b.add([0]); // encoded name
  b.add([0, 0x21, 0, 1, 0, 0, 0, 0, 0, 0x41]); // type, class, ttl, rdlength
  b.add([2]); // two names
  List<int> entry(String n, int suffix, int flags) =>
      n.padRight(15).codeUnits.take(15).toList() + [suffix, flags >> 8, flags & 255];
  b.add(entry('WORKGROUP', 0, 0x8400)); // group name - must be skipped
  b.add(entry(name, 0, 0x0400));
  b.add(List.filled(6, 0xAA)); // unit id
  return b.toBytes();
}

void main() {
  group('IPv4 helpers', () {
    test('mask to prefix', () {
      expect(maskToPrefix('255.255.255.0'), 24);
      expect(maskToPrefix('255.255.252.0'), 22);
      expect(maskToPrefix(null), 24);
      expect(maskToPrefix('garbage'), 24);
    });
    test('hosts of a /24 and limits', () {
      final h = hostsOf('192.168.0.70', 24);
      expect(h.length, 254);
      expect(h.first, '192.168.0.1');
      expect(h.last, '192.168.0.254');
      expect(hostsOf('10.0.0.5', 16).length, 1022); // never more than a /22
    });
    test('broadcast', () {
      expect(broadcastOf('192.168.0.70', 24), '192.168.0.255');
      expect(broadcastOf('10.1.2.3', 22), '10.1.3.255');
    });
  });

  group('NetBIOS', () {
    test('query packet is 50 bytes and asks for node status', () {
      final p = buildNbstat(0x1234);
      expect(p.length, 50);
      expect(p[0], 0x12);
      expect(p[48], 0x00);
      expect(p[47], 0x21);
    });
    test('answer: computer name is read, group name skipped', () {
      expect(parseNbstat(fakeNbstatAnswer('ACCOUNTS-PC')), 'ACCOUNTS-PC');
    });
    test('garbage does not crash', () {
      expect(parseNbstat(Uint8List.fromList([1, 2, 3])), isNull);
    });
  });

  group('categories', () {
    Device dev(String ip, {Set<int> ports = const {}, String name = '', String nb = '', String upnp = ''}) {
      final d = Device(ip)
        ..name = name
        ..netbios = nb
        ..upnpType = upnp;
      d.ports.addAll(ports);
      return d;
    }

    test('gateway', () => expect(categorize(dev('192.168.0.1'), '192.168.0.1').$1, Cat.router));
    test('camera by RTSP', () => expect(categorize(dev('1.1.1.2', ports: {80, 554}), null).$1, Cat.cam));
    test('printer by 9100', () => expect(categorize(dev('1.1.1.3', ports: {9100}), null).$1, Cat.prn));
    test('PC by SMB', () => expect(categorize(dev('1.1.1.4', ports: {445, 139}), null).$1, Cat.pc));
    test('PC by NetBIOS name', () => expect(categorize(dev('1.1.1.5', nb: 'DESIGN-PC'), null).$1, Cat.pc));
    test('iPhone port', () => expect(categorize(dev('1.1.1.6', ports: {62078}), null).$1, Cat.phone));
    test('UPnP router', () => expect(
        categorize(dev('1.1.1.7', upnp: 'urn:schemas-upnp-org:device:InternetGatewayDevice:1'), null).$1, Cat.net));
    test('biometric', () => expect(categorize(dev('1.1.1.8', ports: {4370}), null).$1, Cat.bio));
    test('nothing known', () => expect(categorize(dev('1.1.1.9'), null).$1, Cat.unknown));
    test('PC app names are mapped', () {
      expect(Cat.normalise('Network equipment (router / switch / AP)'), Cat.net);
      expect(Cat.normalise('CCTV cameras / DVR / NVR'), Cat.cam);
      expect(Cat.normalise('Not online now (seen before)'), Cat.offline);
    });
  });

  group('PC data', () {
    test('device from PC snapshot', () {
      final d = Device.fromPc({
        'name': 'DESIGN-PC', 'ip': '192.168.0.3', 'ips': ['192.168.0.3'], 'mac': '6C:4B:90:0A:0B:0C',
        'vendor': 'LiteON', 'category': 'Computers / laptops', 'online': true, 'ip_type': 'DHCP',
        'ports': [135, 445], 'down_bps': 125000.0, 'web_port': null, 'notes': ['x'],
      });
      expect(d.category, Cat.pc);
      expect(d.services, contains('File sharing'));
      expect(d.downBps, 125000.0);
      expect(d.browserUri().toString(), 'http://192.168.0.3');
    });
    test('browser uri uses https and port', () {
      final d = Device('10.0.0.9')..ports.add(8443);
      expect(d.browserUri().toString(), 'https://10.0.0.9:8443');
    });
  });

  testWidgets('About screen builds', (tester) async {
    await tester.pumpWidget(const MaterialApp(home: AboutScreen()));
    expect(find.text('Network Doctor'), findsOneWidget);
  });

  group('SNMP codec', () {
    test('OID and integer round trip', () {
      for (final oid in ['1.3.6.1.2.1.1.1.0', '1.0.8802.1.1.2.1.4.1.1.9', '1.3.6.1.4.1.14988.1']) {
        final b = Uint8List.fromList(snmp.encOid(oid));
        final (tag, body, _) = snmp.readTlv(b, 0);
        expect(tag, snmp.tOid);
        expect(snmp.decOid(body), oid);
      }
      for (final v in [0, 1, 127, 128, 255, 256, -1, -129, 2147483647]) {
        final (tag, body, _) = snmp.readTlv(Uint8List.fromList(snmp.encInt(v)), 0);
        expect(snmp.decValue(tag, body), v);
      }
    });

    test('message round trip and helpers', () {
      final pkt = Uint8List.fromList(snmp.buildMessage(snmp.pGet, 42, ['1.3.6.1.2.1.1.5.0'], 'secret', 1));
      final r = snmp.parseMessage(pkt);
      expect(r.requestId, 42);
      expect(r.varbinds.single.$1, '1.3.6.1.2.1.1.5.0');
      expect(snmp.vendorOf('1.3.6.1.4.1.11863.5.1'), 'TP-Link');
      expect(snmp.uptimeText(9000000), '1 d 1 h 0 min');
      expect(snmp.speedText(2500), '2.5 Gbps');
      expect(snmp.text(Uint8List.fromList('sw-1\x00'.codeUnits)), 'sw-1');
      expect(snmp.inSubtree('1.3.6.1.2.1.2.2.1.2.5', '1.3.6.1.2.1.2.2.1.2'), isTrue);
      expect(snmp.cmpOid('1.3.6.1.2.10', '1.3.6.1.2.9'), greaterThan(0));
      final p = snmp.SwitchPort(1, 'Gi1', '', true, 100, 0, 3, 6);
      expect(p.warnings.length, 2);
    });
  });

  group('Tools', () {
    test('subnet calculator', () {
      final s = subnetOf('10.0.0.5/22')!;
      expect([s.network, s.mask, s.broadcast, s.first, s.last, s.hosts], ['10.0.0.0', '255.255.252.0', '10.0.3.255',
        '10.0.0.1', '10.0.3.254', 1022]);
      expect(subnetOf('192.168.1.7 255.255.255.0')!.prefix, 24);
      expect(subnetOf('192.168.1.300/24'), isNull);
      expect(subnetOf('10.1.1.1/32')!.hosts, 1);
    });

    test('Wake-on-LAN packet', () {
      final mac = parseMac('aa-bb-cc-11-22-33')!;
      final p = magicPacket(mac);
      expect(p.length, 102);
      expect(p.sublist(0, 6), List.filled(6, 255));
      expect(p.sublist(96), [0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33]);
      expect(parseMac('nonsense'), isNull);
    });
  });
}
