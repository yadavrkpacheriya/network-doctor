// SNMP v1 / v2c reader for switches and routers of any brand (read-only).
// Same approach as the PC app's nd_snmp.py: plain UDP, a small BER codec, standard MIBs.

import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

const tInt = 0x02, tOctets = 0x04, tNull = 0x05, tOid = 0x06, tSeq = 0x30;
const tIp = 0x40, tCounter32 = 0x41, tGauge32 = 0x42, tTicks = 0x43, tCounter64 = 0x46;
const tNoSuchObject = 0x80, tNoSuchInstance = 0x81, tEndOfMib = 0x82;
const pGet = 0xA0, pGetNext = 0xA1, pResponse = 0xA2, pGetBulk = 0xA5;

class SnmpException implements Exception {
  SnmpException(this.message);
  final String message;
  @override
  String toString() => message;
}

/// noSuchObject / noSuchInstance / endOfMibView.
class Missing {
  const Missing(this.tag);
  final int tag;
}

// ---------------------------------------------------------------- BER
List<int> _len(int n) {
  if (n < 0x80) return [n];
  final b = <int>[];
  while (n > 0) {
    b.insert(0, n & 0xFF);
    n >>= 8;
  }
  return [0x80 | b.length, ...b];
}

List<int> tlv(int tag, List<int> body) => [tag, ..._len(body.length), ...body];

List<int> encInt(int v) {
  final b = <int>[];
  var x = v;
  do {
    b.insert(0, x & 0xFF);
    x >>= 8;
  } while (!(x == 0 && b[0] < 0x80) && !(x == -1 && b[0] >= 0x80));
  return tlv(tInt, b);
}

List<int> encOid(String oid) {
  final p = oid.split('.').where((s) => s.isNotEmpty).map(int.parse).toList();
  final subs = [p[0] * 40 + p[1], ...p.skip(2)];
  final out = <int>[];
  for (final s in subs) {
    final b = <int>[s & 0x7F];
    var x = s >> 7;
    while (x > 0) {
      b.insert(0, 0x80 | (x & 0x7F));
      x >>= 7;
    }
    out.addAll(b);
  }
  return tlv(tOid, out);
}

String decOid(List<int> b) {
  final subs = <int>[];
  var v = 0;
  for (final c in b) {
    v = (v << 7) | (c & 0x7F);
    if (c & 0x80 == 0) {
      subs.add(v);
      v = 0;
    }
  }
  if (subs.isEmpty) return '';
  final first = subs[0];
  final a = first < 80 ? first ~/ 40 : 2;
  return [a, first - a * 40, ...subs.skip(1)].join('.');
}

/// (tag, body, next offset)
(int, Uint8List, int) readTlv(Uint8List buf, int off) {
  if (off + 2 > buf.length) throw SnmpException('truncated');
  final tag = buf[off];
  var n = buf[off + 1];
  var p = off + 2;
  if (n & 0x80 != 0) {
    final k = n & 0x7F;
    if (p + k > buf.length) throw SnmpException('truncated');
    n = 0;
    for (var i = 0; i < k; i++) {
      n = (n << 8) | buf[p + i];
    }
    p += k;
  }
  if (p + n > buf.length) throw SnmpException('truncated');
  return (tag, Uint8List.sublistView(buf, p, p + n), p + n);
}

Object? decValue(int tag, Uint8List b) {
  switch (tag) {
    case tInt:
      var v = 0;
      for (final c in b) {
        v = (v << 8) | c;
      }
      if (b.isNotEmpty && b[0] & 0x80 != 0) v -= 1 << (8 * b.length);
      return v;
    case tCounter32 || tGauge32 || tTicks || tCounter64:
      var v = 0;
      for (final c in b) {
        v = (v << 8) | c; // Counter64 above 2^63 wraps; harmless for display
      }
      return v;
    case tOid:
      return decOid(b);
    case tIp:
      return b.join('.');
    case tNull:
      return null;
    case tNoSuchObject || tNoSuchInstance || tEndOfMib:
      return Missing(tag);
  }
  return Uint8List.fromList(b);
}

List<int> buildMessage(int pdu, int rid, List<String> oids, String community, int version, [int a = 0, int b = 0]) {
  final vbs = <int>[for (final o in oids) ...tlv(tSeq, [...encOid(o), ...tlv(tNull, [])])];
  final body = [...encInt(rid), ...encInt(a), ...encInt(b), ...tlv(tSeq, vbs)];
  return tlv(tSeq, [...encInt(version), ...tlv(tOctets, community.codeUnits), ...tlv(pdu, body)]);
}

class SnmpReply {
  SnmpReply(this.requestId, this.errorStatus, this.varbinds);
  final int requestId;
  final int errorStatus;
  final List<(String, Object?)> varbinds;
}

SnmpReply parseMessage(Uint8List buf) {
  final (tag, msg, _) = readTlv(buf, 0);
  if (tag != tSeq) throw SnmpException('not SNMP');
  var (_, _, o) = readTlv(msg, 0);
  (_, _, o) = readTlv(msg, o);
  final (_, pdu, _) = readTlv(msg, o);
  final (_, rid, p1) = readTlv(pdu, 0);
  final (_, es, p2) = readTlv(pdu, p1);
  final (_, _, p3) = readTlv(pdu, p2);
  final (_, vbl, _) = readTlv(pdu, p3);
  final vbs = <(String, Object?)>[];
  var q = 0;
  while (q < vbl.length) {
    final (_, vb, nq) = readTlv(vbl, q);
    q = nq;
    final (_, ob, r) = readTlv(vb, 0);
    final (vt, vv, _) = readTlv(vb, r);
    vbs.add((decOid(ob), decValue(vt, vv)));
  }
  return SnmpReply(decValue(tInt, rid) as int, decValue(tInt, es) as int, vbs);
}

List<int> oidKey(String oid) => oid.split('.').where((s) => s.isNotEmpty).map(int.parse).toList();

int cmpOid(String a, String b) {
  final x = oidKey(a), y = oidKey(b);
  for (var i = 0; i < min(x.length, y.length); i++) {
    if (x[i] != y[i]) return x[i].compareTo(y[i]);
  }
  return x.length.compareTo(y.length);
}

bool inSubtree(String oid, String root) {
  final k = oidKey(oid), r = oidKey(root);
  if (k.length < r.length) return false;
  for (var i = 0; i < r.length; i++) {
    if (k[i] != r[i]) return false;
  }
  return true;
}

// ---------------------------------------------------------------- client
class Snmp {
  Snmp(this.host, {this.community = 'public', String version = '2c', this.port = 161, this.timeout = const Duration(seconds: 2)})
      : version = version == '1' ? 0 : 1;
  final String host;
  final String community;
  final int version;
  final int port;
  final Duration timeout;
  final _rnd = Random();

  Future<List<(String, Object?)>> _request(int pdu, List<String> oids, [int a = 0, int b = 0]) async {
    final addr = (await InternetAddress.lookup(host)).first;
    final rid = _rnd.nextInt(0x7FFFFFFF);
    final pkt = buildMessage(pdu, rid, oids, community, version, a, b);
    final sock = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
    try {
      for (var attempt = 0; attempt < 2; attempt++) {
        sock.send(pkt, addr, port);
        final c = Completer<SnmpReply?>();
        final sub = sock.listen((e) {
          if (e != RawSocketEvent.read) return;
          final d = sock.receive();
          if (d == null) return;
          try {
            final r = parseMessage(d.data);
            if (r.requestId == rid && !c.isCompleted) c.complete(r);
          } catch (_) {}
        });
        final r = await c.future.timeout(timeout, onTimeout: () => null);
        await sub.cancel();
        if (r == null) continue;
        if (r.errorStatus == 2) return []; // v1 noSuchName
        if (r.errorStatus != 0) throw SnmpException('error ${r.errorStatus}');
        return r.varbinds;
      }
    } finally {
      sock.close();
    }
    throw SnmpException('no answer (SNMP off, wrong community, or this phone is not allowed)');
  }

  Future<Map<String, Object?>> get(List<String> oids) async {
    final vbs = await _request(pGet, oids);
    return {for (final (o, v) in vbs) if (v is! Missing) o: v};
  }

  Future<List<(String, Object?)>> walk(String root, {int limit = 5000}) async {
    final out = <(String, Object?)>[];
    var cur = root;
    while (out.length < limit) {
      final vbs = version == 1 ? await _request(pGetBulk, [cur], 0, 25) : await _request(pGetNext, [cur]);
      if (vbs.isEmpty) break;
      for (final (o, v) in vbs) {
        if (v is Missing || !inSubtree(o, root) || cmpOid(o, cur) <= 0) return out;
        out.add((o, v));
        cur = o;
      }
    }
    return out;
  }

  /// {index after root: value}
  Future<Map<String, Object?>> table(String root) async {
    final n = root.length + 1;
    return {for (final (o, v) in await walk(root)) o.substring(n): v};
  }
}

// ---------------------------------------------------------------- standard MIBs
const _sys = {
  'descr': '1.3.6.1.2.1.1.1.0', 'objectId': '1.3.6.1.2.1.1.2.0', 'uptime': '1.3.6.1.2.1.1.3.0',
  'name': '1.3.6.1.2.1.1.5.0', 'location': '1.3.6.1.2.1.1.6.0',
};
const _if = '1.3.6.1.2.1.2.2.1.';
const _ifx = '1.3.6.1.2.1.31.1.1.1.';
const _lldpRem = '1.0.8802.1.1.2.1.4.1.1.';
const _lldpLoc = '1.0.8802.1.1.2.1.3.7.1.';

const vendors = {
  9: 'Cisco', 11: 'HP', 171: 'D-Link', 674: 'Dell', 2011: 'Huawei', 2636: 'Juniper', 4526: 'Netgear',
  11863: 'TP-Link', 14988: 'MikroTik', 14823: 'Aruba', 25506: 'H3C', 41112: 'Ubiquiti', 12356: 'Fortinet',
  890: 'Zyxel', 30065: 'Arista', 8072: 'Linux (net-snmp)', 207: 'Allied Telesis', 3902: 'ZTE', 4881: 'Ruijie',
  25053: 'Ruckus', 10002: 'Ubiquiti', 6486: 'Alcatel-Lucent', 1916: 'Extreme',
};

String text(Object? v) {
  if (v is Uint8List) {
    final b = v.toList();
    while (b.isNotEmpty && b.last == 0) {
      b.removeLast();
    }
    if (b.isNotEmpty && b.every((c) => c >= 32 && c < 127 || c == 9 || c == 10 || c == 13)) {
      return String.fromCharCodes(b).trim();
    }
    return v.map((c) => c.toRadixString(16).padLeft(2, '0').toUpperCase()).join(':');
  }
  return v?.toString() ?? '';
}

String vendorOf(Object? objectId) {
  final p = (objectId?.toString() ?? '').split('.');
  if (p.length > 6 && p.take(6).join('.') == '1.3.6.1.4.1') return vendors[int.tryParse(p[6])] ?? '';
  return '';
}

String uptimeText(Object? ticks) {
  var s = ((ticks as int?) ?? 0) ~/ 100;
  final d = s ~/ 86400;
  s %= 86400;
  return '${d > 0 ? '$d d ' : ''}${s ~/ 3600} h ${(s % 3600) ~/ 60} min';
}

String speedText(int mbps) => mbps <= 0
    ? ''
    : mbps >= 1000
        ? '${(mbps / 1000).toStringAsFixed(mbps % 1000 == 0 ? 0 : 1)} Gbps'
        : '$mbps Mbps';

class SwitchPort {
  SwitchPort(this.index, this.name, this.alias, this.up, this.speedMbps, this.inErrors, this.outErrors, this.type);
  final int index;
  final String name;
  final String alias;
  final bool up;
  final int speedMbps;
  final int inErrors;
  final int outErrors;
  final int type;
  List<String> get warnings => [
        if (up && type == 6 && (speedMbps == 10 || speedMbps == 100))
          'runs at $speedMbps Mbps - check the cable or the device\'s network card',
        if (inErrors + outErrors > 0) 'errors in/out $inErrors / $outErrors - bad cable, connector or duplex mismatch',
      ];
}

class SwitchInfo {
  SwitchInfo(this.name, this.descr, this.vendor, this.uptime, this.location, this.ports, this.neighbors);
  final String name, descr, vendor, uptime, location;
  final List<SwitchPort> ports;
  final List<(String, String)> neighbors; // (local port, neighbour name / port)
}

Future<SwitchInfo> readSwitch(String host, {String community = 'public', String version = '2c'}) async {
  final c = Snmp(host, community: community, version: version);
  final s = await c.get(_sys.values.toList());
  String v(String k) => text(s[_sys[k]]);
  if (s.isEmpty) throw SnmpException('no answer (SNMP off, wrong community, or this phone is not allowed)');
  final descr = await c.table('${_if}2'), type = await c.table('${_if}3'), speed = await c.table('${_if}5');
  final oper = await c.table('${_if}8'), inErr = await c.table('${_if}14'), outErr = await c.table('${_if}20');
  Map<String, Object?> name = {}, high = {}, alias = {};
  try {
    name = await c.table('${_ifx}1');
    high = await c.table('${_ifx}15');
    alias = await c.table('${_ifx}18');
  } on SnmpException {
    // old devices without IF-MIB ifXTable
  }
  final ports = <SwitchPort>[];
  for (final idx in descr.keys) {
    final t = (type[idx] as int?) ?? 0;
    if (t == 24) continue; // loopback
    final hi = (high[idx] as int?) ?? 0;
    final sp = (speed[idx] as int?) ?? 0;
    ports.add(SwitchPort(int.tryParse(idx) ?? 0, text(name[idx]).isNotEmpty ? text(name[idx]) : text(descr[idx]),
        text(alias[idx]), oper[idx] == 1, hi > 0 ? hi : sp ~/ 1000000, (inErr[idx] as int?) ?? 0,
        (outErr[idx] as int?) ?? 0, t));
  }
  ports.sort((a, b) => a.index.compareTo(b.index));
  final nb = <(String, String)>[];
  try {
    final rname = await c.table('${_lldpRem}9'), rport = await c.table('${_lldpRem}7');
    final loc = await c.table('${_lldpLoc}4');
    for (final idx in rname.keys) {
      final p = idx.split('.');
      final lp = p.length >= 3 ? p[1] : '';
      nb.add((text(loc[lp]).isNotEmpty ? text(loc[lp]) : lp, '${text(rname[idx])}  ${text(rport[idx])}'.trim()));
    }
  } on SnmpException {
    // no LLDP
  }
  return SwitchInfo(v('name'), v('descr'), vendorOf(s[_sys['objectId']]), uptimeText(s[_sys['uptime']]),
      v('location'), ports, nb);
}
