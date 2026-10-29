// Device model and categorisation, shared by the phone scanner and the PC viewer.

class Cat {
  static const router = 'Router / Gateway';
  static const net = 'Network equipment';
  static const pc = 'Computers / laptops';
  static const cam = 'CCTV cameras / DVR / NVR';
  static const prn = 'Printers / scanners';
  static const bio = 'Biometric / attendance';
  static const phone = 'Phones / tablets';
  static const iot = 'Smart TV / IoT';
  static const unknown = 'Unknown devices';
  static const offline = 'Not online now';

  static const order = [router, net, pc, cam, prn, bio, phone, iot, unknown, offline];

  /// Maps the longer category names used by the PC app onto the phone's names.
  static String normalise(String c) {
    final l = c.toLowerCase();
    if (l.startsWith('router')) return router;
    if (l.startsWith('network')) return net;
    if (l.startsWith('computer')) return pc;
    if (l.startsWith('cctv')) return cam;
    if (l.startsWith('printer')) return prn;
    if (l.startsWith('biometric')) return bio;
    if (l.startsWith('phone')) return phone;
    if (l.startsWith('smart') || l.contains('iot')) return iot;
    if (l.startsWith('not online')) return offline;
    return unknown;
  }
}

const Map<int, String> portNames = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 53: 'DNS', 80: 'Web', 135: 'Windows RPC', 139: 'NetBIOS',
  443: 'Web (https)', 445: 'File sharing', 515: 'LPD print', 554: 'RTSP video', 631: 'IPP print',
  1883: 'MQTT IoT', 3389: 'Remote Desktop', 4370: 'Biometric (ZK/eSSL)', 5000: 'Web/NAS', 5900: 'VNC',
  7547: 'TR-069 router', 8000: 'Hikvision/Web', 8080: 'Web-alt', 8291: 'MikroTik WinBox',
  8443: 'Web-alt (https)', 9100: 'RAW print', 34567: 'XMeye DVR', 37777: 'Dahua DVR', 62078: 'iPhone/iPad',
};

/// One device, either found by the phone or received from the PC app.
class Device {
  Device(this.ip);

  final String ip;
  List<String> allIps = [];
  String name = '';
  String netbios = '';
  String dns = '';
  String mac = '';
  String vendor = '';
  String upnpName = '';
  String upnpModel = '';
  String upnpMaker = '';
  String upnpType = '';
  String server = '';
  final Set<int> ports = {};
  int? rttMs;
  String category = Cat.unknown;
  String reason = '';
  String status = 'Online';
  bool online = true;
  bool isGateway = false;
  bool isSelf = false;
  bool fromPc = false;
  String ipType = '';
  String ipTypeWhy = '';
  double? downBps;
  double? upBps;
  List<String> notes = [];
  int? webPortHint;

  String get displayName => name.isNotEmpty ? name : (isSelf ? 'This phone' : '-');

  List<String> get services => (ports.toList()..sort()).map((p) => portNames[p] ?? 'port $p').toList();

  /// Port to use for "Open in browser".
  int? get webPort {
    if (webPortHint != null) return webPortHint;
    for (final p in const [80, 443, 8080, 8000, 8443, 5000]) {
      if (ports.contains(p)) return p;
    }
    return null;
  }

  Uri browserUri() {
    final p = webPort ?? 80;
    final https = p == 443 || p == 8443;
    return Uri.parse('${https ? 'https' : 'http'}://$ip${(p == 80 || p == 443) ? '' : ':$p'}');
  }

  /// Simple safety notes based on what the device exposes on the LAN.
  List<String> get safetyNotes {
    final out = <String>[];
    if (ports.contains(23)) out.add('Telnet is open - old and unencrypted; often used by malware. Turn it off.');
    if (ports.contains(21)) out.add('FTP is open - passwords travel unencrypted.');
    if (ports.contains(5900)) out.add('VNC remote control is open - make sure it has a strong password.');
    if (category == Cat.cam && (ports.contains(80) || ports.contains(8000))) {
      out.add('Camera / DVR web login - make sure the default password was changed.');
    }
    return out;
  }

  factory Device.fromPc(Map<String, dynamic> j) {
    final d = Device((j['ip'] ?? '') as String);
    d.fromPc = true;
    d.name = (j['name'] ?? '') as String;
    d.allIps = ((j['ips'] as List?) ?? const []).map((e) => e.toString()).toList();
    d.mac = (j['mac'] ?? '') as String;
    d.vendor = (j['vendor'] ?? '') as String;
    d.category = Cat.normalise((j['category'] ?? '') as String);
    d.reason = (j['reason'] ?? '') as String;
    d.status = (j['status'] ?? '') as String;
    d.online = j['online'] == true;
    d.ipType = (j['ip_type'] ?? '') as String;
    d.ipTypeWhy = (j['ip_type_why'] ?? '') as String;
    for (final p in (j['ports'] as List?) ?? const []) {
      if (p is int) d.ports.add(p);
    }
    d.webPortHint = j['web_port'] is int ? j['web_port'] as int : null;
    d.notes = ((j['notes'] as List?) ?? const []).map((e) => e.toString()).toList();
    d.downBps = (j['down_bps'] as num?)?.toDouble();
    d.upBps = (j['up_bps'] as num?)?.toDouble();
    return d;
  }
}

final _camName = RegExp(r'\b(dvr|nvr|cctv|cam|ipc)\b');
final _prnName = RegExp(r'^(npi|brw|epson|hp[0-9a-f]{6})');
final _pcName = RegExp(r'^(desktop|laptop|pc|win)-');
final _phoneName = RegExp(r'(android|iphone|ipad|galaxy|redmi|oppo|vivo|realme|oneplus|poco)');

/// Same ideas as the PC app, using what a phone can see (no MAC addresses on modern phones).
(String, String) categorize(Device d, String? gateway) {
  final p = d.ports;
  final name = '${d.name} ${d.dns}'.toLowerCase();
  final up = '${d.upnpType} ${d.upnpMaker} ${d.upnpModel} ${d.upnpName} ${d.server}'.toLowerCase();
  if (d.ip == gateway) return (Cat.router, 'default gateway of this network');
  if (d.isSelf) return (Cat.phone, 'this phone');
  final camPorts = p.intersection({554, 37777, 34567});
  if (camPorts.isNotEmpty || up.contains('camera') || up.contains('nvr') || up.contains('dvr') ||
      up.contains('hikvision') || up.contains('dahua') || _camName.hasMatch(name)) {
    return (Cat.cam, camPorts.isNotEmpty ? 'video ports ${camPorts.join(', ')}' : 'camera name / UPnP');
  }
  if (p.intersection({9100, 515, 631}).isNotEmpty || up.contains('printer') || _prnName.hasMatch(name)) {
    return (Cat.prn, 'printing ports / name');
  }
  if (p.contains(4370)) return (Cat.bio, 'attendance port 4370');
  if (p.intersection({135, 139, 445, 3389}).isNotEmpty || d.netbios.isNotEmpty || _pcName.hasMatch(name)) {
    return (Cat.pc, d.netbios.isNotEmpty ? 'answers with computer name' : 'Windows services');
  }
  if (up.contains('internetgatewaydevice') || up.contains('wandevice') || p.intersection({8291, 7547}).isNotEmpty ||
      up.contains('router') || up.contains('tp-link') || up.contains('tenda') || up.contains('mikrotik')) {
    return (Cat.net, 'router / access point');
  }
  if (p.contains(62078) || _phoneName.hasMatch(name)) return (Cat.phone, 'phone name / Apple port');
  if (p.contains(1883) || up.contains('mediarenderer') || up.contains(' tv') || up.contains('dial')) {
    return (Cat.iot, 'smart TV / IoT (UPnP)');
  }
  if (p.isNotEmpty) return (Cat.unknown, 'has ${d.services.join(', ')} but no other clues');
  return (Cat.unknown, 'answers, but shares no details');
}
