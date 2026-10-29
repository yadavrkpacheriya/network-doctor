import 'dart:io';

import 'package:flutter/material.dart';
import 'package:network_info_plus/network_info_plus.dart';

import '../net/model.dart';
import '../net/probe.dart';
import '../net/scanner.dart';
import 'common.dart';

/// "This network": the phone scans the Wi-Fi it is connected to, on its own.
class ScanScreen extends StatefulWidget {
  const ScanScreen({super.key});

  @override
  State<ScanScreen> createState() => _ScanScreenState();
}

class _ScanScreenState extends State<ScanScreen> with AutomaticKeepAliveClientMixin {
  String? _ip, _gw, _mask;
  String _error = '';
  Scanner? _scanner;
  double _pct = 0;
  String _progress = '';
  ScanResult? _result;
  String _query = '';
  final List<double?> _gwPing = [];
  late final Ticker _gwTicker = Ticker(const Duration(seconds: 2), _pingGateway);

  @override
  bool get wantKeepAlive => true;

  @override
  void initState() {
    super.initState();
    _readWifi();
  }

  @override
  void dispose() {
    _gwTicker.stop();
    _scanner?.cancel();
    super.dispose();
  }

  Future<void> _readWifi() async {
    final info = NetworkInfo();
    String? ip, gw, mask;
    try {
      ip = await info.getWifiIP();
      gw = await info.getWifiGatewayIP();
      mask = await info.getWifiSubmask();
    } catch (_) {}
    if (ip == null || ip.isEmpty) {
      try {
        for (final ni in await NetworkInterface.list(type: InternetAddressType.IPv4)) {
          for (final a in ni.addresses) {
            if (a.address.startsWith('192.168.') || a.address.startsWith('10.') || a.address.startsWith('172.')) {
              ip ??= a.address;
            }
          }
        }
      } catch (_) {}
    }
    if (gw == null || gw.isEmpty || gw == '0.0.0.0') {
      gw = ip == null ? null : '${ip.substring(0, ip.lastIndexOf('.'))}.1';
    }
    setState(() {
      _ip = ip;
      _gw = gw;
      _mask = mask;
      _error = ip == null ? 'Not connected to Wi-Fi. Connect to the office Wi-Fi and pull down to retry.' : '';
    });
    if (ip != null) _gwTicker.start();
  }

  Future<void> _pingGateway() async {
    final gw = _gw;
    if (gw == null || !mounted) return;
    final ms = await tcpPing(gw, const [80, 443, 53, 8291, 22], timeout: const Duration(milliseconds: 1200));
    if (!mounted) return;
    setState(() {
      _gwPing.add(ms?.toDouble());
      if (_gwPing.length > 60) _gwPing.removeAt(0);
    });
  }

  Future<void> _scan() async {
    final ip = _ip;
    if (ip == null) return _readWifi();
    final s = Scanner();
    setState(() {
      _scanner = s;
      _pct = 0;
      _progress = 'Starting...';
    });
    try {
      final r = await s.run(
        myIp: ip,
        gateway: _gw,
        prefix: maskToPrefix(_mask),
        onProgress: (p, t) {
          if (mounted) {
            setState(() {
              _pct = p;
              _progress = t;
            });
          }
        },
      );
      if (mounted) setState(() => _result = r);
    } on ScanCancelled {
      // stopped by the user
    } catch (e) {
      if (mounted) setState(() => _error = 'Scan failed: $e');
    } finally {
      if (mounted) setState(() => _scanner = null);
    }
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final r = _result;
    final scanning = _scanner != null;
    final ok = _gwPing.whereType<double>().toList();
    final loss = _gwPing.isEmpty ? 0 : 100 * (_gwPing.length - ok.length) / _gwPing.length;
    final header = Column(children: [
      Card(
        margin: const EdgeInsets.fromLTRB(12, 8, 12, 4),
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              const Icon(Icons.wifi),
              const SizedBox(width: 8),
              Expanded(child: Text(_ip == null ? 'Wi-Fi: not connected' : 'This phone $_ip   ·   router $_gw')),
            ]),
            if (_gwPing.isNotEmpty) ...[
              const SizedBox(height: 6),
              Text(ok.isEmpty
                  ? 'Router not answering'
                  : 'Router: ${ok.last.toStringAsFixed(0)} ms now, avg ${(ok.reduce((a, b) => a + b) / ok.length).toStringAsFixed(0)} ms, '
                      'lost ${loss.toStringAsFixed(0)}%'),
              LineChart(height: 60, series: [ChartSeries('router ms', _gwPing, Colors.orange)]),
            ],
            if (_error.isNotEmpty) Padding(
              padding: const EdgeInsets.only(top: 6),
              child: Text(_error, style: TextStyle(color: Colors.red.shade700)),
            ),
          ]),
        ),
      ),
      if (scanning)
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
          child: Column(children: [LinearProgressIndicator(value: _pct), const SizedBox(height: 4), Text(_progress)]),
        ),
      if (r != null && !scanning)
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 6, 16, 0),
          child: Text('${r.devices.length} devices on ${r.network}  ·  scan took ${r.seconds} s',
              style: Theme.of(context).textTheme.bodySmall),
        ),
      if (r != null)
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 6, 12, 0),
          child: TextField(
            decoration: const InputDecoration(prefixIcon: Icon(Icons.search), hintText: 'Search name, IP, service', isDense: true),
            onChanged: (v) => setState(() => _query = v),
          ),
        ),
      if (r == null && !scanning)
        Padding(
          padding: const EdgeInsets.all(24),
          child: Text(
            'Scan finds the devices on this Wi-Fi, sorts them into categories and lets you ping them or open them '
            'in the browser.\n\nPhones cannot see MAC addresses or other devices\' traffic. For the complete '
            'picture (IP conflicts, loops, bandwidth per device) pair with the Network Doctor PC app in the '
            '"Office PC" tab.',
            style: Theme.of(context).textTheme.bodyMedium,
          ),
        ),
    ]);
    return Scaffold(
      appBar: AppBar(title: const Text('This network')),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: scanning ? () => _scanner?.cancel() : _scan,
        icon: Icon(scanning ? Icons.stop : Icons.radar),
        label: Text(scanning ? 'Stop' : (r == null ? 'Scan' : 'Scan again')),
      ),
      body: RefreshIndicator(
        onRefresh: _readWifi,
        child: DeviceList(
            devices: r?.devices ?? const <Device>[], query: _query, header: header, showEmpty: r != null),
      ),
    );
  }
}
