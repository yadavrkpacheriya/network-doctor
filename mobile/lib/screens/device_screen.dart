import 'dart:async';

import 'package:flutter/material.dart';

import '../net/model.dart';
import '../net/probe.dart';
import 'common.dart';

/// One device: details, ping with live graph, open in browser.
class DeviceScreen extends StatelessWidget {
  const DeviceScreen({super.key, required this.device});
  final Device device;

  @override
  Widget build(BuildContext context) {
    final d = device;
    final t = Theme.of(context).textTheme;
    Widget row(String k, String v) => v.isEmpty
        ? const SizedBox.shrink()
        : Padding(
            padding: const EdgeInsets.symmetric(vertical: 3),
            child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
              SizedBox(width: 120, child: Text(k, style: t.bodySmall)),
              Expanded(child: SelectableText(v)),
            ]),
          );
    return Scaffold(
      appBar: AppBar(title: Text(d.displayName)),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        Row(children: [
          Icon(catIcon(d.category), size: 36, color: Theme.of(context).colorScheme.primary),
          const SizedBox(width: 12),
          Expanded(
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(d.category, style: t.titleMedium),
              if (d.reason.isNotEmpty) Text(d.reason, style: t.bodySmall),
            ]),
          ),
        ]),
        const SizedBox(height: 16),
        Wrap(spacing: 8, runSpacing: 8, children: [
          FilledButton.icon(
            onPressed: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => PingScreen(device: d))),
            icon: const Icon(Icons.network_ping),
            label: const Text('Ping'),
          ),
          FilledButton.tonalIcon(
            onPressed: () => openInBrowser(context, d),
            icon: const Icon(Icons.open_in_browser),
            label: Text(d.webPort == null ? 'Open in browser' : 'Open in browser (${d.webPort})'),
          ),
          OutlinedButton.icon(onPressed: () => copyText(context, d.ip), icon: const Icon(Icons.copy), label: const Text('Copy IP')),
        ]),
        const SizedBox(height: 16),
        row('IP address', d.allIps.length > 1 ? d.allIps.join(', ') : d.ip),
        row('Status', d.status),
        if (d.ipType.isNotEmpty) row('IP type', '${d.ipType}  (${d.ipTypeWhy})'),
        row('MAC address', d.mac),
        row('Vendor', d.vendor),
        row('Computer name', d.netbios),
        row('DNS name', d.dns),
        row('UPnP', [d.upnpName, d.upnpMaker, d.upnpModel].where((x) => x.isNotEmpty).join(' · ')),
        row('Services', d.services.join(', ')),
        if (d.downBps != null) row('Bandwidth now', '↓ ${fmtRate(d.downBps)}   ↑ ${fmtRate(d.upBps)}'),
        if (d.rttMs != null) row('Reply time', '${d.rttMs} ms (during scan)'),
        row('Notes', d.notes.join('; ')),
        if (d.safetyNotes.isNotEmpty) ...[
          const SizedBox(height: 12),
          Text('Safety', style: t.titleSmall),
          for (final n in d.safetyNotes)
            ListTile(
              dense: true,
              contentPadding: EdgeInsets.zero,
              leading: Icon(Icons.warning_amber, color: Colors.orange.shade800),
              title: Text(n),
            ),
        ],
        if (d.fromPc) ...[
          const SizedBox(height: 12),
          Text('Bandwidth, apps and dangerous-site details for this device are shown in the PC app '
              '(Devices > Analyse).', style: t.bodySmall),
        ],
      ]),
    );
  }
}

/// Live "ping" using TCP replies (works on every phone without special permissions).
class PingScreen extends StatefulWidget {
  const PingScreen({super.key, required this.device});
  final Device device;

  @override
  State<PingScreen> createState() => _PingScreenState();
}

class _PingScreenState extends State<PingScreen> {
  final List<double?> _res = [];
  Timer? _timer;
  bool _busy = false;

  List<int> get _ports {
    final open = widget.device.ports.toList()..sort();
    return [...open.take(2), 80, 443, 22, 445, 53, 7].toSet().toList();
  }

  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(const Duration(seconds: 1), (_) => _once());
    _once();
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _once() async {
    if (_busy) return;
    _busy = true;
    final ms = await tcpPing(widget.device.ip, _ports, timeout: const Duration(milliseconds: 1500));
    _busy = false;
    if (!mounted) return;
    setState(() {
      _res.add(ms?.toDouble());
      if (_res.length > 120) _res.removeAt(0);
    });
  }

  @override
  Widget build(BuildContext context) {
    final ok = _res.whereType<double>().toList();
    final n = _res.length;
    final lost = n - ok.length;
    double jitter = 0;
    for (var i = 1; i < ok.length; i++) {
      jitter += (ok[i] - ok[i - 1]).abs();
    }
    if (ok.length > 1) jitter /= ok.length - 1;
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: Text('Ping ${widget.device.displayName}')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(widget.device.ip, style: t.titleMedium),
          const SizedBox(height: 8),
          Text('Sent $n   Lost $lost (${n == 0 ? 0 : (100 * lost / n).toStringAsFixed(0)}%)', style: t.titleSmall),
          if (ok.isNotEmpty)
            Text('min ${ok.reduce((a, b) => a < b ? a : b).toStringAsFixed(0)} / '
                'avg ${(ok.reduce((a, b) => a + b) / ok.length).toStringAsFixed(1)} / '
                'max ${ok.reduce((a, b) => a > b ? a : b).toStringAsFixed(0)} ms   jitter ${jitter.toStringAsFixed(1)} ms')
          else if (n > 2)
            const Text('No replies - the device is off, asleep, or blocks everything.'),
          const SizedBox(height: 12),
          LineChart(height: 220, series: [ChartSeries('reply ms', _res, Colors.blue)]),
          const SizedBox(height: 8),
          Text('Red marks = no reply. Phones cannot send classic ICMP ping, so this measures how fast the device '
              'answers a network connection - the result is comparable to ping.', style: t.bodySmall),
          const Spacer(),
          FilledButton.tonalIcon(
            onPressed: () => openInBrowser(context, widget.device),
            icon: const Icon(Icons.open_in_browser),
            label: const Text('Open in browser'),
          ),
        ]),
      ),
    );
  }
}
