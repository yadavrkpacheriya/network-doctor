import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:url_launcher/url_launcher.dart';

import '../net/model.dart';
import 'device_screen.dart';

IconData catIcon(String c) {
  switch (c) {
    case Cat.router:
      return Icons.router;
    case Cat.net:
      return Icons.device_hub;
    case Cat.pc:
      return Icons.computer;
    case Cat.cam:
      return Icons.videocam;
    case Cat.prn:
      return Icons.print;
    case Cat.bio:
      return Icons.fingerprint;
    case Cat.phone:
      return Icons.smartphone;
    case Cat.iot:
      return Icons.tv;
    case Cat.offline:
      return Icons.history;
    default:
      return Icons.help_outline;
  }
}

String fmtRate(double? bps) {
  if (bps == null) return '';
  final bits = bps * 8;
  if (bits >= 1e6) return '${(bits / 1e6).toStringAsFixed(1)} Mbps';
  if (bits >= 1e3) return '${(bits / 1e3).toStringAsFixed(0)} kbps';
  return '${bits.toStringAsFixed(0)} bps';
}

String fmtBytes(num? n) {
  var v = (n ?? 0).toDouble();
  for (final u in ['B', 'KB', 'MB', 'GB']) {
    if (v < 1024 || u == 'GB') return u == 'B' ? '${v.toStringAsFixed(0)} $u' : '${v.toStringAsFixed(1)} $u';
    v /= 1024;
  }
  return '';
}

String hhmm(num t) {
  final d = DateTime.fromMillisecondsSinceEpoch((t * 1000).round());
  String two(int x) => x.toString().padLeft(2, '0');
  return '${two(d.hour)}:${two(d.minute)}:${two(d.second)}';
}

Color sevColor(BuildContext context, String sev) {
  switch (sev) {
    case 'critical':
      return Colors.red.shade700;
    case 'warning':
      return Colors.orange.shade800;
    case 'info':
      return Colors.blue.shade700;
    default:
      return Theme.of(context).colorScheme.outline;
  }
}

Future<void> openInBrowser(BuildContext context, Device d) async {
  final uri = d.browserUri();
  final ok = await launchUrl(uri, mode: LaunchMode.externalApplication);
  if (!ok && context.mounted) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Could not open $uri')));
  }
}

void copyText(BuildContext context, String text) {
  Clipboard.setData(ClipboardData(text: text));
  ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Copied $text'), duration: const Duration(seconds: 1)));
}

/// Devices grouped by category, with search.
class DeviceList extends StatelessWidget {
  const DeviceList({super.key, required this.devices, this.query = '', this.header, this.showEmpty = true});
  final List<Device> devices;
  final bool showEmpty;
  final String query;
  final Widget? header;

  @override
  Widget build(BuildContext context) {
    final q = query.toLowerCase().trim();
    final shown = devices.where((d) {
      if (q.isEmpty) return true;
      return '${d.name} ${d.ip} ${d.mac} ${d.vendor} ${d.category} ${d.services.join(' ')}'.toLowerCase().contains(q);
    }).toList();
    final groups = <String, List<Device>>{};
    for (final d in shown) {
      groups.putIfAbsent(d.category, () => []).add(d);
    }
    final cats = Cat.order.where(groups.containsKey).toList();
    return ListView(
      physics: const AlwaysScrollableScrollPhysics(),
      padding: const EdgeInsets.only(bottom: 96),
      children: [
        if (header != null) header!,
        if (shown.isEmpty && showEmpty)
          const Padding(padding: EdgeInsets.all(32), child: Center(child: Text('No devices to show.'))),
        for (final c in cats) ...[
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
            child: Row(children: [
              Icon(catIcon(c), size: 18, color: Theme.of(context).colorScheme.primary),
              const SizedBox(width: 8),
              Text('$c  (${groups[c]!.length})', style: Theme.of(context).textTheme.titleSmall),
            ]),
          ),
          for (final d in groups[c]!) DeviceTile(device: d),
        ],
      ],
    );
  }
}

class DeviceTile extends StatelessWidget {
  const DeviceTile({super.key, required this.device});
  final Device device;

  @override
  Widget build(BuildContext context) {
    final d = device;
    final sub = <String>[
      d.ip,
      if (d.ipType.isNotEmpty) d.ipType,
      if (d.vendor.isNotEmpty) d.vendor,
      if (d.downBps != null) '↓ ${fmtRate(d.downBps)}  ↑ ${fmtRate(d.upBps)}',
      if (!d.fromPc && d.services.isNotEmpty) d.services.take(3).join(', '),
    ];
    return ListTile(
      dense: true,
      enabled: d.online,
      leading: CircleAvatar(
        radius: 16,
        backgroundColor: d.online ? Theme.of(context).colorScheme.primaryContainer : Theme.of(context).disabledColor,
        child: Icon(catIcon(d.category), size: 18),
      ),
      title: Text(d.displayName, maxLines: 1, overflow: TextOverflow.ellipsis),
      subtitle: Text(sub.join('  ·  '), maxLines: 2, overflow: TextOverflow.ellipsis),
      trailing: d.safetyNotes.isNotEmpty ? Icon(Icons.warning_amber, color: Colors.orange.shade800) : null,
      onTap: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => DeviceScreen(device: d))),
    );
  }
}

/// A small live line chart (used for ping and the PC monitor graph).
class LineChart extends StatelessWidget {
  const LineChart({super.key, required this.series, this.height = 140, this.markers = const []});
  final List<ChartSeries> series;
  final double height;
  final List<double> markers; // x positions 0..1 drawn as red lines (e.g. port down)

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      height: height,
      child: CustomPaint(
        painter: _ChartPainter(series, markers, Theme.of(context).colorScheme.outlineVariant),
        child: const SizedBox.expand(),
      ),
    );
  }
}

class ChartSeries {
  ChartSeries(this.label, this.values, this.color);
  final String label;
  final List<double?> values; // null = gap (e.g. lost ping)
  final Color color;
}

class _ChartPainter extends CustomPainter {
  _ChartPainter(this.series, this.markers, this.grid);
  final List<ChartSeries> series;
  final List<double> markers;
  final Color grid;

  @override
  void paint(Canvas canvas, Size size) {
    final g = Paint()
      ..color = grid
      ..strokeWidth = 1;
    canvas.drawLine(Offset(0, size.height - 1), Offset(size.width, size.height - 1), g);
    for (final m in markers) {
      final x = m.clamp(0.0, 1.0).toDouble() * size.width;
      canvas.drawLine(Offset(x, 0), Offset(x, size.height), Paint()
        ..color = Colors.red
        ..strokeWidth = 2);
    }
    var ty = 2.0;
    for (final s in series) {
      final vals = s.values;
      if (vals.isEmpty) continue;
      final present = vals.whereType<double>().toList();
      final double mx = present.isEmpty ? 1.0 : present.reduce((a, b) => a > b ? a : b).clamp(1.0, double.infinity).toDouble();
      final p = Paint()
        ..color = s.color
        ..strokeWidth = 2
        ..style = PaintingStyle.stroke;
      final path = Path();
      var started = false;
      for (var i = 0; i < vals.length; i++) {
        final x = vals.length == 1 ? size.width : i * size.width / (vals.length - 1);
        final v = vals[i];
        if (v == null) {
          canvas.drawLine(Offset(x, size.height - 8), Offset(x, size.height), Paint()..color = Colors.red);
          started = false;
          continue;
        }
        final y = size.height - 4 - (size.height - 18) * v / mx;
        if (!started) {
          path.moveTo(x, y);
          started = true;
        } else {
          path.lineTo(x, y);
        }
      }
      canvas.drawPath(path, p);
      final tp = TextPainter(
        text: TextSpan(text: '${s.label} (max ${mx.toStringAsFixed(0)})', style: TextStyle(color: s.color, fontSize: 11)),
        textDirection: TextDirection.ltr,
      )..layout();
      tp.paint(canvas, Offset(4, ty));
      ty += 14;
    }
  }

  @override
  bool shouldRepaint(covariant _ChartPainter old) => true;
}

/// Calls [tick] every [every] while the widget is on screen.
class Ticker {
  Ticker(this.every, this.tick);
  final Duration every;
  final FutureOr<void> Function() tick;
  Timer? _t;
  void start() {
    _t?.cancel();
    _t = Timer.periodic(every, (_) => tick());
  }

  void stop() => _t?.cancel();
}
