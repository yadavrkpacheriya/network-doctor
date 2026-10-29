import 'dart:async';

import 'package:flutter/material.dart';
import 'package:network_info_plus/network_info_plus.dart';

import '../net/model.dart';
import '../net/snmp.dart' as snmp;
import '../net/tools.dart';
import 'device_screen.dart';

/// Engineer's tools: ping, port scan, switch details, DNS, speed, Wake-on-LAN, subnet calculator.
class ToolsScreen extends StatelessWidget {
  const ToolsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    Widget tool(IconData icon, String title, String sub, Widget page) => ListTile(
          leading: Icon(icon, color: Theme.of(context).colorScheme.primary),
          title: Text(title),
          subtitle: Text(sub),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => page)),
        );
    return Scaffold(
      appBar: AppBar(title: const Text('Tools')),
      body: ListView(children: [
        tool(Icons.network_ping, 'Ping', 'Reply time and loss to any device or website', const _PingTool()),
        tool(Icons.router, 'Switch / router details', 'Ports, speed, errors and neighbours over SNMP - any brand',
            const _SwitchTool()),
        tool(Icons.speed, 'Internet speed', 'Download, upload and reply time', const _SpeedTool()),
        tool(Icons.lan, 'Port scanner', 'Which services a device offers, risky ones marked', const _PortTool()),
        tool(Icons.dns, 'DNS lookup', 'Find the IP address of a name, and how fast DNS answers', const _DnsTool()),
        tool(Icons.power_settings_new, 'Wake-on-LAN', 'Switch on a PC that is off', const _WolTool()),
        tool(Icons.calculate, 'Subnet calculator', 'Network, mask, broadcast and host range', const _SubnetTool()),
      ]),
    );
  }
}

/// A page with one input, a Run button and a result area.
class _ToolPage extends StatelessWidget {
  const _ToolPage({required this.title, required this.children});
  final String title;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: Text(title)),
        body: ListView(padding: const EdgeInsets.all(16), children: children),
      );
}

Widget _field(TextEditingController c, String label, {String? hint, TextInputType? type, bool secret = false}) =>
    Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: TextField(
        controller: c,
        obscureText: secret,
        keyboardType: type,
        autocorrect: false,
        decoration: InputDecoration(labelText: label, hintText: hint, border: const OutlineInputBorder()),
      ),
    );

Future<String> _gateway() async {
  try {
    return await NetworkInfo().getWifiGatewayIP() ?? '';
  } catch (_) {
    return '';
  }
}

// ---------------------------------------------------------------- ping
class _PingTool extends StatefulWidget {
  const _PingTool();
  @override
  State<_PingTool> createState() => _PingToolState();
}

class _PingToolState extends State<_PingTool> {
  final _host = TextEditingController(text: 'google.com');

  @override
  Widget build(BuildContext context) => _ToolPage(title: 'Ping', children: [
        _field(_host, 'Device IP or website', hint: '192.168.1.1 or google.com', type: TextInputType.url),
        FilledButton.icon(
          onPressed: () {
            final h = _host.text.trim();
            if (h.isEmpty) return;
            Navigator.of(context).push(MaterialPageRoute(builder: (_) => PingScreen(device: Device(h))));
          },
          icon: const Icon(Icons.play_arrow),
          label: const Text('Start'),
        ),
      ]);
}

// ---------------------------------------------------------------- switch / router (SNMP)
class _SwitchTool extends StatefulWidget {
  const _SwitchTool();
  @override
  State<_SwitchTool> createState() => _SwitchToolState();
}

class _SwitchToolState extends State<_SwitchTool> {
  final _host = TextEditingController();
  final _comm = TextEditingController(text: 'public');
  String _ver = '2c';
  bool _busy = false;
  String _error = '';
  snmp.SwitchInfo? _info;

  @override
  void initState() {
    super.initState();
    _gateway().then((g) => mounted && _host.text.isEmpty ? setState(() => _host.text = g) : null);
  }

  Future<void> _read() async {
    setState(() {
      _busy = true;
      _error = '';
      _info = null;
    });
    try {
      final i = await snmp.readSwitch(_host.text.trim(), community: _comm.text.trim(), version: _ver);
      if (mounted) setState(() => _info = i);
    } catch (e) {
      if (mounted) setState(() => _error = 'No SNMP answer: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final i = _info;
    return _ToolPage(title: 'Switch / router details', children: [
      _field(_host, 'Switch or router IP', type: TextInputType.number),
      Row(children: [
        Expanded(child: _field(_comm, 'SNMP community')),
        const SizedBox(width: 12),
        Padding(
          padding: const EdgeInsets.only(bottom: 12),
          child: SegmentedButton<String>(
            segments: const [ButtonSegment(value: '2c', label: Text('v2c')), ButtonSegment(value: '1', label: Text('v1'))],
            selected: {_ver},
            onSelectionChanged: (s) => setState(() => _ver = s.first),
          ),
        ),
      ]),
      FilledButton.icon(
        onPressed: _busy ? null : _read,
        icon: _busy ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2)) : const Icon(Icons.search),
        label: const Text('Read'),
      ),
      const SizedBox(height: 8),
      Text('Turn on SNMP (v2c, read-only) on the switch with a community name first. This never changes anything '
          'on it. Turning ports off / on and live traffic are in the PC app.', style: t.bodySmall),
      if (_error.isNotEmpty) Padding(padding: const EdgeInsets.only(top: 12), child: Text(_error, style: TextStyle(color: Colors.red.shade700))),
      if (i != null) ...[
        const SizedBox(height: 16),
        Text([i.name, i.vendor].where((x) => x.isNotEmpty).join('  -  '), style: t.titleMedium),
        if (i.descr.isNotEmpty) Text(i.descr, style: t.bodySmall),
        Text('Up for ${i.uptime}${i.location.isNotEmpty ? '   ·   ${i.location}' : ''}'),
        const SizedBox(height: 12),
        Text('Ports (${i.ports.length}, ${i.ports.where((p) => p.up).length} up)', style: t.titleSmall),
        for (final p in i.ports)
          ListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            leading: Icon(p.up ? Icons.check_circle : Icons.circle_outlined,
                color: p.warnings.isNotEmpty ? Colors.orange.shade800 : (p.up ? Colors.green : Colors.grey)),
            title: Text('${p.name}${p.alias.isNotEmpty ? '  (${p.alias})' : ''}'),
            subtitle: Text([p.up ? 'up ${snmp.speedText(p.speedMbps)}' : 'down', ...p.warnings].join('\n')),
          ),
        if (i.neighbors.isNotEmpty) ...[
          const SizedBox(height: 12),
          Text('Neighbours (LLDP)', style: t.titleSmall),
          for (final (port, who) in i.neighbors) ListTile(dense: true, contentPadding: EdgeInsets.zero, title: Text(who), subtitle: Text('on $port')),
        ],
      ],
    ]);
  }
}

// ---------------------------------------------------------------- internet speed
class _SpeedTool extends StatefulWidget {
  const _SpeedTool();
  @override
  State<_SpeedTool> createState() => _SpeedToolState();
}

class _SpeedToolState extends State<_SpeedTool> {
  String _status = '';
  SpeedResult? _r;
  bool _busy = false;

  Future<void> _run() async {
    setState(() {
      _busy = true;
      _r = null;
    });
    final r = await speedTest(status: (s) => mounted ? setState(() => _status = s) : null);
    if (mounted) {
      setState(() {
        _busy = false;
        _r = r;
        _status = '';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final r = _r;
    Widget big(String k, String v) => Padding(
          padding: const EdgeInsets.symmetric(vertical: 6),
          child: Row(children: [SizedBox(width: 120, child: Text(k)), Text(v, style: t.headlineSmall)]),
        );
    return _ToolPage(title: 'Internet speed', children: [
      FilledButton.icon(onPressed: _busy ? null : _run, icon: const Icon(Icons.speed), label: const Text('Start test')),
      const SizedBox(height: 12),
      if (_status.isNotEmpty) Text(_status),
      if (r != null) ...[
        if (r.pingMs != null) big('Reply time', '${r.pingMs} ms'),
        if (r.downMbps != null) big('Download', '${r.downMbps!.toStringAsFixed(1)} Mbit/s'),
        if (r.upMbps != null) big('Upload', '${r.upMbps!.toStringAsFixed(1)} Mbit/s'),
        if (r.error.isNotEmpty) Text(r.error, style: TextStyle(color: Colors.red.shade700)),
        const SizedBox(height: 8),
        Text('Over Wi-Fi the result also depends on the signal. Test next to the router to check the line itself.',
            style: t.bodySmall),
      ],
    ]);
  }
}

// ---------------------------------------------------------------- port scanner
class _PortTool extends StatefulWidget {
  const _PortTool();
  @override
  State<_PortTool> createState() => _PortToolState();
}

class _PortToolState extends State<_PortTool> {
  final _host = TextEditingController();
  List<int>? _open;
  int _done = 0;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    _gateway().then((g) => mounted && _host.text.isEmpty ? setState(() => _host.text = g) : null);
  }

  Future<void> _run() async {
    setState(() {
      _busy = true;
      _open = null;
      _done = 0;
    });
    final r = await portScan(_host.text.trim(), progress: (d) => mounted ? setState(() => _done = d) : null);
    if (mounted) {
      setState(() {
        _busy = false;
        _open = r;
      });
    }
  }

  @override
  Widget build(BuildContext context) => _ToolPage(title: 'Port scanner', children: [
        _field(_host, 'Device IP or name', type: TextInputType.url),
        FilledButton.icon(onPressed: _busy ? null : _run, icon: const Icon(Icons.search), label: const Text('Scan')),
        const SizedBox(height: 12),
        if (_busy) LinearProgressIndicator(value: _done / commonPorts.length),
        if (_open != null && _open!.isEmpty) const Text('No open ports: the device is off, has a firewall, or offers no services.'),
        for (final p in _open ?? <int>[])
          ListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            leading: Icon(riskyPorts.containsKey(p) ? Icons.warning_amber : Icons.lock_open,
                color: riskyPorts.containsKey(p) ? Colors.orange.shade800 : null),
            title: Text('$p  ${portName(p)}'),
            subtitle: riskyPorts.containsKey(p) ? Text(riskyPorts[p]!) : null,
          ),
      ]);
}

// ---------------------------------------------------------------- DNS
class _DnsTool extends StatefulWidget {
  const _DnsTool();
  @override
  State<_DnsTool> createState() => _DnsToolState();
}

class _DnsToolState extends State<_DnsTool> {
  final _name = TextEditingController(text: 'google.com');
  DnsResult? _r;

  @override
  Widget build(BuildContext context) => _ToolPage(title: 'DNS lookup', children: [
        _field(_name, 'Name', type: TextInputType.url),
        FilledButton.icon(
          onPressed: () async {
            final r = await dnsLookup(_name.text);
            if (mounted) setState(() => _r = r);
          },
          icon: const Icon(Icons.search),
          label: const Text('Look up'),
        ),
        const SizedBox(height: 12),
        if (_r != null) ...[
          Text(_r!.error.isNotEmpty ? _r!.error : 'Answered in ${_r!.ms} ms'),
          for (final a in _r!.addresses) SelectableText(a, style: Theme.of(context).textTheme.titleMedium),
          if (_r!.addresses.contains('0.0.0.0'))
            const Text('0.0.0.0 means a filter (like the Network Doctor website firewall) blocks this name.'),
        ],
      ]);
}

// ---------------------------------------------------------------- Wake-on-LAN
class _WolTool extends StatefulWidget {
  const _WolTool();
  @override
  State<_WolTool> createState() => _WolToolState();
}

class _WolToolState extends State<_WolTool> {
  final _mac = TextEditingController();
  String _msg = '';

  @override
  Widget build(BuildContext context) => _ToolPage(title: 'Wake-on-LAN', children: [
        _field(_mac, 'MAC address of the PC', hint: 'AA:BB:CC:11:22:33'),
        FilledButton.icon(
          onPressed: () async {
            try {
              await wakeOnLan(_mac.text);
              setState(() => _msg = 'Sent. The PC should start within a few seconds.');
            } catch (e) {
              setState(() => _msg = '$e');
            }
          },
          icon: const Icon(Icons.power_settings_new),
          label: const Text('Wake up'),
        ),
        const SizedBox(height: 12),
        Text(_msg),
        const SizedBox(height: 8),
        Text('Wake-on-LAN must be on in the PC\'s BIOS / network card, and the phone must be on the same network.',
            style: Theme.of(context).textTheme.bodySmall),
      ]);
}

// ---------------------------------------------------------------- subnet calculator
class _SubnetTool extends StatefulWidget {
  const _SubnetTool();
  @override
  State<_SubnetTool> createState() => _SubnetToolState();
}

class _SubnetToolState extends State<_SubnetTool> {
  final _in = TextEditingController(text: '192.168.1.10/24');

  @override
  Widget build(BuildContext context) {
    final s = subnetOf(_in.text);
    Widget row(String k, String v) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 3),
        child: Row(children: [SizedBox(width: 120, child: Text(k)), SelectableText(v)]));
    return _ToolPage(title: 'Subnet calculator', children: [
      TextField(
        controller: _in,
        onChanged: (_) => setState(() {}),
        decoration: const InputDecoration(
            labelText: 'IP and prefix or mask', hintText: '10.0.0.5/22 or 10.0.0.5 255.255.252.0', border: OutlineInputBorder()),
      ),
      const SizedBox(height: 12),
      if (s == null)
        const Text('Type an IP like 192.168.1.10/24')
      else ...[
        row('Network', '${s.network}/${s.prefix}'),
        row('Mask', s.mask),
        row('Wildcard', s.wildcard),
        row('Broadcast', s.broadcast),
        row('Usable', '${s.first} - ${s.last}'),
        row('Hosts', '${s.hosts}'),
      ],
    ]);
  }
}
