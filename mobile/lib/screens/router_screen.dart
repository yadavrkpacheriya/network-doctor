import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../net/routeros.dart';

/// Direct MikroTik login from the phone over the office Wi-Fi (no PC, no Tailscale). Shows the router's DHCP
/// leases and ARP table - which is how the phone gets IP <-> MAC, something Android cannot read on its own -
/// and runs a router command.
class RouterScreen extends StatefulWidget {
  const RouterScreen({super.key});
  @override
  State<RouterScreen> createState() => _RouterScreenState();
}

class _RouterScreenState extends State<RouterScreen> {
  final _host = TextEditingController();
  final _user = TextEditingController();
  final _pass = TextEditingController();
  final _cmd = TextEditingController(text: '/ip/arp/print');
  bool _ssl = false;
  bool _busy = false;
  String _status = '';
  String _info = '';
  List<Map<String, String>> _rows = [];
  String _cmdOut = '';

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final p = await SharedPreferences.getInstance();
    setState(() {
      _host.text = p.getString('ros_host') ?? '192.168.0.1';
      _user.text = p.getString('ros_user') ?? '';
      _ssl = p.getBool('ros_ssl') ?? false;
    });
  }

  Future<void> _save() async {
    final p = await SharedPreferences.getInstance();
    await p.setString('ros_host', _host.text.trim());
    await p.setString('ros_user', _user.text.trim());
    await p.setBool('ros_ssl', _ssl);
  }

  Future<RouterOs> _open() async {
    final r = RouterOs(_host.text.trim(), _user.text.trim(), _pass.text, ssl: _ssl);
    await r.connect();
    return r;
  }

  Future<void> _connect() async {
    setState(() {
      _busy = true;
      _status = 'Connecting...';
      _info = '';
    });
    await _save();
    try {
      final r = await _open();
      final (name, ver) = await r.identity();
      final res = await r.cmd('/system/resource/print');
      final up = res.isNotEmpty ? res[0]['uptime'] ?? '' : '';
      await r.close();
      setState(() {
        _status = 'Connected';
        _info = "$name  -  RouterOS $ver" + (up.isNotEmpty ? '  -  up $up' : '');
      });
    } on RosError catch (e) {
      setState(() => _status = e.message);
    } catch (e) {
      setState(() => _status = '$e');
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _show(String path, String title) async {
    setState(() {
      _busy = true;
      _status = 'Reading $title...';
      _rows = [];
    });
    try {
      final r = await _open();
      final rows = await r.cmd(path);
      await r.close();
      setState(() {
        _rows = rows;
        _status = '${rows.length} $title';
      });
    } on RosError catch (e) {
      setState(() => _status = e.message);
    } catch (e) {
      setState(() => _status = '$e');
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _run() async {
    final line = _cmd.text.trim();
    if (line.isEmpty) return;
    setState(() {
      _busy = true;
      _status = 'Running...';
      _cmdOut = '';
    });
    try {
      final r = await _open();
      final rows = await r.cmd(line.split(RegExp(r'\s+')).first,
          params: _paramsFrom(line));
      await r.close();
      setState(() {
        _cmdOut = rows.isEmpty
            ? '(no rows returned)'
            : rows.map((m) => m.entries.map((e) => '${e.key}=${e.value}').join('  ')).join('\n\n');
        _status = '${rows.length} row(s)';
      });
    } on RosError catch (e) {
      setState(() => _status = e.message);
    } catch (e) {
      setState(() => _status = '$e');
    } finally {
      setState(() => _busy = false);
    }
  }

  // "path k=v k2=v2" -> {k:v,...}
  Map<String, String>? _paramsFrom(String line) {
    final parts = line.split(RegExp(r'\s+'));
    if (parts.length < 2) return null;
    final m = <String, String>{};
    for (final p in parts.skip(1)) {
      final i = p.indexOf('=');
      if (i > 0) m[p.substring(0, i)] = p.substring(i + 1);
    }
    return m.isEmpty ? null : m;
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(title: const Text('Router (MikroTik)')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        Text('Log in to your MikroTik directly over Wi-Fi - no PC needed. Turn the API on in the router: '
            'IP > Services > api (port 8728).', style: TextStyle(color: cs.onSurfaceVariant)),
        const SizedBox(height: 12),
        TextField(controller: _host, decoration: const InputDecoration(labelText: 'Router IP', isDense: true)),
        const SizedBox(height: 8),
        TextField(controller: _user, decoration: const InputDecoration(labelText: 'User', isDense: true)),
        const SizedBox(height: 8),
        TextField(
            controller: _pass,
            obscureText: true,
            decoration: const InputDecoration(labelText: 'Password', isDense: true)),
        Row(children: [
          Checkbox(value: _ssl, onChanged: (v) => setState(() => _ssl = v ?? false)),
          const Text('API-SSL (8729)'),
          const Spacer(),
          FilledButton.icon(
              onPressed: _busy ? null : _connect, icon: const Icon(Icons.login), label: const Text('Connect')),
        ]),
        if (_info.isNotEmpty)
          Card(
            color: cs.primaryContainer,
            child: ListTile(leading: const Icon(Icons.router), title: Text(_info)),
          ),
        if (_status.isNotEmpty) Padding(padding: const EdgeInsets.symmetric(vertical: 8), child: Text(_status)),
        const Divider(),
        Wrap(spacing: 8, children: [
          OutlinedButton.icon(
              onPressed: _busy ? null : () => _show('/ip/arp/print', 'ARP entries (IP - MAC)'),
              icon: const Icon(Icons.lan),
              label: const Text('ARP (IP - MAC)')),
          OutlinedButton.icon(
              onPressed: _busy ? null : () => _show('/ip/dhcp-server/lease/print', 'DHCP leases'),
              icon: const Icon(Icons.dns),
              label: const Text('DHCP leases')),
        ]),
        for (final m in _rows)
          Card(
            margin: const EdgeInsets.symmetric(vertical: 3),
            child: ListTile(
              dense: true,
              title: Text(m['address'] ?? m['mac-address'] ?? m['host-name'] ?? '?'),
              subtitle: Text([
                if (m['mac-address'] != null) 'MAC ${m['mac-address']}',
                if (m['host-name'] != null && (m['host-name'] ?? '').isNotEmpty) m['host-name']!,
                if (m['interface'] != null) 'on ${m['interface']}',
                if (m['status'] != null) m['status']!,
              ].join('  ·  ')),
            ),
          ),
        const Divider(),
        TextField(
            controller: _cmd,
            decoration: const InputDecoration(
                labelText: 'Run a command (e.g. /system/resource/print)', isDense: true, border: OutlineInputBorder())),
        const SizedBox(height: 8),
        Align(
            alignment: Alignment.centerRight,
            child: FilledButton.icon(
                onPressed: _busy ? null : _run, icon: const Icon(Icons.play_arrow), label: const Text('Run'))),
        if (_cmdOut.isNotEmpty)
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: SelectableText(_cmdOut, style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
            ),
          ),
      ]),
    );
  }

  @override
  void dispose() {
    _host.dispose();
    _user.dispose();
    _pass.dispose();
    _cmd.dispose();
    super.dispose();
  }
}
