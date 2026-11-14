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
    if (!mounted) return;
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

  void _set(VoidCallback fn) {
    if (mounted) setState(fn);
  }

  /// Open the router, run [body], and ALWAYS close the socket and clear the busy flag - even on an error or if
  /// the user leaves the screen. Every setState is guarded so it never fires after the widget is disposed.
  Future<void> _task(String busy, Future<void> Function(RouterOs r) body) async {
    _set(() {
      _busy = true;
      _status = busy;
    });
    RouterOs? r;
    try {
      r = await _open();
      await body(r);
    } on RosError catch (e) {
      _set(() => _status = e.message);
    } catch (e) {
      _set(() => _status = '$e');
    } finally {
      await r?.close();
      _set(() => _busy = false);
    }
  }

  Future<void> _connect() async {
    await _save();
    _set(() => _info = '');
    await _task('Connecting...', (r) async {
      final (name, ver) = await r.identity();
      final res = await r.cmd('/system/resource/print');
      final up = res.isNotEmpty ? res[0]['uptime'] ?? '' : '';
      _set(() {
        _status = 'Connected';
        _info = '$name  -  RouterOS $ver${up.isNotEmpty ? '  -  up $up' : ''}';
      });
    });
  }

  Future<void> _show(String path, String title) async {
    _set(() => _rows = []);
    await _task('Reading $title...', (r) async {
      final rows = await r.cmd(path);
      _set(() {
        _rows = rows;
        _status = '$title: ${rows.length}';
      });
    });
  }

  Future<void> _bindAll() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        title: const Text('Bind all devices to their current IP?'),
        content: const Text('Turns every current DHCP lease into a fixed reservation, so each device always '
            'gets the same IP. Nothing on the devices changes. You can remove a reservation later.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(c, true), child: const Text('Bind all')),
        ],
      ),
    );
    if (ok != true) return;
    await _task('Binding...', (r) async {
      final leases = await r.cmd('/ip/dhcp-server/lease/print');
      var n = 0;
      for (final l in leases) {
        if ((l['dynamic'] ?? '') == 'true' && (l['.id'] ?? '').isNotEmpty) {
          await r.talk(['/ip/dhcp-server/lease/make-static', '=.id=${l['.id']}'], check: false);
          n++;
        }
      }
      _set(() => _status = n == 0 ? 'All leases are already fixed.' : 'Bound $n device(s) to their IP.');
    });
  }

  Future<void> _backup() async {
    _set(() => _cmdOut = '');
    await _task('Reading the router config...', (r) async {
      final sb = StringBuffer();
      for (final (path, title) in const [
        ('/ip/address/print', 'IP addresses'),
        ('/ip/dhcp-server/print', 'DHCP servers'),
        ('/ip/dhcp-server/network/print', 'DHCP networks'),
        ('/ip/dns/print', 'DNS'),
        ('/ip/firewall/filter/print', 'Firewall filter'),
        ('/ip/firewall/nat/print', 'NAT'),
        ('/interface/print', 'Interfaces'),
      ]) {
        final rows = await r.cmd(path);
        sb.writeln('### $title (${rows.length})');
        for (final m in rows) {
          sb.writeln(m.entries.where((e) => !e.key.startsWith('.')).map((e) => '${e.key}=${e.value}').join('  '));
        }
        sb.writeln();
      }
      _set(() {
        _cmdOut = sb.toString();
        _status = 'Config read - copy it to keep a backup.';
      });
    });
  }

  Future<void> _run() async {
    final line = _cmd.text.trim();
    if (line.isEmpty) return;
    _set(() => _cmdOut = '');
    await _task('Running...', (r) async {
      final rows = await r.cmd(line.split(RegExp(r'\s+')).first, params: _paramsFrom(line));
      _set(() {
        _cmdOut = rows.isEmpty
            ? '(no rows returned)'
            : rows.map((m) => m.entries.map((e) => '${e.key}=${e.value}').join('  ')).join('\n\n');
        _status = '${rows.length} row(s)';
      });
    });
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

  Widget _rowCard(Map<String, String> m) {
    // one row from any print command: pick a sensible headline, then show the rest
    const titleKeys = ['address', 'name', 'mac-address', 'host-name', 'message', 'interface'];
    String title = '?';
    for (final k in titleKeys) {
      if ((m[k] ?? '').isNotEmpty) {
        title = m[k]!;
        break;
      }
    }
    final rest = m.entries
        .where((e) => !e.key.startsWith('.') && e.value.isNotEmpty && e.value != title)
        .map((e) => '${e.key}=${e.value}')
        .join('  ·  ');
    return Card(
      margin: const EdgeInsets.symmetric(vertical: 3),
      child: ListTile(dense: true, title: Text(title), subtitle: rest.isEmpty ? null : Text(rest)),
    );
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
          OutlinedButton.icon(
              onPressed: _busy ? null : () => _show('/interface/print', 'interfaces'),
              icon: const Icon(Icons.settings_ethernet),
              label: const Text('Interfaces')),
          OutlinedButton.icon(
              onPressed: _busy ? null : () => _show('/log/print', 'log lines'),
              icon: const Icon(Icons.article),
              label: const Text('Router log')),
          FilledButton.tonalIcon(
              onPressed: _busy ? null : _bindAll,
              icon: const Icon(Icons.push_pin),
              label: const Text('Bind all to IP')),
          FilledButton.tonalIcon(
              onPressed: _busy ? null : _backup,
              icon: const Icon(Icons.save),
              label: const Text('Backup config')),
        ]),
        for (final m in _rows) _rowCard(m),
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
