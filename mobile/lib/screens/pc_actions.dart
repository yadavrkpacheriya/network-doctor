import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../net/pc_link.dart';
import 'common.dart';

/// Everything the phone can DO on the office PC (PC app 3.16+): alerts with Troubleshoot, the network map,
/// health checks, tools (slow website, ping / traceroute, network guard, router commands) and device actions.

List<Map<String, dynamic>> _ms(Object? v) =>
    ((v as List?) ?? const []).map((e) => Map<String, dynamic>.from(e as Map)).toList();

Color prioColor(num? p) => switch ((p ?? 3).toInt()) {
      1 => Colors.red.shade700,
      2 => Colors.deepOrange.shade700,
      3 => Colors.blue.shade700,
      _ => Colors.grey.shade600,
    };

void _snack(BuildContext context, String text) {
  ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));
}

Future<bool> _confirm(BuildContext context, String title, String body) async {
  final r = await showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: Text(title),
      content: Text(body),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
        FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Yes, do it')),
      ],
    ),
  );
  return r == true;
}

/// Runs an action on the PC. Short ones show a message; long ones (jobs) open a result page that fills in.
Future<void> runOnPc(BuildContext context, String action, Map<String, dynamic> args, {String? title}) async {
  final pc = PcLink.current;
  if (pc == null) {
    _snack(context, 'Open the Office PC tab first.');
    return;
  }
  try {
    final r = await PcLink.action(pc, action, args);
    if (!context.mounted) return;
    if (r['job'] != null) {
      await Navigator.of(context).push(MaterialPageRoute(
          builder: (_) => JobPage(pc: pc, id: '${r['job']}', title: title ?? '${r['message'] ?? 'Working'}')));
    } else {
      _snack(context, '${r['message'] ?? (r['ok'] == true ? 'Done' : 'Failed')}');
    }
  } on PcError catch (e) {
    if (context.mounted) _snack(context, e.message);
  }
}

class JobPage extends StatefulWidget {
  const JobPage({super.key, required this.pc, required this.id, required this.title});
  final PairedPc pc;
  final String id;
  final String title;

  @override
  State<JobPage> createState() => _JobPageState();
}

class _JobPageState extends State<JobPage> {
  Map<String, dynamic>? _j;
  String _err = '';

  @override
  void initState() {
    super.initState();
    PcLink.waitJob(widget.pc, widget.id, onTick: (j) {
      if (mounted) setState(() => _j = j);
    }).then((j) {
      if (mounted) setState(() => _j = j);
    }).catchError((e) {
      if (mounted) setState(() => _err = '$e');
    });
  }

  @override
  Widget build(BuildContext context) {
    final j = _j;
    final done = j?['done'] == true;
    final text = '${j?['text'] ?? j?['message'] ?? ''}';
    return Scaffold(
      appBar: AppBar(title: Text(widget.title, overflow: TextOverflow.ellipsis), actions: [
        if (text.isNotEmpty)
          IconButton(
              tooltip: 'Copy',
              icon: const Icon(Icons.copy),
              onPressed: () {
                Clipboard.setData(ClipboardData(text: text));
                _snack(context, 'Copied');
              }),
      ]),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        if (!done && _err.isEmpty) const LinearProgressIndicator(),
        const SizedBox(height: 8),
        Text(
            _err.isNotEmpty
                ? _err
                : !done
                    ? 'The PC is working on it...'
                    : j?['ok'] == false
                        ? 'Did not work'
                        : 'Finished',
            style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 8),
        SelectableText(text, style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
      ]),
    );
  }
}

// ------------------------------------------------------------------ alerts
class AlertsTab extends StatefulWidget {
  const AlertsTab({super.key, required this.s, required this.onRefresh});
  final Map<String, dynamic> s;
  final Future<void> Function() onRefresh;

  @override
  State<AlertsTab> createState() => _AlertsTabState();
}

class _AlertsTabState extends State<AlertsTab> {
  bool _open = true;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final all = _ms(widget.s['alerts']);
    final shown = all.where((a) => !_open || a['status'] == 'open').toList()
      ..sort((a, b) => ((a['prio'] as num?) ?? 3).compareTo((b['prio'] as num?) ?? 3));
    return RefreshIndicator(
      onRefresh: widget.onRefresh,
      child: ListView(physics: const AlwaysScrollableScrollPhysics(), padding: const EdgeInsets.all(12), children: [
        SegmentedButton<bool>(
          segments: const [ButtonSegment(value: true, label: Text('Open')), ButtonSegment(value: false, label: Text('All'))],
          selected: {_open},
          onSelectionChanged: (v) => setState(() => _open = v.first),
        ),
        const SizedBox(height: 8),
        if (all.isNotEmpty && all.first['id'] == null)
          const Card(child: ListTile(title: Text('Update Network Doctor on the PC to 3.16 to fix alerts from the phone.'))),
        if (shown.isEmpty) const Card(child: ListTile(leading: Icon(Icons.check_circle, color: Colors.green), title: Text('No alerts'))),
        for (final a in shown)
          Card(
            child: ListTile(
              leading: Icon(a['status'] == 'fixed' ? Icons.check_circle : Icons.warning_amber_rounded,
                  color: a['status'] == 'fixed' ? Colors.green : prioColor(a['prio'] as num?)),
              title: Text('${a['title'] ?? a['text']}', maxLines: 3, overflow: TextOverflow.ellipsis),
              subtitle: Text('${a['prio_text']} · ${hhmm((a['t'] as num?) ?? 0)}'
                  '${((a['count'] as num?) ?? 1) > 1 ? ' · ${a['count']}×' : ''}\nFix: ${a['fix']}',
                  style: t.bodySmall),
              isThreeLine: true,
              trailing: const Icon(Icons.chevron_right),
              onTap: () => Navigator.of(context)
                  .push(MaterialPageRoute(builder: (_) => TroubleshootPage(alert: a)))
                  .then((_) => widget.onRefresh()),
            ),
          ),
      ]),
    );
  }
}

class TroubleshootPage extends StatefulWidget {
  const TroubleshootPage({super.key, required this.alert});
  final Map<String, dynamic> alert;

  @override
  State<TroubleshootPage> createState() => _TroubleshootPageState();
}

class _TroubleshootPageState extends State<TroubleshootPage> {
  final _done = <int>{};

  @override
  Widget build(BuildContext context) {
    final a = widget.alert;
    final t = Theme.of(context).textTheme;
    final steps = ((a['steps'] as List?) ?? const []).map((e) => '$e').toList();
    final fixes = ((a['fixes'] as List?) ?? const []).map((e) => '$e').toList();
    final pcFixes = ((a['pc_fixes'] as List?) ?? const []).map((e) => '$e').toList();
    return Scaffold(
      appBar: AppBar(title: const Text('Troubleshoot')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        Wrap(spacing: 8, crossAxisAlignment: WrapCrossAlignment.center, children: [
          Chip(
              label: Text('${a['prio_text']}', style: const TextStyle(color: Colors.white)),
              backgroundColor: prioColor(a['prio'] as num?)),
          Text(hhmm((a['t'] as num?) ?? 0), style: t.bodySmall),
        ]),
        Text('${a['title'] ?? a['text']}', style: t.titleLarge),
        const SizedBox(height: 4),
        Text('${a['text']}', style: t.bodySmall),
        const SizedBox(height: 10),
        if ('${a['why'] ?? ''}'.isNotEmpty) Text('${a['why']}'),
        const SizedBox(height: 8),
        Text('Fix: ${a['fix']}', style: t.titleSmall),
        const SizedBox(height: 12),
        if (fixes.isNotEmpty) ...[
          Text('Fix it automatically', style: t.titleMedium),
          for (var i = 0; i < fixes.length; i++)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 4),
              child: FilledButton.icon(
                icon: const Icon(Icons.build),
                label: Text(fixes[i]),
                onPressed: () async {
                  if (!await _confirm(context, fixes[i], 'The PC sends this to the router now. Continue?')) return;
                  if (context.mounted) await runOnPc(context, 'alert_fix', {'id': a['id'], 'n': i}, title: fixes[i]);
                },
              ),
            ),
        ],
        for (final f in pcFixes)
          Card(
              child: ListTile(
                  dense: true,
                  title: const Text('On a PC (copy and run in Command Prompt)'),
                  subtitle: SelectableText(f, style: const TextStyle(fontFamily: 'monospace', fontSize: 12)))),
        const SizedBox(height: 12),
        Text('Step by step', style: t.titleMedium),
        for (var i = 0; i < steps.length; i++)
          CheckboxListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            controlAffinity: ListTileControlAffinity.leading,
            value: _done.contains(i),
            onChanged: (v) => setState(() => v == true ? _done.add(i) : _done.remove(i)),
            title: Text('${i + 1}. ${steps[i]}'),
          ),
        const SizedBox(height: 12),
        Wrap(spacing: 8, runSpacing: 8, children: [
          OutlinedButton.icon(
              icon: const Icon(Icons.refresh),
              label: const Text('Re-check now'),
              onPressed: () => runOnPc(context, 'quick', {})),
          if (a['id'] != null)
            FilledButton.tonalIcon(
              icon: Icon(a['status'] == 'fixed' ? Icons.undo : Icons.check),
              label: Text(a['status'] == 'fixed' ? 'Re-open' : 'Mark fixed'),
              onPressed: () async {
                await runOnPc(context, 'alert_status', {'id': a['id'], 'status': a['status'] == 'fixed' ? 'open' : 'fixed'});
                if (context.mounted) Navigator.pop(context);
              },
            ),
          OutlinedButton.icon(
            icon: const Icon(Icons.copy),
            label: const Text('Copy steps'),
            onPressed: () {
              Clipboard.setData(ClipboardData(
                  text: '${a['prio_text']}: ${a['title'] ?? a['text']}\nFix: ${a['fix']}\n'
                      '${[for (var i = 0; i < steps.length; i++) '${i + 1}. ${steps[i]}'].join('\n')}'));
              _snack(context, 'Copied');
            },
          ),
        ]),
      ]),
    );
  }
}

// ------------------------------------------------------------------ network map
class MapTab extends StatelessWidget {
  const MapTab({super.key, required this.s, required this.onRefresh});
  final Map<String, dynamic> s;
  final Future<void> Function() onRefresh;

  @override
  Widget build(BuildContext context) {
    final root = s['map'] as Map?;
    if (root == null) {
      return const Center(
          child: Padding(
              padding: EdgeInsets.all(24),
              child: Text('No network map from the PC yet (Network Doctor 3.16 or newer on the PC, after a scan).')));
    }
    final tops = _ms(root['children']);
    return RefreshIndicator(
      onRefresh: onRefresh,
      child: ListView(physics: const AlwaysScrollableScrollPhysics(), padding: const EdgeInsets.all(8), children: [
        const Padding(
          padding: EdgeInsets.all(8),
          child: Text('Router → ports / switches / access points → devices. Red = problem, orange = warning. '
              'Tag a device with "Connected to" on the PC to place it.'),
        ),
        for (final n in tops) _MapNode(n: n, depth: 0),
      ]),
    );
  }
}

class _MapNode extends StatelessWidget {
  const _MapNode({required this.n, required this.depth});
  final Map<String, dynamic> n;
  final int depth;

  @override
  Widget build(BuildContext context) {
    final kids = _ms(n['children']);
    final bad = '${n['bad'] ?? ''}';
    final col = bad == 'critical'
        ? Colors.red.shade700
        : bad == 'warning'
            ? Colors.orange.shade800
            : null;
    final icon = switch ('${n['kind']}') {
      'router' => Icons.router,
      'port' => Icons.settings_input_hdmi,
      'gear' => Icons.hub,
      'group' => Icons.folder_open,
      'off' => Icons.power_off,
      _ => Icons.devices_other,
    };
    final title = Text('${n['label']}', style: TextStyle(color: col, fontWeight: kids.isEmpty ? null : FontWeight.w600));
    final sub = '${n['sub'] ?? ''}'.isEmpty ? null : Text('${n['sub']}', style: Theme.of(context).textTheme.bodySmall);
    if (kids.isEmpty) {
      return Padding(
        padding: EdgeInsets.only(left: 12.0 * depth),
        child: ListTile(dense: true, leading: Icon(icon, size: 18, color: col), title: title, subtitle: sub),
      );
    }
    return Padding(
      padding: EdgeInsets.only(left: 12.0 * depth),
      child: ExpansionTile(
        initiallyExpanded: depth < 1,
        leading: Icon(icon, color: col),
        title: Row(children: [Flexible(child: title), Text('  (${kids.length})')]),
        subtitle: sub,
        children: [
          // many devices on one port: a compact grid of chips instead of a long list
          if (kids.every((k) => _ms(k['children']).isEmpty) && kids.length > 6)
            Padding(
              padding: EdgeInsets.only(left: 12.0 * (depth + 1), right: 8, bottom: 8),
              child: Wrap(spacing: 6, runSpacing: 6, children: [
                for (final k in kids)
                  Chip(
                    visualDensity: VisualDensity.compact,
                    side: BorderSide(
                        color: '${k['bad']}' == 'critical'
                            ? Colors.red.shade700
                            : '${k['bad']}' == 'warning'
                                ? Colors.orange.shade800
                                : Colors.grey.shade400),
                    label: Text('${k['label']}\n${k['sub'] ?? ''}', style: const TextStyle(fontSize: 11)),
                  ),
              ]),
            )
          else
            for (final k in kids) _MapNode(n: k, depth: depth + 1),
        ],
      ),
    );
  }
}

// ------------------------------------------------------------------ health checks
class HealthTab extends StatelessWidget {
  const HealthTab({super.key, required this.s, required this.onRefresh});
  final Map<String, dynamic> s;
  final Future<void> Function() onRefresh;

  @override
  Widget build(BuildContext context) {
    final checks = _ms(s['checks']);
    final watch = _ms(s['watch']);
    final auto = Map<String, dynamic>.from((s['auto'] as Map?) ?? const {});
    final t = Theme.of(context).textTheme;
    IconData ic(String r) {
      final x = r.toLowerCase();
      if (x.startsWith('ok') || x.startsWith('pass') || x.startsWith('good')) return Icons.check_circle;
      if (x.startsWith('fail') || x.startsWith('problem') || x.startsWith('bad')) return Icons.cancel;
      return Icons.info_outline;
    }

    Color? co(String r) {
      final x = r.toLowerCase();
      if (x.startsWith('ok') || x.startsWith('pass') || x.startsWith('good')) return Colors.green.shade700;
      if (x.startsWith('fail') || x.startsWith('problem') || x.startsWith('bad')) return Colors.red.shade700;
      if (x.startsWith('warn')) return Colors.orange.shade800;
      return null;
    }

    return RefreshIndicator(
      onRefresh: onRefresh,
      child: ListView(physics: const AlwaysScrollableScrollPhysics(), padding: const EdgeInsets.all(12), children: [
        Card(
          child: ListTile(
            leading: const Icon(Icons.schedule),
            title: const Text('Automatic checks'),
            subtitle: Text('${auto['summary'] ?? ''}'),
            trailing: TextButton(onPressed: () => runOnPc(context, 'quick', {}), child: const Text('Check now')),
          ),
        ),
        if (watch.isNotEmpty) ...[
          Text('Watched devices', style: t.titleMedium),
          for (final w in watch)
            ListTile(
              dense: true,
              leading: Icon(w['down'] == true ? Icons.cancel : Icons.check_circle,
                  color: w['down'] == true ? Colors.red.shade700 : Colors.green.shade700),
              title: Text('${w['name'] ?? w['ip']}'),
              subtitle: Text('${w['ip']} · ${w['rtt'] == null ? '-' : '${w['rtt']} ms'} · down ${w['downs'] ?? 0}×'),
            ),
        ],
        Text('Health checks (last scan)', style: t.titleMedium),
        if (checks.isEmpty) const Card(child: ListTile(title: Text('Scan on the PC first'))),
        for (final c in checks)
          Card(
            child: ExpansionTile(
              leading: Icon(ic('${c['result']}'), color: co('${c['result']}')),
              title: Text('${c['name']}'),
              subtitle: Text('${c['result']}', maxLines: 2, overflow: TextOverflow.ellipsis),
              childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
              expandedCrossAxisAlignment: CrossAxisAlignment.start,
              children: [Text('${c['detail'] ?? ''}')],
            ),
          ),
      ]),
    );
  }
}

// ------------------------------------------------------------------ tools
class PcToolsTab extends StatefulWidget {
  const PcToolsTab({super.key, required this.s, this.only});
  final Map<String, dynamic> s;

  /// Which tools to show (slow, ping, guard, router, library); null = all. A single tool opens expanded.
  final List<String>? only;

  @override
  State<PcToolsTab> createState() => _PcToolsTabState();
}

class _PcToolsTabState extends State<PcToolsTab> {
  final _url = TextEditingController(text: 'https://docs.google.com/spreadsheets/');
  final _ip = TextEditingController();
  String? _devIp;
  String _cq = '';

  List<Map<String, dynamic>> get _devs =>
      _ms(widget.s['devices']).where((d) => d['online'] == true).toList()
        ..sort((a, b) => '${a['name']}'.toLowerCase().compareTo('${b['name']}'.toLowerCase()));

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final sites = _ms(widget.s['slow_sites']);
    final cmds = _ms(widget.s['commands']).where((c) => c['where'] == 'Router').toList();
    final shownCmds = cmds
        .where((c) => _cq.isEmpty || '${c['group']} ${c['name']} ${c['cmd']}'.toLowerCase().contains(_cq.toLowerCase()))
        .toList();
    final login = widget.s['router_login'] == true;
    final only = widget.only;
    Widget section(String key, String title, IconData icon, List<Widget> children) =>
        only != null && !only.contains(key) ? const SizedBox.shrink() : Card(
          child: ExpansionTile(
            initiallyExpanded: only != null && only.length == 1,
            leading: Icon(icon),
            title: Text(title),
            childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
            expandedCrossAxisAlignment: CrossAxisAlignment.start,
            children: children,
          ),
        );
    final devPicker = Autocomplete<Map<String, dynamic>>(
      displayStringForOption: (d) => '${d['name'] ?? '-'}  ${d['ip']}',
      optionsBuilder: (v) {
        final q = v.text.toLowerCase().split(' ').where((w) => w.isNotEmpty);
        return _devs.where((d) => q.every((w) => '${d['name']} ${d['ip']} ${d['mac']}'.toLowerCase().contains(w))).take(20);
      },
      onSelected: (d) => setState(() => _devIp = '${d['ip']}'),
      fieldViewBuilder: (ctx, c, f, _) => TextField(
        controller: c,
        focusNode: f,
        decoration: const InputDecoration(labelText: 'User / device (type a name, IP or MAC)', isDense: true),
        onChanged: (v) => _devIp = RegExp(r'^\d+\.\d+\.\d+\.\d+$').hasMatch(v.trim()) ? v.trim() : null,
      ),
    );
    return ListView(padding: const EdgeInsets.all(12), children: [
      if (!login && (only == null || only.any((k) => ['guard', 'router'].contains(k))))
        const Card(
            child: ListTile(
                leading: Icon(Icons.info_outline),
                title: Text('Router changes need the router login saved on the PC (Setup > Router login).'))),
      section('slow', 'Slow website? Find the cause', Icons.speed, [
        devPicker,
        const SizedBox(height: 8),
        TextField(controller: _url, decoration: const InputDecoration(labelText: 'Website', isDense: true)),
        Wrap(spacing: 6, children: [
          for (final x in sites.take(8))
            ActionChip(label: Text('${x['label']}'), onPressed: () => setState(() => _url.text = '${x['url']}')),
        ]),
        const SizedBox(height: 8),
        FilledButton.icon(
          icon: const Icon(Icons.search),
          label: const Text('Find the cause (about 1 minute)'),
          onPressed: () => runOnPc(context, 'slow', {'url': _url.text, if (_devIp != null) 'ip': _devIp},
              title: 'Slow website: ${_url.text}'),
        ),
      ]),
      section('ping', 'Ping / traceroute from the PC', Icons.network_ping, [
        TextField(
            controller: _ip,
            keyboardType: TextInputType.number,
            decoration: const InputDecoration(labelText: 'IP address (a device, the router, 8.8.8.8...)', isDense: true)),
        const SizedBox(height: 8),
        Wrap(spacing: 8, children: [
          FilledButton(
              onPressed: () => runOnPc(context, 'ping', {'ip': _ip.text.trim()}, title: 'Ping ${_ip.text}'),
              child: const Text('Ping')),
          OutlinedButton(
              onPressed: () => runOnPc(context, 'trace', {'ip': _ip.text.trim()}, title: 'Traceroute ${_ip.text}'),
              child: const Text('Traceroute')),
        ]),
      ]),
      section('guard', 'Network guard (on the router)', Icons.shield, [
        for (final g in const [
          ['torrent', 'Block torrents', 'Torrent traffic and torrent websites for every device'],
          ['dns', 'All DNS through the router', 'Exact website names in Usage; stops DNS bypass'],
          ['dhcp', 'Block rogue DHCP', 'A second router cannot give out IP addresses'],
          ['random', 'Block randomized MACs', 'Phones must use their real MAC on the office Wi-Fi'],
        ])
          ListTile(
            contentPadding: EdgeInsets.zero,
            title: Text(g[1]),
            subtitle: Text(g[2]),
            trailing: FilledButton.tonal(
              onPressed: () async {
                if (!await _confirm(context, g[1], '${g[2]}.\n\nThe PC applies this on the router now.')) return;
                if (context.mounted) await runOnPc(context, 'guard', {'opt': g[0]}, title: g[1]);
              },
              child: const Text('Apply'),
            ),
          ),
        const Text('Undo: Security > Network guard on the PC.'),
      ]),
      section('router', 'Router commands', Icons.terminal, [
        TextField(
            decoration: const InputDecoration(prefixIcon: Icon(Icons.search), hintText: 'Find a command', isDense: true),
            onChanged: (v) => setState(() => _cq = v)),
        for (final c in shownCmds.take(60))
          ListTile(
            contentPadding: EdgeInsets.zero,
            dense: true,
            title: Text('${c['name']}'),
            subtitle: Text('${c['group']}\n${c['cmd']}', maxLines: 3, overflow: TextOverflow.ellipsis),
            isThreeLine: true,
            trailing: IconButton(
              icon: const Icon(Icons.play_arrow),
              tooltip: 'Run on the router',
              onPressed: () => _runCmd(c),
            ),
          ),
      ]),
      section('library', 'Other brands, antivirus, drivers (copy)', Icons.library_books, [
        for (final c in _ms(widget.s['commands']).where((c) => c['where'] != 'Router').take(200))
          ListTile(
            contentPadding: EdgeInsets.zero,
            dense: true,
            title: Text('${c['name']}'),
            subtitle: Text('${c['group']} · ${c['where']}\n${c['cmd']}', maxLines: 3, overflow: TextOverflow.ellipsis),
            isThreeLine: true,
            trailing: IconButton(
                icon: const Icon(Icons.copy),
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: '${c['cmd']}'));
                  _snack(context, 'Copied');
                }),
          ),
      ]),
      Text('Changes are made by the office PC; the router login never leaves it.', style: t.bodySmall),
    ]);
  }

  Future<void> _runCmd(Map<String, dynamic> c) async {
    final needed = RegExp(r'\{(\w+)\}').allMatches('${c['cmd']}').map((m) => m.group(1)!).toSet()
      ..removeAll(['gw', 'lip', 'gw_mac', 'gw_mac_dash']);
    final values = <String, String>{};
    for (final k in needed) {
      final v = await _ask(k);
      if (v == null) return;
      values[k] = v;
    }
    if (!mounted) return;
    final changes = RegExp(r'\b(add|set|remove|disable|enable|reboot)\b').hasMatch('${c['cmd']}');
    if (changes && !await _confirm(context, '${c['name']}', 'This changes the router:\n\n${c['cmd']}')) return;
    if (!mounted) return;
    await runOnPc(context, 'router_cmd', {'i': c['i'], 'values': values, if (values['ip'] != null) 'ip': values['ip']},
        title: '${c['name']}');
  }

  Future<String?> _ask(String k) {
    final ctl = TextEditingController();
    final hint = switch (k) {
      'ip' => 'IP address, e.g. 192.168.0.48',
      'mac' => 'MAC, e.g. AA:BB:CC:DD:EE:FF',
      'port' => 'router port, e.g. ether3',
      'limit' => 'speed, e.g. 5M',
      'host' => 'a name, e.g. google.com',
      _ => k,
    };
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Value for {$k}'),
        content: TextField(controller: ctl, autofocus: true, decoration: InputDecoration(hintText: hint)),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, ctl.text.trim()), child: const Text('OK')),
        ],
      ),
    );
  }
}

// ------------------------------------------------------------------ device actions (on the device page)
class PcDeviceActions extends StatelessWidget {
  const PcDeviceActions({super.key, required this.ip, required this.mac, required this.name});
  final String ip;
  final String mac;
  final String name;

  @override
  Widget build(BuildContext context) {
    if (PcLink.current == null) return const SizedBox.shrink();
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Office PC actions', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 6),
          Wrap(spacing: 8, runSpacing: 8, children: [
            FilledButton.tonalIcon(icon: const Icon(Icons.label), label: const Text('Tag'), onPressed: () => _tag(context)),
            FilledButton.tonalIcon(
                icon: const Icon(Icons.network_ping),
                label: const Text('Ping from PC'),
                onPressed: () => runOnPc(context, 'ping', {'ip': ip}, title: 'Ping $ip')),
            FilledButton.tonalIcon(
                icon: const Icon(Icons.route),
                label: const Text('Traceroute'),
                onPressed: () => runOnPc(context, 'trace', {'ip': ip}, title: 'Traceroute $ip')),
            if (mac.isNotEmpty)
              FilledButton.tonalIcon(
                icon: const Icon(Icons.link),
                label: const Text('Bind IP'),
                onPressed: () async {
                  if (!await _confirm(context, 'Bind $ip', 'The router always gives $ip to $mac.')) return;
                  if (context.mounted) await runOnPc(context, 'bind', {'macs': [mac]}, title: 'Bind $ip');
                },
              ),
            if (mac.isNotEmpty)
              FilledButton.tonalIcon(
                icon: const Icon(Icons.block),
                label: const Text('Block internet'),
                onPressed: () async {
                  if (!await _confirm(context, 'Block ${name.isEmpty ? ip : name}',
                      'This device loses internet and the rest of the network until you unblock it.')) {
                    return;
                  }
                  if (context.mounted) await runOnPc(context, 'block', {'mac': mac, 'on': true}, title: 'Block $ip');
                },
              ),
            if (mac.isNotEmpty)
              OutlinedButton(
                  onPressed: () => runOnPc(context, 'block', {'mac': mac, 'on': false}, title: 'Unblock $ip'),
                  child: const Text('Unblock')),
            if (mac.isNotEmpty)
              OutlinedButton(onPressed: () => runOnPc(context, 'wol', {'mac': mac, 'ip': ip}), child: const Text('Wake (WOL)')),
            if (mac.isNotEmpty)
              FilledButton.tonalIcon(
                icon: const Icon(Icons.gpp_bad),
                label: const Text('Quarantine'),
                onPressed: () async {
                  if (!await _confirm(context, 'Quarantine ${name.isEmpty ? ip : name}',
                      'Block ALL this device\'s traffic on the router - full isolation until you release it.')) {
                    return;
                  }
                  if (context.mounted) await runOnPc(context, 'isolate', {'mac': mac, 'ip': ip}, title: 'Quarantine $ip');
                },
              ),
            if (mac.isNotEmpty)
              OutlinedButton(
                  onPressed: () => runOnPc(context, 'unisolate', {'mac': mac, 'ip': ip}, title: 'Release $ip'),
                  child: const Text('Un-quarantine')),
            if (mac.isNotEmpty)
              FilledButton.tonalIcon(
                style: FilledButton.styleFrom(backgroundColor: Colors.red.shade50),
                icon: Icon(Icons.power_settings_new, color: Colors.red.shade700),
                label: Text('Power off', style: TextStyle(color: Colors.red.shade700)),
                onPressed: () async {
                  if (!await _confirm(context, 'Power off ${name.isEmpty ? ip : name}',
                      'Quarantine it now and tell its agent to disconnect / shut down. Admin only.')) {
                    return;
                  }
                  if (context.mounted) await runOnPc(context, 'poweroff', {'mac': mac, 'ip': ip}, title: 'Contain $ip');
                },
              ),
          ]),
        ]),
      ),
    );
  }

  Future<void> _tag(BuildContext context) async {
    final n = TextEditingController(text: name);
    final d = TextEditingController();
    final l = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Tag $ip'),
        content: Column(mainAxisSize: MainAxisSize.min, children: [
          TextField(controller: n, decoration: const InputDecoration(labelText: 'Name')),
          TextField(controller: d, decoration: const InputDecoration(labelText: 'Department')),
          TextField(controller: l, decoration: const InputDecoration(labelText: 'Location / room')),
        ]),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Save')),
        ],
      ),
    );
    if (ok != true || !context.mounted) return;
    await runOnPc(context, 'tag', {
      'mac': mac,
      'name': n.text.trim(),
      if (d.text.trim().isNotEmpty) 'dept': d.text.trim(),
      if (l.text.trim().isNotEmpty) 'location': l.text.trim(),
    });
  }
}


// ------------------------------------------------------------------ sections (coloured groups of pages)
class PcSection {
  const PcSection(this.title, this.icon, this.color, this.pages);
  final String title;
  final IconData icon;
  final Color color;
  final List<(String, Widget Function())> pages;
}

/// One coloured section: chips for its pages on top, the chosen page below.
class SectionView extends StatefulWidget {
  const SectionView({super.key, required this.section});
  final PcSection section;

  @override
  State<SectionView> createState() => _SectionViewState();
}

class _SectionViewState extends State<SectionView> with AutomaticKeepAliveClientMixin {
  int _i = 0;

  @override
  bool get wantKeepAlive => true;

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final sec = widget.section;
    final pages = sec.pages;
    if (_i >= pages.length) _i = 0;
    return Column(children: [
      if (pages.length > 1)
        Container(
          color: sec.color.withValues(alpha: 0.08),
          child: SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            padding: const EdgeInsets.fromLTRB(8, 6, 8, 6),
            child: Row(children: [
              for (var i = 0; i < pages.length; i++)
                Padding(
                  padding: const EdgeInsets.only(right: 6),
                  child: ChoiceChip(
                    label: Text(pages[i].$1),
                    selected: i == _i,
                    showCheckmark: false,
                    selectedColor: sec.color,
                    labelStyle: TextStyle(color: i == _i ? Colors.white : sec.color, fontWeight: FontWeight.w600),
                    side: BorderSide(color: sec.color.withValues(alpha: 0.5)),
                    onSelected: (_) => setState(() => _i = i),
                  ),
                ),
            ]),
          ),
        ),
      Expanded(child: pages[_i].$2()),
    ]);
  }
}

// ------------------------------------------------------------------ Pro: auto-defense, security checks, audit
class ProSecurityTab extends StatelessWidget {
  const ProSecurityTab({super.key, required this.s, required this.onRefresh});
  final Map<String, dynamic> s;
  final Future<void> Function() onRefresh;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final def = Map<String, dynamic>.from((s['defense'] as Map?) ?? const {});
    final armed = def['armed'] == true;
    final contained = _ms(def['contained']);
    return RefreshIndicator(
      onRefresh: onRefresh,
      child: ListView(physics: const AlwaysScrollableScrollPhysics(), padding: const EdgeInsets.all(12), children: [
        Card(
          color: armed ? Colors.red.shade50 : null,
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                Icon(armed ? Icons.shield : Icons.shield_outlined, color: armed ? Colors.red.shade700 : null),
                const SizedBox(width: 8),
                Expanded(child: Text('Auto-defense', style: t.titleMedium)),
                Switch(
                  value: armed,
                  onChanged: (v) async {
                    await runOnPc(context, 'defense_arm', {'armed': v, 'mode': def['mode'] ?? 'auto'});
                    onRefresh();
                  },
                ),
              ]),
              Text(armed
                  ? 'ARMED - ${def['mode'] == 'alert' ? 'alerting only' : 'contains attackers automatically'}'
                      '${def['night_only'] == true ? ' at night' : ''}'
                  : 'Off - attacks are detected and alerted, but nothing is contained automatically.'),
              const SizedBox(height: 6),
              if (armed)
                SegmentedButton<String>(
                  segments: const [
                    ButtonSegment(value: 'auto', label: Text('Act')),
                    ButtonSegment(value: 'alert', label: Text('Alert only')),
                  ],
                  selected: {(def['mode'] ?? 'auto').toString()},
                  onSelectionChanged: (v) async {
                    await runOnPc(context, 'defense_arm', {'armed': true, 'mode': v.first});
                    onRefresh();
                  },
                ),
            ]),
          ),
        ),
        if (contained.isNotEmpty) ...[
          Text('Quarantined now', style: t.titleMedium),
          for (final c in contained)
            Card(
              child: ListTile(
                leading: Icon(Icons.block, color: Colors.red.shade700),
                title: Text('${c['name'] ?? c['ip']}'),
                subtitle: Text('${c['ip'] ?? ''}  ${c['mac'] ?? ''}\n${c['kind'] ?? ''} · ${c['level'] ?? ''} · by ${c['by'] ?? ''}'),
                isThreeLine: true,
                trailing: TextButton(
                  onPressed: () async {
                    await runOnPc(context, 'defense_release', {'mac': c['mac'] ?? '', 'ip': c['ip'] ?? ''});
                    onRefresh();
                  },
                  child: const Text('Release'),
                ),
              ),
            ),
        ],
        const SizedBox(height: 8),
        Text('Checks', style: t.titleMedium),
        Card(
          child: Column(children: [
            ListTile(
              leading: const Icon(Icons.verified_user),
              title: const Text('Security check'),
              subtitle: const Text('Find open ports, default passwords, poisoners - with fixes'),
              trailing: const Icon(Icons.play_arrow),
              onTap: () => runOnPc(context, 'vuln', {}, title: 'Security check'),
            ),
            ListTile(
              leading: const Icon(Icons.public),
              title: const Text('Internet exposure'),
              subtitle: const Text('What Shodan & Censys see of your office'),
              trailing: const Icon(Icons.play_arrow),
              onTap: () => runOnPc(context, 'exposure', {}, title: 'Internet exposure'),
            ),
            ListTile(
              leading: const Icon(Icons.travel_explore),
              title: const Text('Packet capture'),
              subtitle: const Text('20 seconds of traffic, explained'),
              trailing: const Icon(Icons.play_arrow),
              onTap: () => runOnPc(context, 'capture', {'seconds': 20}, title: 'Packet capture'),
            ),
          ]),
        ),
        const SizedBox(height: 8),
        Text('Audit log - who changed what', style: t.titleMedium),
        for (final e in _ms(s['audit']).take(60))
          ListTile(
            dense: true,
            leading: Text('${e['ts'] ?? ''}'.split(' ').last, style: const TextStyle(fontFamily: 'monospace', fontSize: 11)),
            title: Text('${e['user']} · ${e['action']}'),
            subtitle: Text('${e['detail'] ?? ''}  ${e['result'] ?? ''}'),
          ),
      ]),
    );
  }
}
