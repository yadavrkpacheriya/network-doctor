import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:network_info_plus/network_info_plus.dart';

import '../net/model.dart';
import '../net/pc_link.dart';
import '../net/probe.dart';
import 'common.dart';

/// "Office PC": pair with the Network Doctor PC app and show its results.
class PcScreen extends StatefulWidget {
  const PcScreen({super.key});

  @override
  State<PcScreen> createState() => _PcScreenState();
}

class _PcScreenState extends State<PcScreen> with AutomaticKeepAliveClientMixin {
  List<PairedPc> _pcs = [];
  PairedPc? _pc;
  bool _loaded = false;

  @override
  bool get wantKeepAlive => true;

  @override
  void initState() {
    super.initState();
    PcLink.load().then((l) => setState(() {
          _pcs = l;
          _pc = l.isNotEmpty ? l.first : null;
          _loaded = true;
        }));
  }

  Future<void> _paired(PairedPc pc) async {
    _pcs.removeWhere((p) => p.host == pc.host);
    _pcs.insert(0, pc);
    await PcLink.save(_pcs);
    setState(() => _pc = pc);
  }

  Future<void> _unpair() async {
    final pc = _pc;
    if (pc == null) return;
    _pcs.removeWhere((p) => p.host == pc.host);
    await PcLink.save(_pcs);
    setState(() => _pc = _pcs.isNotEmpty ? _pcs.first : null);
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    if (!_loaded) return const Scaffold(body: Center(child: CircularProgressIndicator()));
    final pc = _pc;
    if (pc == null) return PairView(onPaired: _paired);
    return PcDashboard(
      key: ValueKey(pc.host),
      pc: pc,
      others: _pcs,
      onSwitch: (p) => setState(() => _pc = p),
      onUnpair: _unpair,
      onAddPc: () => setState(() => _pc = null),
    );
  }
}

// ------------------------------------------------------------------ pairing
class PairView extends StatefulWidget {
  const PairView({super.key, required this.onPaired});
  final Future<void> Function(PairedPc) onPaired;

  @override
  State<PairView> createState() => _PairViewState();
}

class _PairViewState extends State<PairView> {
  List<FoundPc> _found = [];
  bool _searching = false;
  String _msg = '';

  @override
  void initState() {
    super.initState();
    _search();
  }

  Future<void> _search() async {
    setState(() {
      _searching = true;
      _msg = '';
    });
    String? bcast;
    try {
      final info = NetworkInfo();
      final ip = await info.getWifiIP();
      final mask = await info.getWifiSubmask();
      if (ip != null) bcast = broadcastOf(ip, maskToPrefix(mask));
    } catch (_) {}
    final f = await PcLink.discover(broadcast: bcast);
    if (!mounted) return;
    setState(() {
      _found = f;
      _searching = false;
      if (f.isEmpty) {
        _msg = 'No Network Doctor PC answered. On the PC open Setup > Phone app link and tick '
            '"Allow the Network Doctor phone app to connect", then search again - or enter the PC address.';
      }
    });
  }

  Future<void> _pair(String host, {int port = pcPort, String? name}) async {
    final code = await _askCode(name ?? host);
    if (code == null) return;
    setState(() => _msg = 'Pairing...');
    try {
      final pc = await PcLink.pair(host, code, _phoneName(), port: port);
      await widget.onPaired(pc);
    } on PcError catch (e) {
      setState(() => _msg = e.message);
    }
  }

  String _phoneName() {
    try {
      return '${Platform.operatingSystem} phone';
    } catch (_) {
      return 'phone';
    }
  }

  Future<String?> _askCode(String pcName) {
    final c = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Pair with $pcName'),
        content: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
          const Text('Enter the 6-digit pairing code shown on the PC in Setup > Phone app link.'),
          TextField(
            controller: c,
            autofocus: true,
            keyboardType: TextInputType.number,
            maxLength: 6,
            decoration: const InputDecoration(labelText: 'Pairing code'),
          ),
        ]),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, c.text.trim()), child: const Text('Pair')),
        ],
      ),
    );
  }

  Future<void> _manual() async {
    final c = TextEditingController();
    final host = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('PC address'),
        content: TextField(
          controller: c,
          autofocus: true,
          keyboardType: TextInputType.url,
          decoration: const InputDecoration(labelText: 'IP address of the PC', hintText: '192.168.0.70'),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, c.text.trim()), child: const Text('Next')),
        ],
      ),
    );
    if (host == null || host.isEmpty) return;
    try {
      final h = await PcLink.hello(host);
      await _pair(host, name: (h['name'] ?? host).toString());
    } on PcError catch (e) {
      setState(() => _msg = e.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: const Text('Office PC')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        Text('Connect to the Network Doctor PC app', style: t.titleMedium),
        const SizedBox(height: 8),
        const Text('The PC app watches the network all the time: loops, ports going down, IP conflicts, bandwidth per '
            'device and dangerous sites. Pair once to see all of it here while you are on the office Wi-Fi.'),
        const SizedBox(height: 16),
        if (_searching) const LinearProgressIndicator(),
        for (final f in _found)
          Card(
            child: ListTile(
              leading: const Icon(Icons.computer),
              title: Text(f.name),
              subtitle: Text('${f.host}  ·  version ${f.version}'),
              trailing: const Icon(Icons.chevron_right),
              onTap: () => _pair(f.host, port: f.port, name: f.name),
            ),
          ),
        if (_msg.isNotEmpty) Padding(padding: const EdgeInsets.symmetric(vertical: 12), child: Text(_msg)),
        const SizedBox(height: 8),
        Wrap(spacing: 8, children: [
          FilledButton.icon(onPressed: _searching ? null : _search, icon: const Icon(Icons.search), label: const Text('Search again')),
          OutlinedButton.icon(onPressed: _manual, icon: const Icon(Icons.edit), label: const Text('Enter PC address')),
        ]),
      ]),
    );
  }
}

// ------------------------------------------------------------------ dashboard
class PcDashboard extends StatefulWidget {
  const PcDashboard({
    super.key,
    required this.pc,
    required this.others,
    required this.onSwitch,
    required this.onUnpair,
    required this.onAddPc,
  });
  final PairedPc pc;
  final List<PairedPc> others;
  final void Function(PairedPc) onSwitch;
  final Future<void> Function() onUnpair;
  final VoidCallback onAddPc;

  @override
  State<PcDashboard> createState() => _PcDashboardState();
}

class _PcDashboardState extends State<PcDashboard> {
  Map<String, dynamic>? _s;
  String _err = '';
  bool _loading = false;
  String _query = '';
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _load();
    _timer = Timer.periodic(const Duration(seconds: 6), (_) => _load());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _load() async {
    if (_loading) return;
    _loading = true;
    try {
      final s = await PcLink.state(widget.pc);
      if (mounted) {
        setState(() {
          _s = s;
          _err = '';
        });
      }
    } on PcError catch (e) {
      if (mounted) setState(() => _err = e.message);
    } catch (e) {
      if (mounted) setState(() => _err = 'Unexpected answer from the PC: $e');
    } finally {
      _loading = false;
    }
  }

  Future<void> _scan() async {
    try {
      final r = await PcLink.startScan(widget.pc);
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('PC: $r')));
    } on PcError catch (e) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = _s;
    return DefaultTabController(
      length: 3,
      child: Scaffold(
        appBar: AppBar(
          title: Text(widget.pc.name, overflow: TextOverflow.ellipsis),
          actions: [
            IconButton(tooltip: 'Refresh', onPressed: _load, icon: const Icon(Icons.refresh)),
            IconButton(tooltip: 'Scan on the PC', onPressed: _scan, icon: const Icon(Icons.radar)),
            PopupMenuButton<String>(
              onSelected: (v) async {
                if (v == 'add') widget.onAddPc();
                if (v == 'unpair') await widget.onUnpair();
                if (v.startsWith('pc:')) {
                  widget.onSwitch(widget.others.firstWhere((p) => p.host == v.substring(3)));
                }
              },
              itemBuilder: (_) => [
                for (final p in widget.others.where((p) => p.host != widget.pc.host))
                  PopupMenuItem(value: 'pc:${p.host}', child: Text('Switch to ${p.name}')),
                const PopupMenuItem(value: 'add', child: Text('Pair another PC')),
                const PopupMenuItem(value: 'unpair', child: Text('Remove this PC')),
              ],
            ),
          ],
          bottom: const TabBar(tabs: [Tab(text: 'Problems'), Tab(text: 'Devices'), Tab(text: 'Monitor')]),
        ),
        body: Column(children: [
          if (_err.isNotEmpty)
            MaterialBanner(
              content: Text(_err),
              leading: const Icon(Icons.wifi_off),
              actions: [TextButton(onPressed: _load, child: const Text('Retry'))],
            ),
          if (s != null && s['scanning'] == true) const LinearProgressIndicator(),
          Expanded(
            child: s == null
                ? Center(child: _err.isEmpty ? const CircularProgressIndicator() : const SizedBox.shrink())
                : TabBarView(children: [
                    _ProblemsTab(s: s, onRefresh: _load),
                    _devicesTab(s),
                    _MonitorTab(s: s, onRefresh: _load),
                  ]),
          ),
        ]),
      ),
    );
  }

  Widget _devicesTab(Map<String, dynamic> s) {
    final devs = ((s['devices'] as List?) ?? const [])
        .map((e) => Device.fromPc(Map<String, dynamic>.from(e as Map)))
        .toList();
    return RefreshIndicator(
      onRefresh: _load,
      child: DeviceList(
        devices: devs,
        query: _query,
        header: Padding(
          padding: const EdgeInsets.fromLTRB(12, 8, 12, 0),
          child: TextField(
            decoration: const InputDecoration(prefixIcon: Icon(Icons.search), hintText: 'Search name, IP, MAC, vendor', isDense: true),
            onChanged: (v) => setState(() => _query = v),
          ),
        ),
      ),
    );
  }
}

class _ProblemsTab extends StatelessWidget {
  const _ProblemsTab({required this.s, required this.onRefresh});
  final Map<String, dynamic> s;
  final Future<void> Function() onRefresh;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final rca = Map<String, dynamic>.from((s['rca'] as Map?) ?? const {});
    final finds = ((rca['findings'] as List?) ?? const []).cast<Map>();
    final missing = ((rca['missing'] as List?) ?? const []).map((e) => e.toString()).toList();
    final issues = ((s['issues'] as List?) ?? const []).cast<Map>();
    final scan = s['scan'] as Map?;
    return RefreshIndicator(
      onRefresh: onRefresh,
      child: ListView(physics: const AlwaysScrollableScrollPhysics(), padding: const EdgeInsets.all(12), children: [
        Text('PC ${s['pc']} (${s['pc_ip']}) · network ${s['network']} · '
            '${scan == null ? 'no scan yet' : 'last scan ${scan['finished'] ?? scan['started'] ?? ''}'}',
            style: t.bodySmall),
        const SizedBox(height: 8),
        Text('Root cause', style: t.titleMedium),
        if (finds.isEmpty)
          const Card(child: ListTile(leading: Icon(Icons.check_circle, color: Colors.green), title: Text('No problem pattern found so far'))),
        for (final f in finds)
          Card(
            child: ExpansionTile(
              leading: Icon(Icons.report, color: f['conf'] == 'High' ? Colors.red.shade700 : Colors.orange.shade800),
              title: Text('${f['title']}'),
              subtitle: Text('Confidence: ${f['conf']}'),
              childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
              expandedCrossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Evidence', style: t.labelLarge),
                for (final e in (f['evidence'] as List? ?? const [])) Text('• $e'),
                const SizedBox(height: 8),
                Text('What to do', style: t.labelLarge),
                for (final a in (f['actions'] as List? ?? const []))
                  Padding(padding: const EdgeInsets.only(top: 2), child: Text('→ $a', style: TextStyle(color: Colors.green.shade700))),
              ],
            ),
          ),
        if (missing.isNotEmpty)
          Card(
            color: Theme.of(context).colorScheme.surfaceContainerHighest,
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text('To make the analysis more complete', style: t.labelLarge),
                for (final m in missing) Text('• $m', style: t.bodySmall),
              ]),
            ),
          ),
        const SizedBox(height: 12),
        Text('Problems found by the scan', style: t.titleMedium),
        if (issues.isEmpty) const Card(child: ListTile(title: Text('No problems found by the last scan'))),
        for (final i in issues)
          Card(
            child: ExpansionTile(
              leading: Icon(Icons.circle, size: 14, color: sevColor(context, '${i['sev']}')),
              title: Text('${i['title']}'),
              subtitle: Text('${i['sev']}'.toUpperCase(), style: TextStyle(color: sevColor(context, '${i['sev']}'))),
              childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
              expandedCrossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('${i['detail']}'),
                const SizedBox(height: 6),
                Text('Fix: ${i['fix']}', style: TextStyle(color: Colors.green.shade700)),
                for (final it in (i['items'] as List? ?? const []).take(30))
                  Text('• $it', style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
              ],
            ),
          ),
      ]),
    );
  }
}

class _MonitorTab extends StatelessWidget {
  const _MonitorTab({required this.s, required this.onRefresh});
  final Map<String, dynamic> s;
  final Future<void> Function() onRefresh;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final m = s['monitor'] as Map?;
    if (m == null) {
      return const Center(child: Text('The live monitor is not running on the PC.'));
    }
    final st = Map<String, dynamic>.from((m['status'] as Map?) ?? const {});
    final samples = ((m['samples'] as List?) ?? const []).cast<List>();
    final bcast = samples.map((x) => (x[1] as num?)?.toDouble()).toList();
    final ping = samples.map((x) => (x[2] as num?)?.toDouble()).toList();
    final t0 = samples.isNotEmpty ? (samples.first[0] as num).toDouble() : 0.0;
    final t1 = samples.isNotEmpty ? (samples.last[0] as num).toDouble() : 1.0;
    final markers = <double>[];
    final downs = Map<String, dynamic>.from((m['links_down'] as Map?) ?? const {});
    downs.forEach((iface, times) {
      for (final x in (times as List)) {
        final tt = (x as num).toDouble();
        if (tt >= t0 && t1 > t0) markers.add((tt - t0) / (t1 - t0));
      }
    });
    final talkers = ((m['talkers'] as List?) ?? const []).cast<Map>();
    final events = ((m['events'] as List?) ?? const []).cast<Map>();
    String n(dynamic v, [String unit = '']) => v == null ? '?' : '${(v as num).toStringAsFixed(0)}$unit';
    return RefreshIndicator(
      onRefresh: onRefresh,
      child: ListView(physics: const AlwaysScrollableScrollPhysics(), padding: const EdgeInsets.all(12), children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text('Right now: broadcasts ${n(st['bcast'], '/s')}  ·  router ${n(st['gw_avg'], ' ms')} avg, '
                  'loss ${n(st['gw_loss'], '%')}', style: t.titleSmall),
              const SizedBox(height: 4),
              Text('Traffic data: ${st['flows'] ?? '?'}', style: t.bodySmall),
              Text('Router log: ${st['syslog'] ?? '?'}', style: t.bodySmall),
              Text('Packet sniffer: ${st['sniffer'] ?? '?'}', style: t.bodySmall),
              const SizedBox(height: 8),
              LineChart(
                height: 150,
                markers: markers,
                series: [ChartSeries('broadcasts/s', bcast, Colors.blue), ChartSeries('router ms', ping, Colors.orange)],
              ),
              Text('Last 10 minutes · red lines = a router port went down', style: t.bodySmall),
            ]),
          ),
        ),
        const SizedBox(height: 8),
        Text('Top bandwidth users', style: t.titleMedium),
        if (talkers.isEmpty)
          const Card(child: ListTile(title: Text('No traffic data yet - see Setup on the PC'))),
        for (final x in talkers)
          Card(
            child: ListTile(
              dense: true,
              title: Text('${(x['name'] ?? '').toString().isEmpty ? x['ip'] : x['name']}'),
              subtitle: Text('${x['ip']}  ·  last 10 min ${fmtBytes(x['last10'] as num?)}'),
              trailing: Text('↓ ${fmtRate((x['down_bps'] as num?)?.toDouble())}\n↑ ${fmtRate((x['up_bps'] as num?)?.toDouble())}',
                  textAlign: TextAlign.right),
            ),
          ),
        const SizedBox(height: 8),
        Text('Events', style: t.titleMedium),
        for (final e in events.take(80))
          ListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            leading: Text(hhmm(e['t'] as num), style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
            title: Text('${e['text']}', style: TextStyle(color: sevColor(context, '${e['sev']}'))),
            subtitle: Text('${e['src']}'),
          ),
      ]),
    );
  }
}
