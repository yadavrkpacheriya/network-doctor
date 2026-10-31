import 'dart:math' as math;

import 'package:flutter/material.dart';

import 'common.dart';

/// Office PC tabs added in 1.3: Summary (cards + setup checklist), Usage (apps, websites, productivity, advice)
/// and Inventory. All data comes from the PC's /api/state snapshot.

const catColors = {'work': Color(0xFF2A78D6), 'neutral': Color(0xFF1BAF7A), 'personal': Color(0xFFEB6834)};
const catLabels = {'work': 'Productive', 'neutral': 'Neutral', 'personal': 'Unproductive'};

Color catColor(String c) => catColors[c] ?? Colors.grey;

String fmtMin(num? m) {
  final v = (m ?? 0).round();
  return v < 60 ? '$v min' : '${v ~/ 60} h ${(v % 60).toString().padLeft(2, '0')}';
}

List<Map<String, dynamic>> _maps(Object? v) =>
    ((v as List?) ?? const []).map((e) => Map<String, dynamic>.from(e as Map)).toList();

// ------------------------------------------------------------------ summary
class SummaryTab extends StatelessWidget {
  const SummaryTab({super.key, required this.s, required this.onRefresh, required this.goTo});
  final Map<String, dynamic> s;
  final Future<void> Function() onRefresh;
  final void Function(int tab) goTo;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final devs = _maps(s['devices']);
    final online = devs.where((d) => d['online'] == true).length;
    final issues = _maps(s['issues']);
    final crit = issues.where((i) => i['sev'] == 'critical').length;
    final warn = issues.where((i) => i['sev'] == 'warning').length;
    final usage = s['usage'] as Map?;
    final today = usage?['today'] as Map?;
    final cats = Map<String, dynamic>.from((today?['cats'] as Map?) ?? const {});
    final total = cats.values.fold<num>(0, (a, b) => a + (b as num));
    num work = 0, pers = 0;
    for (final d in _maps(today?['devices'])) {
      work += (d['work'] as num?) ?? 0;
      pers += (d['personal'] as num?) ?? 0;
    }
    final score = work + pers > 0 ? (100 * work / (work + pers)).round() : null;
    final topApps = _maps(today?['apps']);
    final checklist = _maps(s['checklist']);
    final st = Map<String, dynamic>.from(((s['monitor'] as Map?)?['status'] as Map?) ?? const {});
    final feeds = ['flows', 'syslog'].where((k) => '${st[k] ?? ''}'.contains('receiving')).length;
    final cats2 = <String, int>{};
    for (final d in devs.where((d) => d['online'] == true)) {
      final c = '${d['category'] ?? ''}'.split(' (').first.split(' /').first;
      cats2[c] = (cats2[c] ?? 0) + 1;
    }
    final catLine = (cats2.entries.toList()..sort((a, b) => b.value.compareTo(a.value)))
        .take(4)
        .map((e) => '${e.key}: ${e.value}')
        .join('  ');

    Widget card(String title, String value, String sub, Color? col, int tab) => Expanded(
          child: Card(
            child: InkWell(
              onTap: () => goTo(tab),
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(title, style: t.labelMedium),
                  Text(value, style: t.headlineSmall?.copyWith(fontWeight: FontWeight.w600, color: col)),
                  Text(sub, style: t.bodySmall, maxLines: 3, overflow: TextOverflow.ellipsis),
                ]),
              ),
            ),
          ),
        );

    return RefreshIndicator(
      onRefresh: onRefresh,
      child: ListView(physics: const AlwaysScrollableScrollPhysics(), padding: const EdgeInsets.all(12), children: [
        Text('PC ${s['pc']} (${s['pc_ip']}) · version ${s['version']}', style: t.bodySmall),
        const SizedBox(height: 6),
        Row(children: [
          card('Devices online', '$online', catLine, null, 2),
          card('Problems', '${crit + warn}', crit + warn == 0 ? 'nothing serious' : '$crit critical, $warn warnings',
              crit > 0 ? Colors.red.shade700 : (warn > 0 ? Colors.orange.shade800 : Colors.green.shade700), 1),
        ]),
        Row(children: [
          card('Internet today', total > 0 ? fmtBytes(total) : '-',
              total > 0
                  ? '${score == null ? '' : 'productivity $score% · '}${topApps.isNotEmpty ? 'most: ${topApps.first['app']}' : ''}'
                  : 'needs traffic data from the router',
              null, 3),
          card('Router data', '$feeds of 2', feeds == 2 ? 'traffic data and router log arriving' : 'see checklist below',
              feeds == 2 ? Colors.green.shade700 : Colors.orange.shade800, 5),
        ]),
        const SizedBox(height: 8),
        Text('Open alerts (priority, fix, steps)', style: t.titleMedium),
        if (_maps(s['alerts']).where((a) => a['status'] == 'open').isEmpty)
          const Card(child: ListTile(dense: true, title: Text('No open alerts'))),
        for (final a in _maps(s['alerts']).where((a) => a['status'] == 'open').take(25))
          Card(
            child: ExpansionTile(
              dense: true,
              leading: Icon(Icons.warning_amber_rounded,
                  color: (a['prio'] as num? ?? 3) <= 1
                      ? Colors.red.shade700
                      : (a['prio'] as num? ?? 3) == 2
                          ? Colors.orange.shade800
                          : Colors.blue.shade700),
              title: Text('${a['text']}', maxLines: 3, overflow: TextOverflow.ellipsis),
              subtitle: Text('${a['prio_text']} · '
                  '${DateTime.fromMillisecondsSinceEpoch((((a['t'] as num?) ?? 0) * 1000).round()).toString().substring(0, 16)}'
                  '${(a['count'] as num? ?? 1) > 1 ? ' · ${a['count']}×' : ''}\nFix: ${a['fix']}'),
              childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
              expandedCrossAxisAlignment: CrossAxisAlignment.start,
              children: [
                for (final (i, step) in ((a['steps'] as List?) ?? const []).indexed)
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 2),
                    child: Text('${i + 1}. $step'),
                  ),
                const SizedBox(height: 4),
                Text('Automatic fixes: PC app > Alerts > Troubleshoot.', style: t.bodySmall),
              ],
            ),
          ),
        const SizedBox(height: 8),
        Text('Setup checklist', style: t.titleMedium),
        if (checklist.isEmpty)
          const Card(child: ListTile(title: Text('Update Network Doctor on the PC to 3.13 or newer to see this.'))),
        for (final c in checklist)
          Card(
            child: ListTile(
              dense: true,
              leading: Icon(
                  c['ok'] == true
                      ? Icons.check_circle
                      : c['ok'] == null
                          ? Icons.radio_button_unchecked
                          : Icons.cancel,
                  color: c['ok'] == true ? Colors.green.shade700 : (c['ok'] == null ? Colors.grey : Colors.red.shade700)),
              title: Text('${c['title']}'),
              subtitle: Text('${c['detail']}'),
            ),
          ),
        const SizedBox(height: 4),
        Text('Fix the red lines on the PC: Network Doctor > Home.', style: t.bodySmall),
      ]),
    );
  }
}

// ------------------------------------------------------------------ usage
class UsageTab extends StatefulWidget {
  const UsageTab({super.key, required this.s, required this.onRefresh});
  final Map<String, dynamic> s;
  final Future<void> Function() onRefresh;

  @override
  State<UsageTab> createState() => _UsageTabState();
}

class _UsageTabState extends State<UsageTab> {
  bool _week = false;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final usage = widget.s['usage'] as Map?;
    if (usage == null) {
      return const Center(
          child: Padding(
              padding: EdgeInsets.all(24),
              child: Text('No usage data from the PC yet. It needs Network Doctor 3.13 or newer on the PC, '
                  'and traffic data (NetFlow) from the router.')));
    }
    final sm = Map<String, dynamic>.from((usage[_week ? 'week' : 'today'] as Map?) ?? const {});
    final cats = Map<String, dynamic>.from((sm['cats'] as Map?) ?? const {});
    final total = cats.values.fold<num>(0, (a, b) => a + (b as num));
    final apps = _maps(sm['apps']);
    final sites = _maps(sm['sites']);
    final devs = _maps(sm['devices']);
    final insights = _maps(usage['insights']);
    final double maxApp = apps.isEmpty ? 1.0 : math.max(1.0, ((apps.first['bytes'] as num?) ?? 1).toDouble());
    num work = 0, pers = 0;
    for (final d in devs) {
      work += (d['work'] as num?) ?? 0;
      pers += (d['personal'] as num?) ?? 0;
    }
    final score = work + pers > 0 ? (100 * work / (work + pers)).round() : null;
    return RefreshIndicator(
      onRefresh: widget.onRefresh,
      child: ListView(physics: const AlwaysScrollableScrollPhysics(), padding: const EdgeInsets.all(12), children: [
        SegmentedButton<bool>(
          segments: const [ButtonSegment(value: false, label: Text('Today')), ButtonSegment(value: true, label: Text('7 days'))],
          selected: {_week},
          onSelectionChanged: (v) => setState(() => _week = v.first),
        ),
        const SizedBox(height: 8),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text('${fmtBytes(total)} internet traffic', style: t.titleMedium),
              Text('Productive ${fmtMin(work)} · unproductive ${fmtMin(pers)}'
                  '${score == null ? '' : ' · productivity $score%'}', style: t.bodySmall),
              const SizedBox(height: 8),
              if (total > 0) _CatBar(cats: cats, total: total),
              const SizedBox(height: 6),
              Wrap(spacing: 12, children: [
                for (final c in ['work', 'neutral', 'personal'])
                  Row(mainAxisSize: MainAxisSize.min, children: [
                    Container(width: 10, height: 10, decoration: BoxDecoration(color: catColor(c), borderRadius: BorderRadius.circular(3))),
                    const SizedBox(width: 4),
                    Text(catLabels[c]!, style: t.bodySmall),
                  ]),
              ]),
            ]),
          ),
        ),
        const SizedBox(height: 8),
        Text('Apps', style: t.titleMedium),
        if (apps.isEmpty) const Card(child: ListTile(title: Text('No app traffic recorded for this period yet'))),
        for (final a in apps.take(15))
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 4),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                Expanded(child: Text('${a['app']}', overflow: TextOverflow.ellipsis)),
                Text('${fmtBytes(a['bytes'] as num?)} · ${fmtMin(a['minutes'] as num?)}', style: t.bodySmall),
              ]),
              const SizedBox(height: 2),
              ClipRRect(
                borderRadius: BorderRadius.circular(4),
                child: LinearProgressIndicator(
                  value: math.min(1.0, math.max(0.02, ((a['bytes'] as num?) ?? 0).toDouble() / maxApp)),
                  minHeight: 8,
                  color: catColor('${a['cat']}'),
                  backgroundColor: Theme.of(context).colorScheme.surfaceContainerHighest,
                ),
              ),
              Text('${a['group'] ?? ''} · ${catLabels['${a['cat']}'] ?? ''}', style: t.labelSmall),
            ]),
          ),
        const SizedBox(height: 8),
        Text('People / devices', style: t.titleMedium),
        for (final d in devs.take(40))
          Card(
            child: ListTile(
              dense: true,
              title: Text('${d['name']}${'${d['dept'] ?? ''}'.isEmpty ? '' : '  ·  ${d['dept']}'}'),
              subtitle: Text('${fmtBytes(d['bytes'] as num?)} · productive ${fmtMin(d['work'] as num?)} · '
                  'unproductive ${fmtMin(d['personal'] as num?)}'
                  '${'${d['top'] ?? ''}'.isEmpty ? '' : '\nmost unproductive: ${d['top']}'}'),
              trailing: Text(d['score'] == null ? '-' : '${d['score']}%',
                  style: t.titleMedium?.copyWith(
                      color: d['score'] == null
                          ? null
                          : ((d['score'] as num) >= 70
                              ? Colors.green.shade700
                              : ((d['score'] as num) >= 40 ? Colors.orange.shade800 : Colors.red.shade700)))),
            ),
          ),
        const SizedBox(height: 8),
        Text('Websites', style: t.titleMedium),
        for (final x in sites.take(25))
          ListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            leading: Container(width: 10, height: 10, decoration: BoxDecoration(color: catColor('${x['cat']}'), shape: BoxShape.circle)),
            title: Text('${x['site']}'),
            subtitle: Text('${x['app']}'),
            trailing: Text(
                '${fmtBytes(x['bytes'] as num?)}${((x['visits'] as num?) ?? 0) > 0 ? '\n${x['visits']} visits' : ''}',
                textAlign: TextAlign.right,
                style: t.bodySmall),
          ),
        const SizedBox(height: 8),
        Text('What the advisor learned', style: t.titleMedium),
        for (final i in insights)
          Card(
            color: i['sev'] == 'warning' ? Colors.orange.withValues(alpha: 0.12) : null,
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text('${i['title']}', style: t.titleSmall),
                Text('${i['text']}'),
                if ('${i['action'] ?? ''}'.isNotEmpty)
                  Padding(
                    padding: const EdgeInsets.only(top: 4),
                    child: Text('What to do: ${i['action']}', style: TextStyle(color: Colors.green.shade700)),
                  ),
              ]),
            ),
          ),
        const SizedBox(height: 4),
        Text('Change categories on the PC: Usage > App list (per department too).', style: t.bodySmall),
      ]),
    );
  }
}

class _CatBar extends StatelessWidget {
  const _CatBar({required this.cats, required this.total});
  final Map<String, dynamic> cats;
  final num total;

  @override
  Widget build(BuildContext context) {
    return ClipRRect(
      borderRadius: BorderRadius.circular(5),
      child: SizedBox(
        height: 14,
        child: Row(children: [
          for (final c in ['work', 'neutral', 'personal'])
            if (((cats[c] as num?) ?? 0) > 0)
              Expanded(
                flex: math.max(1, (1000 * ((cats[c] as num?) ?? 0) / total).round()),
                child: Container(color: catColor(c)),
              ),
        ]),
      ),
    );
  }
}

// ------------------------------------------------------------------ inventory
class InventoryTab extends StatefulWidget {
  const InventoryTab({super.key, required this.s, required this.onRefresh});
  final Map<String, dynamic> s;
  final Future<void> Function() onRefresh;

  @override
  State<InventoryTab> createState() => _InventoryTabState();
}

class _InventoryTabState extends State<InventoryTab> {
  String _q = '';
  bool _onlyPcs = false;
  bool _onlyAttention = false;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final rows = _maps(widget.s['inventory']).where((r) {
      if (_onlyPcs && '${r['model'] ?? ''}'.isEmpty) return false;
      if (_onlyAttention && '${r['flag_text'] ?? ''}'.isEmpty) return false;
      if (_q.isEmpty) return true;
      return r.values.join(' ').toLowerCase().contains(_q.toLowerCase());
    }).toList();
    return RefreshIndicator(
      onRefresh: widget.onRefresh,
      child: ListView(physics: const AlwaysScrollableScrollPhysics(), padding: const EdgeInsets.all(12), children: [
        TextField(
          decoration: const InputDecoration(prefixIcon: Icon(Icons.search), hintText: 'Search name, IP, MAC, serial, user', isDense: true),
          onChanged: (v) => setState(() => _q = v),
        ),
        Row(children: [
          Checkbox(value: _onlyPcs, onChanged: (v) => setState(() => _onlyPcs = v ?? false)),
          const Flexible(child: Text('PCs with details')),
          Checkbox(value: _onlyAttention, onChanged: (v) => setState(() => _onlyAttention = v ?? false)),
          const Flexible(child: Text('Needs attention')),
          const Spacer(),
          Text('${rows.length}', style: t.bodySmall),
        ]),
        if (_maps(widget.s['inventory']).isEmpty)
          const Card(child: ListTile(title: Text('No inventory from the PC yet (Network Doctor 3.14 or newer on the PC).'))),
        for (final r in rows.take(400))
          Card(
            child: ExpansionTile(
              leading: Icon(r['online'] == true ? Icons.circle : Icons.circle_outlined,
                  size: 12, color: r['online'] == true ? Colors.green.shade700 : Colors.grey),
              title: Text('${'${r['name'] ?? ''}'.isEmpty ? r['ip'] : r['name']}'),
              subtitle: Text('${r['ip']} · ${r['category'] ?? ''}${'${r['dept'] ?? ''}'.isEmpty ? '' : ' · ${r['dept']}'}'
                  '${'${r['flag_text'] ?? ''}'.isEmpty ? '' : '\n⚠ ${r['flag_text']}'}'),
              childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
              expandedCrossAxisAlignment: CrossAxisAlignment.start,
              children: [
                for (final f in const [
                  ['MAC', 'mac'], ['Maker', 'vendor'], ['Host name', 'host'], ['Location', 'location'],
                  ['Status', 'status'], ['First seen', 'first_seen'], ['Windows', 'os'], ['Model', 'model'],
                  ['Serial no.', 'serial'], ['CPU', 'cpu'], ['RAM GB', 'ram_gb'], ['Disk GB', 'disk_gb'],
                  ['Free GB', 'disk_free_gb'], ['User', 'user'], ['RAM sticks', 'ram_detail'],
                  ['Disks', 'disks'], ['Graphics', 'gpu'], ['Monitors', 'monitors'], ['Keyboard', 'keyboards'],
                  ['Mouse', 'mice'], ['Printers', 'printers'], ['Antivirus', 'antivirus'], ['Firewall', 'firewall'],
                  ['Drivers', 'driver_problems'], ['Last update', 'last_update'], ['BIOS', 'bios'],
                  ['Programs', 'software_count'], ['Attention', 'flag_text'],
                ])
                  if ('${r[f[1]] ?? ''}'.isNotEmpty)
                    Padding(
                      padding: const EdgeInsets.symmetric(vertical: 1),
                      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        SizedBox(width: 92, child: Text(f[0], style: t.labelMedium)),
                        Expanded(child: SelectableText('${r[f[1]]}')),
                      ]),
                    ),
              ],
            ),
          ),
      ]),
    );
  }
}
