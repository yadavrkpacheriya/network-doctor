import 'package:flutter/material.dart';
import 'package:network_info_plus/network_info_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../net/dvrip.dart';
import '../net/nvr_dupes.dart';
import '../net/probe.dart';
import '../net/tools.dart';

/// NVR / DVR cameras - phone-only, over office Wi-Fi. Finds every recorder on the network, reads the cameras
/// ALREADY ADDED to each, then shows: duplicate cameras (same camera on two channels, or on two recorders) and
/// ORPHAN cameras (live on the network but in no recorder = not being recorded). Each duplicate shows exactly
/// where it sits (which NVR + channel). Read-only; nothing is deleted here.
class NvrScreen extends StatefulWidget {
  const NvrScreen({super.key});
  @override
  State<NvrScreen> createState() => _NvrScreenState();
}

class _NvrScreenState extends State<NvrScreen> {
  final _user = TextEditingController(text: 'admin');
  final _pass = TextEditingController();
  bool _busy = false;
  String _status = '';
  List<NvrRecorder> _recorders = [];
  DupResult? _dup;
  bool _lowCoverage = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final p = await SharedPreferences.getInstance();
    if (!mounted) return;
    setState(() {
      _user.text = p.getString('nvr_user') ?? 'admin';
      _pass.text = p.getString('nvr_pass') ?? ''; // saved for future use so it isn't re-typed each run
    });
  }

  void _set(VoidCallback fn) {
    if (mounted) setState(fn);
  }

  Future<void> _scan() async {
    final p = await SharedPreferences.getInstance();
    await p.setString('nvr_user', _user.text.trim());
    await p.setString('nvr_pass', _pass.text); // remember for next time
    _set(() {
      _busy = true;
      _status = 'Finding the network...';
      _recorders = [];
      _dup = null;
    });
    try {
      final ip = await NetworkInfo().getWifiIP();
      final sub = ip == null ? null : subnetOf(ip);
      if (sub == null) {
        _set(() => _status = 'Could not read the Wi-Fi network. Connect to the office Wi-Fi and try again.');
        return;
      }
      final hosts = hostsOf(ip!, sub.prefix);
      // 1) find recorders (DVRIP 34567 open) and cameras (RTSP/web) in one sweep
      final recorderIps = <String>[];
      final camLive = <(String, String)>[];
      var done = 0;
      _set(() => _status = 'Looking for recorders and cameras... 0/${hosts.length}');
      await pool<String>(hosts, 40, (h) async {
        final open = await portScan(h, ports: const [34567, 554, 80, 8000], cancelled: () => !mounted);
        if (open.contains(34567)) recorderIps.add(h);
        if (open.contains(554) || open.contains(80) || open.contains(8000)) camLive.add((h, ''));
        done++;
        if (done % 16 == 0) _set(() => _status = 'Looking for recorders and cameras... $done/${hosts.length}');
      }, cancelled: () => !mounted);

      if (recorderIps.isEmpty) {
        _set(() => _status = 'No DVR/NVR found on this network (nothing answering on port 34567).');
        return;
      }
      // 2) log in to each recorder and read its channels
      final recs = <NvrRecorder>[];
      var i = 0;
      for (final rip in recorderIps) {
        i++;
        _set(() => _status = 'Reading recorder $i of ${recorderIps.length} ($rip)...');
        try {
          final chans = await listChannels(rip, _user.text.trim(), _pass.text);
          recs.add(NvrRecorder(rip, rip, chans));
        } catch (e) {
          recs.add(NvrRecorder(rip, '$rip (login failed)', const []));
        }
      }
      // 3) duplicates + orphans. The orphan check ("live but in no recorder") is only trustworthy when most
      // channels resolved to a camera IP. On recorders that hide channel IPs, almost nothing resolves, so every
      // camera would look like an orphan - a false alarm. Only run it when coverage is good.
      final dup = findDuplicates(recs);
      final totalCh = recs.fold<int>(0, (s, r) => s + r.channels.length);
      final withIp = recs.fold<int>(0, (s, r) => s + r.channels.where((c) => c.ip.trim().isNotEmpty).length);
      final lowCoverage = totalCh > 0 && withIp < 0.6 * totalCh;
      final orphans = lowCoverage ? <OrphanCam>[] : findOrphans(recs, camLive);
      _set(() {
        _recorders = recs;
        _dup = DupResult(dup.within, dup.cross, orphans);
        _lowCoverage = lowCoverage;
        final okRec = recs.where((r) => r.channels.isNotEmpty).length;
        final orphanTxt = lowCoverage
            ? 'missing-camera list hidden (recorders don\'t report channel IPs).'
            : '${orphans.length} camera(s) not in any recorder.';
        _status = '$okRec of ${recs.length} recorder(s) read. '
            '${dup.within.length} within-duplicate(s), ${dup.cross.length} across-recorder duplicate(s). $orphanTxt';
      });
    } catch (e) {
      _set(() => _status = 'Error: $e');
    } finally {
      _set(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final dup = _dup;
    return Scaffold(
      appBar: AppBar(title: const Text('NVR / DVR cameras')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text('Finds every DVR/NVR on the office Wi-Fi, reads the cameras already added to each, and shows '
              'duplicates and cameras that are live but in no recorder. No PC needed.', style: t.bodySmall),
          const SizedBox(height: 12),
          Row(children: [
            Expanded(child: TextField(controller: _user, decoration: const InputDecoration(labelText: 'Camera/NVR user', isDense: true))),
            const SizedBox(width: 10),
            Expanded(child: TextField(controller: _pass, obscureText: true, decoration: const InputDecoration(labelText: 'Password', isDense: true))),
          ]),
          const SizedBox(height: 12),
          FilledButton.icon(
              onPressed: _busy ? null : _scan,
              icon: _busy
                  ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                  : const Icon(Icons.search),
              label: Text(_busy ? 'Scanning...' : 'Scan all DVR/NVR')),
          if (_status.isNotEmpty) ...[
            const SizedBox(height: 10),
            Text(_status, style: t.bodySmall),
          ],
          if (dup != null) ...[
            const Divider(height: 28),
            if (_lowCoverage)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Text(
                    "These recorders don't report channel IPs, so the 'not in any recorder' list is unreliable and "
                    'is hidden. Duplicates found by channel name/IP are still shown.',
                    style: TextStyle(color: Colors.orange.shade900, fontSize: 12)),
              ),
            if (dup.isEmpty && !_lowCoverage)
              Row(children: [
                Icon(Icons.check_circle, color: Colors.green.shade700),
                const SizedBox(width: 8),
                const Expanded(child: Text('No duplicates, and every live camera is in a recorder.')),
              ]),
            if (dup.cross.isNotEmpty) ...[
              _sectionTitle('Same camera on 2+ recorders (recording twice)', Colors.red.shade700),
              for (final c in dup.cross)
                _card(Icons.content_copy, Colors.red.shade700, c.camera,
                    c.places.map((p) => 'on ${p.nvrName}  ·  channel ${p.chan}').join('\n')),
            ],
            if (dup.within.isNotEmpty) ...[
              _sectionTitle('Same camera on 2 channels of one recorder', Colors.orange.shade800),
              for (final w in dup.within)
                _card(Icons.filter_2, Colors.orange.shade800, w.camera,
                    'on ${w.nvrName}  ·  channels ${w.channels.join(', ')}'),
            ],
            if (dup.orphans.isNotEmpty) ...[
              _sectionTitle('Live cameras NOT in any recorder (not being recorded)', Colors.red.shade700),
              for (final o in dup.orphans)
                _card(Icons.videocam_off, Colors.red.shade700, o.ip, o.name.isNotEmpty ? o.name : 'not added to any DVR/NVR'),
            ],
          ],
          if (_recorders.isNotEmpty) ...[
            const Divider(height: 28),
            Text('Cameras added to each recorder', style: t.titleSmall),
            for (final r in _recorders) _recorderCard(r),
          ],
        ],
      ),
    );
  }

  Widget _sectionTitle(String s, Color c) => Padding(
        padding: const EdgeInsets.only(top: 12, bottom: 4),
        child: Text(s, style: TextStyle(fontWeight: FontWeight.bold, color: c)),
      );

  Widget _card(IconData icon, Color c, String title, String sub) => Card(
        margin: const EdgeInsets.symmetric(vertical: 3),
        child: ListTile(
          dense: true,
          leading: Icon(icon, color: c),
          title: Text(title, style: const TextStyle(fontWeight: FontWeight.w600)),
          subtitle: Text(sub),
        ),
      );

  Widget _recorderCard(NvrRecorder r) {
    return Card(
      margin: const EdgeInsets.symmetric(vertical: 4),
      child: ExpansionTile(
        leading: const Icon(Icons.dvr),
        title: Text(r.name),
        subtitle: Text(r.channels.isEmpty ? 'could not read channels' : '${r.channels.length} camera(s) added'),
        children: [
          for (final ch in r.channels)
            ListTile(
              dense: true,
              leading: CircleAvatar(radius: 12, child: Text('${ch.chan}', style: const TextStyle(fontSize: 11))),
              title: Text(ch.name),
              subtitle: Text(ch.ip.isNotEmpty ? ch.ip : 'no IP read'),
              trailing: ch.online == null
                  ? null
                  : Icon(ch.online! ? Icons.circle : Icons.circle_outlined,
                      size: 12, color: ch.online! ? Colors.green : Colors.grey),
            ),
        ],
      ),
    );
  }
}
