import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:url_launcher/url_launcher.dart';

import '../main.dart' show appVersion;
import '../net/update.dart';

class AboutScreen extends StatelessWidget {
  const AboutScreen({super.key});

  static final _repo = Uri.parse('https://github.com/yadavrkpacheriya/network-doctor');
  static final _privacy = Uri.parse('https://github.com/yadavrkpacheriya/network-doctor/blob/main/mobile/PRIVACY.md');

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: const Text('About')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        Row(children: [
          Icon(Icons.health_and_safety, size: 48, color: Theme.of(context).colorScheme.primary),
          const SizedBox(width: 12),
          Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('Network Doctor', style: t.titleLarge),
            Text('Version $appVersion'),
          ]),
        ]),
        const SizedBox(height: 12),
        const UpdateCard(),
        const SizedBox(height: 16),
        const Text('Finds the devices on your Wi-Fi, sorts them into categories, and lets you ping them and open '
            'them in the browser. Paired with the Network Doctor PC app it also shows loops, ports going down, '
            'IP conflicts, rogue DHCP servers, bandwidth per device and dangerous sites.'),
        const SizedBox(height: 16),
        Text('What a phone can and cannot see', style: t.titleSmall),
        const Text('• Android and iPhone do not allow apps to read other devices\' MAC addresses or their traffic.\n'
            '• Devices that block every connection may not appear in the phone scan.\n'
            '• The PC app sees everything; the "Office PC" tab shows its results.'),
        const SizedBox(height: 16),
        Text('Privacy', style: t.titleSmall),
        const Text('Everything stays on your network: no accounts, no tracking, no ads. Scans only talk to devices '
            'on your own Wi-Fi. The only internet request is the check for a new version on GitHub (once a day; '
            'it can be switched off above).'),
        const SizedBox(height: 16),
        Wrap(spacing: 8, children: [
          OutlinedButton.icon(
              onPressed: () => launchUrl(_privacy, mode: LaunchMode.externalApplication),
              icon: const Icon(Icons.privacy_tip_outlined),
              label: const Text('Privacy policy')),
          OutlinedButton.icon(
              onPressed: () => launchUrl(_repo, mode: LaunchMode.externalApplication),
              icon: const Icon(Icons.code),
              label: const Text('Source code')),
        ]),
      ]),
    );
  }
}


/// "Check for updates": newest Android release on GitHub, and a button that downloads the APK.
class UpdateCard extends StatefulWidget {
  const UpdateCard({super.key});

  @override
  State<UpdateCard> createState() => _UpdateCardState();
}

class _UpdateCardState extends State<UpdateCard> {
  String _msg = '';
  bool _busy = false;
  bool _auto = true;
  AppUpdate? _u;

  @override
  void initState() {
    super.initState();
    _loadAuto();
  }

  Future<void> _loadAuto() async {
    try {
      final p = await SharedPreferences.getInstance();
      if (mounted) setState(() => _auto = p.getBool('update_auto') ?? true);
    } catch (_) {}
  }

  Future<void> _check() async {
    setState(() {
      _busy = true;
      _msg = 'Checking GitHub...';
    });
    try {
      final u = await checkForUpdate(appVersion);
      setState(() {
        _u = u;
        _msg = u == null ? 'You have the newest version ($appVersion).' : 'Version ${u.version} is available.';
      });
    } on UpdateError catch (e) {
      setState(() => _msg = e.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final u = _u;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            const Icon(Icons.system_update),
            const SizedBox(width: 8),
            Expanded(child: Text('Updates', style: Theme.of(context).textTheme.titleSmall)),
            FilledButton.tonal(onPressed: _busy ? null : _check, child: const Text('Check for updates')),
          ]),
          if (_msg.isNotEmpty) Padding(padding: const EdgeInsets.only(top: 8), child: Text(_msg)),
          if (u != null)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Wrap(spacing: 8, children: [
                FilledButton.icon(
                    onPressed: () => launchUrl(Uri.parse(u.apkUrl), mode: LaunchMode.externalApplication),
                    icon: const Icon(Icons.download),
                    label: Text('Download ${u.version}')),
                OutlinedButton(
                    onPressed: () => launchUrl(Uri.parse(u.pageUrl), mode: LaunchMode.externalApplication),
                    child: const Text("What's new")),
              ]),
            ),
          if (u != null)
            const Padding(
              padding: EdgeInsets.only(top: 6),
              child: Text('After the download, open the file and tap Install (allow "Install unknown apps" for the '
                  'browser once). Your pairing with the PC is kept.'),
            ),
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            dense: true,
            title: const Text('Check automatically once a day'),
            value: _auto,
            onChanged: (v) async {
              setState(() => _auto = v);
              try {
                (await SharedPreferences.getInstance()).setBool('update_auto', v);
              } catch (_) {}
            },
          ),
        ]),
      ),
    );
  }
}
