import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import '../main.dart' show appVersion;

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
        const Text('Everything stays on your network. The app sends nothing to the internet: no accounts, no '
            'tracking, no ads. Scans only talk to devices on your own Wi-Fi.'),
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
