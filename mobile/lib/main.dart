import 'dart:async';

import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import 'net/update.dart';

import 'screens/about_screen.dart';
import 'screens/pc_screen.dart';
import 'screens/scan_screen.dart';
import 'screens/tools_screen.dart';

const appVersion = '1.6.0';

void main() => runApp(const NetworkDoctorApp());

class NetworkDoctorApp extends StatelessWidget {
  const NetworkDoctorApp({super.key});

  @override
  Widget build(BuildContext context) {
    const seed = Color(0xFF0B6BCB);
    return MaterialApp(
      title: 'Network Doctor',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(colorSchemeSeed: seed, useMaterial3: true, brightness: Brightness.light),
      darkTheme: ThemeData(colorSchemeSeed: seed, useMaterial3: true, brightness: Brightness.dark),
      home: const HomeShell(),
    );
  }
}

class HomeShell extends StatefulWidget {
  const HomeShell({super.key});

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> with WidgetsBindingObserver {
  int _tab = 0;
  AppUpdate? _update;
  Timer? _updTimer;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _check();
    // the app may stay open past 15:00: look again every 10 minutes (only goes online once a day)
    _updTimer = Timer.periodic(const Duration(minutes: 10), (_) => _check());
  }

  void _check() {
    dailyCheck(appVersion).then((u) {
      if (mounted && u != null) setState(() => _update = u);
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) _check();
  }

  @override
  void dispose() {
    _updTimer?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final u = _update;
    return Scaffold(
      body: Column(children: [
        if (u != null)
          SafeArea(
            bottom: false,
            child: MaterialBanner(
              leading: const Icon(Icons.system_update),
              content: Text('Network Doctor ${u.version} is available (you have $appVersion).'),
              actions: [
                TextButton(onPressed: () => setState(() => _update = null), child: const Text('Later')),
                FilledButton(
                    onPressed: () => launchUrl(Uri.parse(u.apkUrl), mode: LaunchMode.externalApplication),
                    child: const Text('Update')),
              ],
            ),
          ),
        Expanded(
            child: IndexedStack(index: _tab, children: const [ScanScreen(), ToolsScreen(), PcScreen(), AboutScreen()])),
      ]),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (i) => setState(() => _tab = i),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.wifi_find_outlined), selectedIcon: Icon(Icons.wifi_find), label: 'This network'),
          NavigationDestination(icon: Icon(Icons.handyman_outlined), selectedIcon: Icon(Icons.handyman), label: 'Tools'),
          NavigationDestination(icon: Icon(Icons.computer_outlined), selectedIcon: Icon(Icons.computer), label: 'Office PC'),
          NavigationDestination(icon: Icon(Icons.info_outline), selectedIcon: Icon(Icons.info), label: 'About'),
        ],
      ),
    );
  }
}
