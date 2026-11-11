import 'dart:async';
import 'dart:ui';

import 'package:flutter/material.dart';
import 'package:package_info_plus/package_info_plus.dart';

import 'net/telemetry.dart';
import 'net/update.dart';

import 'screens/about_screen.dart';
import 'screens/pc_screen.dart';
import 'screens/scan_screen.dart';
import 'screens/tools_screen.dart';

/// The installed app's real version (e.g. "1.13.0"), read from the Android package itself. This used to
/// be a string literal here that had to be hand-bumped on every release and was repeatedly forgotten -
/// which showed as a stale "Version 1.12.0" in About and an "update available" nag that never went away
/// even after installing the new version, since the compare was against this same frozen string. Starts
/// as 'unknown' only until main() below fills it in, before the UI is ever built.
String appVersion = 'unknown';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  try {
    appVersion = (await PackageInfo.fromPlatform()).version;
  } catch (_) {}
  // Unhandled errors would otherwise just vanish - no console is open on a phone. Both hooks only
  // ever COUNT a sanitised crash (nd_telemetry.dart is a no-op until the person opts in); they never
  // change how the error is shown or reported to anyone else.
  FlutterError.onError = (details) {
    Telemetry.instance.noteError('flutter', details.exception, details.stack);
    FlutterError.presentError(details);
  };
  PlatformDispatcher.instance.onError = (error, stack) {
    Telemetry.instance.noteError('async', error, stack);
    return false; // still let the platform's own default handling happen
  };
  runApp(const NetworkDoctorApp());
}

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
    Telemetry.instance.load().then((_) => _sendTelemetry());
    // the app may stay open past 15:00: look again every 10 minutes (only goes online once a day)
    _updTimer = Timer.periodic(const Duration(minutes: 10), (_) {
      _check();
      _sendTelemetry();
    });
  }

  void _check() {
    dailyCheck(appVersion).then((u) {
      if (mounted && u != null) setState(() => _update = u);
    });
  }

  void _sendTelemetry() {
    if (!Telemetry.instance.enabled) return;
    Telemetry.instance.sendNow(appVersion: appVersion);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _check();
      _sendTelemetry();
    }
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
                    // the real download+install (with progress and checksum verification) lives on the
                    // About tab's Updates card - this just gets the user there instead of opening a browser
                    onPressed: () => setState(() {
                          _update = null;
                          _tab = 3;
                        }),
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
