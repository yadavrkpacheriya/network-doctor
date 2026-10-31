import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:network_doctor/main.dart' as app;

/// Opens every screen of the phone app (demo office PC) and takes a screenshot of each.
/// Run: flutter drive --driver=test_driver/integration_test.dart --target=integration_test/screens_test.dart
///      --dart-define=ND_DEMO=true
void main() {
  final binding = IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('every screen opens', (tester) async {
    app.main();
    await tester.pumpAndSettle(const Duration(seconds: 3));
    await binding.convertFlutterSurfaceToImage();
    var n = 0;
    Future<void> shot(String name) async {
      await tester.pumpAndSettle(const Duration(milliseconds: 600));
      n++;
      await binding.takeScreenshot('${n.toString().padLeft(2, '0')}-$name');
    }

    await shot('this-network');
    await tester.tap(find.descendant(of: find.byType(NavigationBar), matching: find.text('Tools')));
    await shot('tools');
    await tester.tap(find.descendant(of: find.byType(NavigationBar), matching: find.text('Office PC')));
    await tester.pumpAndSettle(const Duration(seconds: 2));
    const sections = ['Home', 'Alerts', 'Devices', 'Internet & Usage', 'Security', 'Fix & Commands'];
    for (final sec in sections) {
      final tab = find.descendant(of: find.byType(TabBar), matching: find.textContaining(sec));
      await tester.ensureVisible(tab.first);
      await tester.pumpAndSettle();
      await tester.tap(tab.first);
      await tester.pumpAndSettle(const Duration(seconds: 1));
      final chips = find.byType(ChoiceChip);
      final count = chips.evaluate().length;
      if (count == 0) {
        await shot(sec.replaceAll(' ', '-').replaceAll('&', 'and'));
        continue;
      }
      for (var i = 0; i < count; i++) {
        await tester.tap(find.byType(ChoiceChip).at(i));
        final label = ((find.byType(ChoiceChip).at(i).evaluate().first.widget as ChoiceChip).label as Text).data ?? '$i';
        await shot('${sec.replaceAll(' ', '-').replaceAll('&', 'and')}-${label.replaceAll(RegExp(r'[^A-Za-z0-9]+'), '-')}');
      }
    }
    // an alert's Troubleshoot page
    final alertsTab = find.descendant(of: find.byType(TabBar), matching: find.textContaining('Alerts')).first;
    await tester.ensureVisible(alertsTab);
    await tester.pumpAndSettle();
    await tester.tap(alertsTab);
    await tester.pumpAndSettle(const Duration(seconds: 1));
    await tester.tap(find.byType(ChoiceChip).first);
    await tester.pumpAndSettle();
    final first = find.byIcon(Icons.chevron_right);
    if (first.evaluate().isNotEmpty) {
      await tester.tap(first.first);
      await shot('troubleshoot');
      await tester.pageBack();
    }
    await tester.tap(find.descendant(of: find.byType(NavigationBar), matching: find.text('About')));
    await shot('about');
  });
}
