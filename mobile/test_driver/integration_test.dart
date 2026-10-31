import 'dart:io';

import 'package:integration_test/integration_test_driver_extended.dart';

/// Saves every screenshot the screen test takes into build/screens/ on the computer running the test.
Future<void> main() => integrationDriver(onScreenshot: (name, bytes, [args]) async {
      final f = File('build/screens/$name.png');
      await f.create(recursive: true);
      await f.writeAsBytes(bytes);
      return true;
    });
