import 'package:flutter/material.dart';

/// Is the Wi-Fi this phone is joined to right now password-protected? Useful away from the office -
/// on an unfamiliar or public network there is no way to know who else is on it.
///
/// Reads one thing from Android (WifiInfo.currentSecurityType, via MainActivity.kt) and nothing else:
/// no SSID, no other devices, no traffic. Needs Android 13+; older phones always show "unknown" rather
/// than a guess.
enum WifiSecurity { secured, weak, open, unknown }

class WifiSecurityCheck {
  static const _channel = MethodChannel('network_doctor/wifi_security');

  // WifiInfo.SECURITY_TYPE_* (android.net.wifi.WifiInfo), mirrored here so no Android-only import is
  // needed on the Dart side.
  static const _open = 0;
  static const _wep = 1;
  static const _owe = 6; // "enhanced open": encrypted over the air, but still no password - anyone can join

  /// The raw WifiInfo.SECURITY_TYPE_* value, or null if it can't be read (pre-Android 13, not on
  /// Wi-Fi, or any error).
  static Future<int?> rawType() async {
    try {
      return await _channel.invokeMethod<int>('securityType');
    } catch (_) {
      return null;
    }
  }

  static WifiSecurity classify(int? type) {
    if (type == null || type < 0) return WifiSecurity.unknown;
    if (type == _open || type == _owe) return WifiSecurity.open;
    if (type == _wep) return WifiSecurity.weak;
    return WifiSecurity.secured; // PSK, EAP, SAE (WPA3), WAPI, Passpoint, and anything added later
  }

  static Future<WifiSecurity> check() async => classify(await rawType());
}

extension WifiSecurityText on WifiSecurity {
  String get label {
    switch (this) {
      case WifiSecurity.secured:
        return 'Password-protected';
      case WifiSecurity.weak:
        return 'Weak (WEP)';
      case WifiSecurity.open:
        return 'Open - no password';
      case WifiSecurity.unknown:
        return 'Could not check';
    }
  }

  String get advice {
    switch (this) {
      case WifiSecurity.secured:
        return 'This network needs a password. Still only as trustworthy as whoever runs it.';
      case WifiSecurity.weak:
        return 'WEP can be broken in minutes. Avoid signing in to anything here, including this PC\'s remote access.';
      case WifiSecurity.open:
        return 'Anyone nearby could potentially see unencrypted traffic. Avoid signing in to anything sensitive; '
            'reach your office PC through its Remote access address instead of trusting this network.';
      case WifiSecurity.unknown:
        return 'This phone\'s Android version cannot report this. Treat an unfamiliar network as unsafe until '
            'you know otherwise.';
    }
  }

  IconData get icon {
    switch (this) {
      case WifiSecurity.secured:
        return Icons.lock_outline;
      case WifiSecurity.weak:
        return Icons.lock_open;
      case WifiSecurity.open:
        return Icons.no_encryption;
      case WifiSecurity.unknown:
        return Icons.help_outline;
    }
  }

  Color color(BuildContext context) {
    switch (this) {
      case WifiSecurity.secured:
        return Colors.green.shade700;
      case WifiSecurity.weak:
      case WifiSecurity.open:
        return Colors.red.shade700;
      case WifiSecurity.unknown:
        return Colors.orange.shade800;
    }
  }
}
