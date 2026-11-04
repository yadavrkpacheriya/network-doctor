package io.github.yadavrkpacheriya.network_doctor

import android.content.Context
import android.net.wifi.WifiManager
import android.os.Build
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * One small native call Flutter has no plugin for: which security type the Wi-Fi this phone is
 * currently joined to is using (open / WEP / WPA-and-up). WifiInfo.getCurrentSecurityType() (added in
 * Android 13 specifically so apps would not need location access just to ask this) needs no extra
 * permission - nothing else about the network (its name, other devices, traffic) is read here or by
 * this channel at all. On an older Android this always answers null; the Dart side then shows the
 * check as "could not tell" rather than guessing.
 */
class MainActivity : FlutterActivity() {
    private val channelName = "network_doctor/wifi_security"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channelName).setMethodCallHandler { call, result ->
            when (call.method) {
                "securityType" -> result.success(currentSecurityType())
                else -> result.notImplemented()
            }
        }
    }

    private fun currentSecurityType(): Int? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return null
        return try {
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            @Suppress("DEPRECATION")
            val info = wm?.connectionInfo ?: return null
            info.currentSecurityType
        } catch (e: Exception) {
            null
        }
    }
}
