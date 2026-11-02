#!/usr/bin/env python3
"""
Adds what Network Doctor needs to the Android / iOS projects that `flutter create` generates.
Safe to run many times (every change is skipped when already present).

Android: network permissions, app name, plain-HTTP to the office PC (LAN only), browser intent query,
         release signing from android/key.properties (Play Store upload key) when it exists.
iOS:     local-network permission text, Bonjour/multicast description, local HTTP allowed, app name.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
changed = []


def edit(path, fn):
    if not os.path.exists(path):
        print(f"skip (missing): {os.path.relpath(path, ROOT)}")
        return
    with open(path, encoding="utf-8") as f:
        old = f.read()
    new = fn(old)
    if new != old:
        with open(path, "w", encoding="utf-8") as f:
            f.write(new)
        changed.append(os.path.relpath(path, ROOT))


# ---------------------------------------------------------------- Android manifest
PERMS = ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE",
         "android.permission.ACCESS_WIFI_STATE", "android.permission.CHANGE_WIFI_MULTICAST_STATE"]


def manifest(s):
    for p in PERMS:
        if p not in s:
            s = s.replace("<application", f'<uses-permission android:name="{p}"/>\n    <application', 1)
    s = re.sub(r'android:label="[^"]*"', 'android:label="Network Doctor"', s, count=1)
    if "usesCleartextTraffic" not in s:
        s = s.replace("<application", '<application\n        android:usesCleartextTraffic="true"', 1)
    if 'android:scheme="https"' not in s:
        intents = ('        <intent><action android:name="android.intent.action.VIEW"/><data android:scheme="https"/></intent>\n'
                   '        <intent><action android:name="android.intent.action.VIEW"/><data android:scheme="http"/></intent>\n')
        if "<queries>" in s:
            s = s.replace("<queries>", "<queries>\n" + intents, 1)
        else:
            s = s.replace("</manifest>", "    <queries>\n" + intents + "    </queries>\n</manifest>", 1)
    return s


# ---------------------------------------------------------------- Android Gradle (Kotlin DSL or Groovy)
KTS_IMPORTS = '''import java.util.Properties
import java.io.FileInputStream

'''
KTS_HEAD = '''val keystoreProperties = Properties()
val keystorePropertiesFile = rootProject.file("key.properties")
if (keystorePropertiesFile.exists()) {
    keystoreProperties.load(FileInputStream(keystorePropertiesFile))
}

'''
KTS_SIGNING = '''    signingConfigs {
        create("release") {
            if (keystorePropertiesFile.exists()) {
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
                storeFile = file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["storePassword"] as String
            }
        }
    }
'''


def gradle_kts(s):
    if "keystorePropertiesFile" not in s:
        # Gradle rule: only imports may come before plugins {}; the key loading goes just before android {}
        s = KTS_IMPORTS + s
        s = re.sub(r"(\n)(android\s*\{)", lambda m: m.group(1) + KTS_HEAD + m.group(2), s, count=1)
        s = re.sub(r"(\nandroid\s*\{\n)", r"\1" + KTS_SIGNING.replace("\\", "\\\\"), s, count=1)
        s = s.replace('signingConfig = signingConfigs.getByName("debug")',
                      'signingConfig = if (keystorePropertiesFile.exists()) signingConfigs.getByName("release") '
                      'else signingConfigs.getByName("debug")')
    return s


GROOVY_HEAD = '''def keystoreProperties = new Properties()
def keystorePropertiesFile = rootProject.file('key.properties')
if (keystorePropertiesFile.exists()) {
    keystoreProperties.load(new FileInputStream(keystorePropertiesFile))
}

'''
GROOVY_SIGNING = '''    signingConfigs {
        release {
            if (keystorePropertiesFile.exists()) {
                keyAlias keystoreProperties['keyAlias']
                keyPassword keystoreProperties['keyPassword']
                storeFile file(keystoreProperties['storeFile'])
                storePassword keystoreProperties['storePassword']
            }
        }
    }
'''


def gradle_groovy(s):
    if "keystorePropertiesFile" not in s:
        s = s.replace("\nandroid {", "\n" + GROOVY_HEAD + "android {", 1)
        s = s.replace("\nandroid {\n", "\nandroid {\n" + GROOVY_SIGNING, 1)
        s = s.replace("signingConfig signingConfigs.debug",
                      "signingConfig keystorePropertiesFile.exists() ? signingConfigs.release : signingConfigs.debug")
    return s


# ---------------------------------------------------------------- iOS Info.plist
PLIST_KEYS = {
    "NSLocalNetworkUsageDescription":
        "<string>Network Doctor scans your Wi-Fi network to find and test devices and to connect to the "
        "Network Doctor PC app.</string>",
    "NSBonjourServices": "<array>\n\t\t<string>_http._tcp</string>\n\t</array>",
    "NSAppTransportSecurity": "<dict>\n\t\t<key>NSAllowsLocalNetworking</key>\n\t\t<true/>\n\t</dict>",
}


def plist(s):
    for k, v in PLIST_KEYS.items():
        if f"<key>{k}</key>" not in s:
            s = s.replace("</dict>\n</plist>", f"\t<key>{k}</key>\n\t{v}\n</dict>\n</plist>", 1)
    s = re.sub(r"(<key>CFBundleDisplayName</key>\s*<string>)[^<]*(</string>)", r"\1Network Doctor\2", s)
    return s


def main():
    edit(os.path.join(ROOT, "android/app/src/main/AndroidManifest.xml"), manifest)
    kts = os.path.join(ROOT, "android/app/build.gradle.kts")
    if os.path.exists(kts):
        edit(kts, gradle_kts)
    else:
        edit(os.path.join(ROOT, "android/app/build.gradle"), gradle_groovy)
    edit(os.path.join(ROOT, "ios/Runner/Info.plist"), plist)
    print("patched:", ", ".join(changed) if changed else "nothing to change")
    return 0


if __name__ == "__main__":
    sys.exit(main())
