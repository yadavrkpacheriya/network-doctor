# Network Doctor - Privacy Policy

_Last updated: 29 October 2026 (version 3.7)_

Network Doctor is a network diagnostic tool for office and home networks. It is available as a Windows/Mac app and an Android app. This policy explains what the apps do with information.

## In short

- Network Doctor does **not** collect, sell or share personal data.
- There are **no accounts, no advertising and no analytics or tracking**.
- Scan results stay on your own device or on your own office PC.

## What the apps look at

To do their job, the apps examine the local network the device is connected to. This includes device IP addresses, device names, the services devices offer, and the network's response times.

On Windows and Mac only, the app also reads MAC addresses. If the router is set up to send them, it also uses traffic summaries (which addresses talk to which) and router log messages.

This information:
- is processed on the device running the app;
- is stored only on that device: on Windows in `%APPDATA%\NetworkDoctor`, on Mac in `~/Library/Application Support/NetworkDoctor`, and on Android inside the app's private storage;
- is never uploaded to the developer or to any third party.

## Phone app and office PC link

You can pair the Android app with the Network Doctor PC app. The phone then reads the PC's results directly over your local network.

- Pairing needs a one-time code shown on the PC.
- The connection works only between devices on the same local network.
- Requests from the internet are refused.
- No cloud service is involved.

## PC fix script reports

If you use the optional PC fix script on office PCs, each PC sends its computer name, signed-in user name and network adapter MAC addresses to the Network Doctor PC app over your local network (TCP 8787). This needs a secret key built into the script; anything else is refused. The details are stored only on the Network Doctor PC, to name the devices.

## LAN speed test

When you tick *Receiver ON* in *Tools > LAN speed test*, the PC accepts speed tests from other PCs on the office network (TCP 8789) for 60 minutes. Only random test data is exchanged, and addresses from the internet are refused.

## Internet connections the apps make

| Connection | Purpose | What is sent |
|---|---|---|
| GitHub (`api.github.com`, `github.com`) | Check for and download updates (Windows/Mac) | A request for the latest version; no personal data |
| Public block-list sites (abuse.ch, Spamhaus, Emerging Threats, FireHOL, Tor Project) | Download lists of known malicious internet addresses | A normal download request; no personal data |
| `rdap.org` and the regional internet registries | Look up which organisation owns an *internet* server your devices talk to | The internet server's public IP address only - never your own devices' details |
| The device's DNS server | Look up names of devices and servers | The address being looked up |
| Cloudflare (`speed.cloudflare.com`) - only when you press *Run speed test* | Measure internet speed, find the public IP and ISP | Test data; no personal data |
| DNS servers you choose in *Tools > DNS* (for example 1.1.1.1, 8.8.8.8, 9.9.9.9) - only when you use that tool | Look up a name, or compare DNS servers | The names being looked up |

These services receive your public IP address as part of any internet connection. Their own privacy policies apply.

## Android permissions

| Permission | Why |
|---|---|
| Internet / network state / Wi-Fi state | Scan the Wi-Fi network you are connected to and talk to the office PC |
| Wi-Fi multicast | Find devices that announce themselves (UPnP) |

The Android app does not ask for location, contacts, camera, microphone or storage permissions.

## Children

Network Doctor is a tool for network administrators. It is not directed at children.

## Changes

If this policy changes, the new version will be published at this address with a new date.

## Contact

Questions about this policy can be raised as an issue at
https://github.com/yadavrkpacheriya/network-doctor/issues
