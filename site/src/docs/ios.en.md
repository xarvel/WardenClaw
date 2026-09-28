---
title: "iPhone app"
description: "The WardenClaw iOS app<!-- feature:hardwareKey --> with a YubiKey over NFC<!-- /feature -->. What works, what to set up in Apple Developer."
---

# iPhone app

The iOS app does what the Android app does: pairing with wardend by QR code, a device key,
cards with the recomputed digest, the journal. Build instructions: `app/docs/BUILD.md` in the repository.

<!-- feature:hardwareKey -->

## YubiKey on iPhone

The hardware second factor (`require_hardware`, `protocol/HARDWARE.md` in the repository) works on iPhone **over NFC only**:
hold the YubiKey (5 NFC, 5C NFC) to the top edge of the phone when the system sheet appears.
Registration, PIN and error messages are the same as on Android.

- **USB-C is not supported on iPhone.** Yubico's iOS library reaches a USB-C key only through the
  smart card interface, which carries PIV and OATH but not FIDO2. The app says so instead of
  asking you to plug the key in.
- **Lightning (YubiKey 5Ci)** is off in the published app: it needs the app to be registered in
  Yubico's MFi program. A self-built app can turn it on with a plugin option.

The app needs the **NFC Tag Reading** capability on its App ID and asks for the FIDO applet
(`A0000006472F0001`) only.

<!-- /feature -->

## Apple Developer checklist

For a self-built app (a paid Apple Developer Program membership is needed for push):

| App ID | capabilities |
|---|---|
| `com.wardenclaw.app` | <!-- feature:hardwareKey -->NFC Tag Reading, <!-- /feature --><!-- feature:phoneJudge -->Increased Memory Limit, <!-- /feature -->Push Notifications, Time Sensitive Notifications |

No App Group is used. The APNs key (`.p8`) belongs to the relay, not to wardend or the app:
[Push notifications](../apns/). What the iPhone shows on
the lock screen: [Notifications on a locked phone](../notifications/).
