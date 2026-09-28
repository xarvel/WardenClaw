---
title: "<!-- feature:appleWatch -->iPhone and Apple Watch apps<!-- /feature --><!-- feature:!appleWatch -->iPhone app<!-- /feature -->"
description: "The WardenClaw iOS app<!-- feature:hardwareKey --> with a YubiKey over NFC<!-- /feature --><!-- feature:appleWatch -->, and the Apple Watch app as an approver of its own with a Secure Enclave key<!-- /feature -->. What works, what to set up in Apple Developer<!-- feature:appleWatch -->, how to pair the watch<!-- /feature -->."
---

# iPhone<!-- feature:appleWatch --> and Apple Watch apps<!-- /feature --><!-- feature:!appleWatch --> app<!-- /feature -->

The iOS app does what the Android app does: pairing with wardend by QR code, a device key,
cards with the recomputed digest, the journal.<!-- feature:appleWatch --> On top of that it carries an **Apple Watch app**
that approves on its own.<!-- /feature --> Build instructions: `app/docs/BUILD.md` in the repository.

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

<!-- feature:appleWatch -->

## Apple Watch

The watch is **not a mirror of the phone**. It is a separate trusted device of wardend:

- its own P-256 key, generated in the watch's Secure Enclave and never leaving it
  (`alg: "es256"` in `trusted_devices`);
- it talks to wardend over HTTPS itself and checks that every response is signed by the key it
  pinned at pairing;
- it gets its own push notifications. A push carries only the card id; the watch fetches the
  card and recomputes the digest before it shows it. Server side: [Apple Watch and APNs](../apns/).

What you can do on the wrist:

- **Deny** any card, from the notification or in the app.
- **Approve** only inside the app: hold the ring for about 1.5 seconds or turn the Digital Crown
  all the way. The notification has only **Open** and **Deny**; Open comes first, because the
  double tap gesture of Series 9 and Ultra 2 presses the first action.
- Cards that need the YubiKey can only be denied on the watch. Approve them on the phone. <!-- feature-item:hardwareKey -->
- Before signing an approval the watch checks the card exactly like the phone and `wardenctl`:
  the 13 fields of the envelope, the server id pinned at pairing, the digest, the card id. On any
  mismatch it can only deny.

### Pairing the watch

The watch has no camera, so the phone passes it the link:

1. Install WardenClaw on the watch (Watch app on the iPhone → Available Apps).
2. On the server run `wardend pair start`. Each link works once: the watch needs its own.
3. In the iPhone app: Mode → Apple Watch → "Scan QR for the watch". Keep WardenClaw open on the
   watch.
4. The watch creates its key and asks wardend to pair. Compare the fingerprint on the watch with
   `wardend pair list`, then `wardend pair approve <id>`.
5. The watch registers for notifications by itself. wardend needs the `apns` section with the
   topic `com.wardenclaw.app.watchkitapp`, see [Apple Watch and APNs](../apns/).

To remove the watch: Settings on the watch → Unpair (deletes the key there), and
`wardend pair revoke <id>` on the server (also deletes its push tokens).

### Key storage

The key sits in the Secure Enclave with access limited to signing (`.privateKeyUsage`); its
handle is in the Keychain as "this device only, when unlocked": no backups, no migration to a new
watch, no signing while the watch is off the wrist and locked. Asking for the passcode on every
signature (`.userPresence`) is possible in a self-built app, but off by default: the watch is
already locked away from your wrist, and a passcode prompt on each Deny would make the
notification action useless.

<!-- /feature -->

## Apple Developer checklist

For a self-built app (a paid Apple Developer Program membership is needed for push):

| App ID | capabilities |
|---|---|
| `com.wardenclaw.app` | <!-- feature:hardwareKey -->NFC Tag Reading, <!-- /feature --><!-- feature:phoneJudge -->Increased Memory Limit, <!-- /feature -->Push Notifications, Time Sensitive Notifications |
| `com.wardenclaw.app.watchkitapp` <!-- feature-item:appleWatch --> | Push Notifications |

No App Group is used. The APNs key (`.p8`) belongs to the server, not the app: how to create it
and where wardend reads it is on [<!-- feature:appleWatch -->Apple Watch and APNs<!-- /feature --><!-- feature:!appleWatch -->Push notifications (APNs)<!-- /feature -->](../apns/). What the iPhone shows on
the lock screen: [Notifications on a locked phone](../notifications/).
