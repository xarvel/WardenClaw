# Apple Watch and APNs

Neither is part of this release.

- **Apple Watch**: the watch app is not ported to the relay transport and its feature flag is off.
- **APNs**: wardend sends no pushes and has no `apns` configuration. Pushes (APNs, FCM) are sent by the
  relay: [protocol/README.md](../../protocol/README.md), section 8.
