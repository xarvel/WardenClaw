---
title: "Push notifications"
description: "Push notifications for new cards are sent by the relay through APNs and FCM. The command travels end-to-end encrypted, and the server operator configures nothing."
---

# Push notifications

A phone does not let the app keep its connection to the relay in the background. When wardend sends a card to a device that has no live connection, the relay sends a push notification: through Apple Push Notification service (APNs) to an iPhone, through Firebase Cloud Messaging (FCM) to an Android phone.

## Nothing to configure on the server

wardend sends no pushes and holds no push credentials. The app registers its push token with the relay once you allow notifications, and the relay sends the pushes with the credentials of the app's publisher. With the hosted relay (`wss://relay.wardenclaw.dev`) there is nothing to set up: no APNs key, no config key, no command.

## What is in a push

The visible text is fixed. For APNs:

```json
{"aps":{"alert":{"title":"Approval request","body":"Open to review"},"sound":"default","interruption-level":"time-sensitive","mutable-content":1,"category":"WARDENCLAW_CARD"},"relay":{"sid":"…","id":"…","to":"…","kind":"…","exp":…,"body":"…"}}
```

`relay.body` is the card as wardend sent it: end-to-end encrypted (X25519 + XChaCha20-Poly1305) for this one device. The relay, Apple and Google see ciphertext and the routing fields (supervisor id, device id, message id, kind, expiry), never the command, its arguments, the host or a path. Only the app holds the key to decrypt it; it checks the supervisor's signature and the expiry before it shows the card. A body over 3072 characters is left out of the push; the app then fetches the encrypted message from the relay.

FCM gets the members of `relay` as a data message. The notification expires with the card (`apns-expiration`), and a repeated push for the same message replaces the previous one (`apns-collapse-id`).

## A relay of your own

A self-hosted relay needs push credentials of its own: an APNs key and topic for the iPhone app, an FCM service account for the Android app, both for an app you build and sign yourself. They are secrets of the relay, not of wardend: [relay/README.md](%REPO_URL%/blob/main/relay/README.md). Without them the relay still routes and queues, and a closed app learns about cards when it is opened.

## Apple Watch

The Apple Watch app is not available in this release.

## Protocol

The wire formats (`push.register`, the APNs and FCM payloads) are in the protocol specification, [protocol/README.md](%REPO_URL%/blob/main/protocol/README.md).

What the notification shows on the lock screen and the phone settings it needs: [Notifications on a locked phone](../notifications/).
