---
title: "<!-- feature:appleWatch -->Apple Watch and push notifications (APNs)<!-- /feature --><!-- feature:!appleWatch -->Push notifications (APNs)<!-- /feature -->"
description: "<!-- feature:appleWatch -->Pair an Apple Watch as its own approver with a Secure Enclave key, and let<!-- /feature --><!-- feature:!appleWatch -->Let<!-- /feature --> wardend send APNs push notifications for new cards. The push carries only the card id, never the command."
---

# <!-- feature:appleWatch -->Apple Watch and push notifications (APNs)<!-- /feature --><!-- feature:!appleWatch -->Push notifications (APNs)<!-- /feature -->

<!-- feature:appleWatch -->

An Apple Watch can be a WardenClaw approver of its own. It is paired with wardend like the phone, but it signs with a P-256 key that its Secure Enclave generates and never lets out (`es256`). The watch fetches cards over the same signed HTTPS channel as the phone. To wake it up when a card appears, wardend sends a push notification through Apple Push Notification service (APNs).

<!-- /feature -->

<!-- feature:!appleWatch -->

iOS does not let the iPhone app keep its own connection to wardend in the background. To wake it up when a card appears, wardend sends a push notification through Apple Push Notification service (APNs); the app then fetches the card over the same signed HTTPS channel as always.

<!-- /feature -->

<!-- feature:appleWatch -->

Both parts are optional. Without an `apns` section in the config everything works as before: the app sees cards by long poll, and ntfy can ping it if you set `ntfy_url`.

<!-- /feature -->

<!-- feature:!appleWatch -->

Push is optional. Without an `apns` section in the config everything works as before: the app sees cards by long poll, and ntfy can ping it if you set `ntfy_url`.

<!-- /feature -->

<!-- feature:appleWatch -->

## What the watch can and cannot do

- **Deny** from the notification or from the app. A deny is an ordinary ticket signed with the watch key.
- **Approve** only inside the watch app, after an explicit confirmation. The notification offers no "Allow" action: a double tap on Series 9 and Ultra 2 presses the first non-destructive action, and that must never be an approval.
- **Cards that need a hardware key** (`meta.hardware.required`, see `require_hardware` in the policy) cannot be approved from the watch: the watch has no way to tap a YubiKey, and wardend rejects its `allow` with `hardware_required`. Approve those on the phone with the key; deny still works from the watch. <!-- feature-item:hardwareKey -->
- Revoking the watch (`wardend pair revoke <id>`) also deletes its push tokens.

<!-- /feature -->

## What is in a push

Exactly this, for every card:

```json
{"aps":{"alert":{"title":"Approval request","body":"Open to review"},"category":"WARDEN_APPROVAL","sound":"default","interruption-level":"time-sensitive"},"cardId":"wd-…"}
```

No command, arguments, host, path or risk score. Apple, the lock screen and anyone next to <!-- feature:appleWatch -->your wrist<!-- /feature --><!-- feature:!appleWatch -->your phone<!-- /feature --> learn only that a card exists. The app then fetches the card itself over the signed channel, recomputes its digest and shows it. The notification expires with the card (`apns-expiration`) and a repeated push for the same card replaces the previous one (`apns-collapse-id`).

## Create the APNs key in Apple Developer

You need a paid Apple Developer Program membership: free accounts cannot send push notifications.

1. Sign in to [developer.apple.com/account](https://developer.apple.com/account), open **Certificates, Identifiers & Profiles**.
2. **Identifiers**: make sure the app ID<!-- feature:appleWatch -->s exist and have<!-- /feature --><!-- feature:!appleWatch --> exists and has<!-- /feature --> the **Push Notifications** capability enabled: the iOS app (`com.wardenclaw.app`)<!-- feature:appleWatch --> and the watch app (for example `com.wardenclaw.app.watchkitapp`)<!-- /feature -->. If you build the app<!-- feature:appleWatch -->s<!-- /feature --> yourself, use your own bundle id<!-- feature:appleWatch -->s<!-- /feature --> here and below.
3. **Keys**, then **+**. Give the key a name (for example `wardend APNs`), tick **Apple Push Notifications service (APNs)**. If Apple asks you to configure it, choose the environment **Sandbox & Production** and the team-scoped key (all topics), then **Save**, **Continue**, **Register**.
4. **Download** the file `AuthKey_XXXXXXXXXX.p8`. Apple lets you download it **only once**; keep a copy in your password manager.
5. Note two values: the **Key ID** (10 characters, shown on the key page and in the file name) and your **Team ID** (10 characters, under **Membership details**).

One key serves all your apps and both environments. If it leaks, revoke it on the same **Keys** page and create a new one: nobody can approve anything with it, but they could send notifications to your devices.

## Put the key on the server

The key is a secret: only wardend may read it. For the hardened install (wardend runs as root, config in `/etc/wardend`):

```shell
chmod 600 AuthKey_ABC123DEFG.p8
scp -p AuthKey_ABC123DEFG.p8 server:     # to your home on the server, not the shared /tmp; -p keeps mode 600
ssh server
sudo install -o root -g root -m 600 AuthKey_ABC123DEFG.p8 /etc/wardend/AuthKey_ABC123DEFG.p8
rm AuthKey_ABC123DEFG.p8
```

For a single-user install use `install -m 600 AuthKey_ABC123DEFG.p8 ~/.wardend/` instead. wardend checks the permissions at start: a key readable by the group or by everyone stops it in `ticket` and `deny-list` modes, like a writable config.

## Config

Add an `apns` key to the object in your existing `config.json` (`sudoedit /etc/wardend/config.json` for the hardened install). Don't replace the file with this snippet: it holds your paired devices and the mode.

<!-- feature:appleWatch -->

```json
{
  "apns": {
    "key_file": "/etc/wardend/AuthKey_ABC123DEFG.p8",
    "key_id": "ABC123DEFG",
    "team_id": "TEAM123456",
    "topic_ios": "com.wardenclaw.app",
    "topic_watch": "com.wardenclaw.app.watchkitapp"
  }
}
```

<!-- /feature -->

<!-- feature:!appleWatch -->

```json
{
  "apns": {
    "key_file": "/etc/wardend/AuthKey_ABC123DEFG.p8",
    "key_id": "ABC123DEFG",
    "team_id": "TEAM123456",
    "topic_ios": "com.wardenclaw.app"
  }
}
```

<!-- /feature -->

| Field | Meaning |
|---|---|
| `key_file` | Path to the `.p8` key, mode 0600. |
| `key_id` | Key ID from **Keys**. |
| `team_id` | Team ID from **Membership details**. |
| `topic_ios` | Bundle id of the iOS app. Devices may register tokens only for <!-- feature:appleWatch -->these two topics<!-- /feature --><!-- feature:!appleWatch -->this topic<!-- /feature -->. |
| `topic_watch` <!-- feature-item:appleWatch --> | Bundle id of the watch app. Either topic may be left out. |

Check the config and restart wardend: `sudo wardend config-check --config /etc/wardend/config.json && sudo systemctl restart wardend` (a config wardend can't read would stop wardend, and the agent with it; [what config-check checks](../cli/#wardend-config-check)). If the key can't be loaded, wardend starts anyway, writes a warning and runs without APNs; `wardend status` shows the reason under `push.error`.

<!-- feature:appleWatch -->

The watch needs to reach wardend over HTTPS, the same public address as the phone (`public_url`, for example through a Cloudflare tunnel).

<!-- /feature -->

## <!-- feature:appleWatch -->Pair the watch and check pushes<!-- /feature --><!-- feature:!appleWatch -->Check pushes<!-- /feature -->

1. Pair the phone as usual. In the watch app, start pairing: the phone passes the pairing link to the watch, the watch creates its key and sends the request. <!-- feature-item:appleWatch -->
2. On the server: `wardend pair list` shows the request with the key type `es256`. Compare the fingerprint with the watch screen, then `wardend pair approve <id>`. <!-- feature-item:appleWatch -->
3. The app<!-- feature:appleWatch -->s register their push tokens by themselves<!-- /feature --><!-- feature:!appleWatch --> registers its push token by itself once you allow notifications<!-- /feature -->. `wardend push list` shows the tokens (truncated), their topic and environment.
4. `wardend push test` sends a test notification (card id `wd-test`) to every token and prints Apple's answer for each one. Add `--device <deviceId prefix>` to test one device. `200` means Apple accepted it; `400 BadDeviceToken` usually means the token's environment is wrong (a development build uses `sandbox`); a token answered with `410` is removed.

## Protocol

The wire formats (<!-- feature:appleWatch -->the `es256` key and signatures, <!-- /feature -->the signed `push/register` request, the headers wardend sends to Apple) are in the protocol specification, [protocol/README.md](%REPO_URL%/blob/main/protocol/README.md), <!-- feature:appleWatch -->sections 7 and 8, with test vectors in `protocol/vectors/es256_vectors.json`<!-- /feature --><!-- feature:!appleWatch -->section 8<!-- /feature -->.

<!-- feature:appleWatch -->

The iOS side (the watchOS app, pairing the watch from the iPhone, YubiKey on iOS) is described in [iOS, Apple Watch and YubiKey](../ios/).

<!-- /feature -->

<!-- feature:!appleWatch -->

What the iPhone app needs in Apple Developer: [iPhone app](../ios/). What the notification shows on the lock screen: [Notifications on a locked phone](../notifications/).

<!-- /feature -->
