---
title: Notifications on a locked phone
description: An approval request pops up even when the phone is locked. The lock screen shows the host, the risk and the time left, never the command. How the Android and iPhone apps do it, the "like an incoming call" mode, battery settings and what iOS needs.
---

# Notifications on a locked phone

When the agent runs a command that needs your signature, the request reaches the phone even if
it lies locked on the table. The notification tells you whether it is urgent: which server, how
risky, how much time is left. It never lets you approve: tapping it opens the card, and the app
asks for your fingerprint, face or passcode before it signs.

## What the lock screen shows (Android)

```
Approval request
pi · risk: high · 1:40 left
```

- **Host** from the signed envelope, **risk** (high when a rule or a spoofed letter fired, else the
  judge's score or "not rated"), **time left** as a countdown until the server denies the request
  by itself.
- **No command.** Anyone who holds your phone can read the lock screen. Android's own "hide
  sensitive content" helps only if you turned it on (on a Pixel it is off by default: sensitive
  content is shown), so WardenClaw does not put the command into the notification at all. If you
  want it there anyway, turn on **Mode → Notifications → Show the command on the lock screen**.
- **No Allow and no Deny** in the notification. A tap asks Android to unlock the phone and then
  opens the card. The decision is made only in the app, after the owner check.
- The phone **wakes the screen** and plays the sound of the "Approval requests" channel. You can
  change the sound or vibration in Android's settings for that channel.
- **Several requests** fold into one group: "Waiting for a decision: 3", with the host, risk and
  countdown of each. A Pixel lock screen shows the newest one and turns the rest into small icons;
  swipe down to see the whole group (still without commands).
- A request that was **decided** elsewhere (in the app, <!-- feature:appleWatch -->on the watch, <!-- /feature -->on another phone) removes its
  notification. One that **expired** turns into a quiet "Expired, denied · pi · 21:32", and the feed
  keeps a **Missed** block until you hide it: the agent got a denial, and you should know you were
  asked.
- The quiet **persistent notification** of the background service tells the real state: "Connected
  to pi", "No connection to pi since 14:02, retrying", or "Not paired".

The first time the service starts, the app explains why it needs the notification permission
before Android asks for it. If you said no, **Mode → Notifications** has a button to the settings.

## Like an incoming call (Android, optional)

**Mode → Notifications → Like an incoming call** opens a new request full screen over the lock
screen and turns the screen on, like a call: host, risk, the countdown, and two buttons, **Open**
(unlock, then the card) and **Later** (the notification stays). Nothing can be approved there.
The mode is off by default.

It uses Android's full-screen intent. Since Android 14 that needs a permission the user grants:
if WardenClaw does not have it, the switch opens the system page ("Full-screen notifications" on a
Pixel; the name differs between Android versions).

**Google Play.** Play grants `USE_FULL_SCREEN_INTENT` by default only to apps whose core function
is calling or alarms; for every other app installed from Play it is revoked, and the app must ask
the user to allow it, as WardenClaw does. An app on Play also has to fill in the full-screen intent
declaration in Play Console, and Google may reject it if the use does not fit. That is why the mode
is optional and off by default: the regular notification already reaches the lock screen.

## Battery (Android)

Without a push service, the app keeps a long-poll connection to your own wardend from a
foreground service. Android may still put the app to sleep:

- **Mode → Notifications → Allow background use** opens the system dialog that turns battery
  optimization off for WardenClaw (or Settings → Apps → WardenClaw → App battery usage →
  Unrestricted).
- The service starts again by itself after a reboot (once you unlock the phone the first time) and
  after an app update. If Android refuses, you get a notification "Open WardenClaw to receive
  requests again".
- On Google Play, `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` is allowed only for some kinds of apps. A
  Play build may have to fall back to the settings page; a self-built or F-Droid-style build keeps
  the direct dialog.

## iPhone

iOS does not let an app keep its own connection in the background, so on the iPhone the server
sends a push through Apple (APNs) when a card appears<!-- feature:appleWatch -->, as it does for the watch<!-- /feature -->.

- **On the server**, wardend needs an `apns` section with `topic_ios: "com.wardenclaw.app"` and the
  `.p8` key: see [<!-- feature:appleWatch -->Apple Watch and APNs<!-- /feature --><!-- feature:!appleWatch -->Push notifications (APNs)<!-- /feature -->](../apns/). Without it the app says "The server has no
  APNs configured" and works as before (cards appear while the app is open).
- **In the app** nothing to set up: after pairing it asks for the notification permission (with an
  explanation first), registers its push token with wardend by a request signed with the phone's
  key, and removes it when you turn notifications off or forget the server. The status is under
  **Mode → Notifications**.
- **On the lock screen**: "Approval request · Open to review". The push carries only the card id:
  no command, no host, no path goes through Apple. The app fetches the card itself over the signed
  channel and checks it.
- The push is **time-sensitive**: it shows on the lock screen and breaks through Focus. You can turn
  that off in iOS Settings → WardenClaw → Notifications → Time-Sensitive Notifications.
- **No buttons** in the notification. A tap opens the card; approving needs Face ID or the
  passcode in the app.
- **Host and time left on the iPhone lock screen** would need a Notification Service Extension that
  fetches the card over the signed channel before the notification is shown and rewrites its text.
  It is not built yet: the extension would need the device key in a shared keychain group and a
  network call within its 30 second budget.

For a self-built iOS app, the App ID `com.wardenclaw.app` needs the **Push Notifications** and
**Time Sensitive Notifications** capabilities in Apple Developer (Certificates, Identifiers &
Profiles → Identifiers), and the provisioning profile must be generated again after you turn them
on. See the checklist on [iPhone<!-- feature:appleWatch --> and Apple Watch<!-- /feature --><!-- feature:!appleWatch --> app<!-- /feature -->](../ios/).
