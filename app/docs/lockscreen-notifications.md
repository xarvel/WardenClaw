# Approval request on a locked phone

Requirement: an approval request appears as a notification even when the phone is locked.
The command is not visible on the lock screen (anyone holding the phone can read it); approval
requires unlocking and biometrics inside the app.

## Current state

The entries below are a dated work log. Since then the HTTP transport and the push code in
wardend (`daemon/push.go`, `daemon/apns.go`, the `apns` config section) were removed: the app
and wardend talk through the relay, and the relay sends the push (APNs for iPhone, FCM for
Android) with the app publisher's credentials. The operator configures nothing for push. The
Android build now includes Firebase Messaging when a `google-services.json` is supplied. See
protocol/README.md section 8 and `src/core/phonePush.ts`.

## Work log

### Sep 28, 2026, part 1

- Reviewed code: `modules/wardenwatch` (specialUse service + notifications), `src/core/background.ts`,
  server `daemon/push.go`, `daemon/apns.go`, protocol sections 7-8. UX review 2026-09-27, F-50...F-57.
- EAS: Starter plan, 1500 of 4500 cents used in the period (Android medium 100, iOS 200).
- Decisions:
  - **Command only with an explicit option.** `VISIBILITY_PRIVATE` hides content on the lock screen
    only if Android "Show sensitive content" is turned off (enabled by default on Pixel). The app
    cannot set the channel `lockscreenVisibility` (the system overwrites it on channel creation).
    So the full notification without the option also has no command, and the public version
    (`setPublicVersion`) defines what is shown when content is hidden.
    With the "Show command on lock screen" option the command goes into the full version and
    visibility is set to `PUBLIC`.
  - One notification per request plus a group summary (`GROUP_ALERT_CHILDREN`): a resolved request
    is dismissed, an expired one changes to "Expired, denied" and leaves the group.
  - Countdown: chronometer in the title (`setChronometerCountDown`) and the text "expires in M:SS",
    updated by a native timer every second, only while the screen is on, with a budget of at most
    4 updates per second (Android 5 limit).
  - iOS: a minimal custom module `modules/wardenpush` (Swift), not `expo-notifications`: that
    pulls Firebase into the Android build, and the project intentionally has no Firebase.

### Sep 28, 2026, part 1 (code)

Android (`modules/wardenwatch`):
- `Notifier.kt` rewritten: channels `wardenclaw.requests.v2` (high importance, sound, vibration;
  old `wardenclaw.requests` without vibration is deleted), `wardenclaw.missed` (silent),
  `wardenclaw.status`; request notification with a public version, group summary, "Expired,
  denied", chronometer and "expires in M:SS" text, screen wake (wake lock for 5 s).
- `IncomingActivity.kt`: "incoming call" mode (full-screen intent), "Open" and "Later" buttons,
  no approval. On Android 14+ checks `canUseFullScreenIntent()` and navigates to settings.
- `BootReceiver.kt`: `BOOT_COMPLETED`, `MY_PACKAGE_REPLACED` start the service if it was enabled
  (flag in SharedPreferences), otherwise shows a notification "Open WardenClaw".
- Persistent notification: status from JS (`setStatus`): connected, disconnected since HH:MM,
  not paired.
- Manifest plugin: permissions `RECEIVE_BOOT_COMPLETED`, `USE_FULL_SCREEN_INTENT`, `WAKE_LOCK`,
  `TURN_SCREEN_ON`, `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`, receiver and activity.

JS: `background.ts` (notification sync, status, explanation before the system permission request),
`missed.ts` (Missed block in the feed, AsyncStorage), settings "Show command on lock screen" and
"Incoming call style", button "Allow background operation".

iOS: module `modules/wardenpush` (Swift): permission, APNs token, environment from embedded
profile, `WARDEN_APPROVAL` category with no actions, tap opens the card. `phonePush.ts`:
token registration with the relay over the session (`push.register`, protocol/README.md section 8),
deregistration on disable and "Forget server".
`app.json`: `aps-environment`, `com.apple.developer.usernotifications.time-sensitive`.

Server: no change needed; push is sent with the `apns-topic` of its own token. New tests
`daemon/push_phone_test.go`: push to both iPhone and watch with their own topics, payload without
the command; server with `topic_ios` only. Checks: `tsc --noEmit` clean, `test-core.mjs` 25/25,
Go push tests 7/7.

### Sep 28, 2026, part 2 (builds, server, site)

- Commits: `383e202` (server test), `36b8b1d` (app), `31fd89a` (deeplink
  `wardenclaw://pair?...` fills the link field on Connect, pairing only on tap),
  `b2c14b2` (site: "Notifications on a locked phone" page, en and ru; App ID checklist in `ios.*`).
- EAS: Android `bench` `4780ccfe-6a73-4fc8-8cb9-d870ecb5c862` (commit 36b8b1d, no deeplink),
  iOS `simulator` `0de9d437-93f2-4458-b436-9a3139315e8b` (queued after Android).
- Site built in a copy `/srv/scratch/notif-site` (`npm ci`, `astro build`: 16 pages, no errors).
- Live signature verification from JS against a test wardend: a signed `push.register` reached
  `push_not_configured` (409, signature accepted); body modified after signing: 401
  `bad_signature`; `push.unregister`: 200.
- Test wardend: `systemd-run --user --unit=notif-wardend`, mode ticket, port 19887, state at
  `/srv/scratch/notif-test/state`; the tree reads commands from FIFO `/srv/scratch/notif-test/fifo`
  (bash built-ins only). Pairing RPC from under the live wardend filter is refused ("the agent
  cannot manage pairing itself"), so `wardend pair start/approve` for the test instance go through
  `systemd-run --user`, as in `daemon/redteam/run.sh`.
- Pixel: PIN, `lock_screen_allow_private_notifications=1` (full content on the lock screen by
  default, confirming the decision not to put the command in the notification), app not paired,
  language English, `POST_NOTIFICATION` denied, `stay_on_while_plugged_in=15`.

### What needs to be enabled in Apple Developer (before the next iOS device build)

`app.json` now requires `aps-environment` and
`com.apple.developer.usernotifications.time-sensitive` for the main app. The simulator build
needs no signature, but a device build (preview, production, TestFlight) needs a profile with
these capabilities:

1. developer.apple.com -> Certificates, Identifiers & Profiles -> Identifiers -> `com.wardenclaw.app`:
   enable **Push Notifications** and **Time Sensitive Notifications**, save.
2. Recreate the provisioning profile: either `eas credentials` (iOS, production profile, delete
   the old provisioning profile, EAS will create a new one), or run `eas build` for iOS once
   interactively with an Apple login: EAS will then sync the capabilities and profile.
   Non-interactive `eas build` without an Apple cookie session does not enable capabilities,
   and signing will fail on an entitlements/profile mismatch.

Nothing is configured on wardend: the relay sends the push.

### Sep 28, 2026, part 3 (Pixel 9 Pro, Android 17, build 4780ccfe)

- Installed over (versionCode 5), `adb reverse tcp:19887`, paired by pasting the link (no
  deeplink in this build yet), `wardend pair approve` via `systemd-run`: "Connected · mode ticket".
- Immediately after pairing: own "Notification requests" explanation, then system Android dialog: ok.
- Service: foreground `specialUse`, `wardenclaw.watch`. Channel `wardenclaw.requests.v2`:
  importance 4, sound, vibration `[0, 300, 200, 300]`, `mLockscreenVisibility=-1000` (system
  ignores the app's value, as expected).
- Request: "Approval request · example-pi · risk not rated · expires in 1:36"; public version the
  same, without the command. Sound and vibration fired, heads-up appeared.
- **Bug 1:** heads-up dismissed after ~1.4 s: countdown update fired with `GROUP_ALERT_SUMMARY`.
  **Bug 2:** persistent notification stayed "Connecting to server..." (service resets status in
  onCreate, JS did not resend the same status). **Bug 3:** notification options visible before
  pairing. All three fixed in `cd2eb58`, build `a52589ed`.
- Summary: "Waiting for decision: 2 · example-pi · nearest expires in 1:32", group with countdown
  in the notification shade header. Expiry: silent "Expired, denied · example-pi · 3:37 am" in
  the missed channel. Feed: "Missed (3)" with time, host and command, "Dismiss".
- Request resolved by another device (second test key, `wardend approve --deny`) dismissed its
  notification.
- "Incoming call style" with `USE_FULL_SCREEN_INTENT` denied (appops deny): app opened the system
  "Full-screen notifications" page; hint and button in settings. The permission is granted by
  default for apps not installed from Play.
- Notification volume lowered to 1 of 7 for the night test (was 5), restore later.

### Sep 28, 2026, part 4 (build a52589ed, phone locked)

- While waiting for the build, the screen timed out (03:42:58) and the phone locked (PIN). All
  further testing on a locked phone; heads-up screenshots with the fixed build could not be taken
  (heads-up only appears on an unlocked phone), the fix was verified by code and the log from
  build 1.
- Update over locked: `MY_PACKAGE_REPLACED` started the service without opening the app, JS
  connected, persistent notification "Connected to example-pi · Waiting for approval requests"
  (bug 2 fixed).
- **Screen wake works** without the `TURN_SCREEN_ON` permission (it is `signature|privileged|appop`):
  screen went off at 03:42:58, came on at 04:00:11.495, request sound at 04:00:11.742.
- Lock screen: "Approval request · example-pi · risk not rated · expires in 1:37", no command.
  Pixel shows only the most recent request, others as icons; group of three in the shade over the
  lock screen, each with host, risk, countdown, no command.
- **Bug 4:** "Expired, denied" not visible on the lock screen: low-importance channel, Pixel hides
  silent notifications. **Bug 5:** "expires in" text lagged behind the chronometer by 1-2 s.
  **Minor:** risk label missing the word "risk" on the incoming call screen. Fixed in `f63fcff`,
  third build.
- "Incoming call style" (appops allow): screen woke from Dozing, `IncomingActivity` over the lock
  screen: host, risk, 1:34, "Command visible after unlock", "Later", "Open". "Open" triggered the
  system PIN entry (bouncer), "Later" closed the screen, the notification remained.

### Sep 28, 2026, part 5 (build 576e259f, final)

- Update over locked phone: service started via `MY_PACKAGE_REPLACED`, channel
  `wardenclaw.missed` deleted, `wardenclaw.missed.v2` with importance 3 (no sound).
- Request while screen off: screen turned on, lock screen shows "Approval request ·
  example-pi · risk not rated · expires in 1:29", chronometer 01:28 (less than a second
  difference: the update reaches SystemUI with a delay).
- Expiry: "Expired, denied · example-pi · 4:26 am" on the lock screen (bug 4 fixed).
- "Incoming call style": "risk not rated", countdown, "Command visible after unlock".
- No command text in any lock screen or shade-over-lock-screen screenshot; command visible only
  inside the app after unlocking (`11_feed_missed.png`).
- Cleanup: `adb reverse` removed, test wardend stopped (no unit), `am force-stop`
  com.wardenclaw.app (service stopped), `POST_NOTIFICATIONS` revoked again (as before),
  `USE_FULL_SCREEN_INTENT` appops default, notification volume 5 (as before), screen off.
  Phone locked with PIN: only the maintainer can unlock. The app still has the test server
  127.0.0.1:19887 and Russian UI language: Connect -> "Forget server", Mode -> "Language".
  The old app (previous applicationId) was not touched.

Not verified on device: heads-up on the fixed build (phone locked itself while the build ran;
heads-up only appears on an unlocked phone), `BOOT_COMPLETED` (requires reboot and PIN; same code
as `MY_PACKAGE_REPLACED`), deeplink `wardenclaw://pair` (available from `31fd89a`, pairing was
done by pasting the link), iOS on device (only a simulator build exists).

EAS: Android `4780ccfe-6a73-4fc8-8cb9-d870ecb5c862`, `a52589ed-654d-45fe-b2e3-ad0c57c3401d`,
`576e259f-ba99-4810-89c7-bd9a92778d9a` (final, `f63fcff`); iOS simulator
`0de9d437-93f2-4458-b436-9a3139315e8b` (`36b8b1d`, BUILD SUCCEEDED, WardenPush built without
warnings). Credits: +500 cents for the session (3 Android at 100, iOS 200).
