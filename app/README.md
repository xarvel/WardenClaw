# WardenClaw (Android, iOS)

*Take back control.* Nothing runs on your machine until your phone signs it.

Phone-side approver for `wardend`: shows approval cards, signs decisions with the device key
(optionally a YubiKey tap), keeps a local hash-chained journal (the owner can clear it from the
Journal tab; the wipe is recorded as the first entry of the new chain). Expo SDK 57, React Native 0.86.
Android is the main platform; iOS builds too.
The first release leaves out the YubiKey and the on-device judge: they are
behind build flags, on only in the `bench` profile (see [docs/release-scope.md](docs/release-scope.md)).

**Building:** see [docs/BUILD.md](docs/BUILD.md) for local iOS and Android builds
(`scripts/local/doctor.sh`, `ios.sh`, `android.sh`; with `eas build --local` or without EAS at all).

The app lives in `app/` of the WardenClaw monorepo. EAS uploads the git root of the monorepo,
so the upload filter is the root [`.easignore`](../.easignore): it keeps only `app/` and never
uploads local env files (`app/.env*`). Build values come only from the profile env in `eas.json`;
`production` and `preview` refuse personal `EXPO_PUBLIC_WARDENCLAW_*` values
(`scripts/check-build-env.mjs`, see [docs/BUILD.md](docs/BUILD.md)). Cloud builds:
`scripts/eas_build.sh` from `app/` (uses EAS build credits); the tests read the protocol vectors
from `../protocol/vectors/`.

## Modes: the phone decides, wardend always waits

`wardend` has no modes of its own. Every launch outside an approved process tree becomes a card
and waits for a ticket signed by a paired approver; without one the request expires and the
command is refused (fail-closed). What happens to a card is decided only on the phone, Mode tab
(`src/core/autosign.ts`, `src/core/controller.ts`):

- **Manual** (default, and the mode after every app start): you sign every card. The judge is not
  called; the local blocklist and injection rules still mark cards.
- **Autopilot** (`delegate`): the judge model allows a card on its own when its risk is at or below
  the threshold and denies on its own; everything else waits for you. Three denies in a row
  drop the app back to Manual.
- **Observe**: the phone signs **every** card the moment it arrives, without the judge and without
  asking, dangerous cards included, and only writes the journal. The journal marks such entries
  ("Signed in Observe", a red DANGEROUS badge with the reasons), the banner above the tabs and the
  Android service notification carry one summary line (signed N, dangerous M); there is no
  notification per card. The exceptions that still wait for you in Observe: a `rootexec` card (root
  outside the gate: no automatic approver may allow it, protocol/README.md 3a), a card whose
  envelope the phone could not recompute (only a deny can be signed), and a card the server
  requires a hardware key for.

Observe and Autopilot are turned on only by the owner (biometrics or the device passcode) for one
hour; enabling again extends, Stop ends it, and the mode is not stored across restarts. Observe
takes the same timer as Autopilot because it signs more than Autopilot does.

**Harness service launches.** A card wardend labels `meta.class: "service"` (the gateway's node
workers, `lsof`, `systemctl show`, the claude-cli pack) is signed by rule in every mode, Manual
included, and appears only in the journal ("Signed by rule: service launch"). Mode tab → "Ask me
about harness service launches too" (off by default) brings them to the feed; turning the switch
off again asks the owner. A service launch that trips a local rule or a flag waits for you in
Manual and Autopilot (the class is server meta, not signed); in Observe it is signed and marked. A
service launch with a `rootexec` envelope is never a service launch.

## Language

The UI is English only, regardless of the system language. All strings live in
`src/core/i18n/en.ts` and the feature dictionaries in `src/core/i18n/features/`.

## Links the app understands

Any app on the phone, or a web page on a tap, can open a `wardenclaw://` link, so a link never
acts on its own (`src/core/links.ts`):

- `wardenclaw://feed?card=<id>` opens that card; `wardenclaw://feed` opens the feed.
- `wardenclaw://pair?…` (the QR of `wardend pair start`) fills the link field on the Connect
  tab; connecting takes the Connect button and the owner's confirmation.
- `wardenclaw://judge?url=<encoded>&model=<encoded>[&key=<encoded>]` fills the judge URL, the
  model name and, when `key` is present, the API key field on the Mode tab and marks the form
  "Filled from a link" (or "…, including the API key"). Nothing is saved until Save, which asks
  for the owner's confirmation as for any judge change; the key reaches SecureStore by that path
  alone. A link with any other parameter (`apiKey`, `token`, `timeout`, …) is refused as a whole,
  and the Mode tab says why. The URL must be `https://`, or `http://` on `localhost`/`127.x`/`::1`
  only; the key is 1–512 characters without spaces or control characters, percent-encoded like
  the other values. A link with `key` carries a secret: show its QR only to your own devices, as
  you would a pairing link.
- `wardenclaw://bench?…` exists only in the `bench` build (`docs/BUILD.md`).

## Background notifications

The app and `wardend` never connect to each other directly: both keep an outbound WebSocket to
the relay (default `wss://relay.wardenclaw.dev`) and exchange end-to-end encrypted frames through
it ([`protocol/README.md`](../protocol/README.md)). In the background the phone learns about a
new card in two ways:

- **Android foreground service** (`modules/wardenwatch`): keeps the relay session open, so cards
  arrive as they do in the foreground.
- **Push from the relay** (`modules/wardenpush`, `src/core/phonePush.ts`): the app registers its
  token with the relay (`push.register`, protocol/README.md section 8), and the relay sends a
  push when a frame for this phone arrives while it has no live connection: APNs on iPhone, FCM on
  Android (for when Android has stopped the service). The push is sent with the app publisher's
  credentials, not by `wardend`; it carries only the encrypted frame, which neither the relay nor
  Apple or Google can open. The Android build gets FCM only if a `google-services.json` is
  supplied at build time (`app.config.ts`); without it the app works without push.

Android service details:

- `modules/wardenwatch` is a local Expo module with an Android foreground service of type
  `specialUse`. While it runs, it keeps a headless JS task (`WardenWatch`) active, so React
  Native does not pause JS timers in the background and the relay session of wardend
  (`src/core/wardendSession.ts`, `src/core/relaySession.ts`) stays connected.
- A new card while the app is not in the foreground raises a local notification with the
  fixed text “New approval request”, without command details. Tapping it opens the app on
  that card (`wardenclaw://feed?card=<id>`). There are deliberately no Allow/Deny actions in
  the notification. Resolved or expired cards remove their notification. A card the phone signs
  by itself (Observe, the service rule, Autopilot) raises no notification: the persistent service
  notification carries the summary instead ("Observe until HH:MM · signed N, dangerous M").
- The service notification sits in a minimum-importance channel (no sound, no status bar
  icon on most launchers).
- Mode tab → Notifications → “Background notifications”: on by default once a server is
  paired. Turning it on asks for `POST_NOTIFICATIONS` (Android 13+).
- Why `specialUse` and not `dataSync`: with targetSdk 35+ `dataSync` services are limited to
  6 hours per day (`Service.onTimeout`). `specialUse` requires
  `FOREGROUND_SERVICE_SPECIAL_USE` and the `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` property; the
  config plugin `modules/wardenwatch/plugin/withWardenWatch.js` adds both, plus the service
  declaration. Play Store review would ask to justify the subtype; sideloaded builds don't care.
- Android 12+ does not allow starting a foreground service from the background, so the
  service is started from the visible app (after pairing, on app start, or when the toggle
  is turned on). `START_STICKY` lets the system restart it after it kills the process.
- No wake lock is held: incoming data on the relay connection wakes the CPU. If notifications arrive late,
  set battery usage for WardenClaw to “Unrestricted”.

## Experimental: local judge models

The Experimental tab can run a local judge on the phone. **No model weights are included in
this repository or in the APK.** The app downloads them from Hugging Face only when you ask,
checks each file against the SHA-256 in `src/bench/catalog.ts`, and stores them in the app's
private storage. The weights stay under their own licenses:

| model in the app | files | license |
|---|---|---|
| Qwen3-4B (`qwen4`) | [unsloth/Qwen3-4B-Instruct-2507-GGUF](https://huggingface.co/unsloth/Qwen3-4B-Instruct-2507-GGUF), Q4_0; base [Qwen/Qwen3-4B-Instruct-2507](https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507) | Apache-2.0 |
| Kev-multi (`kevm`) | [onnx-community/kev-0.6b-ONNX](https://huggingface.co/onnx-community/kev-0.6b-ONNX), q4; base [jaredpalmer/kev-0.6b](https://huggingface.co/jaredpalmer/kev-0.6b) (Qwen3-0.6B-Base) | Apache-2.0 |

The benchmark screen can also download retired candidates, all Apache-2.0: Qwen3-1.7B
(`unsloth/Qwen3-1.7B-GGUF`), Qwen3-4B-Instruct-2507 Q4_K_M, Qwen2.5-1.5B-Instruct
(`Qwen/Qwen2.5-1.5B-Instruct-GGUF`; other Qwen2.5 sizes such as 3B and 72B have a different
Qwen license) and Laya (`receptron/laya-onnx`, base `convaiinnovations/laya`, ModernBERT). If a
build ever ships weights inside the app (for example in a Play asset pack), it has to include
the Apache-2.0 text and the model's notices.

## License

Copyright (C) 2026 The WardenClaw Authors (see [AUTHORS](../AUTHORS)).

The WardenClaw app is free software: you can redistribute it and/or modify it under the terms
of the **GNU General Public License, version 3 or (at your option) any later version**
([LICENSE](LICENSE), SPDX `GPL-3.0-or-later`), with the following **additional permission for
app store distribution** under section 7 of the GPL. The same text, with its preamble, is in
[COPYING.exceptions](COPYING.exceptions):

> As an additional permission under section 7 of the GNU General Public
> License, version 3, the copyright holders of the WardenClaw app give you
> permission to convey this program, or a work based on it, in object code
> form through an application store or distribution service operated by a
> third party, such as the Apple App Store or Google Play, even though the
> terms of service or usage rules of that store, or the technical measures
> it applies to the copies it distributes (for example digital rights
> management, code signing that keeps a recipient from installing a
> modified version on the same device, or limits on the number of devices
> or on further redistribution), impose on recipients restrictions that the
> GPL would not otherwise permit, provided that all of the following
> conditions are met:
>
>   a) those restrictions are imposed by the operator of the store or
>      service and not by you, and you impose no further restrictions of
>      your own on the exercise of the rights granted by the GPL;
>
>   b) you comply with the GPL in every other respect; in particular you
>      make the Corresponding Source of the object code you convey,
>      including your modifications, available under the GPL to every
>      recipient, free of charge and free of those restrictions, as
>      section 6 of the GPL permits (for example from a public source code
>      repository); and
>
>   c) the conveyed program, or its store listing, states that the program
>      is licensed under the GPL with this additional permission and tells
>      recipients where to obtain the Corresponding Source and the text of
>      the GPL.
>
> This permission is limited to the conflict between the GPL and the terms
> or technical measures of such a store or service; it grants no other
> exception from the GPL. As section 7 of the GPL allows, when you convey a
> copy of a covered work you may remove this additional permission from
> that copy or from any part of it. If you modify the program you may
> extend this permission to your modifications, but you are not obliged to
> do so.

The protocol specification and test vectors the app implements live in
[`protocol/`](../protocol/) at the repository root under the **Apache License 2.0**; the license
map of the whole repository is in the root [LICENSE](../LICENSE).

Source files carry `SPDX-License-Identifier: GPL-3.0-or-later` (the app store permission applies
to all of them, see above). Third-party components and their licenses are listed in
[NOTICE](NOTICE). "WardenClaw", the logo and the app icons in `assets/` are trademarks and are
not licensed for use in forks; see [TRADEMARKS.md](../TRADEMARKS.md).
Contributions: [CONTRIBUTING.md](../CONTRIBUTING.md) (DCO sign-off); vulnerabilities:
[SECURITY.md](../SECURITY.md).
