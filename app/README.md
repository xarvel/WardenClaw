# WardenClaw (Android, iOS)

*Take back control.* Nothing runs on your machine until your phone signs it.

Phone-side approver for `wardend`: shows approval cards, signs decisions with the device key
(optionally a YubiKey tap), keeps a local hash-chained journal (the owner can clear it from the
Journal tab; the wipe is recorded as the first entry of the new chain). Expo SDK 57, React Native 0.86.
Android is the main platform; iOS builds without YubiKey and background notifications for now.
The first release leaves out the YubiKey, the Apple Watch app and the on-device judge: they are
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

## Language

The UI is English only, regardless of the system language. All strings live in
`src/core/i18n/en.ts` and the feature dictionaries in `src/core/i18n/features/`.

## Background notifications

No third-party push service is involved: the phone keeps its own connection to the user's
`wardend`, the same way it does in the foreground.

- `modules/wardenwatch` is a local Expo module with an Android foreground service of type
  `specialUse`. While it runs, it keeps a headless JS task (`WardenWatch`) active, so React
  Native does not pause JS timers in the background and the existing long-poll to
  `/v1/pending` (`src/core/wardendClient.ts`, loop in `src/core/controller.ts`) keeps going.
- A new card while the app is not in the foreground raises a local notification with the
  fixed text “New approval request”, without command details. Tapping it opens the app on
  that card (`wardenclaw://feed?card=<id>`). There are deliberately no Allow/Deny actions in
  the notification. Resolved or expired cards remove their notification.
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
- No wake lock is held: incoming long-poll data wakes the CPU. If notifications arrive late,
  set battery usage for WardenClaw to “Unrestricted”.

### Optional: ntfy (not implemented)

If a persistent connection per phone is not wanted, `wardend` could publish a content-free
wake-up to a self-hosted [ntfy](https://ntfy.sh) server, and the app would subscribe with
ntfy's Android client or UnifiedPush distributor instead of running its own service:

1. Self-host ntfy next to `wardend` (for example behind the same Cloudflare tunnel) with
   access control, and create a random, unguessable topic per paired device.
2. `wardend` publishes only a bare event (`{"t":"pending"}`, no command, no id) to that
   topic when a new record appears.
3. The app registers as a UnifiedPush receiver; on a message it performs one signed
   `GET /v1/pending` and shows the same “New approval request” notification. Card contents
   are still fetched and verified with the pinned server key, so ntfy never sees them.

This trades the always-on service for a dependency on the ntfy app or distributor being
installed and allowed to run in the background.

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
