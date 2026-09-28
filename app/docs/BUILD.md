# Building WardenClaw locally

The app is an Expo (SDK 57, React Native 0.86) project with Continuous Native Generation:
`ios/` and `android/` are generated from `app.json` and the config plugins and are never
committed. You can build it three ways:

| way | needs | signing | cost |
|---|---|---|---|
| `eas build --local` (recommended) | Expo account, this machine | credentials stored in EAS | free, runs on your machine |
| fully local, no EAS | nothing online | your own keystore / Apple team | free |
| EAS cloud (`scripts/eas_build.sh`) | Expo account | credentials stored in EAS | uses EAS build credits |

The scripts in `app/scripts/local/` wrap the first two. They run on macOS (iOS and Android) and
Linux (Android only).

## Platform status

| feature | Android | iOS |
|---|---|---|
| approvals, pairing (QR), device key, journal | yes | yes |
| YubiKey (FIDO2) | NFC and USB-C | NFC only (iPhone 7 and newer); USB-C is not supported, see below |
| Apple Watch approver | no | not available in this release, see "Apple Watch" |
| background notifications | own foreground service; shows on the lock screen without the command, see [lockscreen-notifications.md](lockscreen-notifications.md); FCM push from the relay (`modules/wardenpush`) when the build has a `google-services.json` | APNs push from the relay (`modules/wardenpush`, time-sensitive) |
| experimental on-device judge (llama.rn, onnxruntime) | yes | experimental; production adviser remains CPU-only until the iPhone benchmark is validated |
| judge benchmark screen | hidden entry on the Mode tab | hidden entry on the Mode tab; supports CPU/Metal comparison |

**First release.** The YubiKey, the Apple Watch app and the on-device judge are behind build
flags: `EXPO_PUBLIC_WARDENCLAW_FEATURE_HARDWARE_KEY`, `_APPLE_WATCH` and `_PHONE_JUDGE` are `"0"`
in the `production` and `preview` profiles of `eas.json` and `"1"` in `bench`. With a flag off the
feature's code and strings are not in the JS bundle, its config plugins and entitlements are left
out (`app.config.ts`), and its native modules are not autolinked (`react-native.config.js` for
llama.rn and onnxruntime, `plugins/withFeatureAutolinking.js` for `modules/yubikey`,
`modules/applewatch` and `@bacons/apple-targets`): no watch target, no llama or onnxruntime
libraries in the APK. What each flag controls is in `features.js`; how to bring a feature back is
in [release-scope.md](release-scope.md). The rows above describe the builds with the flags on.

Native modules in `app/modules/`: `yubikey` (Kotlin and Swift), `applewatch` (Swift,
WatchConnectivity, iOS only), `wardenwatch` (Kotlin, Android only), `wardenpush` (Swift and Kotlin:
the push token for the relay, APNs on iOS and FCM on Android), and `benchprobe` (Kotlin and Swift). The iOS benchmark probe records battery level, power state, thermal state,
structured logs, and SHA-256 verification. Public iOS APIs do not expose current draw,
battery temperature, or a charge counter, so those fields are reported as unavailable rather
than estimated.
The Apple Watch app lives in `app/targets/watch/` (see "Apple Watch" below).

iOS minimum is 16.4 (`ios.deploymentTarget`, required by Expo SDK 57; llama.rn needs 13+ and
onnxruntime 15.1+). llama.rn uses Metal. The app requests the
`com.apple.developer.kernel.increased-memory-limit` entitlement so a 4B model fits in memory;
EAS enables that capability on the App ID when it syncs credentials.

The physical-device benchmark procedure and acceptance criteria are in
[`judge-bench-ios-spike.md`](judge-bench-ios-spike.md).

## Requirements

Run the doctor first. It checks everything below and prints the `brew` commands for what is
missing:

```sh
cd app
scripts/local/doctor.sh          # all platforms on macOS, Android on Linux
scripts/local/doctor.sh ios      # or only one platform
```

- Node 20.19.4+, 22.13+ or 24.3+ (`app/.nvmrc` says 24), npm, git, rsync
- iOS: macOS, Xcode 16 or newer (opened once, license accepted, `xcode-select` pointing at
  Xcode.app) **with the watchOS platform** (`xcodebuild -downloadPlatform watchOS`: every iOS
  build also builds the embedded Apple Watch app), CocoaPods, fastlane (`eas build --local`
  archives and signs with it), iOS and watchOS simulator runtimes for simulator builds
- Android: JDK 17, Android SDK with `platforms;android-36`, `build-tools;36.0.0`,
  `ndk;27.1.12297006`, `cmake;3.22.1`, `platform-tools`, and `ANDROID_HOME` set
- about 30 GB free disk for the first iOS plus Android build
- optional: `eas-cli` installed globally (`npm i -g eas-cli`; otherwise the scripts use
  `npx eas-cli@latest`), watchman

A typical macOS setup:

```sh
brew install node@24 cocoapods fastlane watchman rsync
brew install --cask zulu@17 android-commandlinetools
echo 'export JAVA_HOME=$(/usr/libexec/java_home -v 17)' >> ~/.zprofile
echo 'export ANDROID_HOME=/opt/homebrew/share/android-commandlinetools' >> ~/.zprofile
source ~/.zprofile
yes | sdkmanager --licenses
sdkmanager "platforms;android-36" "build-tools;36.0.0" "ndk;27.1.12297006" "cmake;3.22.1" "platform-tools"
npm install -g eas-cli
```

### Build values and `app/.env.local`

`EXPO_PUBLIC_*` values are baked into the JS bundle, so a build for distribution must not carry
personal ones. The rules:

- A build gets its values only from the profile `env` in `app/eas.json`. `production` and
  `preview` set `EXPO_PUBLIC_WARDENCLAW_GATEWAY_URL`, `_MODEL_URL` and `_MODEL` explicitly to
  `unset` (the eas.json schema rejects empty values; an explicit profile value also overrides
  EAS environment variables on expo.dev) and `EXPO_PUBLIC_WARDENCLAW_BENCH` to `0`; `bench`
  extends `preview` and only adds `EXPO_PUBLIC_WARDENCLAW_BENCH=1`.
- Local env files never leave your machine: the root `.easignore` excludes `app/.env` and
  `app/.env.*` (except `.env.example`), and `scripts/local/*.sh` do not copy them to the stage.
- `scripts/check-build-env.mjs <profile>` refuses a `production` or `preview` build if any
  `EXPO_PUBLIC_WARDENCLAW_*` is set to anything but empty or `unset` in the profile env, the shell or (for local builds) the
  env files next to the build. It prints variable names, never values. `scripts/eas_build.sh`
  and `scripts/local/*.sh` run it before every build.
- Personal values for the dev server (`npx expo start`) go to `app/.env.local` (not in git). The
  code reads the gateway and judge hints only under `__DEV__`, so even a release build made with
  a filled `.env.local` does not contain them; without a URL and model name saved in the app the
  judge does not call any network.

```sh
cp app/.env.example app/.env.local     # optional; empty values are fine
```

The `trash-put` path rule is no longer a build value: set it in the app, "Mode" → "Local rules".

### `bench` build

`EXPO_PUBLIC_WARDENCLAW_BENCH=1` (the `bench` profile) adds the on-device judge benchmark, the
test cards of `wardenclaw://bench?…` (marked "TEST", never sent anywhere, the judge model never
sees their text) and a switch that turns off screen protection for documentation screenshots.
In every other build the code is not in the bundle: `App.tsx` and `ModeScreen.tsx` load
`src/bench/entry.ts` with `require` inside a condition on the variable, which Metro folds to
`false` before collecting dependencies. `metro.config.js` keys the transform cache on the flag,
so a local `preview` build after a `bench` one does not reuse bench transforms. Quick check of a
bundle: no `WARDEN_BENCH` string in it.

## Where the build runs, where artifacts go

By default the scripts do not build inside your checkout. They copy the monorepo (without
`node_modules`, `ios/`, `android/`, build outputs) with `rsync` to a staging directory and build
there, so Pods, Gradle caches and macOS `node_modules` never land in a synced folder.

| variable | default | meaning |
|---|---|---|
| `WC_STAGE_DIR` | `~/.cache/wardenclaw/stage` | staging copy of the monorepo |
| `WC_IN_PLACE=1` | off | build in the checkout itself (plain clones, CI) |
| `WC_OUT_DIR` | `~/WardenClaw-builds` | finished `.ipa`, `.apk`, `.aab`, simulator `.tar.gz` |

Artifacts are named `wardenclaw-<platform>-<profile>-<timestamp>.<ext>`. `eas build --local`
also keeps its own temporary working directory only while it runs.

## First time: EAS account and iOS credentials

`eas build --local` compiles on your machine but still talks to EAS for the project link,
version numbers (`cli.appVersionSource: remote`) and signing credentials. None of that uses
build credits.

```sh
cd app
eas login                          # your Expo account (the `owner` in app.json, or your fork's)
eas credentials --platform ios     # once: sign in to Apple (Apple ID, 2FA code)
```

In `eas credentials` choose the `production` profile, then "Build Credentials" and let EAS create
or reuse the Distribution Certificate and the App Store provisioning profile for
`com.wardenclaw.app` (it registers the bundle id if needed; the Increased Memory Limit
capability is switched on for the App ID during the first build). You need a paid Apple Developer Program membership. After this, local iOS builds do not ask
for the Apple login again.

The Android keystore used by the cloud builds is already stored in EAS; local EAS builds use
the same one, so they install over earlier builds.

## iOS: TestFlight

```sh
cd app
scripts/local/ios.sh               # = ios.sh build: eas build --platform ios --profile production --local
scripts/local/ios.sh submit        # uploads the newest .ipa from ~/WardenClaw-builds
```

`submit` uses `eas submit --platform ios --path <ipa>` (free, it asks for an App Store Connect
login or API key the first time and creates the app record if needed). Without EAS, set an
App Store Connect API key (Users and Access → Integrations → App Store Connect API, role
App Manager) and the script uploads with `xcrun altool`:

```sh
export ASC_KEY_ID=ABC123XYZ ASC_ISSUER_ID=00000000-0000-0000-0000-000000000000
export ASC_KEY_PATH=~/Downloads/AuthKey_ABC123XYZ.p8
scripts/local/ios.sh submit
```

(`notarytool` is for macOS apps and is not used for iOS uploads.) Processing in App Store
Connect takes 5 to 30 minutes, then the build appears in TestFlight. The export compliance
question is answered by `ITSAppUsesNonExemptEncryption = false` in `app.json`.

Quick check without Apple signing, in the iOS simulator:

```sh
scripts/local/ios.sh sim           # eas build --local, profile simulator, installs into the booted simulator
scripts/local/ios.sh sim-xcode     # the same without EAS: prebuild + pod install + xcodebuild
```

## YubiKey on iOS

The `yubikey` module has a Swift implementation (`modules/yubikey/ios/`) with the same JS API as
on Android, on top of Yubico's YubiKit for iOS 4.7.0. The config plugin adds, at prebuild:

- the entitlement `com.apple.developer.nfc.readersession.formats = [TAG]` (App ID capability
  **NFC Tag Reading**);
- in `Info.plist`: `NFCReaderUsageDescription` and the FIDO applet id `A0000006472F0001` in
  `com.apple.developer.nfc.readersession.iso7816.select-identifiers` (without it iOS never reports
  the key);
- in the `Podfile`: `pod 'YubiKit', :git => …, :tag => '4.7.0', :modular_headers => true`
  (CocoaPods trunk only has 4.4.0, and the Swift module needs the pod as a module).

Transports on iPhone:

- **NFC** (iPhone 7 and newer): the system NFC sheet, hold the key to the top edge of the phone.
- **USB-C (iPhone 15 and newer): not supported.** YubiKit's USB-C path goes through CryptoTokenKit
  smart card sessions and carries only smart-card applications (PIV, OATH), not FIDO2. The app
  says so on the Mode tab instead of asking you to plug the key in.
- **Lightning (YubiKey 5Ci)**: off by default. `["./modules/yubikey/plugin/withYubikey",
  {"lightning": true}]` declares `com.yubico.ylp` in `UISupportedExternalAccessoryProtocols`; an
  App Store or TestFlight build with that key needs the app to be registered in Yubico's MFi
  program first, otherwise review rejects it.

## Apple Watch

**Not available in this release.** The feature flag is off, and the watch target has not been
ported to the relay: its client (`targets/watch/App`) speaks to an HTTP endpoint of wardend that
no longer exists, so a build with the flag on compiles but the watch cannot pair or receive
cards. What follows describes the code that is in the tree. Work log: [`ios-watch.md`](ios-watch.md).

Design that stays valid for a port: the watch is an independent approver with its own P-256 key
in the Secure Enclave; the phone only hands it a pairing link over WatchConnectivity, because the
watch has no camera. Approving happens only inside the watch app (hold the ring for about 1.5 s or
turn the Digital Crown to the end); the notification category `WARDEN_APPROVAL` has **Open** first
and **Deny** second, never Approve. Before signing `allow` the watch checks the card like the
phone and wardenctl (exactly the 13 fields of envelope v1, `supervisorId` equal to the pinned one,
digest recomputed, `id == "wd-" + digest[:32]`); cards with `meta.hardware.required` can only be
denied.

### How it is built

`app/targets/watch/` is a target for [`@bacons/apple-targets`](https://github.com/EvanBacon/expo-apple-targets)
(5.0.0, `type: "watch"`): `expo prebuild` adds a single-target watchOS app `WardenClawWatch`
(bundle id `com.wardenclaw.app.watchkitapp`, watchOS 10+) to `ios/WardenClaw.xcodeproj`, embeds it
into the iPhone app ("Embed Watch Content") and registers it for EAS credentials
(`extra.eas.build.experimental.ios.appExtensions`), so `eas build --local` signs both. Every
`.swift` under `targets/watch/` is compiled into the watch app (`App/`: UI, key, client;
`Protocol/`: canonical JSON, envelope check, signing strings). `Assets.xcassets` in that folder is
generated at prebuild from `assets/icon.png` and is not committed.

Why this and not a separate XcodeGen project: the plugin keeps the watch inside the one generated
project, so `ios.sh build`, EAS credentials and TestFlight work unchanged. It works with SDK 57
(checked with `expo prebuild` on Linux), although its SDK 57 release (6.0.0) is still a pull
request; if a later SDK breaks it, pin or upgrade the plugin before anything else.

The protocol code is also a SwiftPM package, `app/targets/Package.swift`, with XCTest against
`protocol/vectors/*.json` (canonical, hw, transport, es256; on macOS also the Ed25519 and P-256
signatures through CryptoKit):

```sh
scripts/local/ios.sh swift-test     # or: cd app/targets && swift test
```

Commands:

```sh
scripts/local/ios.sh watch-sim      # watch app only, watchOS simulator, no signing, no Pods
scripts/local/ios.sh sim-xcode      # iPhone app for the simulator (builds the watch app too)
scripts/local/ios.sh xcode          # open the workspace (Xcode creates the WardenClawWatch scheme on first open)
```

The watch simulator has no Secure Enclave: there, and only there, the watch uses a software
P-256 key in the Keychain so the UI can be tried.

### Key storage

`SecureEnclave.P256.Signing.PrivateKey` with access control `.privateKeyUsage`; its opaque
`dataRepresentation` sits in the Keychain as `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`: not
in backups, not moved to a new watch, unusable while the watch is locked (taken off the wrist).
Unpairing on the watch deletes the key; a new pairing makes a new key and a new device id.

`.userPresence` (ask for the watch passcode on every signature) is **off by default**, and that
is a decision, not an omission (P0 review, 27.09.2026). The flag belongs to the key, not to one
signature: it cannot be asked for "allow on a dangerous card" only. The same key signs every
request of the watch, not only decisions, so with `.userPresence` the watch would ask for the
passcode over and over while the app is open and on every deny from a notification. What protects a stolen watch instead: the key is usable only
while the watch is unlocked (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`), and watchOS locks it
as soon as it leaves the wrist (wrist detection; keep it on). An allow always takes a deliberate
1.5 s hold or a full turn of the Digital Crown, dangerous cards are marked with their reasons,
and cards that need the YubiKey cannot be approved on the watch at all. To turn `.userPresence`
on anyway, add the compilation condition `WC_WATCH_USER_PRESENCE` to the `WardenClawWatch` target
(Build Settings → Active Compilation Conditions) and pair the watch again (the flag applies to
newly created keys).

## Apple Developer: what to set up

A paid Apple Developer Program membership is needed (push notifications do not exist on free
accounts). In [Certificates, Identifiers & Profiles](https://developer.apple.com/account/resources/identifiers/list):

| App ID | capabilities |
|---|---|
| `com.wardenclaw.app` | Push Notifications, Time Sensitive Notifications; with the feature flags on also NFC Tag Reading (YubiKey) and Increased Memory Limit (local judge) |
| `com.wardenclaw.app.watchkitapp` (only with the Apple Watch flag on) | Push Notifications |

`eas build --local` (after `eas credentials --platform ios`) registers both bundle ids, turns on
the capabilities it finds in the entitlements and creates both provisioning profiles; check the
list above afterwards. By hand in Xcode: Signing & Capabilities for both targets, one team.

- No App Group is used: the watch and the phone share nothing but the pairing link.
- No APNs key goes into the app or onto wardend. Pushes are sent by the relay with the app
  publisher's credentials; an operator of wardend creates nothing in Apple Developer. Only whoever
  runs their own relay for their own build of the app sets the push secrets there
  ([`relay/README.md`](../../relay/README.md)).
- App Store Connect: one app record for `com.wardenclaw.app`; the watch app ships inside it.

### First run on the Mac

```sh
cd app
scripts/local/doctor.sh ios                # Xcode 16+, watchOS platform, CocoaPods, fastlane
xcodebuild -downloadPlatform watchOS       # if the doctor asks for it
scripts/local/ios.sh swift-test            # protocol vectors in Swift (a few seconds)
scripts/local/ios.sh watch-sim             # the watch app compiles and starts in the simulator
scripts/local/ios.sh sim-xcode             # the iPhone app with the embedded watch app compiles
scripts/local/ios.sh xcode                 # device run: pick your team for WardenClaw and WardenClawWatch
scripts/local/ios.sh build                 # TestFlight .ipa (EAS signs both targets)
scripts/local/ios.sh submit
```

Compiler errors in `targets/watch/App/`, `modules/yubikey/ios/` or `modules/applewatch/ios/` are
likely on the first build: that Swift was written without Xcode (see `ios-watch.md`, "not
verified"). The protocol code in `targets/watch/Protocol/` is already compiled and tested.

## Android: APK and AAB

```sh
cd app
scripts/local/android.sh eas               # profile bench: APK, arm64-v8a only (fastest)
scripts/local/android.sh eas preview       # APK, all ABIs
scripts/local/android.sh eas production    # AAB for Google Play
scripts/local/android.sh install           # adb install -r of the newest APK (ANDROID_SERIAL for a specific phone)
```

Profiles (`eas.json`):

| profile | Android | iOS |
|---|---|---|
| `production` | AAB (`app-bundle`), store | App Store / TestFlight `.ipa` |
| `preview` | APK, all ABIs, internal | (ad hoc, needs registered devices; not used) |
| `bench` | APK, arm64-v8a, two llama.rn CPU variants | not used |
| `simulator` | APK | simulator `.app`, no signing |

`production`, `preview` and `bench` auto-increment the build number (`versionCode`,
`CFBundleVersion`) on EAS; the user-visible version is `expo.version` in `app.json`.

## Fully local, without EAS (forks)

No Expo account is needed. Everything comes from `app.json` via `expo prebuild`.

Android:

```sh
cd app
scripts/local/android.sh keystore          # once: ~/.config/wardenclaw/upload.jks + upload-keystore.env (back them up)
scripts/local/android.sh gradle apk        # prebuild + ./gradlew assembleRelease
scripts/local/android.sh gradle aab        # prebuild + ./gradlew bundleRelease
WC_ABIS=arm64-v8a scripts/local/android.sh gradle apk   # one ABI, much faster
```

The script adds a release `signingConfig` to the generated `android/app/build.gradle` that reads
`ORG_GRADLE_PROJECT_WC_UPLOAD_*` from the environment, so passwords are never written into the
project. `versionCode` is the commit count (`WC_VERSION_CODE` overrides it). A build signed with
your keystore cannot be installed over one signed by EAS (and vice versa): Android would require
uninstalling first, which deletes the device key and the journal, so you would have to pair
again.

iOS:

```sh
scripts/local/ios.sh xcode         # prebuild + pod install, opens WardenClaw.xcworkspace
```

In Xcode select the `WardenClaw` and `WardenClawWatch` targets → Signing & Capabilities, pick your team
(change the bundle identifiers if `com.wardenclaw.app` is not yours), then Product → Archive and distribute
from the Organizer. For a fork, also change `ios.bundleIdentifier`, `android.package`, `owner`
and `extra.eas.projectId` in `app.json` (remove the last two if you do not use EAS).

By hand, without the scripts:

```sh
cd app && npm ci
npx expo prebuild --clean
cd ios && pod install && open WardenClaw.xcworkspace         # iOS
cd android && ./gradlew assembleRelease                      # Android (debug-signed unless you add signing)
```

## Common problems

- **`pod install` fails or pods are stale.** `cd <stage>/app/ios && pod repo update && pod install`,
  or delete the stage (`rm -rf ~/.cache/wardenclaw/stage`) and build again. On Apple silicon,
  install CocoaPods with Homebrew rather than the system Ruby.
- **The first iOS build is slow.** 15 to 30 minutes is normal: Pods, React Native and the
  llama.rn JSI bindings compile from source (the llama.cpp core comes prebuilt as
  `rnllama.xcframework`). Later builds reuse the caches.
- **"You have not agreed to the Xcode license".** `sudo xcodebuild -license accept`. If
  `xcodebuild` says it needs Xcode, not the command line tools:
  `sudo xcode-select -s /Applications/Xcode.app/Contents/Developer`.
- **`sdkmanager: command not found` or missing NDK/CMake.** Install
  `android-commandlinetools`, set `ANDROID_HOME`, run the `sdkmanager` line printed by
  `doctor.sh`. Accept licenses with `yes | sdkmanager --licenses`.
- **Gradle picks the wrong Java.** `export JAVA_HOME=$(/usr/libexec/java_home -v 17)`.
- **`fastlane` not found during `eas build --local` for iOS.** `brew install fastlane`.
- **"No matching provisioning profile" / credentials errors.** Run
  `eas credentials --platform ios` again and let it repair the profile.
- **`INSTALL_FAILED_UPDATE_INCOMPATIBLE` on `adb install`.** The phone has a build signed with a
  different key (EAS vs local keystore). See the note above before uninstalling.
- **llama.rn native artifacts did not download.** `npm ci` runs
  `node_modules/llama.rn/install/download-native-artifacts.js` from the app's `postinstall`; run
  it again by hand if the network dropped.
- **`expo prebuild` changed `package.json`.** Prebuild rewrites the `ios`/`android` scripts; this
  only happens in the stage copy.
