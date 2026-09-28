# iOS: YubiKey and Apple Watch, work log

Journal of the iOS YubiKey module and the Apple Watch app (started 2026-09-27). Newest entries at
the bottom. Swift code in this repo is written on a Raspberry Pi without Xcode: whatever could
not be compiled here is listed under "not verified".

## 2026-09-27

- Start. Read BUILD.md, modules/yubikey (Kotlin), modules/wardenwatch, protocol/README.md,
  protocol/HARDWARE.md, the Apple Watch research note.
- Research (web, Sep 27): `@bacons/apple-targets` 5.0.0 (Jul 17) has `type: "watch"` (single-target
  watchOS app, "Embed Watch Content"), SDK 57 support is an open PR (#210, 6.0.0 unpublished).
  yubikit-ios 4.7.0: FIDO2 with raw clientDataHash over NFC and Lightning; **no FIDO2 over USB-C**
  (YKFSmartCardConnection refuses fido2Session). CocoaPods trunk stops at 4.4.0, so the Podfile gets
  the git tag 4.7.0 with modular headers.
- The wardend side (other agent, daemon/docs/watch-apns.md): es256 deviceId = hex(sha256(65-byte
  SEC1)), `alg` is part of the pairing signing string, body requests sign
  canonicalJson({action, body, deviceId, nonce, ts}); vectors in protocol/vectors/es256_vectors.json.
- Swift protocol code: app/targets/watch/Protocol (JSON parser, canonical JSON, envelope check,
  signing strings, pairing link), SwiftPM package app/targets/Package.swift with XCTest against
  protocol/vectors. **Swift 6.4.0 toolchain for Debian 13 aarch64 installed without sudo in
  /srv/scratch/swift (1 GB, /tmp is a RAM tmpfs with 3 GB free); `swift test`: 9 tests green on
  Linux**, including canonical_vectors byte for byte, hw, transport and es256 signing strings.
- iOS YubiKey module written (modules/yubikey/ios, config plugin iOS part). Not compiled (no Xcode).
- Commit 6a694a1: YubiKey on iOS (NFC). Prebuild on the Pi in a clone (/srv/scratch/wc-prebuild):
  entitlements (TAG), Info.plist (AID, usage string), Podfile (YubiKit git 4.7.0) and iOS
  autolinking of the Yubikey pod verified.
- Watch app sources written: targets/watch/App (DeviceKey: Secure Enclave P-256 in Keychain
  WhenUnlockedThisDeviceOnly; WardendClient: signed requests, response signature check with the
  pinned Ed25519 key, pair es256, pending, decide, push register; WatchModel; PhoneLink
  (WatchConnectivity, a link arriving while paired needs a tap on the watch); Views: list, card,
  approve by 1.5 s hold or Digital Crown, deny; notification category WARDEN_APPROVAL = [Open, Deny]).
  `swiftc -parse` clean. Not typechecked (SwiftUI/WatchKit/CryptoKit do not exist on Linux).
- Next: expo-target.config.js + Info.plist, prebuild check, iPhone side (WatchConnectivity module,
  "Apple Watch" section), docs, commits.
- Commit 493fa4b: the watch app. Watch build path chosen: `@bacons/apple-targets` 5.0.0 (see
  "Decisions"). Prebuild on the Pi with SDK 57 creates target WardenClawWatch (watchOS 10,
  com.wardenclaw.app.watchkitapp), the embed phase, the target dependency, generated.entitlements
  (aps-environment) and the EAS appExtensions entry.
- iPhone side: modules/applewatch (WatchConnectivity), "Apple Watch" section on the Mode tab.
- Docs: BUILD.md (YubiKey on iOS, Apple Watch, Apple Developer, first run on the Mac), site page
  docs/ios (en/ru, links to the other agent's docs/apple-watch). Site built in /tmp/wc-site.

## Decisions

- **Watch build: @bacons/apple-targets, not XcodeGen.** The plugin puts the watch target into the
  one generated Xcode project, embeds it and registers it with EAS credentials, so `ios.sh build`,
  signing and TestFlight need no extra steps. A separate XcodeGen project would need a second
  signing setup and a manual embed step into the archive after every prebuild. Risk: its SDK 57
  release (6.0.0, PR #210) is not published; 5.0.0 works for prebuild on SDK 57 (checked here).
  MARKETING_VERSION of the watch is synced to `expo.version` by the plugin; CURRENT_PROJECT_VERSION
  is `ios.buildNumber || 1`: if App Store validation complains about CFBundleVersion of the
  embedded watch app, set `ios.buildNumber` or bump the watch build setting.
- **Shared Swift**: only the watch needs the protocol in Swift (the iPhone app does it in
  TypeScript). The code lives in targets/watch/Protocol (compiled into the watch by folder sync)
  and is a SwiftPM target of targets/Package.swift for tests.
- **Watch does not sign `risk`** (no judge on the wrist) and never `hw`.
- **A pairing link that arrives while paired** needs a confirmation on the watch: a queued
  WatchConnectivity transfer must not silently replace the pairing.
- **APNs environment** is read from embedded.mobileprovision (development profile: sandbox;
  none, as in App Store/TestFlight: production).
- **Phone push** (expo-notifications + /v1/push/register with the Ed25519 key) is not done: it
  needs a new dependency, a body-signing helper in TS and notification routing; not "almost free".
- **Lightning 5Ci** behind a plugin option (MFi registration needed for App Store).

## Verified on the Pi

- `swift test` (Swift 6.4.0, Linux): the protocol code against canonical, hw, transport and es256
  vectors, parser strictness, number formatting, display command. 9 tests.
- `tsc --noEmit`, `npm test` (13 tests, including the Podfile insertion of withYubikey).
- `expo prebuild --platform ios --no-install` in a clone: entitlements, Info.plist (plistlib),
  Podfile, autolinking (Yubikey, AppleWatch pods), watch target in project.pbxproj.
- `swiftc -parse` of every Swift file; the CBOR helper of the iOS YubiKey module compiled and run.
- Site built from a copy (/tmp/wc-site).

## Not verified (needs Xcode on the Mac)

- ~~Compilation of targets/watch/App, modules/yubikey/ios, modules/applewatch/ios~~: compiled for
  the simulator in EAS build ccf3a710 (see "First compilation"). Device slices (iphoneos,
  watchOS arm64_32/arm64) and the Secure Enclave branch of DeviceKey.swift: not compiled yet.
- On macOS `swift test` additionally runs the CryptoKit branch (SHA-256 via CryptoKit, Ed25519 and
  P-256 signature checks): not run here.
- Runtime: NFC sheet flow, Secure Enclave key, WatchConnectivity delivery, APNs registration,
  double tap behaviour, EAS signing of the watch target, App Store validation of the embedded app.

## First compilation

EAS Build, profile `simulator` (Release, `generic/platform=iOS Simulator`, Xcode with the
iPhoneSimulator/WatchSimulator 26.5 SDKs), started from a clean clone in /tmp, not from the share.
Xcode logs: `eas build:view <id> --json` → `artifacts.xcodeBuildLogsUrl` (tar.gz with log.txt;
the server sends it with a content encoding, so `curl --compressed` saves the log text itself).
xcodebuild stops scheduling new targets after the first error, so one failed build shows the
errors of one target only.

- **eabbec70-2706-444d-a2aa-e7cce442704e** (commit 123170c): BUILD FAILED, one error:
  `YubikeyModule.swift:106: value of type 'YKFFIDO2Session' has no member 'getAssertion'`.
  The watch target was already compiled in that build: `WardenClawWatch` (Release-watchsimulator,
  x86_64 and arm64, whole-module) compiled all of targets/watch/App and targets/watch/Protocol
  without errors or warnings and was linked. The AppleWatch and BenchProbe pods had not been
  reached (only their auxiliary files were written).
- Fix (ac468b2): `session.getAssertionWithClientDataHash(cdh, rpId:allowList:options:completion:)`.
  Swift keeps the whole first selector piece here, while `makeCredential(withClientDataHash:…)`
  is split; both spellings are the ones in Yubico's FIDO2Tests.swift for 4.7.0. Same call, same
  semantics. The other YubiKit uses were checked against the 4.7.0 headers (YKFFIDO2Session,
  YKFFIDO2Type, YKFFIDO2MakeCredentialResponse/AuthenticatorData, YKFFIDO2GetAssertionResponse,
  YubiKitManager and YKFManagerDelegate, YKFConnectionProtocol `fido2Session`,
  YubiKitDeviceCapabilities, YubiKitExternalLocalization, YKFFIDO2Error): they match.
- Before the next build: AppleWatchModule.swift and BenchProbeModule.swift reviewed against
  ExpoModulesCore 57.0.19 (Function/AsyncFunction parameter-pack signatures, OnCreate,
  `sendEvent(_:_: [String: Any?])`, Promise), UIKit, CryptoKit and WatchConnectivity; the closure
  shapes type-checked on the Pi against copies of the Expo signatures (Swift 6.4, `-swift-version 5`);
  `swiftc -parse` of every Swift file; `swift test` in targets: 9 tests green.
- **ccf3a710-956c-4f48-a840-5ede9f2fa3f0** (commit ac468b2): **BUILD SUCCEEDED**, 0 errors, no
  warnings in modules/ or targets/. Checked in the log and in the artifact (simulator .app tarball):
  - pods Yubikey, AppleWatch, BenchProbe (Swift, x86_64 and arm64) and YubiKit (256 ObjC files)
    compiled; the app links `-lYubikey -lAppleWatch -lBenchProbe -lYubiKit`; the app binary has
    YubikeyModule, AppleWatchModule and BenchProbeModule in it;
  - `WardenClawWatch`: SwiftCompile of all 9 sources (App/ and Protocol/) for x86_64 and arm64
    watchsimulator, Ld, universal binary, CodeSign, Validate, copied to
    `WardenClaw.app/Watch/WardenClawWatch.app`, `ValidateEmbeddedBinary` passed;
  - watch Info.plist: com.wardenclaw.app.watchkitapp, 0.1.0 (1) as the iPhone app,
    WKCompanionAppBundleIdentifier com.wardenclaw.app, WKApplication, WKRunsIndependentlyOfCompanionApp,
    MinimumOSVersion 10.0.
  - EAS: Starter plan, 400 of 4500 cents of included build credit used in the cycle that started
    Sep 27 18:22 (two iOS medium builds, $2 each), overage 0.
- Still not compiled: the device slices (iphoneos arm64; watchOS arm64_32 and arm64) and the
  `#else` branch of DeviceKey.swift (Secure Enclave key; the simulator uses the software key).
  Reviewed by hand: SecureEnclave.P256.Signing.PrivateKey(compactRepresentable:accessControl:) /
  (dataRepresentation:), no integer literal that overflows the 32-bit Int of arm64_32, timestamps
  are Int64. A device build needs signing (Apple Developer account, credentials for both App IDs);
  a compile-only check without signing would be a custom EAS build with
  `CODE_SIGNING_ALLOWED=NO` (one more included build credit).
