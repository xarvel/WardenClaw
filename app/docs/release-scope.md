# Composition of the first release in the app: YubiKey, Apple Watch and the on-phone judge behind flags (2026-09-28)

The maintainer's decision: the first release does not include YubiKey (second factor), Apple Watch
(the watch) and the judge on the phone itself (local models: llama.rn, onnxruntime-react-native,
@huggingface/tokenizers, the "Experimental: on-device judge" section). The judge by URL (remote
model) stays. The features will come back, so they are hidden behind build flags rather than cut
out. Zone: `app/` only. No push and no EAS builds. The flag names match the site's `FEATURES` in
meaning (`site/src/config.ts`: `hardwareKey`, `appleWatch`, `phoneJudge`).

## Flags

| Feature | Variable | production, preview | bench |
|---|---|---|---|
| YubiKey | `EXPO_PUBLIC_WARDENCLAW_FEATURE_HARDWARE_KEY` | `"0"` | `"1"` |
| Apple Watch | `EXPO_PUBLIC_WARDENCLAW_FEATURE_APPLE_WATCH` | `"0"` | `"1"` |
| On-phone judge | `EXPO_PUBLIC_WARDENCLAW_FEATURE_PHONE_JUDGE` | `"0"` | `"1"` |

The values are set in one place: the `env` of the profiles in `app/eas.json`. What stands behind
each flag in the native build (plugins, modules, entitlements) is described in one place:
`app/features.js`. Without the variable (a local `expo start` without `.env.local`) the feature is
off.

## How it works

- JS. A feature's code is pulled in only by the expression
  `process.env.EXPO_PUBLIC_WARDENCLAW_FEATURE_… === "1" ? require("…") : null` right on the spot
  (the bench technique from `docs/app-hardening.md`: babel-preset-expo substitutes the value, Metro
  drops the module from the graph). Spots: `App.tsx` (judge), `ModeScreen.tsx` (YubiKey, Apple
  Watch, Experimental blocks), `FeedScreen.tsx` (key tap modal, key rule lines, local model opinion,
  visible cards for the judge), `controller.ts` (`hardwareKey.ts`, `noteHumanDecision`). For the
  judge an entry point `src/localjudge/entry.ts` was added: without the flag neither
  `src/localjudge` nor the engines `src/bench/engines` (llama.rn, onnxruntime, tokenizers) get into
  the bundle.
- UI without the feature. There are no YubiKey, Apple Watch and Experimental blocks on the "Mode"
  tab, the card has no local model opinion line and no key rule lines. The key protocol
  (`src/core/hardware.ts`, wardend `meta.hardware`) stays: the server can require a key even without
  an app that supports keys. Such a card in a build without YubiKey says "The server allows this
  request only with a hardware key, and this version of the app has no key support: approve it on
  the server or deny it here", the "Allow" button is disabled, "Deny" works.
- Native. `app.json` stays the full config (all features), `app.config.ts` removes what is disabled
  from it: the plugins `./modules/yubikey/plugin/withYubikey`, `@bacons/apple-targets` (the watch
  target `targets/watch`), `llama.rn`; the entitlements `increased-memory-limit` and
  `extended-virtual-addressing` (needed by the local model); `NFCReaderUsageDescription`.
  Autolinking:
  - React Native libraries (`llama.rn`, `onnxruntime-react-native`) are excluded by
    `react-native.config.js` (`platforms: { android: null, ios: null }`, it is read by
    `expo-modules-autolinking react-native-config` from Gradle and the Podfile);
  - Expo modules (`modules/yubikey`, `modules/applewatch`, the module of `@bacons/apple-targets`
    itself) are excluded by the plugin `plugins/withFeatureAutolinking.js`: on prebuild it writes
    `expoAutolinking.exclude = [...]` into `android/settings.gradle` and
    `use_expo_modules!(exclude: [...])` into `ios/Podfile` (`expo-modules-autolinking` takes exclude
    only from `package.json` or from these arguments);
  - `@huggingface/tokenizers` is pure JS, it is dropped from the bundle.
- Strings. The feature dictionaries were moved out of `src/core/i18n/en.ts` and `ru.ts` into
  `src/core/i18n/features/{hardwareKey,appleWatch,phoneJudge,bench}.ts` (90, 23, 39 and 32 keys:
  `hw.*`, `yk.*`, `aw.*`, `exp.*`, `bench.*`, the key lines on the card, key binding and unbinding).
  `src/core/i18n/index.ts` pulls in a dictionary only when its flag is on (with the same technique),
  the `MsgKey` type includes their keys via `typeof import(...)`, so tsc still checks every `t()`.
  Without the flag `t()` for such a key returns the key itself, but a disabled feature does not show
  it anyway. Texts that are visible even without the feature were rewritten without YubiKey:
  `err.hwRequired` ("the server requires a hardware key"), the journal entry about a wardend refusal
  over the key, the `pushLog` lines.
- `metro.config.js`: the transform cache version also depends on the feature flags (otherwise a
  local release export after bench would take modules from the cache).
- `scripts/check-build-env.mjs`: in production and preview the feature flags must be explicitly
  `"0"` (otherwise an EAS variable on expo.dev could supply them), `"1"` in the profile or the
  environment: rejected.

### Deviation from the task: `modules/wardenwatch` stays

The task listed `withWardenWatch` and `modules/wardenwatch` among the watch parts. This is not the
watch: it is the Android background service (foreground service `specialUse`, long-poll to wardend,
request notifications, a receiver after reboot, the "like a call" screen), without it the Android
app does not receive requests in the background. The module and the plugin stay in the release. The
watch is `modules/applewatch` (WatchConnectivity, iOS only), `targets/watch` and
`src/ui/AppleWatch.tsx`. `modules/wardenpush` (APNs on iPhone) is not the watch either and stays.

## How to bring a feature back

1. `app/eas.json`: in `build.production.env` and `build.preview.env` set the feature's flag to `"1"`
   (`EXPO_PUBLIC_WARDENCLAW_FEATURE_HARDWARE_KEY`, `…_APPLE_WATCH` or `…_PHONE_JUDGE`).
   `scripts/check-build-env.mjs`: remove this variable from `FEATURE_FLAGS` (otherwise the
   production and preview builds will reject `"1"`), adjust the "release composition" test in
   `scripts/test-core.mjs` the same way.
2. Nothing else needs to change: `app.json`, the feature's code, its strings, plugins and modules
   are in place; the config (`app.config.ts`), autolinking (`react-native.config.js`,
   `withFeatureAutolinking`) and the bundle follow the flag. Check: `npx expo config --json`
   (plugins, entitlements, `extra.features`),
   `node node_modules/expo-modules-autolinking/bin/expo-modules-autolinking.js react-native-config --json --platform android`
   (llama.rn and onnxruntime in the list), `expo export` and a search through the bundle.
3. A local build or dev server with the feature: the variable in the environment or in
   `app/.env.local` (`features.js` reads `.env*` itself, because `react-native.config.js` is run by
   Gradle and CocoaPods without the Expo CLI).
4. On the site the feature comes back with its own flag (`site/src/config.ts`, `FEATURES`), in the
   daemon with its own (the `daemon/` zone).

## Progress

### 12:53-13:03, analysis and code

- Read `docs/app-hardening.md` (the bench technique), the site log, `app.json`, `eas.json`, the
  modules. `wardenwatch` turned out to be the Android background service, not the watch (see
  above).
- Expo SDK 57 (`expo-modules-autolinking` 57.0.13, reading the sources in `node_modules`):
  autolinking options come only from `package.json` (`expo.autolinking.exclude`, static) and the
  `--exclude` argument, which is passed by `use_expo_modules!(exclude:)` (Podfile,
  `autolinking_manager.rb`) and `expoAutolinking.exclude` (settings.gradle,
  `ExpoAutolinkingSettingsExtension.kt`). React Native libraries: the project's
  `react-native.config.js` overrides the dependency's config, `null` for a platform means "do not
  link" (`androidResolver.js`, `iosResolver.js`). The name of a local module from `modules/` for
  exclude: the directory name in lower case (`scanning.js`).
- Code: `features.js`, `app.config.ts`, `react-native.config.js`, `plugins/withFeatureAutolinking.js`,
  `src/localjudge/entry.ts`, edits to `App.tsx`, `ModeScreen.tsx`, `FeedScreen.tsx`,
  `controller.ts`, `metro.config.js`, `eas.json`, `check-build-env.mjs`, the `feed.hwUnsupported`
  string (en, ru).

### 13:00-13:05, checks

- In the clone `/srv/scratch/app-hardening/mono/app` (rsync without `node_modules`, `.env*`, native
  directories): `npx --no-install tsc --noEmit` 0 errors; `node --test scripts/test-core.mjs` 40/40
  (new "release composition" test: flags in `eas.json`, `check-build-env` rejecting `"1"`,
  `features.js` and `react-native.config.js` with flags 0 and 1, the exclusion plugin on
  settings.gradle and the Podfile together with `withYubikey`, and that outside the features' code
  there are no static imports of their modules, only flag-gated inclusions, 9 of them).
- `npx expo config --json`, flags 0: plugins without withYubikey, apple-targets and llama.rn, plus
  `withFeatureAutolinking {"exclude":["yubikey","applewatch"]}` (before apple-targets was added to
  the list); entitlements only `aps-environment` and `time-sensitive`; no
  `NFCReaderUsageDescription`; `extra.features` all false. Flags 1: plugins and entitlements as in
  `app.json`.
- `react-native-config --json`: flags 0, android and ios: async-storage, slider, expo, safe-area,
  screens; flags 1: plus `llama.rn` and `onnxruntime-react-native`.
- `expo-modules-autolinking resolve`: android without exclude 21 modules (with `yubikey`), with
  `--exclude yubikey applewatch` 20; apple without exclude 23 (`applewatch`, `yubikey`,
  `@bacons/apple-targets`), with exclude 21. Hence the decision to exclude the
  `@bacons/apple-targets` module too (the app does not call it).
- `expo export --no-bytecode`, release (flags 0), android and ios (78 s): the bundle has no modules
  of YubiKey, the watch, llama, onnxruntime, tokenizers, `localjudge`, `LocalOpinion`,
  `Experimental`, `HardwareKeySection`, `HardwareTapModal`, `registerYubikey`. Remaining: property
  names on `null` in dead branches (`refreshLocalModels`, `noteHumanDecision`, like `handleBenchUrl`
  for bench) and i18n dictionary strings (`YubiKey` 70, `Apple Watch` 10, `hw-register` 12): data,
  not shown on screen.

### 13:05-13:10, strings, prebuild, size

- Commit `e624a7d` (flags, config, autolinking, JS, test, this log).
- The feature strings were moved to `src/core/i18n/features/*` (see "How it works"). tsc 0 errors,
  tests 40/40 (the tests turn on all flags before loading the modules: they also check the features
  that are off in the release).
- The "release composition" test was verified to fail: a static `import { ExperimentalSection }` in
  `ModeScreen.tsx` (in a temporary copy) breaks it.
- `expo export` after moving the strings out. Release android 1,692,172 bytes, ios 1,689,268
  (before the flags, the control bench android 1,935,609): `YubiKey`, `Apple Watch`, `hw-register`,
  `llama`, `onnx`, `InferenceSession`, `Tokenizer`, `huggingface`, `on-device`, `LocalOpinion`,
  `HardwareKeySection`, `AppleWatchSection`, `ExperimentalSection` and the keys
  `hw.`/`yk.`/`aw.`/`exp.`/`bench.` in the release: 0. Remaining: property names on `null`
  (`refreshLocalModels`, `noteHumanDecision`, `handleBenchUrl`), substrings `exp.`/`yk.` from
  third-party code (`Math.exp`, `cmyk.rgb`), `NFC` from `normalize("NFC")` and `...Experimental`
  from React Native flags. In bench everything is in place: `YubiKey` 67, `Apple Watch` 12,
  `llama` 112, `InferenceSession` 13, `HardwareKeySection`, `AppleWatchSection`, `LocalOpinion`,
  `mockui`. `leaktest` (fake values from the clone's `.env.local`) is nowhere.
- `expo prebuild --no-install --platform all` in copies (`/srv/scratch/release-scope/prebuild-*`,
  9 s each). Release: `settings.gradle` with `expoAutolinking.exclude = ["yubikey", "applewatch",
  "@bacons/apple-targets"]` before `useExpoModules()`, `Podfile` with
  `use_expo_modules!(exclude: [...])` and without YubiKit; `WardenClaw.xcodeproj` has one app
  target, the word watch does not occur even once; entitlements only `aps-environment` and
  `time-sensitive`; Info.plist has no `NFCReaderUsageDescription`; the Android manifest has no NFC,
  the service `wardenwatch.WatchService` is present, `com.wardenclaw.BENCH=false`. Bench: two app
  targets (the watch, 32 mentions of watch), YubiKit in the Podfile, entitlements with
  `increased-memory-limit`, `extended-virtual-addressing` and NFC, NFC in the manifest,
  `BENCH=true`.
- APK size (from the contents of `preview-8.apk`, 330 MB, universal for 4 ABIs): `libonnxruntime.so`
  101.6 MB, 7 variants of `librnllama*.so` and `librnllama_jni.so`, `libonnxruntimejsi.so` together
  204.7 MB out of 313.7 MB of entries. Without the on-phone judge the universal preview is expected
  at about 125 MB (minus YubiKit in dex as well, under 1 MB, and 0.24 MB of JS). For arm64-v8a
  only: other libraries 23.3 MB, dex 10.8, the rest 8.6, i.e. about 43 MB. The next largest:
  `libreactnative.so` 25 MB and `libbarhopper_v3.so` 19 MB (QR recognition via ML Kit in
  expo-camera) for 4 ABIs. The figures are estimates: there were no EAS builds.

### 13:10-13:12, final string cleanup

- Check "flags 1 = app.json": `expo config --json` with all flags `"1"` and without `app.config.ts`
  (in a temporary copy) match byte for byte, except `extra.features`.
- A case-insensitive search through the bundle with `\uXXXX` decoded (Russian strings in the bundle
  are escaped, a plain grep does not see them) found the journal entry caption "On-device opinion
  (experimental)": `journal.kind.localOpinion` was moved to the judge dictionary, `JournalScreen`
  shows "Event" for old entries of this kind without the flag (`tOr`, key `journal.kind.event`).
- Release result (android 1,691,943 bytes, ios 1,689,039): `YubiKey`, `Apple Watch`, `watchOS`,
  the Russian word for "watch", `llama`, `onnx`, `Tokenizer`, `hw-register`, the Russian word for
  "experiment", `On-device`: 0. The matches for the Russian stems of "local" and "on the phone" and
  for `NFC` are unrelated: the Russian strings "Local rules" and "digest … recomputed on the phone",
  `normalize("NFC")`. tsc 0 errors, tests 40/40.

## What is left

- Native compilation was not checked here (Gradle and Xcode were not run, there were no EAS builds):
  checked were `expo config`, the autolinking lists and `expo prebuild`. On the first `preview`
  build: the APK size (expected about 125 MB universal, about 43 MB arm64-v8a only), that the app
  starts and the "Mode" tab has no YubiKey, Apple Watch and Experimental blocks, that a card with
  `meta.hardware` shows "the server allows this request only with a hardware key".
- iOS: bench and the release have the same bundle id, but different entitlements
  (`increased-memory-limit`, `extended-virtual-addressing`, NFC). Check on the first iOS release
  build whether EAS capability sync switches these capabilities on the App ID back and forth
  between bench and the release (if so: a separate bundle id for bench or
  `EXPO_NO_CAPABILITY_SYNC=1` in one of the profiles).
- `postinstall` still downloads the llama.rn native artifacts on every install, in the EAS release
  build too (in `node_modules/llama.rn`: ios 847 MB, android 107 MB), even though they are not
  linked. They could be downloaded only with the judge flag, but without an EAS build there is no
  way to check that the profile env is already there at the install step, so this was not done.
- The comment in the root `.easignore` ("bench only adds EXPO_PUBLIC_WARDENCLAW_BENCH=1") is
  outdated: bench also turns on the feature flags. The file is outside `app/`, left untouched.
- The repository keeps `targets/watch`, `modules/applewatch`, `modules/yubikey`, `src/localjudge`:
  this is intended, they are needed by bench and for bringing the features back. The `simulator`
  profile has no env, the features are off in it.
- If wardend in the release requires a key by the `require_hardware` rule (the `daemon/` zone), the
  app without YubiKey does not let you allow such a card, only deny it; allow it on the server.
