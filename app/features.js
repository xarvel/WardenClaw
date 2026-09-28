// SPDX-License-Identifier: GPL-3.0-or-later
// Features outside the first release: YubiKey, Apple Watch, phone judge (docs/release-scope.md).
// Flag values come from the eas.json profile: production and preview "0", bench "1"; locally
// from the environment or app/.env.local. This file only describes what each flag controls in
// the native build: config plugins (app.config.ts) and native modules (react-native.config.js,
// plugins/withFeatureAutolinking.js). The names match the site's FEATURES in meaning
// (site/src/config.ts: hardwareKey, appleWatch, phoneJudge).
//
// In the app's JS the flag is read directly in the expression:
//   process.env.EXPO_PUBLIC_WARDENCLAW_FEATURE_… === "1" ? require("…") : null
// Only then does babel-preset-expo inline the value and Metro drop the module from the bundle
// (the same technique as EXPO_PUBLIC_WARDENCLAW_BENCH, docs/app-hardening.md).

/** @type {Record<"hardwareKey" | "appleWatch" | "phoneJudge", { env: string, plugins: string[], expoModules: string[], rnModules: string[], iosEntitlements: string[], iosInfoPlist: string[] }>} */
const FEATURES = {
  hardwareKey: {
    env: "EXPO_PUBLIC_WARDENCLAW_FEATURE_HARDWARE_KEY",
    plugins: ["./modules/yubikey/plugin/withYubikey"],
    expoModules: ["yubikey"],
    rnModules: [],
    iosEntitlements: [],
    iosInfoPlist: ["NFCReaderUsageDescription"],
  },
  appleWatch: {
    env: "EXPO_PUBLIC_WARDENCLAW_FEATURE_APPLE_WATCH",
    // @bacons/apple-targets only builds the watch target (targets/watch); the app does not call
    // its own Expo module (ExtensionStorage for App Group)
    plugins: ["@bacons/apple-targets"],
    expoModules: ["applewatch", "@bacons/apple-targets"],
    rnModules: [],
    iosEntitlements: [],
    iosInfoPlist: [],
  },
  phoneJudge: {
    env: "EXPO_PUBLIC_WARDENCLAW_FEATURE_PHONE_JUDGE",
    plugins: ["llama.rn"],
    expoModules: [],
    // @huggingface/tokenizers is pure JS: only the bundle leaves it out of the release
    rnModules: ["llama.rn", "onnxruntime-react-native"],
    iosEntitlements: ["com.apple.developer.kernel.increased-memory-limit", "com.apple.developer.kernel.extended-virtual-addressing"],
    iosInfoPlist: [],
  },
};

let envLoaded = false;
/** app/.env* as in Expo CLI: Gradle and CocoaPods run react-native.config.js and do not read them. */
function loadEnvFiles() {
  if (envLoaded) return;
  envLoaded = true;
  try {
    require("@expo/env").load(__dirname, { silent: true });
  } catch {
    // without @expo/env: process environment only (as on EAS, env files are not uploaded there)
  }
}

/** @param {keyof typeof FEATURES} name */
function enabled(name) {
  loadEnvFiles();
  return process.env[FEATURES[name].env] === "1";
}

/** Flag → enabled or not, for all three features. */
function features() {
  return Object.fromEntries(Object.keys(FEATURES).map((k) => [k, enabled(/** @type {keyof typeof FEATURES} */ (k))]));
}

/** @param {"plugins" | "expoModules" | "rnModules" | "iosEntitlements" | "iosInfoPlist"} field */
function disabledList(field) {
  return Object.entries(FEATURES)
    .filter(([k]) => !enabled(/** @type {keyof typeof FEATURES} */ (k)))
    .flatMap(([, f]) => f[field]);
}

module.exports = { FEATURES, enabled, features, disabledList };
