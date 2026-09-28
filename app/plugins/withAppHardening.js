// SPDX-License-Identifier: GPL-3.0-or-later
// App protection config plugin:
//  - Android: FLAG_SECURE in MainActivity.onCreate, before the first frame. Screenshots, screen
//    recording, the Recents preview and screen-reading assistants do not see agent commands. The
//    protection can be removed only in the bench build (toggle on the "Mode" screen, for
//    documentation screenshots); IncomingActivity ("like a call") is protected by
//    modules/wardenwatch (ScreenGuard.kt).
//  - Bench build marker in the manifest (meta-data com.wardenclaw.BENCH) and Info.plist
//    (WardenClawBench): with it, native code allows removing screen protection and writing the
//    benchmark log. The value comes from EXPO_PUBLIC_WARDENCLAW_BENCH at prebuild (bench profile
//    in eas.json).
// The iOS app switcher snapshot is covered by the overlay in App.tsx (PrivacyShield).
const { withAndroidManifest, withInfoPlist, withMainActivity } = require("expo/config-plugins");

const BENCH_META = "com.wardenclaw.BENCH";
const MARK = "WardenClaw: FLAG_SECURE";

function isBench() {
  return process.env.EXPO_PUBLIC_WARDENCLAW_BENCH === "1";
}

/** Inserted after super.onCreate(...) in the Expo template's onCreate; template changed: build error, not a silent skip. */
function addSecureFlag(src) {
  if (src.includes(MARK)) return src;
  const re = /(\n([ \t]*)super\.onCreate\([^)]*\)\s*\n)/;
  const m = re.exec(src);
  if (!m) throw new Error("withAppHardening: super.onCreate(...) not found in MainActivity.kt (Expo template changed?)");
  const ind = m[2];
  const code = [
    `${ind}// ${MARK} (plugins/withAppHardening.js). Only the bench build can switch it off.`,
    `${ind}run {`,
    `${ind}  @Suppress("DEPRECATION")`,
    `${ind}  val meta = packageManager.getApplicationInfo(packageName, android.content.pm.PackageManager.GET_META_DATA).metaData`,
    `${ind}  val bench = meta?.getBoolean("${BENCH_META}", false) == true`,
    `${ind}  val off = bench && getSharedPreferences("wardenclaw.screen", MODE_PRIVATE).getBoolean("protect_off", false)`,
    `${ind}  if (!off) window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)`,
    `${ind}}`,
    "",
  ].join("\n");
  return src.replace(re, `$1${code}`);
}

function withBenchMeta(manifest, bench) {
  const app = manifest.application?.[0];
  if (!app) throw new Error("withAppHardening: <application> not found in AndroidManifest");
  const list = (app["meta-data"] ?? []).filter((x) => x?.$?.["android:name"] !== BENCH_META);
  list.push({ $: { "android:name": BENCH_META, "android:value": bench ? "true" : "false" } });
  app["meta-data"] = list;
  return manifest;
}

module.exports = function withAppHardening(config) {
  const bench = isBench();
  config = withMainActivity(config, (cfg) => {
    if (cfg.modResults.language !== "kt") throw new Error("withAppHardening: MainActivity must be Kotlin");
    cfg.modResults.contents = addSecureFlag(cfg.modResults.contents);
    return cfg;
  });
  config = withAndroidManifest(config, (cfg) => {
    withBenchMeta(cfg.modResults.manifest, bench);
    return cfg;
  });
  config = withInfoPlist(config, (cfg) => {
    cfg.modResults.WardenClawBench = bench;
    return cfg;
  });
  return config;
};
module.exports.addSecureFlag = addSecureFlag;
module.exports.withBenchMeta = withBenchMeta;
