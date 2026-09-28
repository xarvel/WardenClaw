// SPDX-License-Identifier: GPL-3.0-or-later
// Config plugin for the background service: permissions and declarations in the app manifest.
// Type specialUse (Android 14+): a persistent connection to the user's own server, none of the
// system types fits (dataSync is limited to 6 h/day since targetSdk 35).
// Besides the service: a BOOT_COMPLETED and MY_PACKAGE_REPLACED receiver (the service comes up
// after a reboot and an update), the "like an incoming call" screen (full-screen intent, off by
// default, on Android 14+ the user grants the permission), screen wake-up for a new request.
// Wiring in app.json: "plugins": [..., "./modules/wardenwatch/plugin/withWardenWatch"].
const { withAndroidManifest } = require("expo/config-plugins");

const PKG = "com.wardenclaw.modules.wardenwatch";
const SERVICE = `${PKG}.WatchService`;
const RECEIVER = `${PKG}.BootReceiver`;
const INCOMING = `${PKG}.IncomingActivity`;
const SUBTYPE =
  "Keeps a long-poll connection to the user's own self-hosted wardend server so that approval requests for commands on that server are shown while the app is in the background. No third-party push service is used.";

const PERMISSIONS = [
  "android.permission.FOREGROUND_SERVICE",
  "android.permission.FOREGROUND_SERVICE_SPECIAL_USE",
  "android.permission.POST_NOTIFICATIONS",
  "android.permission.RECEIVE_BOOT_COMPLETED",
  // "Like an incoming call" mode. Google Play grants it by itself only to calling and alarm apps.
  "android.permission.USE_FULL_SCREEN_INTENT",
  // The screen turns on for a few seconds when a new request arrives
  "android.permission.WAKE_LOCK",
  "android.permission.TURN_SCREEN_ON",
  // System dialog "run in the background without restrictions" (button in the notification settings)
  "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
];

function ensurePermission(manifest, name) {
  const list = manifest["uses-permission"] ?? [];
  if (!list.some((x) => x?.$?.["android:name"] === name)) list.push({ $: { "android:name": name } });
  manifest["uses-permission"] = list;
}

/** Replace the element with the same android:name, or add it. */
function upsert(list, item) {
  const name = item.$["android:name"];
  return [...(list ?? []).filter((x) => x?.$?.["android:name"] !== name), item];
}

function withWardenWatchManifest(manifest) {
  for (const p of PERMISSIONS) ensurePermission(manifest, p);
  const app = manifest.application?.[0];
  if (!app) throw new Error("withWardenWatch: <application> not found in AndroidManifest");
  app.service = upsert(app.service, {
    $: { "android:name": SERVICE, "android:exported": "false", "android:foregroundServiceType": "specialUse" },
    property: [{ $: { "android:name": "android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE", "android:value": SUBTYPE } }],
  });
  // exported: the system sends BOOT_COMPLETED and MY_PACKAGE_REPLACED; the receiver checks the
  // action and only brings the service up if it was enabled before
  app.receiver = upsert(app.receiver, {
    $: { "android:name": RECEIVER, "android:exported": "true" },
    "intent-filter": [
      {
        action: [{ $: { "android:name": "android.intent.action.BOOT_COMPLETED" } }, { $: { "android:name": "android.intent.action.MY_PACKAGE_REPLACED" } }],
      },
    ],
  });
  app.activity = upsert(app.activity, {
    $: {
      "android:name": INCOMING,
      "android:exported": "false",
      "android:excludeFromRecents": "true",
      "android:launchMode": "singleTop",
      "android:taskAffinity": "",
      "android:showWhenLocked": "true",
      "android:turnScreenOn": "true",
      "android:theme": "@android:style/Theme.DeviceDefault.NoActionBar",
    },
  });
  return manifest;
}

module.exports = function withWardenWatch(config) {
  return withAndroidManifest(config, (cfg) => {
    withWardenWatchManifest(cfg.modResults.manifest);
    return cfg;
  });
};
module.exports.withWardenWatchManifest = withWardenWatchManifest;
