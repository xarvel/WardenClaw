// SPDX-License-Identifier: GPL-3.0-or-later
// Apple Watch app target for @bacons/apple-targets: `expo prebuild` adds it to ios/WardenClaw.xcodeproj
// as a single-target watchOS app embedded in the iPhone app ("Embed Watch Content").
// Every .swift file in this folder and its subfolders is compiled in (Xcode folder sync), including
// Protocol/ (the protocol code that app/targets/Package.swift tests against protocol/vectors).
// Info.plist here is merged with the generated one (WKCompanionAppBundleIdentifier is set by the plugin).
/** @type {import('@bacons/apple-targets/app.plugin').ConfigFunction} */
module.exports = (config) => ({
  type: "watch",
  name: "WardenClawWatch",
  displayName: "WardenClaw",
  // com.wardenclaw.app.watchkitapp: the APNs topic wardend must allow (see daemon/docs/watch-apns.md)
  bundleIdentifier: ".watchkitapp",
  deploymentTarget: "10.0",
  icon: "../../assets/icon.png",
  colors: { $accent: "#3B82F6" },
  entitlements: {
    // Push Notifications capability on the App ID com.wardenclaw.app.watchkitapp. "development" is
    // what Xcode writes; exporting for TestFlight/App Store turns it into "production".
    "aps-environment": "development",
  },
});
