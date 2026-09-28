// SPDX-License-Identifier: GPL-3.0-or-later
// Metro: the default Expo config plus a cache version derived from the bench build flag.
// EXPO_PUBLIC_* are inlined during transformation, but Metro's transform cache ignores them:
// without this, a local preview build after bench would take modules with the benchmark enabled
// from the cache (verified 28.09: a repeated export reused the cache and ignored the flag).
// The same goes for the flags of features outside the first release (features.js,
// docs/release-scope.md).
const { getDefaultConfig } = require("expo/metro-config");
const { features } = require("./features");

const config = getDefaultConfig(__dirname);
const flags = Object.entries(features())
  .map(([name, on]) => `+${name}=${on ? "1" : "0"}`)
  .join("");
config.cacheVersion = `${config.cacheVersion ?? ""}+bench=${process.env.EXPO_PUBLIC_WARDENCLAW_BENCH === "1" ? "1" : "0"}${flags}`;

module.exports = config;
