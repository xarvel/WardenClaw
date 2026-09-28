// SPDX-License-Identifier: GPL-3.0-or-later
// React Native autolinking: libraries of disabled features are not linked (features.js,
// docs/release-scope.md). This file is read by expo-modules-autolinking (react-native-config from
// Gradle and Podfile) and @react-native-community/cli; `platforms: { android: null, ios: null }` on
// a dependency means "do not link" (expo-modules-autolinking/build/reactNativeConfig,
// androidResolver and iosResolver return null).
const { disabledList } = require("./features");

const off = { platforms: { android: null, ios: null } };

module.exports = {
  dependencies: Object.fromEntries(disabledList("rnModules").map((name) => [name, off])),
};
