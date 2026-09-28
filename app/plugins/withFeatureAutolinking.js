// SPDX-License-Identifier: GPL-3.0-or-later
// Config plugin: Expo modules of disabled features (modules/yubikey, modules/applewatch) are not
// linked. expo-modules-autolinking takes exclude only from package.json (static) or from Gradle
// and Podfile arguments, so the list derived from build flags (features.js) is written at prebuild:
//   android/settings.gradle: expoAutolinking.exclude = [...] before expoAutolinking.useExpoModules()
//   ios/Podfile:             use_expo_modules!(exclude: [...])
// Empty list: files are left unchanged. Included from app.config.ts.
const { withPodfile, withSettingsGradle } = require("expo/config-plugins");

const MARK = "// wardenclaw: features left out of this build (features.js)";
const POD_MARK = "# wardenclaw: features left out of this build (features.js)";

function settingsWithExclude(contents, exclude) {
  if (contents.includes(MARK)) return contents;
  const re = /^([ \t]*)expoAutolinking\.useExpoModules\(\)/m;
  const m = re.exec(contents);
  if (!m) throw new Error("withFeatureAutolinking: `expoAutolinking.useExpoModules()` not found in android/settings.gradle");
  const line = `${m[1]}${MARK}\n${m[1]}expoAutolinking.exclude = [${exclude.map((x) => JSON.stringify(x)).join(", ")}]\n`;
  return contents.slice(0, m.index) + line + contents.slice(m.index);
}

function podfileWithExclude(contents, exclude) {
  if (contents.includes(POD_MARK)) return contents;
  const re = /^([ \t]*)use_expo_modules!\s*$/m;
  const m = re.exec(contents);
  if (!m) throw new Error("withFeatureAutolinking: a bare `use_expo_modules!` not found in ios/Podfile");
  const list = exclude.map((x) => `'${x}'`).join(", ");
  const repl = `${m[1]}${POD_MARK}\n${m[1]}use_expo_modules!(exclude: [${list}])`;
  return contents.slice(0, m.index) + repl + contents.slice(m.index + m[0].length);
}

module.exports = function withFeatureAutolinking(config, { exclude = [] } = {}) {
  if (!exclude.length) return config;
  config = withSettingsGradle(config, (cfg) => {
    cfg.modResults.contents = settingsWithExclude(cfg.modResults.contents, exclude);
    return cfg;
  });
  return withPodfile(config, (cfg) => {
    cfg.modResults.contents = podfileWithExclude(cfg.modResults.contents, exclude);
    return cfg;
  });
};

module.exports.settingsWithExclude = settingsWithExclude;
module.exports.podfileWithExclude = podfileWithExclude;
