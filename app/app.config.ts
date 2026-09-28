// SPDX-License-Identifier: GPL-3.0-or-later
// App config: the whole app.json (all features) minus the features disabled by build flags
// (features.js, docs/release-scope.md). A disabled feature's plugins are not applied, its
// entitlements and Info.plist strings are removed from iOS, its Expo modules are excluded from
// autolinking (plugins/withFeatureAutolinking.js; React Native libraries are excluded by
// react-native.config.js).
// All flags "1" (bench profile): the config matches app.json.
// Android push (FCM, modules/wardenpush): the Firebase configuration is not in git. An EAS build
// gets it from the file environment variable GOOGLE_SERVICES_JSON, a local build from
// ./google-services.json; a build without either works, without push (the "Mode" screen says so).
import type { ConfigContext, ExpoConfig } from "expo/config";

// node built-ins, without @types/node in the app's tsconfig
declare const __dirname: string;
const { existsSync } = require("fs") as { existsSync(file: string): boolean };
const { join } = require("path") as { join(...parts: string[]): string };

type Field = "plugins" | "expoModules" | "rnModules" | "iosEntitlements" | "iosInfoPlist";
const { disabledList, features } = require("./features") as { disabledList: (field: Field) => string[]; features: () => Record<string, boolean> };

const pluginName = (p: string | [] | [string] | [string, unknown]) => (Array.isArray(p) ? p[0] : p);

export default ({ config }: ConfigContext): ExpoConfig => {
  const offPlugins = new Set(disabledList("plugins"));
  const plugins = (config.plugins ?? []).filter((p) => !offPlugins.has(pluginName(p) as string));
  const exclude = disabledList("expoModules");
  if (exclude.length) plugins.push(["./plugins/withFeatureAutolinking", { exclude }]);

  const ios = { ...config.ios, infoPlist: { ...config.ios?.infoPlist }, entitlements: { ...config.ios?.entitlements } };
  for (const k of disabledList("iosInfoPlist")) delete ios.infoPlist[k];
  for (const k of disabledList("iosEntitlements")) delete ios.entitlements[k];

  const googleServicesFile = process.env.GOOGLE_SERVICES_JSON || (existsSync(join(__dirname, "google-services.json")) ? "./google-services.json" : undefined);
  const android = { ...config.android, ...(googleServicesFile ? { googleServicesFile } : {}) };

  return {
    ...config,
    name: config.name ?? "WardenClaw",
    slug: config.slug ?? "wardenclaw",
    ios,
    android,
    plugins,
    extra: { ...config.extra, features: features() },
  };
};
