// SPDX-License-Identifier: GPL-3.0-or-later
// Refuse to build a distribution profile (production, preview) with personal values.
// EXPO_PUBLIC_* are baked into the JS bundle, so for those profiles every EXPO_PUBLIC_WARDENCLAW_*
// must be empty or "unset" (BENCH and FEATURE_* flags must be empty or "0"). This is checked in
// every place the build might pick up a value:
//   - profile env in eas.json (with extends resolution): GATEWAY_URL, MODEL_URL and MODEL are set
//     explicitly to "unset" (eas.json schema does not accept empty strings), feature flags outside
//     the release (features.js, docs/release-scope.md) are explicitly "0"; an explicit profile value
//     overrides both .env files and EAS environment variables on expo.dev;
//   - process environment (for local builds and in case of shell exports);
//   - .env* files in the app directory: all of them for local builds, or only if .easignore at the
//     monorepo root no longer excludes them for cloud builds.
// Prints only variable names and where they were found, never the values.
// Usage: node scripts/check-build-env.mjs <profile> [--local] [--app-dir <app-dir>]
// Profiles bench, simulator and development are not checked (personal debug builds).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PREFIX = "EXPO_PUBLIC_WARDENCLAW_";
const BENCH = `${PREFIX}BENCH`;
const REQUIRED_EMPTY = [`${PREFIX}GATEWAY_URL`, `${PREFIX}MODEL_URL`, `${PREFIX}MODEL`];
/** Features outside the first release (features.js): must be explicitly "0" in a distribution build. */
export const FEATURE_FLAGS = [`${PREFIX}FEATURE_HARDWARE_KEY`, `${PREFIX}FEATURE_APPLE_WATCH`, `${PREFIX}FEATURE_PHONE_JUDGE`];
const FLAGS = new Set([BENCH, ...FEATURE_FLAGS]);
const UNSET = "unset";
const DEV_PROFILES = new Set(["bench", "simulator", "development"]);
const ENV_FILES = [".env", ".env.local", ".env.production", ".env.production.local", ".env.preview", ".env.preview.local"];

/** Returns true if the value does not carry a personal setting: empty or "unset"; for flags (BENCH, FEATURE_*) empty or "0". */
export function isClean(name, value) {
  const v = String(value ?? "").trim();
  return FLAGS.has(name) ? v === "" || v === "0" : v === "" || v === UNSET;
}

/** Minimal .env parser: KEY=VALUE, optional export prefix, quotes, comments. */
export function parseDotenv(text) {
  const out = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    let v = m[2];
    const q = v[0];
    if ((q === '"' || q === "'") && v.lastIndexOf(q) > 0) v = v.slice(1, v.lastIndexOf(q));
    else v = v.replace(/\s+#.*$/, "").trim();
    out[m[1]] = v;
  }
  return out;
}

/** Profile env with extends resolution (parent first, child overrides). */
export function profileEnv(eas, profile, seen = new Set()) {
  const p = eas?.build?.[profile];
  if (!p) throw new Error(`profile "${profile}" not found in eas.json`);
  if (seen.has(profile)) throw new Error(`extends cycle at "${profile}"`);
  seen.add(profile);
  const base = p.extends ? profileEnv(eas, p.extends, seen) : {};
  return { ...base, ...(p.env ?? {}) };
}

/** Build problems (strings without values); empty list means the build is clean. */
export function checkBuildEnv({ profile, eas, processEnv, files, local, easignore }) {
  if (DEV_PROFILES.has(profile)) return [];
  const problems = [];
  const env = profileEnv(eas, profile);
  for (const name of REQUIRED_EMPTY) {
      // without an explicit profile value the build picks up an EAS variable (expo.dev) or a shell export
    if (String(env[name] ?? "").trim() === "") problems.push(`eas.json build.${profile}.env: ${name} must be set explicitly to "${UNSET}"`);
  }
  for (const name of FEATURE_FLAGS) {
    if (String(env[name] ?? "").trim() === "") problems.push(`eas.json build.${profile}.env: ${name} must be set explicitly to "0"`);
  }
  for (const [name, value] of Object.entries(env)) {
    if (name.startsWith(PREFIX) && !isClean(name, value)) problems.push(`eas.json build.${profile}.env: ${name} is not empty`);
  }
  for (const [name, value] of Object.entries(processEnv)) {
    if (name.startsWith(PREFIX) && !isClean(name, value)) problems.push(`environment: ${name} is not empty`);
  }
  const uploadsEnvFiles = !/^app\/\.env$/m.test(easignore ?? "") || !/^app\/\.env\.\*$/m.test(easignore ?? "");
  if (local || uploadsEnvFiles) {
    for (const [file, vars] of Object.entries(files)) {
      for (const [name, value] of Object.entries(vars)) {
        if (name.startsWith(PREFIX) && !isClean(name, value)) problems.push(`${file}: ${name} is not empty${local ? "" : " (and .easignore does not exclude app/.env*)"}`);
      }
    }
  }
  return problems;
}

function main(argv) {
  const args = argv.slice(2);
  const profile = args.find((a) => !a.startsWith("--") && args[args.indexOf(a) - 1] !== "--app-dir");
  if (!profile) {
    console.error("usage: node scripts/check-build-env.mjs <profile> [--local] [--app-dir <app>]");
    return 2;
  }
  const i = args.indexOf("--app-dir");
  const appDir = i >= 0 ? path.resolve(args[i + 1]) : path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const eas = JSON.parse(fs.readFileSync(path.join(appDir, "eas.json"), "utf8"));
  const files = {};
  for (const f of ENV_FILES) {
    const p = path.join(appDir, f);
    if (fs.existsSync(p)) files[`app/${f}`] = parseDotenv(fs.readFileSync(p, "utf8"));
  }
  const ignorePath = path.join(appDir, "..", ".easignore");
  const easignore = fs.existsSync(ignorePath) ? fs.readFileSync(ignorePath, "utf8") : "";
  const problems = checkBuildEnv({ profile, eas, processEnv: process.env, files, local: args.includes("--local"), easignore });
  if (problems.length) {
    console.error(`refusing to build "${profile}": personal EXPO_PUBLIC_WARDENCLAW_* values would be baked into the bundle`);
    for (const p of problems) console.error(`  - ${p}`);
    console.error("Keep personal values in app/.env.local (dev server only) and unset them in the shell.");
    return 1;
  }
  console.error(DEV_PROFILES.has(profile) ? `build env: profile "${profile}" is a personal debug build, not checked` : `build env: profile "${profile}" ok, no personal EXPO_PUBLIC_WARDENCLAW_* values`);
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exit(main(process.argv));
