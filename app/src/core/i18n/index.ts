// SPDX-License-Identifier: GPL-3.0-or-later
// Localization: English is the only UI language for now; the mechanism stays so that other languages
// can be added later (a language = its id in Lang and LANGS plus a dictionary with the keys of en in
// DICTS; a key missing there falls back to en). The system language is ignored; the choice is saved in
// settings (settings.ts: loadLang/saveLang), and a saved language that is no longer supported (for
// example "ru" from older builds) reads as English. Here only the current language and t(). Pure
// module (no RN): tests compile it together with wardendProto/hardware/execEnvelope.
import { en } from "./en";

// Strings of features outside the first release and of the bench build live in ./features and load
// only with the build flag (features.js, docs/release-scope.md): without it they are not in the
// bundle, t() for such a key returns the key itself, but a disabled feature does not show it anyway.
type FeatureDict = { en: Record<string, string> };
const featureDicts = [
  process.env.EXPO_PUBLIC_WARDENCLAW_FEATURE_HARDWARE_KEY === "1" ? require("./features/hardwareKey") : null,
  process.env.EXPO_PUBLIC_WARDENCLAW_FEATURE_APPLE_WATCH === "1" ? require("./features/appleWatch") : null,
  process.env.EXPO_PUBLIC_WARDENCLAW_FEATURE_PHONE_JUDGE === "1" ? require("./features/phoneJudge") : null,
  process.env.EXPO_PUBLIC_WARDENCLAW_BENCH === "1" ? require("./features/bench") : null,
].filter((d): d is FeatureDict => d !== null);
const EN: Record<string, string> = Object.assign({}, en, ...featureDicts.map((d) => d.en));

type FeatureKey =
  | keyof typeof import("./features/hardwareKey").en
  | keyof typeof import("./features/appleWatch").en
  | keyof typeof import("./features/phoneJudge").en
  | keyof typeof import("./features/bench").en;

export type Lang = "en";
export type MsgKey = keyof typeof en | FeatureKey;
export type MsgParams = Record<string, string | number>;

export const DEFAULT_LANG: Lang = "en";
export const LANGS: { id: Lang; name: string }[] = [{ id: "en", name: "English" }];
const DICTS: Record<Lang, Record<string, string>> = { en: EN };

let current: Lang = DEFAULT_LANG;
const subs = new Set<() => void>();

export function isLang(v: unknown): v is Lang {
  return LANGS.some((l) => l.id === v);
}

export function getLang(): Lang {
  return current;
}

/** An unsupported value (a stale saved "ru", a call from plain JS) is ignored: the language stays as it is. */
export function setLang(lang: Lang) {
  if (!isLang(lang) || lang === current) return;
  current = lang;
  for (const s of subs) s();
}

export function subscribeLang(fn: () => void): () => void {
  subs.add(fn);
  return () => {
    subs.delete(fn);
  };
}

export function isMsgKey(k: string): boolean {
  return Object.prototype.hasOwnProperty.call(EN, k);
}

/** String in the current language; {name} in the string is replaced with the value from params. */
export function t(key: MsgKey, params?: MsgParams): string {
  const s = DICTS[current][key] ?? EN[key] ?? key;
  if (!params) return s;
  return s.replace(/\{(\w+)\}/g, (m, k: string) => (k in params ? String(params[k]) : m));
}

/** For keys built from a reason code (wdr.<reason>, yk.<code>…): no key → fallback. */
export function tOr(key: string, fallback: string, params?: MsgParams): string {
  return isMsgKey(key) ? t(key as MsgKey, params) : fallback;
}
