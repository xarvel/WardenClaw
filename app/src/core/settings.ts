// SPDX-License-Identifier: GPL-3.0-or-later
// Settings: mode/threshold/model in AsyncStorage, the model key only in SecureStore (secure.ts).
import AsyncStorage from "@react-native-async-storage/async-storage";
import { AppMode, DEFAULT_MODEL_SETTINGS, ModelSettings } from "./decide";
import { DEFAULT_LANG, Lang, isLang } from "./i18n";
import { RelayStateRec, RelayStateWriter, loadRelayState } from "./relayState";
import type { BiometricMode } from "./safety";
import { SK, secureDelete, secureGet, secureSet } from "./secure";
import { devHint } from "./store";
import type { WardendLinkRec } from "./wardendSession";

const K_MODE = "wc.mode.v1";
const K_THRESHOLD = "wc.threshold.v1";
const K_MODEL_URL = "wc.model.url.v1";
const K_MODEL_NAME = "wc.model.name.v1";
const K_MODEL_TIMEOUT = "wc.model.timeout.v1";

export const DEFAULT_THRESHOLD = 30;

// Hint for debugging with Metro (npx expo start): model URL and name from app/.env.local. In any
// release build, bench included, __DEV__ = false, and Metro drops these lines from the bundle:
// without settings saved in the app, the judge does not go to the network.
const DEV_MODEL_URL: string = __DEV__ ? devHint(process.env.EXPO_PUBLIC_WARDENCLAW_MODEL_URL) : "";
const DEV_MODEL_NAME: string = __DEV__ ? devHint(process.env.EXPO_PUBLIC_WARDENCLAW_MODEL) : "";

export async function loadMode(): Promise<AppMode> {
  const v = await AsyncStorage.getItem(K_MODE);
  // Safe default: on start never higher than "Observe".
  if (v === "observe" || v === "delegate") return "observe";
  return "manual";
}
export async function saveMode(mode: AppMode) {
  await AsyncStorage.setItem(K_MODE, mode);
}

export async function loadThreshold(): Promise<number> {
  const v = Number(await AsyncStorage.getItem(K_THRESHOLD));
  return Number.isFinite(v) && v >= 0 && v <= 100 && (await AsyncStorage.getItem(K_THRESHOLD)) !== null ? Math.round(v) : DEFAULT_THRESHOLD;
}
export async function saveThreshold(t: number) {
  await AsyncStorage.setItem(K_THRESHOLD, String(Math.max(0, Math.min(100, Math.round(t)))));
}

export type ModelPrefs = Omit<ModelSettings, "apiKey">;

export async function loadModelPrefs(): Promise<ModelPrefs> {
  const [url, model, timeout] = await Promise.all([AsyncStorage.getItem(K_MODEL_URL), AsyncStorage.getItem(K_MODEL_NAME), AsyncStorage.getItem(K_MODEL_TIMEOUT)]);
  const t = Number(timeout);
  return {
    url: url ?? (DEV_MODEL_URL || DEFAULT_MODEL_SETTINGS.url),
    model: model ?? (DEV_MODEL_NAME || DEFAULT_MODEL_SETTINGS.model),
    timeoutMs: Number.isFinite(t) && t > 0 ? t : DEFAULT_MODEL_SETTINGS.timeoutMs,
  };
}
export async function saveModelPrefs(p: ModelPrefs) {
  await Promise.all([AsyncStorage.setItem(K_MODEL_URL, p.url.trim()), AsyncStorage.setItem(K_MODEL_NAME, p.model.trim()), AsyncStorage.setItem(K_MODEL_TIMEOUT, String(p.timeoutMs))]);
}

export async function hasModelKey(): Promise<boolean> {
  return !!(await secureGet(SK.modelKey));
}
export async function saveModelKey(key: string) {
  if (key.trim()) await secureSet(SK.modelKey, key.trim());
  else await secureDelete(SK.modelKey);
}
/** Full model settings for a call: the key is read from SecureStore only here. */
export async function loadModelSettings(): Promise<ModelSettings> {
  const prefs = await loadModelPrefs();
  const apiKey = (await secureGet(SK.modelKey)) ?? "";
  return { ...prefs, apiKey };
}

// ---------------------------------------------------------------------------
// Local rules: paths where trash-put is forbidden (formerly a build constant, now a setting)
// ---------------------------------------------------------------------------
const K_NO_TRASH = "wc.rules.no_trash_paths.v1";

export async function loadNoTrashPaths(): Promise<string[]> {
  try {
    const v = JSON.parse((await AsyncStorage.getItem(K_NO_TRASH)) ?? "[]") as unknown;
    return Array.isArray(v) ? v.filter((p): p is string => typeof p === "string" && !!p.trim()) : [];
  } catch {
    return [];
  }
}
export async function saveNoTrashPaths(paths: string[]) {
  await AsyncStorage.setItem(K_NO_TRASH, JSON.stringify(paths));
}

// ---------------------------------------------------------------------------
// The link to wardend and the OpenClaw adapter
// ---------------------------------------------------------------------------
const K_ADAPTER_OPENCLAW = "wc.adapter.openclaw.v1";

export async function loadWardendLink(): Promise<WardendLinkRec | null> {
  const raw = await secureGet(SK.wardend);
  if (!raw) return null;
  try {
    const r = JSON.parse(raw) as WardendLinkRec;
    return r.relay && r.key && r.enc && r.supervisorId ? r : null;
  } catch {
    return null;
  }
}
export async function saveWardendLink(r: WardendLinkRec) {
  await secureSet(SK.wardend, JSON.stringify(r));
}
export async function clearWardendLink() {
  await secureDelete(SK.wardend);
}

/** Relay transport, per supervisor: the resume seq and the ids already handled (relayState.ts). Not secret: AsyncStorage. */
export function loadRelayStateFor(supervisorId: string): Promise<RelayStateRec> {
  return loadRelayState(AsyncStorage, supervisorId);
}
export function relayStateWriter(supervisorId: string, initial: RelayStateRec, onError?: (e: unknown) => void): RelayStateWriter {
  return new RelayStateWriter(AsyncStorage, supervisorId, initial, onError);
}

/** OpenClaw adapter (the gateway: its cards and the wardenclaw-gate plugin): off by default. */
export async function loadOpenClawAdapter(): Promise<boolean> {
  return (await AsyncStorage.getItem(K_ADAPTER_OPENCLAW)) === "1";
}
export async function saveOpenClawAdapter(on: boolean) {
  await AsyncStorage.setItem(K_ADAPTER_OPENCLAW, on ? "1" : "0");
}

// ---------------------------------------------------------------------------
// UI language and background notifications
// ---------------------------------------------------------------------------
const K_LANG = "wc.lang.v1";
const K_BG_NOTIFY = "wc.bg_notify.v1";

/**
 * UI language: the saved choice if it is a supported language, otherwise English (a "ru" saved by
 * older builds reads as English). The system language is ignored.
 */
export async function loadLang(): Promise<Lang> {
  const v = await AsyncStorage.getItem(K_LANG);
  return isLang(v) ? v : DEFAULT_LANG;
}
export async function saveLang(lang: Lang) {
  await AsyncStorage.setItem(K_LANG, lang);
}

/** "Background notifications": on until the user explicitly turns them off. */
export async function loadBgNotify(): Promise<boolean> {
  return (await AsyncStorage.getItem(K_BG_NOTIFY)) !== "0";
}
export async function saveBgNotify(on: boolean) {
  await AsyncStorage.setItem(K_BG_NOTIFY, on ? "1" : "0");
}

// What a request notification shows: both options are off until the user explicitly turns them on
const K_NOTIF_COMMAND = "wc.notif.show_command.v1";
const K_NOTIF_FULLSCREEN = "wc.notif.fullscreen.v1";
const K_NOTIF_ASKED = "wc.notif.asked.v1"; // the explanation before the system permission prompt was already shown

export async function loadNotifPrefs(): Promise<{ showCommand: boolean; fullScreen: boolean }> {
  const [c, f] = await Promise.all([AsyncStorage.getItem(K_NOTIF_COMMAND), AsyncStorage.getItem(K_NOTIF_FULLSCREEN)]);
  return { showCommand: c === "1", fullScreen: f === "1" };
}
export async function saveNotifPref(key: "showCommand" | "fullScreen", on: boolean) {
  await AsyncStorage.setItem(key === "showCommand" ? K_NOTIF_COMMAND : K_NOTIF_FULLSCREEN, on ? "1" : "0");
}
export async function loadNotifAsked(): Promise<boolean> {
  return (await AsyncStorage.getItem(K_NOTIF_ASKED)) === "1";
}
export async function saveNotifAsked() {
  await AsyncStorage.setItem(K_NOTIF_ASKED, "1");
}

// ---------------------------------------------------------------------------
// Confirmation before signing: always for dangerous cards and roots, for all cards per setting
// ---------------------------------------------------------------------------
const K_BIOMETRIC = "wc.biometric.v1";

export async function loadBiometricMode(): Promise<BiometricMode> {
  return (await AsyncStorage.getItem(K_BIOMETRIC)) === "all" ? "all" : "risky";
}
export async function saveBiometricMode(mode: BiometricMode) {
  await AsyncStorage.setItem(K_BIOMETRIC, mode);
}
