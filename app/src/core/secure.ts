// SPDX-License-Identifier: GPL-3.0-or-later
// All of the app's SecureStore entries in one place. This device only: on iOS an entry does not go
// into backups and does not move to a new iPhone (THIS_DEVICE_ONLY), and the device key also only
// with a passcode set (without one iOS does not create the entry, and erases it when the passcode
// is removed).
// On Android SecureStore encrypts with a Keystore key and stays out of backups (backup rules); the
// keychainAccessible option has no effect there.
// The first launch after install erases entries that survived app removal: iOS keeps the Keychain
// after removal, and without this a reinstall would silently bring back the old identity and the
// link to the server.
import AsyncStorage from "@react-native-async-storage/async-storage";
import * as FS from "expo-file-system/legacy";
import * as SecureStore from "expo-secure-store";
import { defaultDatabaseDirectory } from "expo-sqlite";
import { Platform } from "react-native";

export const SK = {
  identity: "wc.identity.v1", // Ed25519 device key (identity.ts)
  token: "wc.token.v1", // OpenClaw gateway device token
  gatewayUrl: "wc.gateway_url.v1",
  modelKey: "wc.model.key.v1", // judge API key
  wardend: "wc.wardend.v1", // server address and pinned key
  hwKey: "wc.hwkey.v1", // bound YubiKey record
} as const;
export type SecureKey = (typeof SK)[keyof typeof SK];
const ALL_KEYS: SecureKey[] = Object.values(SK);

const DEVICE_ONLY: SecureStore.SecureStoreOptions = { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY };
const DEVICE_WITH_PASSCODE: SecureStore.SecureStoreOptions = { keychainAccessible: SecureStore.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY };
const optionsFor = (key: SecureKey) => (key === SK.identity ? DEVICE_WITH_PASSCODE : DEVICE_ONLY);

export function secureGet(key: SecureKey): Promise<string | null> {
  return SecureStore.getItemAsync(key, optionsFor(key));
}
export function secureSet(key: SecureKey, value: string): Promise<void> {
  return SecureStore.setItemAsync(key, value, optionsFor(key));
}
export function secureDelete(key: SecureKey): Promise<void> {
  return SecureStore.deleteItemAsync(key, optionsFor(key));
}

const K_INSTALLED = "wc.installed.v1"; // AsyncStorage: the app has already run since this install
const K_DEVICE_ONLY = "wc.secure.device_only.v1"; // AsyncStorage: old entries were rewritten with THIS_DEVICE_ONLY

/** Data of a previous version in the app sandbox: the journal (created on every start) or settings. */
async function hasAppData(): Promise<boolean> {
  try {
    const keys = await AsyncStorage.getAllKeys();
    if (keys.some((k) => k.startsWith("wc."))) return true;
  } catch {}
  try {
    const dir = defaultDatabaseDirectory.startsWith("file://") ? defaultDatabaseDirectory : `file://${defaultDatabaseDirectory}`;
    return (await FS.getInfoAsync(`${dir.replace(/\/+$/, "")}/wardenclaw.db`)).exists;
  } catch {
    return false;
  }
}

/**
 * Before the first SecureStore read (bootstrap). Fresh install (no marker and no data of a previous
 * version in the sandbox): erase all entries. Update from an old version: entries are kept, and on
 * iOS they are rewritten once with THIS_DEVICE_ONLY (setItemAsync on an existing entry changes only
 * the data, so delete and write again).
 */
export async function prepareSecureStore(): Promise<{ wiped: boolean; migrated: number; failed: number }> {
  let wiped = false;
  if ((await AsyncStorage.getItem(K_INSTALLED)) !== "1") {
    if (!(await hasAppData())) {
      for (const k of ALL_KEYS) await secureDelete(k).catch(() => {});
      wiped = true;
    }
    await AsyncStorage.setItem(K_INSTALLED, "1");
  }
  let migrated = 0;
  let failed = 0;
  if (Platform.OS === "ios" && (await AsyncStorage.getItem(K_DEVICE_ONLY)) !== "1") {
    for (const k of ALL_KEYS) {
      const v = await SecureStore.getItemAsync(k).catch(() => null);
      if (v === null) continue;
      await SecureStore.deleteItemAsync(k).catch(() => {});
      try {
        await secureSet(k, v);
        migrated++;
      } catch {
        // device key without a passcode: keep it on this device only instead of losing it
        await SecureStore.setItemAsync(k, v, DEVICE_ONLY).then(
          () => void migrated++,
          () => void failed++,
        );
      }
    }
    await AsyncStorage.setItem(K_DEVICE_ONLY, "1");
  }
  return { wiped, migrated, failed };
}
