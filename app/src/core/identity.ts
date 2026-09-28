// SPDX-License-Identifier: GPL-3.0-or-later
// Ed25519 device identity (as in OpenClaw): deviceId = sha256(raw 32-byte pubkey) hex.
// The key lives only in SecureStore and only on this device (secure.ts): on iOS it does not go into
// backups and is not created without a passcode. The key is a software key, not yet protected by
// hardware biometrics; a non-extractable key in Secure Enclave / Android Keystore is planned.
import { errMsg } from "./errMsg";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { sha256 } from "@noble/hashes/sha256";
import { getRandomBytes } from "expo-crypto";
import { b64url, bytesToHex, hexToBytes, utf8Encode } from "./bytes";
import { EncKeyRec, loadOrCreateEncKey as loadOrCreateEncKeyIn } from "./relayState";
import { SK, secureDelete, secureGet, secureSet } from "./secure";

// noble/ed25519 v2 requires sha512 for synchronous operations
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

export type DeviceIdentity = {
  deviceId: string;
  privateKeyHex: string;
  publicKeyHex: string;
  createdAt: string;
};

/** The device key was not saved: on iOS a WHEN_PASSCODE_SET entry is not created without a passcode.
 * See the key non-extractability roadmap item (Secure Enclave / Android Keystore).
 */
export class IdentityStoreError extends Error {}

export async function loadIdentity(): Promise<DeviceIdentity | null> {
  const raw = await secureGet(SK.identity);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as DeviceIdentity;
    if (parsed.deviceId && parsed.privateKeyHex && parsed.publicKeyHex) return parsed;
  } catch {}
  return null;
}

export async function loadOrCreateIdentity(): Promise<DeviceIdentity> {
  const existing = await loadIdentity();
  if (existing) return existing;
  const priv = getRandomBytes(32);
  const pub = ed.getPublicKey(priv);
  const identity: DeviceIdentity = {
    deviceId: bytesToHex(sha256(pub)),
    privateKeyHex: bytesToHex(priv),
    publicKeyHex: bytesToHex(pub),
    createdAt: new Date().toISOString(),
  };
  try {
    await secureSet(SK.identity, JSON.stringify(identity));
  } catch (e) {
    throw new IdentityStoreError(errMsg(e));
  }
  return identity;
}

/** The device's X25519 key of the relay transport (protocol/README.md 5.1): its own SecureStore
 * entry with the protection of the identity, generated on first use. */
export async function loadOrCreateEncKey(): Promise<EncKeyRec> {
  try {
    return await loadOrCreateEncKeyIn({ get: () => secureGet(SK.encKey), set: (v) => secureSet(SK.encKey, v) }, getRandomBytes);
  } catch (e) {
    throw new IdentityStoreError(errMsg(e));
  }
}

export async function deleteIdentity(): Promise<void> {
  await secureDelete(SK.identity);
  await secureDelete(SK.encKey);
}

export function publicKeyB64Url(identity: DeviceIdentity): string {
  return b64url.encode(hexToBytes(identity.publicKeyHex));
}

export function signPayload(identity: DeviceIdentity, payload: string): string {
  const sig = ed.sign(utf8Encode(payload), hexToBytes(identity.privateKeyHex));
  return b64url.encode(sig);
}
