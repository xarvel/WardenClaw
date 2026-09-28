// SPDX-License-Identifier: GPL-3.0-or-later
// Binding a YubiKey on the phone: registration via the native module (modules/yubikey), storing
// the key record in SecureStore, a "signer" for tickets. wardend gets the public part via the blob
// wchw1:… (`wardend hw-register`); the app does not touch the server.
import { getRandomBytes } from "expo-crypto";
import * as Yubikey from "../../modules/yubikey";
import { b64url, hexToBytes, utf8Encode } from "./bytes";
import type { DeviceIdentity } from "./identity";
import { HW_RP_ID, HardwareKey, HardwareSigner, clientDataHash, clientDataJSON, registrationBlob } from "./hardware";
import { SK, secureDelete, secureGet, secureSet } from "./secure";

export async function loadHardwareKey(): Promise<HardwareKey | null> {
  const raw = await secureGet(SK.hwKey);
  if (!raw) return null;
  try {
    const k = JSON.parse(raw) as HardwareKey;
    return k.credentialId && k.rpId ? k : null;
  } catch {
    return null;
  }
}

export async function saveHardwareKey(k: HardwareKey): Promise<void> {
  await secureSet(SK.hwKey, JSON.stringify(k));
}

export async function deleteHardwareKey(): Promise<void> {
  await secureDelete(SK.hwKey);
}

/**
 * "Tap the YubiKey" wizard: makeCredential (rpId wardenclaw, EdDSA→ES256, non-resident), the
 * registration challenge is random (the server is offline: trust comes from the owner inserting
 * the blob themselves).
 */
export async function registerYubikey(identity: DeviceIdentity, name: string, pin?: string | null): Promise<HardwareKey> {
  const json = clientDataJSON("webauthn.create", getRandomBytes(32));
  const r = await Yubikey.register({
    rpId: HW_RP_ID,
    userId: b64url.encode(hexToBytes(identity.deviceId)),
    userName: `wardenclaw-${identity.deviceId.slice(0, 8)}`,
    clientDataHash: b64url.encode(clientDataHash(json)),
    pin: pin || null,
  });
  const cleanName = name.trim() || "YubiKey";
  return {
    credentialId: r.credentialId,
    rpId: HW_RP_ID,
    name: cleanName,
    alg: r.alg,
    addedAt: new Date().toISOString(),
    requireUv: !!pin,
    blob: registrationBlob({ credentialId: r.credentialId, attestationObject: r.attestationObject, clientDataJSON: json, rpId: HW_RP_ID, name: cleanName }),
  };
}

/** Signer for tickets: a key tap over the ticket's clientDataHash. */
export function yubikeySigner(key: HardwareKey, pin?: string | null): HardwareSigner {
  return async (req) => {
    const a = await Yubikey.getAssertion(req.clientDataHash, key.credentialId, { rpId: key.rpId, pin: pin || null });
    return { credentialId: a.credentialId, clientDataJSON: b64url.encode(utf8Encode(req.clientDataJSON)), authenticatorData: a.authenticatorData, signature: a.signature };
  };
}

export const yubikeyAvailability = Yubikey.availability;
export const cancelYubikey = Yubikey.cancel;
export const onYubikeyStatus = Yubikey.onStatus;
export type { YubikeyStatus } from "../../modules/yubikey";
export { YubikeyError } from "../../modules/yubikey";
