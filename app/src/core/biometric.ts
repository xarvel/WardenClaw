// SPDX-License-Identifier: GPL-3.0-or-later
// Owner confirmation (expo-local-authentication): before signing an allow and before every change
// that weakens protection. Strong biometrics only (Android class 3: fingerprint, 3D face scan); if
// there is none or it is weak (face via the front camera), the device passcode is asked for.
// A refusal (deny) needs no confirmation.
// If the phone has no screen lock, there is nothing to confirm with: the settings warn about this.
// If the biometrics module does not respond, actions where confirmation is mandatory (root,
// dangerous card, weakening protection) are not performed: fail-closed (safety.ts, ownerGate).
import { Platform } from "react-native";
import * as LocalAuthentication from "expo-local-authentication";
import { ownerGate, type OwnerAuthLevel } from "./safety";

export type { OwnerAuthLevel } from "./safety";

export async function ownerAuthLevel(): Promise<OwnerAuthLevel> {
  try {
    const level = await LocalAuthentication.getEnrolledLevelAsync();
    // iOS reports Face ID and Touch ID as BIOMETRIC_WEAK (2) although they are strong biometrics;
    // on Android weak biometrics are not accepted with biometricsSecurityLevel "strong", the
    // passcode is used instead.
    const strong = Platform.OS === "ios" ? LocalAuthentication.SecurityLevel.BIOMETRIC_WEAK : LocalAuthentication.SecurityLevel.BIOMETRIC_STRONG;
    if (level >= strong) return "biometric";
    if (level >= LocalAuthentication.SecurityLevel.SECRET) return "passcode";
    return "none";
  } catch {
    return "unavailable"; // no native module (Expo Go, web) or the module crashed
  }
}

/** confirmed: the owner confirmed (or there is nothing to confirm with); cancelled: cancel or failure; unavailable: confirming is impossible, the action is not performed. */
export type OwnerCheck = "confirmed" | "cancelled" | "unavailable";

/** failClosed: without a working module, do not let through (roots, dangerous cards, weakening protection). */
export async function confirmOwner(prompt: string, cancel: string, failClosed: boolean): Promise<OwnerCheck> {
  const gate = ownerGate(await ownerAuthLevel(), failClosed, __DEV__);
  if (gate === "allow") return "confirmed";
  if (gate === "refuse") return "unavailable";
  try {
    const r = await LocalAuthentication.authenticateAsync({
      promptMessage: prompt,
      cancelLabel: cancel,
      disableDeviceFallback: false,
      requireConfirmation: true,
      biometricsSecurityLevel: "strong",
    });
    return r.success ? "confirmed" : "cancelled";
  } catch {
    return "unavailable";
  }
}
