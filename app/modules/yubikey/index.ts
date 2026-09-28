// SPDX-License-Identifier: GPL-3.0-or-later
// YubiKey (FIDO2 over NFC or USB-C): the JS wrapper of the native module modules/yubikey.
// During register/getAssertion the native side listens on both transports at once: hold or plug in.
//   register()                           → a new credential on the key (attestation for `wardend hw-register`)
//   getAssertion(clientDataHash, credId) → the key's signature over authenticatorData || clientDataHash
// Bytes on the bridge are base64url. There is no module in Expo Go: availability() explains what to do.
// iOS (ios/YubikeyModule.swift, YubiKit iOS): NFC only (and Lightning 5Ci if enabled in the plugin).
// USB-C on iPhone 15+ is not supported: YubiKit cannot do FIDO2 over USB-C. availability() says so in note.
import { Platform } from "react-native";
import Native, { NativeAssertionResult, NativeRegisterResult, NativeStatusEvent } from "./src/YubikeyModule";
import { tOr } from "../../src/core/i18n";

/** ok: at least one transport works. nfc/usb: what exactly is available; note: a hint (e.g. NFC is off, but USB is there). */
export type YubikeyAvailability =
  | { ok: true; nfc: boolean; usb: boolean; note?: string }
  | { ok: false; reason: "no-module" | "no-nfc" | "nfc-off"; message: string };

export type { NativeStatusEvent as YubikeyStatus };

export type YubikeyErrorCode =
  | "NO_MODULE"
  | "IOS_UNSUPPORTED" // no longer emitted: kept for compatibility with saved errors
  | "NO_ACTIVITY"
  | "BUSY"
  | "NFC_DISABLED"
  | "NFC_UNAVAILABLE"
  | "USB_PERMISSION_DENIED"
  | "TIMEOUT"
  | "CANCELLED"
  | "PIN_REQUIRED"
  | "PIN_INVALID"
  | "PIN_BLOCKED"
  | "PIN_NOT_SUPPORTED"
  | "NO_CREDENTIALS"
  | "DENIED"
  | "UNSUPPORTED_ALGORITHM"
  | "BAD_RESPONSE"
  | "CTAP_ERROR"
  | "FAILED";

export class YubikeyError extends Error {
  constructor(
    public code: YubikeyErrorCode | string,
    message: string,
  ) {
    super(message);
  }
}


/** A readable message for a native module error code, in the current UI language. */
export function yubikeyMessage(code: string, fallback?: string): string {
  return tOr(`yk.${code}`, fallback ?? code);
}

export function availability(): YubikeyAvailability {
  if (!Native) return { ok: false, reason: "no-module", message: yubikeyMessage("NO_MODULE") };
  try {
    const hasNfc = Native.hasNfc ? Native.hasNfc() : Native.isSupported();
    const usb = Native.hasUsb ? Native.hasUsb() : false;
    const nfcOn = hasNfc && Native.isNfcEnabled();
    if (!hasNfc && !usb) return { ok: false, reason: "no-nfc", message: yubikeyMessage("NO_TRANSPORT") };
    if (!nfcOn && !usb) return { ok: false, reason: "nfc-off", message: yubikeyMessage("NFC_DISABLED") };
    // No NFC or it is off, but USB is there: work over USB and say plainly that NFC will not be used.
    // iPhone: no USB-C for FIDO2 (YubiKit); say so, so that the key is not plugged in for nothing.
    const note = !hasNfc ? yubikeyMessage("USB_ONLY") : !nfcOn ? yubikeyMessage("NFC_OFF_USB_OK") : Platform.OS === "ios" && !usb ? yubikeyMessage("IOS_NFC_ONLY") : undefined;
    return { ok: true, nfc: nfcOn, usb, note };
  } catch (e) {
    return { ok: false, reason: "no-module", message: String((e as Error)?.message ?? e) };
  }
}

/** Subscribe to transport events (USB: plugged in, asking for permission, waiting for a touch, removed). */
export function onStatus(listener: (e: NativeStatusEvent) => void): () => void {
  const sub = Native?.addListener?.("onStatus", listener);
  return () => sub?.remove();
}

function wrap(e: unknown): YubikeyError {
  const code = String((e as { code?: string })?.code ?? "FAILED");
  const msg = String((e as Error)?.message ?? e);
  return new YubikeyError(code, yubikeyMessage(code, msg));
}

function native() {
  if (!Native) throw new YubikeyError("NO_MODULE", yubikeyMessage("NO_MODULE"));
  return Native;
}

export type RegisterOptions = { rpId: string; userId: string; userName: string; clientDataHash: string; pin?: string | null };

export async function register(o: RegisterOptions): Promise<NativeRegisterResult> {
  try {
    return await native().register(o.rpId, o.userId, o.userName, o.clientDataHash, o.pin ?? null);
  } catch (e) {
    throw e instanceof YubikeyError ? e : wrap(e);
  }
}

/** clientDataHash and credentialId are base64url. */
export async function getAssertion(clientDataHash: string, credentialId: string, o: { rpId: string; pin?: string | null }): Promise<NativeAssertionResult> {
  try {
    return await native().getAssertion(o.rpId, clientDataHash, credentialId, o.pin ?? null);
  } catch (e) {
    throw e instanceof YubikeyError ? e : wrap(e);
  }
}

export async function cancel(): Promise<void> {
  if (Native) await Native.cancel().catch(() => {});
}
