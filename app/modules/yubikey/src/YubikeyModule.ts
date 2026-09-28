// SPDX-License-Identifier: GPL-3.0-or-later
// Native part (Kotlin, android/): yubikit-android, CTAP2 over NFC and USB-C. In Expo Go and on iOS/web
// there is no module: requireOptionalNativeModule returns null, the index.ts wrapper reports it.
import { requireOptionalNativeModule } from "expo";

export type NativeRegisterResult = { credentialId: string; attestationObject: string; alg: number };
export type NativeAssertionResult = { credentialId: string; authenticatorData: string; signature: string; signCount: number };

export type UsbState = "connected" | "permission" | "touch" | "removed" | "permission-denied";
export type NativeStatusEvent = { transport: "usb" | "nfc"; state: UsbState };

export type NativeYubikey = {
  isSupported(): boolean;
  isNfcEnabled(): boolean;
  hasNfc?(): boolean;
  hasUsb?(): boolean;
  addListener?(event: "onStatus", listener: (e: NativeStatusEvent) => void): { remove(): void };
  register(rpId: string, userId: string, userName: string, clientDataHash: string, pin: string | null): Promise<NativeRegisterResult>;
  getAssertion(rpId: string, clientDataHash: string, credentialId: string, pin: string | null): Promise<NativeAssertionResult>;
  cancel(): Promise<void>;
};

export default requireOptionalNativeModule<NativeYubikey>("Yubikey");
