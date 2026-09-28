// SPDX-License-Identifier: GPL-3.0-or-later
// Native part (Swift, ios/): WatchConnectivity. iOS only; absent on Android, in Expo Go and web.
import { requireOptionalNativeModule } from "expo";

export type WatchLinkStatus = { supported: boolean; activated: boolean; paired: boolean; installed: boolean; reachable: boolean };
export type WatchStatusEvent =
  | { type: "pairStatus"; status: string; fingerprint?: string; host?: string; error?: string }
  | { type: "state" };

export type NativeAppleWatch = {
  status(): WatchLinkStatus;
  sendPairingLink(link: string, name: string): Promise<"delivered" | "queued">;
  addListener?(event: "onWatchStatus", listener: (e: WatchStatusEvent) => void): { remove(): void };
};

export default requireOptionalNativeModule<NativeAppleWatch>("AppleWatch");
