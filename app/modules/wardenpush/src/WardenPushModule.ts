// SPDX-License-Identifier: GPL-3.0-or-later
// Native part: the push token (APNs in Swift, ios/; FCM in Kotlin, android/), permission,
// notification taps. In Expo Go and on the web the module is absent: requireOptionalNativeModule
// returns null.
import { requireOptionalNativeModule } from "expo";

export type PushSetting = "enabled" | "disabled" | "notSupported" | "unknown";
export type PushPermission = {
  status: "granted" | "denied" | "notDetermined" | "provisional" | "ephemeral" | "unknown";
  timeSensitive: PushSetting;
  lockScreen: PushSetting;
  alert: PushSetting;
};
export type PushRegistration = { token: string; environment: "sandbox" | "production"; topic: string };

export type NativeWardenPush = {
  /** Android: false when the build has no Firebase configuration (no google-services.json): no push. */
  available?(): boolean;
  getPermission(): Promise<PushPermission>;
  requestPermission(): Promise<PushPermission>;
  register(): Promise<PushRegistration>;
  takeLaunchCardId(): string | null;
  clearDelivered(cardId: string | null): void;
  /** Not push-related: exclude a directory from iCloud backup (NSURLIsExcludedFromBackupKey), for
   *  the journal database. Optional: builds before 28.09 lack it.
   *  false: setting the attribute failed. */
  excludeFromBackup?(path: string): boolean;
  /** onOpenCard (iOS): a notification was tapped. onToken (Android): Firebase issued a new token. */
  addListener?(event: "onOpenCard", listener: (e: { cardId: string }) => void): { remove(): void };
  addListener?(event: "onToken", listener: () => void): { remove(): void };
};

export default requireOptionalNativeModule<NativeWardenPush>("WardenPush");
