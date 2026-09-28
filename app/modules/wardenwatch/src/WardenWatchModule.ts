// SPDX-License-Identifier: GPL-3.0-or-later
// Native part (Kotlin, android/): foreground service specialUse + local notifications.
// In Expo Go, on iOS and web the module is absent: requireOptionalNativeModule returns null.
import { requireOptionalNativeModule } from "expo";

/** Notification texts in the UI language; Kotlin substitutes {host}, {risk}, {left}, {n}, {hosts}, {time}. */
export type WatchTexts = {
  serviceTitle: string;
  serviceText: string;
  requestTitle: string;
  requestLine: string;
  requestLineNoExpiry: string;
  riskLine: string;
  summaryTitle: string;
  summaryLine: string;
  expiredTitle: string;
  expiredText: string;
  commandHidden: string;
  open: string;
  later: string;
  pausedTitle: string;
  pausedText: string;
  pausedCrashText: string; // the service stopped after repeated background task failures
  channelService: string;
  channelRequests: string;
  channelMissed: string;
  channelStatus: string;
};

/** A request in a notification: everything except command is visible on the lock screen. */
export type WatchRequest = {
  id: string;
  host: string;
  risk: string; // ready-made word: "high"
  danger: boolean;
  createdAt: number;
  expiresAt: number; // 0: no deadline
  command: string | null; // only with the "Show the command on the lock screen" option
  alert: boolean; // sound, pop-up and screen wake-up (a new request while the app is in the background)
};

export type WatchUpdate = {
  pending: WatchRequest[];
  expired: { id: string; host: string; at: number }[];
  fullScreen: boolean;
};

export type NativeWardenWatch = {
  configure(texts: WatchTexts): void;
  start(): boolean;
  stop(): void;
  isRunning(): boolean;
  setStatus(title: string, text: string): void;
  update(json: string): void;
  cancelAllRequests(): void;
  notificationsEnabled(): boolean;
  canUseFullScreenIntent(): boolean;
  openFullScreenSettings(): boolean;
  ignoringBatteryOptimizations(): boolean;
  requestIgnoreBatteryOptimizations(): boolean;
  openNotificationSettings(): boolean;
  /**
   * FLAG_SECURE on the app screen; false: not a bench build, protection cannot be removed.
   * Absent in builds before 28.09.
   */
  setScreenSecure?(secure: boolean): boolean;
  /** The manifest has the bench build marker (plugins/withAppHardening.js). */
  isBenchBuild?(): boolean;
};

export default requireOptionalNativeModule<NativeWardenWatch>("WardenWatch");
