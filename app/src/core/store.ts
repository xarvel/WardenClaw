// SPDX-License-Identifier: GPL-3.0-or-later
// Minimal reactive state store (useSyncExternalStore), no external dependencies.
import { useSyncExternalStore } from "react";
import type { Card, UnshownRecord } from "./approvals";
import type { AppMode, Verdict } from "./decide";
import type { HardwareKey, ServerHardware } from "./hardware";
import type { JudgeLinkRoute } from "./links";
import type { BiometricMode, OwnerAuthLevel } from "./safety";
import type { MissedItem } from "./missed";
import type { WardendState } from "./wardendSession";

export type { WardendState };

export type AppState = {
  ready: boolean;
  deviceId: string;
  cards: Card[];
  unshown: UnshownRecord[]; // requests with an envelope of unknown version: the feed shows a count and "update the app", no buttons
  mode: AppMode; // manual (the owner signs), observe (the phone signs everything), delegate (autopilot: the judge)
  threshold: number; // risk threshold for automatic allow in delegate mode
  verdicts: Record<string, Verdict | "pending">; // approvalId → judge verdict
  consecutiveDenies: number;
  escalation: string | null; // escalation notice (reset to manual)
  askService: boolean; // "Ask me about harness service launches too": the service rule (autosign.ts) is off
  autoStats: { signed: number; dangerous: number }; // automatic signatures in the current mode session, and how many of them were dangerous cards
  modelReady: boolean; // URL+model+key are set
  logLines: string[];
  hardwareKey: HardwareKey | null; // bound YubiKey (second factor for high risk)
  wardend: WardendState;
  bgNotify: boolean; // "Background notifications" (on by default)
  bg: BackgroundState;
  notif: NotifPrefs;
  missed: MissedItem[]; // expired without a decision: the "Missed" block in the feed until closed by hand
  focusCardId: string | null; // card opened by tapping a notification
  pendingPairLink: string | null; // wardenclaw://pair?… from a deep link (camera, am start): fill in on "Connect"
  pendingJudgeLink: JudgeLinkRoute | null; // wardenclaw://judge?… from a deep link: fill in the judge form on "Mode" (or show why it was refused)
  biometricMode: BiometricMode; // confirmation before signing: dangerous and roots, or every approval
  ownerAuth: OwnerAuthLevel | null; // how the phone can confirm the owner (null: not checked yet)
  snack: { id: number; text: string; tone: "allow" | "deny" | "info" } | null; // snackbar after a decision
  autoUntil: number | null; // observe or autopilot turns itself off at this moment (back to manual)
  serverHw: ServerHardware | null; // status of wardend: require_hardware rules and the keys it knows
  noTrashPaths: string[]; // local rule: trash-put on these paths always goes to a human
  identityError: string | null; // the device key was not saved (iOS without a passcode)
  screenProtect: boolean; // screen protection (FLAG_SECURE, iOS overlay); turned off only in the bench build
};

/** Background service (foreground service) and notification permission. */
export type BackgroundState = {
  supported: boolean; // native module present (not Expo Go): service on Android, APNs on iOS
  running: boolean;
  permission: "granted" | "denied" | "unknown";
  fullScreenAllowed: boolean; // Android 14+: full-screen intent permission ("like a call")
  batteryUnrestricted: boolean | null; // Android: battery optimization is off for the app
  push: PushStatus; // registration of the push token (APNs, FCM) with the relay
  timeSensitive: boolean | null; // iOS: time-sensitive notifications are allowed
};

/** not-in-build: an Android build without a Firebase configuration; not-configured: the relay has no credentials for the platform. */
export type PushStatus = { state: "off" | "registering" | "registered" | "no-permission" | "not-configured" | "not-in-build" | "error"; detail: string | null };

/** What to show in a request notification (notification settings). */
export type NotifPrefs = {
  showCommand: boolean; // "Show the command on the lock screen", off by default
  fullScreen: boolean; // "Like an incoming call" (Android, full-screen intent), off by default
};

/** Hint from app/.env.local; "unset" (how the production and preview profiles in eas.json clear the value) means "none". */
export function devHint(v: string | undefined): string {
  return v && v.trim() && v.trim() !== "unset" ? v.trim() : "";
}

let state: AppState = {
  ready: false,
  deviceId: "",
  cards: [],
  unshown: [],
  mode: "manual",
  threshold: 30,
  verdicts: {},
  consecutiveDenies: 0,
  escalation: null,
  askService: false,
  autoStats: { signed: 0, dangerous: 0 },
  modelReady: false,
  logLines: [],
  hardwareKey: null,
  wardend: { status: "unpaired", relay: null, host: null, supervisorId: null, pairId: null, policyMode: null, lastError: null, lastReason: null, lastOkAt: null, signed: 0 },
  bgNotify: true,
  bg: { supported: false, running: false, permission: "unknown", fullScreenAllowed: false, batteryUnrestricted: null, push: { state: "off", detail: null }, timeSensitive: null },
  notif: { showCommand: false, fullScreen: false },
  missed: [],
  focusCardId: null,
  pendingPairLink: null,
  pendingJudgeLink: null,
  biometricMode: "risky",
  ownerAuth: null,
  snack: null,
  autoUntil: null,
  serverHw: null,
  noTrashPaths: [],
  identityError: null,
  screenProtect: true,
};

const subs = new Set<() => void>();

export function getState() {
  return state;
}

export function setState(patch: Partial<AppState> | ((s: AppState) => Partial<AppState>)) {
  const p = typeof patch === "function" ? patch(state) : patch;
  state = { ...state, ...p };
  for (const s of subs) s();
}

/** Subscription outside React (the background service watches cards and status). */
export function subscribe(fn: () => void): () => void {
  subs.add(fn);
  return () => {
    subs.delete(fn);
  };
}

/** Ring buffer for the screen; to the system log (logcat, Console.app) only in a debug build:
 *  the lines carry the beginnings of commands, verdict reasons and server addresses. */
export function pushLog(line: string) {
  const stamp = new Date().toISOString().slice(11, 19);
  if (__DEV__) console.log(`[wardenclaw ${stamp}] ${line}`);
  setState((s) => ({ logLines: [...s.logLines.slice(-199), `${stamp} ${line}`] }));
}

export function useAppState<T>(selector: (s: AppState) => T): T {
  return useSyncExternalStore(
    (cb) => {
      subs.add(cb);
      return () => {
        subs.delete(cb);
      };
    },
    () => selector(state),
    () => selector(state),
  );
}
