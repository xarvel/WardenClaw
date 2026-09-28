// SPDX-License-Identifier: GPL-3.0-or-later
// Minimal reactive state store (useSyncExternalStore), no external dependencies.
import { useSyncExternalStore } from "react";
import type { Card, UnshownRecord } from "./approvals";
import type { AppMode, Verdict } from "./decide";
import type { HardwareKey, ServerHardware } from "./hardware";
import type { BiometricMode, OwnerAuthLevel } from "./safety";
import type { MissedItem } from "./missed";

/** OpenClaw adapter status (connection to the gateway). */
export type ConnStatus =
  | "off" // adapter is off (default)
  | "unpaired" // no token: the pairing wizard is needed
  | "connecting"
  | "connected"
  | "reconnecting"
  | "pairing" // PAIRING_REQUIRED, waiting for approve on the Pi
  | "auth-failed"; // token revoked/invalid

export type AppState = {
  ready: boolean;
  gatewayUrl: string;
  deviceId: string;
  hasToken: boolean;
  status: ConnStatus;
  statusDetail: string;
  pairingRequestId: string | null;
  serverVersion: string | null;
  scopes: string[];
  cards: Card[];
  unshown: UnshownRecord[]; // requests with an envelope of unknown version: the feed shows a count and "update the app", no buttons
  mode: AppMode;
  threshold: number; // risk threshold for automatic allow in delegate mode
  verdicts: Record<string, Verdict | "pending">; // approvalId → judge verdict
  consecutiveDenies: number;
  escalation: string | null; // escalation notice (reset to "Observe")
  modelReady: boolean; // URL+model+key are set
  lastError: string | null;
  logLines: string[];
  gate: GateState;
  hardwareKey: HardwareKey | null; // bound YubiKey (second factor for high risk)
  wardend: WardendState;
  openclawAdapter: boolean; // OpenClaw adapter is enabled in settings
  bgNotify: boolean; // "Background notifications" (on by default)
  bg: BackgroundState;
  notif: NotifPrefs;
  missed: MissedItem[]; // expired without a decision: the "Missed" block in the feed until closed by hand
  focusCardId: string | null; // card opened by tapping a notification
  pendingPairLink: string | null; // wardenclaw://pair?… from a deep link (camera, am start): fill in on "Connect"
  biometricMode: BiometricMode; // confirmation before signing: dangerous and roots, or every approval
  ownerAuth: OwnerAuthLevel | null; // how the phone can confirm the owner (null: not checked yet)
  snack: { id: number; text: string; tone: "allow" | "deny" | "info" } | null; // snackbar after a decision
  autopilotUntil: number | null; // autopilot (delegation) turns itself off at this moment
  serverHw: ServerHardware | null; // /v1/status of wardend: require_hardware rules and the keys it knows
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
  push: PushStatus; // iOS: APNs token registration in wardend
  timeSensitive: boolean | null; // iOS: time-sensitive notifications are allowed
};

export type PushStatus = { state: "off" | "registering" | "registered" | "no-permission" | "not-configured" | "error"; detail: string | null };

/** What to show in a request notification (notification settings). */
export type NotifPrefs = {
  showCommand: boolean; // "Show the command on the lock screen", off by default
  fullScreen: boolean; // "Like an incoming call" (Android, full-screen intent), off by default
};

/** Direct connection to wardend (the main transport). */
export type WardendState = {
  status: "unpaired" | "checking" | "awaiting-approval" | "connected" | "unavailable" | "rejected";
  url: string | null;
  host: string | null;
  supervisorId: string | null;
  pairId: string | null;
  mode: string | null; // supervisor mode: observe | deny-list | ticket
  policyMode: string | null; // tripwire | root; which execs need a signature when mode is ticket
  lastError: string | null;
  lastReason: string | null; // wardend reason code (untrusted_device, …) for the status in the notification shade
  lastOkAt: number | null;
  signed: number;
};

/** Connection state with the wardenclaw-gate plugin (gateway HTTP routes; only in the OpenClaw adapter). */
export type GateState = {
  status: "off" | "polling" | "unavailable";
  mode: "observe" | "enforce" | null;
  lastError: string | null;
  lastOkAt: number | null;
  signed: number; // how many decisions were signed this session
};

// Default OpenClaw gateway address (adapter, optional): empty, the user enters the address when
// pairing. The hint from app/.env.local (EXPO_PUBLIC_WARDENCLAW_GATEWAY_URL) only works when
// debugging with Metro: in a release build __DEV__ = false and the string is not in the bundle.
export const DEFAULT_GATEWAY_URL: string = __DEV__ ? devHint(process.env.EXPO_PUBLIC_WARDENCLAW_GATEWAY_URL) : "";

/** Hint from app/.env.local; "unset" (how the production and preview profiles in eas.json clear the value) means "none". */
export function devHint(v: string | undefined): string {
  return v && v.trim() && v.trim() !== "unset" ? v.trim() : "";
}

let state: AppState = {
  ready: false,
  gatewayUrl: DEFAULT_GATEWAY_URL,
  deviceId: "",
  hasToken: false,
  status: "off",
  statusDetail: "",
  pairingRequestId: null,
  serverVersion: null,
  scopes: [],
  cards: [],
  unshown: [],
  mode: "manual",
  threshold: 30,
  verdicts: {},
  consecutiveDenies: 0,
  escalation: null,
  modelReady: false,
  lastError: null,
  logLines: [],
  gate: { status: "off", mode: null, lastError: null, lastOkAt: null, signed: 0 },
  hardwareKey: null,
  wardend: { status: "unpaired", url: null, host: null, supervisorId: null, pairId: null, mode: null, policyMode: null, lastError: null, lastReason: null, lastOkAt: null, signed: 0 },
  openclawAdapter: false,
  bgNotify: true,
  bg: { supported: false, running: false, permission: "unknown", fullScreenAllowed: false, batteryUnrestricted: null, push: { state: "off", detail: null }, timeSensitive: null },
  notif: { showCommand: false, fullScreen: false },
  missed: [],
  focusCardId: null,
  pendingPairLink: null,
  biometricMode: "risky",
  ownerAuth: null,
  snack: null,
  autopilotUntil: null,
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
