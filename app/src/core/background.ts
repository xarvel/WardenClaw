// SPDX-License-Identifier: GPL-3.0-or-later
// Request notifications while the app is in the background or the phone is locked. No cloud, no FCM:
// our own foreground service (modules/wardenwatch) keeps a headless task active, so the long-poll
// to wardend (wardendSession.wardendLoop) keeps running in the same JS context. On iPhone there is no
// background connection of our own, APNs is used there (src/core/phonePush.ts).
//
// What the lock screen shows (Android): "Approval request · pi · risk: high · 1:40 left".
// No command text until the user turns on "Show the command on the lock screen" themselves: anyone
// holding the phone can read it. There are no "Allow" and "Deny" buttons in the notification on
// purpose: a tap leads through unlocking to the card, the decision is made only in the app after
// biometrics. Several requests collapse into a group with a summary; a decided request removes its
// notification, an expired one turns into a quiet "Expired, denied", and "Missed" stays in the feed.
// The service's persistent notification shows the real status: the server mode when connected
// (observe does not wait), otherwise no connection or not paired.
import { errMsg } from "./errMsg";
import { Alert, AppRegistry, AppState, PermissionsAndroid, Platform } from "react-native";
import { WATCH_TASK, watch, type WatchRequest } from "../../modules/wardenwatch";
import type { Card } from "./approvals";
import { bootstrap } from "./controller";
import { isUnrated, riskTone, type Verdict } from "./decide";
import { headlineText, sanitizeText } from "./display";
import { AppState as Store, getState, pushLog, setState, subscribe } from "./store";
import { subscribeLang, t } from "./i18n";
import { loadNotifAsked, saveBgNotify, saveNotifAsked, saveNotifPref } from "./settings";
import { appendEntry } from "./journal";
import { cardHost } from "./missed";
import { cardSafety } from "./safety";
import { explainProtocolError } from "./protocolVersion";
import { linkFault, runCopy, type RunCopy } from "./serverMode";

/** How many command characters the notification shows (only with the "Show the command" option). */
const COMMAND_MAX = 300;

let inited = false;
let taskDone: (() => void) | null = null;
const shown = new Set<string>(); // requests that currently have a notification
const seenInApp = new Set<string>(); // cards that were in the feed while the app was open: no sound
let syncing = false;
let syncAgain = false;
let notifTimer: ReturnType<typeof setTimeout> | null = null;
let lastStatus = "";
let runningCheck: ReturnType<typeof setInterval> | null = null;
let startedAt = 0; // when the app last started the service: the service does not set the running flag right away
/** How often the open app checks the "service running" flag, and how long to wait after a start. */
const RUNNING_CHECK_MS = 10_000;
const RUNNING_SETTLE_MS = 5_000;

/** Registers the service's headless task. Call from index.ts before registerRootComponent. */
export function registerBackgroundTask() {
  if (Platform.OS !== "android") return;
  AppRegistry.registerHeadlessTask(WATCH_TASK, () => async () => {
    // Keep the task pending while the service is alive, so RN does not stop JS timers in the background
    taskDone?.();
    const done = new Promise<void>((resolve) => {
      taskDone = resolve;
    });
    try {
      await bootstrap();
    } catch (e) {
      pushLog(`background: bootstrap failed: ${errMsg(e)}`);
    }
    initBackground();
    // On start the service resets the status to "connecting": send the real one again
    pushServiceStatus(getState(), true);
    syncBackground();
    await done;
  });
}

function finishTask() {
  const f = taskDone;
  taskDone = null;
  f?.();
}

const active = () => AppState.currentState === "active";

/** Subscriptions to cards, status and language. Idempotent; called by App and the headless task. */
export function initBackground() {
  if (inited || Platform.OS !== "android") return;
  inited = true;
  refreshState();
  if (active()) for (const c of getState().cards) seenInApp.add(c.id);
  let last = getState();
  let lastSig = serviceSignature(last);
  subscribe(() => {
    const s = getState();
    if (s.cards !== last.cards || s.verdicts !== last.verdicts || s.missed !== last.missed || s.notif !== last.notif || s.wardend.host !== last.wardend.host) {
      if (active()) for (const c of s.cards) seenInApp.add(c.id);
      scheduleNotifications();
    }
    last = s;
    const sig = serviceSignature(s);
    if (sig !== lastSig) {
      lastSig = sig;
      syncBackground();
    }
    pushServiceStatus(s);
  });
  subscribeLang(() => {
    configureTexts();
    lastStatus = "";
    pushServiceStatus(getState());
    scheduleNotifications();
  });
  checkRunningWhileActive(active());
  AppState.addEventListener("change", (st) => {
    checkRunningWhileActive(st === "active");
    if (st === "active") {
      // The app is open: cards and "Missed" are visible in the feed, notifications are no longer needed
      for (const c of getState().cards) seenInApp.add(c.id);
      watch?.cancelAllRequests();
      shown.clear();
      refreshState();
      syncBackground();
      return;
    }
    // Backgrounded or locked: pending requests go to the lock screen (silently, they were already seen)
    scheduleNotifications();
  });
}

/**
 * While the app is open, the "service running" flag is checked against the service every
 * RUNNING_CHECK_MS: the service can stop on its own (three task failures within 30 s,
 * WatchService.giveUp), and until the next syncBackground "Mode" would show it as running. The
 * service is not started from here: with the same cause that is another failure loop; returning to
 * the app starts it (for example, via the service notification).
 */
function checkRunningWhileActive(on: boolean) {
  if (!on || !watch) {
    if (runningCheck) clearInterval(runningCheck);
    runningCheck = null;
    return;
  }
  if (runningCheck) return;
  runningCheck = setInterval(() => {
    if (!watch || !active() || Date.now() - startedAt < RUNNING_SETTLE_MS) return;
    const running = watch.isRunning();
    if (getState().bg.running !== running) setState((st) => ({ bg: { ...st.bg, running } }));
  }, RUNNING_CHECK_MS);
}

function serviceSignature(s: Store): string {
  return [s.ready, s.bgNotify, s.wardend.status, s.openclawAdapter, s.hasToken].join("|");
}

/** There is a source of cards: a wardend server is paired (or the OpenClaw adapter is on with a token). */
function hasSource(s: Store): boolean {
  return s.wardend.status === "connected" || s.wardend.status === "unavailable" || (s.openclawAdapter && s.hasToken);
}

// ---------------------------------------------------------------------------
// Request notifications
// ---------------------------------------------------------------------------

/** Risk level as a word: rules and flags (dangerous) → high; otherwise the judge's rating; no rating → "not rated". */
export function riskWord(card: Card, v: Verdict | "pending" | null | undefined): { word: string; danger: boolean } {
  const danger = cardSafety(card, v).dangerous;
  if (danger) return { word: t("notif.risk.high"), danger };
  if (v && v !== "pending" && !isUnrated(v) && v.risk !== null) {
    const tone = riskTone(v.risk);
    return { word: t(tone === "high" ? "notif.risk.high" : tone === "mid" ? "notif.risk.mid" : "notif.risk.low"), danger: tone === "high" };
  }
  return { word: t("notif.risk.none"), danger: false };
}

function commandLine(card: Card): string {
  const text = card.view ? headlineText(card.view) : card.command ?? card.summary;
  const s = sanitizeText(text).replace(/\s+/g, " ").trim();
  return s.length > COMMAND_MAX ? `${s.slice(0, COMMAND_MAX)}…` : s;
}

function scheduleNotifications() {
  if (!watch || notifTimer) return;
  // Several store changes in a row (cards, verdict) → one notification update
  notifTimer = setTimeout(() => {
    notifTimer = null;
    try {
      syncNotifications();
    } catch (e) {
      pushLog(`background: notify failed: ${errMsg(e)}`);
    }
  }, 150);
}

function syncNotifications() {
  if (!watch || active()) return;
  const s = getState();
  if (!s.bgNotify) return;
  const now = Date.now();
  const cards = s.cards.filter((c) => !c.expiresAtMs || c.expiresAtMs > now - 1000);
  const ids = new Set(cards.map((c) => c.id));
  for (const id of [...seenInApp]) if (!ids.has(id)) seenInApp.delete(id);
  const expired: { id: string; host: string; at: number }[] = [];
  for (const id of [...shown]) {
    if (ids.has(id)) continue;
    shown.delete(id);
    // Not in "Missed" means it was decided (here, on the watch, by another phone):
    // the notification is simply removed
    const m = s.missed.find((x) => x.id === id);
    if (m) expired.push({ id, host: m.host ?? s.wardend.host ?? "?", at: m.expiredAt });
  }
  const pending: WatchRequest[] = cards.map((c) => {
    const first = !shown.has(c.id);
    shown.add(c.id);
    const risk = riskWord(c, s.verdicts[c.id]);
    return {
      id: c.id,
      host: cardHost(c) ?? s.wardend.host ?? "?",
      risk: risk.word,
      danger: risk.danger,
      createdAt: c.createdAtMs,
      expiresAt: c.expiresAtMs ?? 0,
      command: s.notif.showCommand ? commandLine(c) : null,
      alert: first && !seenInApp.has(c.id),
    };
  });
  watch.update(JSON.stringify({ pending, expired, fullScreen: s.notif.fullScreen }));
}

function configureTexts() {
  watch?.configure({
    serviceTitle: t("notif.service.title"),
    serviceText: t("notif.service.text"),
    requestTitle: t("notif.request.title"),
    requestLine: t("notif.request.line"),
    requestLineNoExpiry: t("notif.request.lineNoExpiry"),
    riskLine: t("notif.riskLine"),
    summaryTitle: t("notif.summary.title"),
    summaryLine: t("notif.summary.line"),
    expiredTitle: t("notif.expired.title"),
    expiredText: t("notif.expired.text"),
    commandHidden: t("notif.commandHidden"),
    open: t("notif.open"),
    later: t("notif.later"),
    pausedTitle: t("notif.paused.title"),
    pausedText: t("notif.paused.text"),
    pausedCrashText: t("notif.paused.crashText"),
    channelService: t("notif.channel.service"),
    channelRequests: t("notif.channel.requests"),
    channelMissed: t("notif.channel.missed"),
    channelStatus: t("notif.channel.status"),
  });
}

// ---------------------------------------------------------------------------
// Persistent notification: the real connection status
// ---------------------------------------------------------------------------

function hhmm(ms: number): string {
  const d = new Date(ms);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

function hostOf(url: string | null): string | null {
  const m = url ? /^\w+:\/\/([^/:]+)/.exec(url) : null;
  return m ? m[1] : null;
}

const NOTIF_MODE: Record<RunCopy, "wd.mode.observe" | "wd.mode.denylist" | "wd.mode.tripwire" | "wd.mode.root" | "wd.mode.ticket"> = {
  observe: "wd.mode.observe",
  denylist: "wd.mode.denylist",
  tripwire: "wd.mode.tripwire",
  root: "wd.mode.root",
  ticket: "wd.mode.ticket",
};
const NOTIF_DETAIL: Record<RunCopy, "feed.hint.observe" | "feed.hint.denylist" | "feed.hint.tripwire" | "feed.hint.root" | "feed.hint.ticket"> = {
  observe: "feed.hint.observe",
  denylist: "feed.hint.denylist",
  tripwire: "feed.hint.tripwire",
  root: "feed.hint.root",
  ticket: "feed.hint.ticket",
};

/** Shade title and text. Connected names the server mode; observe does not say it is waiting for requests. */
export function serviceStatus(s: Store): { title: string; text: string } {
  const w = s.wardend;
  const host = w.host || hostOf(w.url) || "wardend";
  switch (w.status) {
    case "connected": {
      const copy = runCopy(w.mode, w.policyMode);
      if (!copy) return { title: t("notif.st.connected", { host }), text: t("notif.st.connectedText") };
      return { title: t(NOTIF_MODE[copy]), text: t("notif.st.modeLine", { host, detail: t(NOTIF_DETAIL[copy]) }) };
    }
    case "unavailable": {
      const fault = linkFault(w.status, w.lastReason);
      if (fault === "revoked") return { title: t("wd.fault.revoked"), text: t("notif.st.revokedText", { host }) };
      if (fault === "clock") return { title: t("wd.fault.clock"), text: t("wdr.stale_timestamp") };
      if (fault === "foreign") return { title: t("wd.fault.foreign"), text: t("wdr.unsigned_response") };
      // the TCP connection may be fine; the two sides do not speak the same protocol
      if (fault === "protocol") return { title: t("wd.fault.protocol"), text: explainProtocolError(w.lastError)?.text ?? t("notif.st.downText") };
      return { title: t("notif.st.down", { host }), text: w.lastOkAt ? t("notif.st.downSince", { time: hhmm(w.lastOkAt) }) : t("notif.st.downText") };
    }
    case "checking":
      return { title: t("notif.st.checking", { host }), text: t("notif.st.connectedText") };
    case "awaiting-approval":
      return { title: t("notif.st.awaiting"), text: t("notif.st.awaitingText", { host }) };
    default:
      if (s.openclawAdapter && s.hasToken) {
        return s.status === "connected" ? { title: t("notif.st.gateway"), text: t("notif.st.connectedText") } : { title: t("notif.st.gatewayDown"), text: t("notif.st.downText") };
      }
      return { title: t("notif.st.unpaired"), text: t("notif.st.unpairedText") };
  }
}

function pushServiceStatus(s: Store, force = false) {
  if (!watch || !s.ready) return;
  const st = serviceStatus(s);
  const sig = `${st.title}\n${st.text}`;
  if (sig === lastStatus && !force) return;
  lastStatus = sig;
  try {
    watch.setStatus(st.title, st.text);
  } catch (e) {
    pushLog(`background: status failed: ${errMsg(e)}`);
  }
}

// ---------------------------------------------------------------------------
// Permissions, service, battery
// ---------------------------------------------------------------------------

/** Re-read permissions and battery (after returning from Android settings). */
export function refreshState() {
  const w = watch;
  if (!w) return;
  setState((s) => ({
    bg: {
      ...s.bg,
      supported: true,
      running: w.isRunning(),
      permission: w.notificationsEnabled() ? "granted" : "denied",
      fullScreenAllowed: w.canUseFullScreenIntent(),
      batteryUnrestricted: w.ignoringBatteryOptimizations(),
    },
  }));
}

/**
 * A clear moment for the system prompt: first our own explanation of why notifications are needed
 * and what the lock screen will show, then the Android dialog. On its own it asks once (after
 * pairing); the toggle in settings (explicit) asks again.
 */
export async function askNotificationPermission(explicit: boolean): Promise<boolean> {
  if (Platform.OS !== "android" || Number(Platform.Version) < 33) return true;
  const perm = PermissionsAndroid.PERMISSIONS.POST_NOTIFICATIONS;
  if (await PermissionsAndroid.check(perm)) return true;
  if (!active()) return false;
  if (!explicit && (await loadNotifAsked())) return false;
  await saveNotifAsked();
  const agreed = await new Promise<boolean>((resolve) =>
    Alert.alert(
      t("bg.permAsk.title"),
      t("bg.permAsk.body"),
      [
        { text: t("bg.permAsk.later"), style: "cancel", onPress: () => resolve(false) },
        { text: t("bg.permAsk.allow"), onPress: () => resolve(true) },
      ],
      { cancelable: true, onDismiss: () => resolve(false) },
    ),
  );
  if (!agreed) return false;
  const r = await PermissionsAndroid.request(perm);
  // "Don't ask again" is already set: the system dialog will not appear, open the settings
  if (r === PermissionsAndroid.RESULTS.NEVER_ASK_AGAIN) watch?.openNotificationSettings();
  refreshState();
  return r === PermissionsAndroid.RESULTS.GRANTED;
}

/** Bring the service in line with the setting: needed → start (only from the visible app), not needed → stop. */
export function syncBackground() {
  if (syncing) {
    syncAgain = true;
    return;
  }
  syncing = true;
  doSync()
    .catch((e) => pushLog(`background: ${errMsg(e)}`))
    .finally(() => {
      syncing = false;
      if (syncAgain) {
        syncAgain = false;
        syncBackground();
      }
    });
}

async function doSync() {
  if (!watch) return;
  const s = getState();
  const want = s.ready && s.bgNotify && hasSource(s);
  const running = watch.isRunning();
  if (want) {
    configureTexts();
    pushServiceStatus(getState());
    if (active()) await askNotificationPermission(false);
    refreshState();
    if (!running) {
      // Android 12+ forbids starting a foreground service from the background: only from the open app
      // (after a reboot and after an update, BootReceiver starts the service)
      if (!active()) return;
      const ok = watch.start();
      if (ok) startedAt = Date.now();
      pushLog(ok ? "background: service started" : "background: service start refused by Android");
      // The service's onCreate reset the status: send it again once the service is up
      if (ok) setTimeout(() => pushServiceStatus(getState(), true), 1500);
    }
  } else if (running) {
    watch.stop();
    finishTask();
    watch.cancelAllRequests();
    shown.clear();
    pushLog("background: service stopped");
  }
  // The service sets the flag in onStartCommand asynchronously: re-read a bit later
  setTimeout(() => setState((st) => ({ bg: { ...st.bg, running: watch?.isRunning() ?? false } })), 1500);
  setState((st) => ({ bg: { ...st.bg, running: watch?.isRunning() || (want && active()) } }));
}

/** The "Background notifications" toggle on the "Mode" tab. */
export async function setBackgroundNotifications(on: boolean) {
  await saveBgNotify(on);
  setState({ bgNotify: on });
  appendEntry({ ts: Date.now(), kind: "info", approval_id: null, approval_kind: null, summary: t(on ? "j.bgOn" : "j.bgOff"), decided_by: "me", decision: null, latency_ms: null, payload: null });
  if (on && Platform.OS === "android") await askNotificationPermission(true);
}

/** "Show the command on the lock screen" and "Like an incoming call". */
export async function setNotifPref(key: "showCommand" | "fullScreen", on: boolean) {
  await saveNotifPref(key, on);
  setState((s) => ({ notif: { ...s.notif, [key]: on } }));
  // Android 14+: without the full-screen intent permission the mode won't work, open settings right away
  if (key === "fullScreen" && on && watch && !watch.canUseFullScreenIntent()) watch.openFullScreenSettings();
}

export { cardIdFromUrl } from "./links";
