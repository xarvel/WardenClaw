// SPDX-License-Identifier: GPL-3.0-or-later
// Orchestration: identity (SecureStore), then cards, the journal, and decisions.
// The link to wardend (through the relay) lives in wardendSession.ts.
import { Card, gateAllowRefusal, gateTicketScope, normalizeGatePending, splitUnshown, UnshownRecord } from "./approvals";
import { DecisionTarget, GateDecideResponse, GatePending, SignedDecision, signDecision, signDecisionWithHardware } from "./gate";
import { GateDecision } from "./canonical";
import { CLIENT_VERSION } from "./protocolVersion";
import { DeviceIdentity, IdentityStoreError, loadOrCreateEncKey, loadOrCreateIdentity, publicKeyB64Url, signPayload } from "./identity";
import { encPrivate } from "./relayState";
import type { RelaySocket } from "./relaySession";
import { appendEntry, clearJournal, initJournal } from "./journal";
import { journalMsg } from "./journalText";
import { errMsg } from "./errMsg";
import { activeWardendLink, adoptWardendLink, bindWardendSession, relayHost, sendWardendTicket, startWardend, wardendStateFromLink } from "./wardendSession";
export { forgetWardend, pairWithWardend, refreshServerStatus } from "./wardendSession";
import { getState, pushLog, setState } from "./store";
import { AppMode, LayeredJudge, MODEL_MIN_TTL_MS, Verdict, setNoTrashPaths } from "./decide";
import { AUTO_MODE_TTL_MS, AutoSigner, FALLBACK_MODE, autoPlan } from "./autosign";
import { loadThreshold, saveThreshold, loadModelSettings, loadModelPrefs, saveModelPrefs, saveModelKey, hasModelKey, loadWardendLink, saveWardendLink, clearWardendLink, loadRelayStateFor, relayStateWriter, loadLang, loadBgNotify, loadBiometricMode, saveBiometricMode, loadNotifPrefs, loadNoTrashPaths, saveNoTrashPaths, loadAskService, saveAskService, ModelPrefs } from "./settings";
import { loadMissed, noteMissed } from "./missed";
import { BiometricMode, biometricModeWeakens, cardSafety, judgeChanged, needsOwnerCheck, pathListWeakens, thresholdWeakens } from "./safety";
import { confirmOwner, ownerAuthLevel } from "./biometric";
import { addRecent, trimOldest } from "./bounded";
import { MsgKey, MsgParams, setLang, t } from "./i18n";
import { HardwareKey, HardwareSigner, clientDataHash, clientDataJSON, isRetryableHardwareReason, needsHardware, pickCredential, signableRisk } from "./hardware";
import { getRandomBytes } from "expo-crypto";
import { b64url } from "./bytes";

import { prepareSecureStore } from "./secure";

// Features outside the first release (features.js, docs/release-scope.md): without the build flag the
// YubiKey module and the phone judge are not in the bundle. The key protocol (./hardware: wardend
// meta.hardware, what requires a key) stays: the server can require a key even without the key-enabled app.
const hwKey: typeof import("./hardwareKey") | null = process.env.EXPO_PUBLIC_WARDENCLAW_FEATURE_HARDWARE_KEY === "1" ? require("./hardwareKey") : null;
const phoneJudge: typeof import("../localjudge/entry") | null = process.env.EXPO_PUBLIC_WARDENCLAW_FEATURE_PHONE_JUDGE === "1" ? require("../localjudge/entry") : null;

const EXPIRY_GRACE_MS = 3000;
export { AUTO_MODE_TTL_MS };

/** Timeout for test card creation requests. */
const TEST_CARD_TIMEOUT_MS = 120000;
/** How long to wait for test cards to be delivered before returning. */
const TEST_CARD_SETTLE_MS = 6000;

let identity: DeviceIdentity | null = null;
let tickTimer: ReturnType<typeof setInterval> | null = null;
// Both capped at the last RESOLVED_MEMORY ids (bounded.ts): cards live for minutes, the process for weeks.
const myDecisions = new Map<string, { decision: string; at: number; who: Who }>(); // id → what we pressed (or who signed automatically)

/** Who signs a card: the owner on this phone, or an automatic signer (autosign.ts). */
export type Who = "me" | AutoSigner;

/** A card an automatic signer is handling right now: the notifications do not announce it, nobody waits for it. */
export function autoSigning(id: string): boolean {
  const d = myDecisions.get(id);
  return !!d && d.who !== "me";
}
const seenResolved = new Set<string>();
const judge = new LayeredJudge(loadModelSettings);
const ESCALATION_DENIES = 3;
// Dev: on Fast Refresh the module re-executes, while the old timer stays alive.
// The wardend module shuts its own socket down the same way.
type Globals = { __wcTick?: ReturnType<typeof setInterval> | null };
const g = globalThis as unknown as Globals;
if (g.__wcTick) {
  clearInterval(g.__wcTick);
  g.__wcTick = null;
}


/** The owner did not confirm (biometrics or passcode cancelled, module not responding): nothing was signed or changed. */
export class OwnerNotConfirmed extends Error {}

/**
 * Owner confirmation before a change that weakens protection (autopilot, threshold, judge,
 * biometric mode, trash-put rule), and before pairing, "Forget server", unlinking the
 * YubiKey. Without a working biometric module the change is not made (fail-closed).
 */
async function requireOwner(prompt: MsgKey, params?: MsgParams): Promise<void> {
  const r = await confirmOwner(t(prompt, params), t("common.cancel"), true);
  if (r === "confirmed") return;
  throw new OwnerNotConfirmed(t(r === "unavailable" ? "owner.unavailable" : "owner.notConfirmed"));
}

let booting: Promise<void> | null = null;

/** Idempotent: called both by the UI (App) and by the background task if the service started the process without UI. */
export function bootstrap(): Promise<void> {
  if (!booting) {
    booting = doBootstrap().catch((e) => {
      booting = null;
      throw e;
    });
  }
  return booting;
}

async function doBootstrap() {
  // Before the first SecureStore read and before the journal: a fresh install erases records that survived
  // app removal; old records on iOS are rewritten as "this device only".
  const prep = await prepareSecureStore().catch((e) => {
    pushLog(`secure store: ${errMsg(e)}`);
    return null;
  });
  setLang(await loadLang());
  initJournal();
  if (prep?.wiped) appendEntry({ ts: Date.now(), kind: "info", approval_id: null, approval_kind: null, ...journalMsg("j.freshInstall"), decided_by: null, decision: null, latency_ms: null });
  if (prep && (prep.migrated || prep.failed)) pushLog(`secure store: ${prep.migrated} records moved to this-device-only${prep.failed ? `, ${prep.failed} failed` : ""}`);
  try {
    identity = await loadOrCreateIdentity();
  } catch (e) {
    // iOS without a passcode: the device key is not saved, and without it there is neither pairing nor signing
    const msg = e instanceof IdentityStoreError ? t("err.identityNoPasscode") : errMsg(e);
    setState({ ready: true, identityError: msg });
    pushLog(`identity: ${msg}`);
    return;
  }
  const [threshold, hardwareKey, link, bgNotify, biometricMode, notif, missed, noTrashPaths, askService] = await Promise.all([loadThreshold(), hwKey ? hwKey.loadHardwareKey().catch(() => null) : null, loadWardendLink(), loadBgNotify(), loadBiometricMode(), loadNotifPrefs(), loadMissed(), loadNoTrashPaths(), loadAskService()]);
  adoptWardendLink(link);
  setNoTrashPaths(noTrashPaths);
  // The mode is not stored: observe and autopilot are timed and turned on by the owner's hand, so
  // every start is manual.
  const mode: AppMode = FALLBACK_MODE;
  setState({
    identityError: null,
    noTrashPaths,
    askService,
    ready: true,
    deviceId: identity.deviceId,
    bgNotify,
    notif,
    missed,
    mode,
    threshold,
    hardwareKey,
    biometricMode,
    wardend: { ...getState().wardend, ...wardendStateFromLink(link) },
  });
  refreshOwnerAuth();
  await refreshModelReady();
  pushLog(`device ${identity.deviceId.slice(0, 12)}…, wardend: ${link ? (link.paired ? link.host || relayHost(link.relay) : "awaiting approval") : "not connected"}, mode ${mode}, threshold ${threshold}`);
  if (!tickTimer) {
    tickTimer = setInterval(tick, 1000);
    g.__wcTick = tickTimer;
  }
  if (link) startWardend();
}


/** Wardend is forgotten or stopped trusting this phone: its cards and unshown records go. */
function removeWardendCards() {
  for (const c of getState().cards) if (c.kind === "gate") removeCard(c.id);
  if (getState().unshown.length) setState({ unshown: [] });
}

/**
 * Records with an envelope of unknown version (splitUnshown): not cards but a count in the feed and
 * "update the app"; one journal entry per new id. They neither vanish silently nor get allowed.
 */
function syncUnshown(list: UnshownRecord[]) {
  const known = new Set(getState().unshown.map((u) => u.id));
  const fresh = list.filter((u) => !known.has(u.id));
  for (const u of fresh) {
    appendEntry({ ts: Date.now(), kind: "requested", approval_id: u.id, approval_kind: "gate", ...journalMsg("j.unshown", { v: u.v }, { v: u.v }), decided_by: null, decision: null, latency_ms: null });
    pushLog(`wardend: record ${u.id.slice(0, 8)} has envelope v=${u.v}: this app version cannot show it, update the app`);
  }
  if (fresh.length || known.size !== list.length) setState({ unshown: list });
}

/** Bring the cards in line with wardend's pending list: add new ones, close the ones that disappeared. */
function syncGateCards(all: GatePending[]) {
  const { shown: pending, unshown } = splitUnshown(all);
  syncUnshown(unshown);
  const ids = new Set(pending.map((p) => p.id));
  const sup = activeWardendLink()?.supervisorId ?? null;
  for (const p of pending) addCard(normalizeGatePending(p, sup), "wardend");
  for (const c of getState().cards) {
    if (c.kind !== "gate" || ids.has(c.id)) continue;
    if (!seenResolved.has(c.id) && !myDecisions.has(c.id)) {
      addRecent(seenResolved, c.id);
      const expired = c.expiresAtMs !== null && Date.now() >= c.expiresAtMs - 1500;
      appendEntry({ ts: Date.now(), kind: expired ? "expired" : "resolved", approval_id: c.id, approval_kind: "gate", summary: c.summary, decided_by: expired ? "timeout" : "other", decision: expired ? "timeout" : "?", latency_ms: Date.now() - c.createdAtMs, payload: null });
      if (expired) noteMissed(c);
      pushLog(`wardend: record ${c.id.slice(0, 8)} ${expired ? "expired" : "closed by someone else"}`);
    }
    removeCard(c.id);
  }
}

/** Whether a YubiKey is needed to allow this card (wardend meta.hardware + our own risk assessment). */
export function hardwareRequirement(card: Card): { need: boolean; why: string; risk: number | undefined } {
  const v = getState().verdicts[card.id];
  const risk = signableRisk(v && v !== "pending" ? v : null);
  const r = needsHardware(card.gate?.exec?.hardware ?? null, risk ?? null);
  return { ...r, risk };
}

/** "Key touch required" error: the UI opens the touch wizard, the agent hands the card over to the human. */
export class HardwareRequired extends Error {
  constructor(public why: string) {
    super(t("err.hwRequired", { why }));
  }
}

/** Sign a decision on a card and send it to wardend. allow-once → allow. */
async function resolveGateCard(card: Card, decision: "allow-once" | "deny", who: Who, verdict: Verdict | null, proposed: string | null, matched: boolean | null, started: number, hardware?: HardwareSigner) {
  if (!card.gate) throw new Error(t("err.notGateCard"));
  // allow only for what the phone recomputed itself: the wardend exec envelope
  const refusal = gateAllowRefusal(card);
  if (refusal && decision !== "deny") throw new Error(t("err.refuseSign", { why: refusal }));
  const hwReq = hardwareRequirement(card);
  if (decision !== "deny" && hwReq.need && !hardware) throw new HardwareRequired(hwReq.why);
  // the signature carries the ticket type and the supervisorId of this wardend
  const target: DecisionTarget = { id: card.id, digest: card.gate.digest, ticket: gateTicketScope(card) };
  const opts = { risk: hwReq.risk, hardware: decision === "deny" ? undefined : hardware };
  const { signed, response } = await decideViaWardend(target, decision === "deny" ? "deny" : "allow", opts);
  const applied = response.ok === true;
  if (!applied && decision !== "deny" && isRetryableHardwareReason(response.reason)) {
    // wardend keeps the exec queued: the card is not removed, the key can be tapped again
    pushLog(`gate ${card.id.slice(0, 8)}: second factor rejected (${response.reason}${response.hardwareRule ? `, rule ${response.hardwareRule}` : ""})`);
    appendEntry({ ts: Date.now(), kind: "error", approval_id: card.id, approval_kind: "gate", summary: `hardware key: ${response.reason}${response.hardwareRule ? ` (${response.hardwareRule})` : ""}`, decided_by: null, decision, latency_ms: null, payload: JSON.stringify({ signed, response }) });
    myDecisions.delete(card.id);
    return { applied: false, status: response.reason ?? "rejected", retry: true };
  }
  pushLog(`gate ${card.id.slice(0, 8)} ${signed.payload.decision} (${who}): ${applied ? `ok (${response.status ?? "?"}${response.late ? ", late" : ""})` : `rejected: ${response.reason ?? "?"}`}`);
  // An automatic signature is marked in the journal: who signed (observe, the service rule, the
  // judge) and, for observe and the service rule, whether the card was dangerous and why: observe
  // signs such cards too, so the journal is where they stand out.
  const safety = who === "me" ? null : cardSafety(card, verdict);
  const auto = who === "me" ? "" : `${t(who === "observe" ? "j.autoObserve" : who === "service" ? "j.autoService" : "j.autoJudge")}: `;
  const danger = safety?.dangerous ? t("j.dangerousSuffix", { reasons: safety.reasons.join("; ") }) : "";
  appendEntry({
    ts: Date.now(),
    kind: who === "me" ? "resolved" : "auto_resolved",
    approval_id: card.id,
    approval_kind: "gate",
    summary: `${auto}${card.summary}${matched !== null ? t("j.matchedSuffix", { yn: t(matched ? "common.yes" : "common.no") }) : ""}${danger}`,
    decided_by: applied ? (who === "me" ? "me" : "agent") : "other",
    decision: applied ? decision : response.reason ?? "rejected",
    latency_ms: Date.now() - card.createdAtMs,
    payload: JSON.stringify({ gate: { digest: card.gate.digest }, signed, response, roundtripMs: Date.now() - started, proposed, matched, verdict, ...(who === "me" ? {} : { auto: who, mode: getState().mode, dangerous: !!safety?.dangerous, reasons: safety?.reasons ?? [] }) }),
  });
  if (applied) {
    setState((s) => ({
      wardend: { ...s.wardend, signed: s.wardend.signed + 1 },
      ...(who === "me" ? {} : { autoStats: { signed: s.autoStats.signed + 1, dangerous: s.autoStats.dangerous + (safety?.dangerous ? 1 : 0) } }),
    }));
  }
  addRecent(seenResolved, card.id);
  removeCard(card.id);
  return { applied, status: applied ? response.status ?? "ok" : response.reason ?? "rejected" };
}

/**
 * Sign a ticket and send it to wardend through the relay. The answer is wardend's own: boxed for this phone and about this card and decision
 * (relaySession.ts sendTicket). No answer throws: the decision is not applied, the card stays.
 */
async function decideViaWardend(target: DecisionTarget, decision: GateDecision, opts: { risk?: number; hardware?: HardwareSigner }): Promise<{ signed: SignedDecision; response: GateDecideResponse }> {
  if (!identity) throw new Error(t("err.noIdentity"));
  const signed = opts.hardware ? await signDecisionWithHardware(identity, target, decision, opts.hardware, opts.risk) : signDecision(identity, target, decision, Date.now(), opts.risk);
  const r = (await sendWardendTicket(signed)) as GateDecideResponse;
  return { signed, response: r.ok && !r.status ? { ...r, status: "ok" } : r };
}

function addCard(card: Card | null, origin: string) {
  if (!card) return;
  if (card.expiresAtMs && card.expiresAtMs < Date.now()) return;
  const cards = getState().cards;
  if (cards.some((c) => c.id === card.id)) return;
  if (seenResolved.has(card.id)) return;
  setState({ cards: [...cards, card] });
  appendEntry({ ts: Date.now(), kind: "requested", approval_id: card.id, approval_kind: card.kind, summary: card.summary, decided_by: null, decision: null, latency_ms: null, payload: JSON.stringify({ origin, raw: card.raw }) });
  pushLog(`card ${card.kind} ${card.id.slice(0, 8)} (${origin}): ${card.summary.slice(0, 80)}`);
  // Blocklist and injection rules in any mode (local and instant); the model only on autopilot.
  judgeCard(card).catch((e) => pushLog(`judge ${card.id.slice(0, 8)}: ${errMsg(e)}`));
}

/** Assess a card added bypassing addCard (bench build mock cards): local rules only. */
export function judgeNow(card: Card) {
  judgeCard(card).catch((e) => pushLog(`judge ${card.id.slice(0, 8)}: ${errMsg(e)}`));
}

/**
 * Judge, then the automatic signer (autosign.ts): the verdict goes to the journal; on autopilot the
 * judge's allow/deny is signed, in observe every card is signed at once, a harness service launch
 * is signed by rule in every mode. What a rule may not sign stays in the feed for the owner.
 */
async function judgeCard(card: Card) {
  if (getState().verdicts[card.id]) return;
  setState((s) => ({ verdicts: { ...s.verdicts, [card.id]: "pending" } }));
  // the test card's text is not sent to the remote judge: it is not from the server and decides nothing;
  // the model is called only on autopilot (observe signs without a judge, manual has no assessment);
  // model requests go one at a time (decide.ts), a card that expires before an answer could come is not sent
  const v = await judge.evaluate(card, { callModel: getState().mode === "delegate" && !card.mock, minTtlMs: MODEL_MIN_TTL_MS });
  if (!getState().cards.some((c) => c.id === card.id)) return; // already decided or expired
  setState((s) => ({ verdicts: { ...s.verdicts, [card.id]: v } }));
  if (v.source !== "manual") {
    // manual source: no matches and no model, nothing to journal
    appendEntry({
      ts: Date.now(),
      kind: "verdict",
      approval_id: card.id,
      approval_kind: card.kind,
      // key and codes (deny, blocklist), not a ready string: rendered in words in the display language (journalText.ts)
      ...journalMsg("j.verdict", { summary: card.summary, decision: v.decision, risk: v.risk ?? "-", source: v.source, reason: v.reason ?? "" }, { verdict: v, mode: getState().mode, threshold: getState().threshold }),
      decided_by: "agent",
      decision: v.decision,
      latency_ms: v.latencyMs,
    });
    pushLog(`verdict ${card.id.slice(0, 8)}: ${v.decision.toUpperCase()} risk ${v.risk ?? "-"} (${v.source}, ${v.latencyMs} ms): ${v.reason}`);
  }
  if (card.mock) return;
  if (seenResolved.has(card.id) || myDecisions.has(card.id)) return; // the human got there first
  const st = getState();
  const plan = autoPlan(card, v, { mode: st.mode, threshold: st.threshold, askService: st.askService, hwNeed: hardwareRequirement(card).need, dangerous: cardSafety(card, v).dangerous });
  if (!plan) return;
  if (plan.kind === "hold") {
    // a rule wanted to sign and may not (rootexec, envelope not recomputed, hardware key, a dangerous service launch): the owner decides
    pushLog(`auto ${card.id.slice(0, 8)}: ${plan.by} may not sign it (${plan.why}): the owner decides`);
    appendEntry({ ts: Date.now(), kind: "info", approval_id: card.id, approval_kind: card.kind, ...journalMsg("j.autoHold", { summary: card.summary, by: t(plan.by === "observe" ? "j.autoObserve" : plan.by === "service" ? "j.autoService" : "j.autoJudge"), why: plan.why }, { auto: plan.by, hold: plan.why }), decided_by: "agent", decision: null, latency_ms: null });
    return;
  }
  await resolveCard(card, plan.decision, plan.by, v);
  if (plan.by !== "judge") return;
  if (plan.decision === "deny") {
    // Re-read the state: otherwise parallel verdicts overwrite the counter.
    const cur = getState();
    if (cur.mode !== "delegate") return; // escalation already happened
    const n = cur.consecutiveDenies + 1;
    setState({ consecutiveDenies: n });
    if (n >= ESCALATION_DENIES) {
      const msg = t("err.escalation", { n });
      await setMode(FALLBACK_MODE, "escalation");
      setState({ escalation: msg, consecutiveDenies: 0 });
      appendEntry({ ts: Date.now(), kind: "escalation", approval_id: card.id, approval_kind: card.kind, summary: msg, decided_by: "agent", decision: null, latency_ms: null, payload: null });
      pushLog(`ESCALATION: ${msg}`);
    }
  } else {
    setState({ consecutiveDenies: 0 });
  }
}

const MODE_WHY: Partial<Record<"stop" | "escalation" | "expired" | "judge", MsgKey>> = { stop: "j.modeStop", escalation: "j.modeEscalation", expired: "j.modeExpired", judge: "j.modeJudge" };

/**
 * The app mode. Observe and autopilot (delegate) are turned on only by the owner: biometrics or
 * passcode, for an hour (AUTO_MODE_TTL_MS), enabling again extends; both drop back to manual when
 * the hour is out. Observe takes the same timer as autopilot because it signs more than autopilot
 * does: it may not outlive it. Leaving a mode needs no confirmation.
 */
export async function setMode(mode: AppMode, why: "user" | "stop" | "escalation" | "expired" | "judge" = "user") {
  if (mode !== "manual") {
    if (why !== "user") return; // an automatic mode never turns itself on, for any reason
    await requireOwner(mode === "delegate" ? "owner.delegate" : "owner.observe", { threshold: getState().threshold });
  }
  const prev = getState().mode;
  // The counter of consecutive denies and the counters of automatic signatures live within one mode session.
  setState({
    mode,
    autoUntil: mode !== "manual" ? Date.now() + AUTO_MODE_TTL_MS : null,
    ...(prev !== mode ? { consecutiveDenies: 0, autoStats: { signed: 0, dangerous: 0 } } : {}),
    ...(why !== "escalation" ? { escalation: null } : {}),
  });
  if (prev !== mode) {
    const suffix = why !== "user" && MODE_WHY[why] ? t(MODE_WHY[why] as MsgKey) : "";
    appendEntry({ ts: Date.now(), kind: "info", approval_id: null, approval_kind: null, summary: `${t("j.modeChanged", { prev, mode })}${suffix}`, decided_by: null, decision: null, latency_ms: null, payload: null });
    pushLog(`mode ${prev} → ${mode} (${why})`);
  }
  // Switching to observe or autopilot: the cards already pending are assessed and signed by the new rules
  // (a manual-mode card has no assessment; an observe-mode one has no model verdict).
  if (mode !== "manual" && prev !== mode) {
    for (const c of getState().cards) {
      if (myDecisions.has(c.id)) continue;
      setState((s) => {
        const verdicts = { ...s.verdicts };
        delete verdicts[c.id];
        return { verdicts };
      });
      judgeCard(c).catch(() => {});
    }
  }
}

/**
 * "Ask me about harness service launches too": on, service launches come as cards like any other;
 * off (the default), the phone signs them by rule and only the journal shows them. Turning it off
 * weakens protection, so the owner confirms.
 */
export async function setAskService(on: boolean) {
  if (getState().askService && !on) await requireOwner("owner.askService");
  setState({ askService: on });
  await saveAskService(on);
  appendEntry({ ts: Date.now(), kind: "info", approval_id: null, approval_kind: null, summary: t(on ? "j.askServiceOn" : "j.askServiceOff"), decided_by: "me", decision: null, latency_ms: null, payload: null });
}

/** Confirmation before signing: "Dangerous and roots" (default) or "Every approval". */
export async function setBiometricMode(mode: BiometricMode) {
  if (biometricModeWeakens(getState().biometricMode, mode)) await requireOwner("owner.bioRisky");
  setState({ biometricMode: mode });
  await saveBiometricMode(mode);
  refreshOwnerAuth();
}

/** How the phone can confirm the owner: biometrics, device passcode, or nothing. */
export function refreshOwnerAuth() {
  ownerAuthLevel()
    .then((ownerAuth) => setState({ ownerAuth }))
    .catch(() => setState({ ownerAuth: "unavailable" }));
}

/** Snackbar after a decision (FeedScreen shows it for 4 s). */
let snackSeq = 0;
export function showSnack(text: string, tone: "allow" | "deny" | "info") {
  setState({ snack: { id: ++snackSeq, text, tone } });
}

/** Autopilot threshold: raising it (more gets allowed automatically) only with owner confirmation. */
export async function setThreshold(value: number) {
  const v = Math.max(0, Math.min(100, Math.round(value)));
  if (thresholdWeakens(getState().threshold, v)) await requireOwner("owner.threshold", { n: v });
  setState({ threshold: v });
  await saveThreshold(v);
}

/**
 * Save the judge. Different address, different model or a new key: owner confirmation, and
 * autopilot turns off (the trust was in the previous judge). Only the timeout changes without asking.
 */
export async function saveJudgeSettings(next: ModelPrefs, newKey: string): Promise<void> {
  const prev = await loadModelPrefs();
  const changed = judgeChanged(prev, next) || !!newKey.trim();
  if (changed) await requireOwner("owner.judge");
  await saveModelPrefs(next);
  if (newKey.trim()) await saveModelKey(newKey.trim());
  if (changed) await autopilotOffForJudge();
  await refreshModelReady();
}

/** Delete the judge key: this does not weaken protection, but the judge is now different, so autopilot turns off. */
export async function deleteJudgeKey(): Promise<void> {
  await saveModelKey("");
  await autopilotOffForJudge();
  await refreshModelReady();
}

async function autopilotOffForJudge() {
  // observe does not use the judge: only autopilot trusted it
  if (getState().mode === "delegate") await setMode(FALLBACK_MODE, "judge");
}

/** Local rule "trash-put on these paths is forbidden": a path can be removed only with confirmation. */
export async function setNoTrashPathsSetting(paths: string[]): Promise<void> {
  if (pathListWeakens(getState().noTrashPaths, paths)) await requireOwner("owner.noTrash");
  await saveNoTrashPaths(paths);
  setNoTrashPaths(paths);
  setState({ noTrashPaths: paths });
}

export function dismissEscalation() {
  setState({ escalation: null });
}

/**
 * "Clear journal" (Journal tab): the record on this phone is erased, so only the owner does it, and
 * without a working biometric module it is not done (fail-closed). The server's journal is not
 * touched; the wipe itself becomes the first entry of the new chain (journal.ts).
 */
export async function clearJournalAsOwner(): Promise<number> {
  await requireOwner("owner.clearJournal");
  const r = clearJournal();
  pushLog(`journal cleared by the owner: ${r.removed} entries removed, previous head ${r.previousHead.slice(0, 16)}…`);
  return r.removed;
}

export async function refreshModelReady() {
  const [prefs, key] = await Promise.all([loadModelPrefs(), hasModelKey()]);
  setState({ modelReady: !!prefs.url && !!prefs.model && key });
}

function removeCard(id: string) {
  setState((s) => {
    const verdicts = { ...s.verdicts };
    delete verdicts[id];
    return { cards: s.cards.filter((c) => c.id !== id), verdicts };
  });
}


// ---------------------------------------------------------------------------
// YubiKey: linking ("Mode" screen) and "Allow" with a touch (feed)
// ---------------------------------------------------------------------------

/** Linking wizard: present the key → record in SecureStore; blob for `wardend hw-register`. */
export async function bindHardwareKey(name: string, pin?: string | null): Promise<HardwareKey> {
  if (!identity) throw new Error(t("err.noIdentity"));
  if (!hwKey) throw new Error("hardware keys are not in this build");
  const key = await hwKey.registerYubikey(identity, name, pin);
  await hwKey.saveHardwareKey(key);
  setState({ hardwareKey: key });
  appendEntry({ ts: Date.now(), kind: "info", approval_id: null, approval_kind: null, ...journalMsg("j.hwBound", { name: key.name, id: key.credentialId.slice(0, 12) }, { credentialId: key.credentialId, alg: key.alg, rpId: key.rpId, requireUv: key.requireUv }), decided_by: "me", decision: null, latency_ms: null });
  pushLog(`hardware key bound: ${key.name}, credential ${key.credentialId.slice(0, 12)}…`);
  return key;
}

export async function unbindHardwareKey(): Promise<void> {
  await requireOwner("owner.hwUnbind");
  const k = getState().hardwareKey;
  await hwKey?.deleteHardwareKey();
  setState({ hardwareKey: null });
  appendEntry({ ts: Date.now(), kind: "info", approval_id: null, approval_kind: null, ...journalMsg("j.hwUnbound", { name: k ? `: ${k.name}` : "" }), decided_by: "me", decision: null, latency_ms: null });
}

/** "Allow" with a key touch. PIN if the key was linked with PIN (require_uv) or the key itself requires it. */
export async function approveWithHardware(card: Card, pin?: string | null) {
  const meta = card.gate?.exec?.hardware ?? null;
  const pick = pickCredential(meta, getState().hardwareKey);
  if (!pick.ok) throw new Error(pick.reason);
  if (!hwKey) throw new Error("hardware keys are not in this build");
  return resolveCard(card, "allow-once", "me", undefined, hwKey.yubikeySigner(pick.key, pin));
}

/** A decision on a card: the owner on this phone, or an automatic signer (judgeCard). allow-always is intentionally absent. */
export async function resolveCard(card: Card, decision: "allow-once" | "deny", who: Who = "me", verdictOverride?: Verdict, hardware?: HardwareSigner): Promise<{ applied: boolean; status: string; retry?: boolean }> {
  // Allow signed by the human: for dangerous cards and roots (any exec card) always biometrics
  // or device passcode, for the rest per the setting. For dangerous cards and roots without a working
  // biometric module nothing is signed (fail-closed). Deny does not ask.
  if (who === "me" && decision === "allow-once") {
    const s = cardSafety(card, getState().verdicts[card.id]);
    if (needsOwnerCheck(s, getState().biometricMode)) {
      const r = await confirmOwner(t(s.dangerous ? "bio.promptDanger" : "bio.prompt"), t("common.cancel"), s.dangerous || s.root);
      if (r !== "confirmed") throw new OwnerNotConfirmed(t(r === "unavailable" ? "feed.snack.ownerUnavailable" : "feed.snack.notConfirmed"));
    }
  }
  // Bench build test card (wardenclaw://bench?mockcard=…): not sent anywhere,
  // only removed from the feed; the decision is recorded next to the local judge's opinion (Experimental).
  if (card.mock) {
    let status = "mock (not sent)";
    // Mock requiring a YubiKey (mockhw=1): the key signs a random challenge, a touch check
    // over NFC/USB without wardend. The signature goes nowhere, only its beginning is logged.
    if (hardware && decision === "allow-once") {
      const json = clientDataJSON("webauthn.get", getRandomBytes(32));
      const a = await hardware({ clientDataJSON: json, clientDataHash: b64url.encode(clientDataHash(json)) });
      pushLog(`mock ${card.id}: hardware key signed, credential ${a.credentialId.slice(0, 12)}…, signature ${a.signature.slice(0, 12)}…`);
      status = "mock signed by the hardware key (not sent)";
    }
    phoneJudge?.noteHumanDecision(card, decision, false);
    removeCard(card.id);
    return { applied: false, status };
  }
  const started = Date.now();
  myDecisions.set(card.id, { decision, at: started, who });
  trimOldest(myDecisions);
  const vRaw = verdictOverride ?? getState().verdicts[card.id];
  const verdict = vRaw && vRaw !== "pending" ? vRaw : null;
  const proposed = verdict ? (verdict.decision === "allow" ? "allow-once" : verdict.decision === "deny" ? "deny" : "ask") : null;
  const matched = proposed === null || proposed === "ask" ? null : proposed === decision; // ask = the judge proposed no decision
  try {
    const r = await resolveGateCard(card, decision, who, verdict, proposed, matched, started, hardware);
    if (who === "me") phoneJudge?.noteHumanDecision(card, decision, r.applied);
    return r;
  } catch (e) {
    myDecisions.delete(card.id);
    if (e instanceof HardwareRequired) throw e;
    const msg = errMsg(e);
    pushLog(`gate ${card.id.slice(0, 8)} error: ${msg}`);
    appendEntry({ ts: Date.now(), kind: "error", approval_id: card.id, approval_kind: "gate", ...journalMsg("j.signSendError", { msg }), decided_by: null, decision, latency_ms: null });
    throw e;
  }
}

/** Once per second: observe and autopilot expiry; remove expired cards (timeout) if wardend did not close them. */
function tick() {
  const now = Date.now();
  const st = getState();
  if (st.mode !== "manual" && st.autoUntil !== null && now >= st.autoUntil) {
    setMode(FALLBACK_MODE, "expired").catch((e) => pushLog(`${st.mode} expiry: ${errMsg(e)}`));
  }
  // unshown records expire on the server by themselves; with no server connection we remove them by deadline
  if (st.unshown.some((u) => u.expiresAtMs !== null && u.expiresAtMs + EXPIRY_GRACE_MS < now)) setState((s) => ({ unshown: s.unshown.filter((u) => u.expiresAtMs === null || u.expiresAtMs + EXPIRY_GRACE_MS >= now) }));
  const expired = st.cards.filter((c) => c.expiresAtMs && c.expiresAtMs + EXPIRY_GRACE_MS < now);
  if (!expired.length) return;
  for (const c of expired) {
    if (!seenResolved.has(c.id) && !myDecisions.has(c.id)) {
      addRecent(seenResolved, c.id);
      appendEntry({ ts: now, kind: "expired", approval_id: c.id, approval_kind: c.kind, summary: c.summary, decided_by: "timeout", decision: "timeout", latency_ms: c.expiresAtMs ? c.expiresAtMs - c.createdAtMs : null, payload: null });
      noteMissed(c, now);
      pushLog(`card ${c.id.slice(0, 8)} expired`);
    }
    removeCard(c.id);
  }
}

bindWardendSession({
  device: () => {
    const id = identity;
    return id ? { deviceId: id.deviceId, publicKey: publicKeyB64Url(id), sign: (payload) => signPayload(id, payload) } : null;
  },
  identityError: () => getState().identityError,
  encPrivate: async () => encPrivate(await loadOrCreateEncKey()),
  requireOwner,
  // React Native's WebSocket has the members the session uses; its event types are wider
  socket: (url) => new WebSocket(url) as unknown as RelaySocket,
  random: getRandomBytes,
  version: CLIENT_VERSION,
  saveLink: saveWardendLink,
  clearLink: clearWardendLink,
  loadRelayState: loadRelayStateFor,
  relayStateWriter,
  state: () => getState().wardend,
  setState: (patch, serverHw) => setState((s) => ({ wardend: { ...s.wardend, ...patch }, ...(serverHw !== undefined ? { serverHw } : {}) })),
  note: (kind, body, by) => appendEntry({ ts: Date.now(), kind, approval_id: null, approval_kind: null, ...body, decided_by: by ?? null, decision: null, latency_ms: null }),
  log: pushLog,
  removeCards: removeWardendCards,
  syncCards: syncGateCards,
});
