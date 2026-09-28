// SPDX-License-Identifier: GPL-3.0-or-later
// The link to wardend. The phone never talks to wardend directly: both keep an outgoing WebSocket
// to the relay (protocol/README.md), which forwards boxes it cannot open. Here: pairing from the
// QR, the card feed, tickets, push tokens and the connection state the user sees. The card list
// and the owner check stay in controller.ts.
// Pure module (no Expo/RN): the platform is injected (bindWardendSession), the tests drive it
// against an in-memory relay.
import type { GatePending } from "./gate";
import type { ServerHardware } from "./hardware";
import { parseServerHardware } from "./hardware";
import { journalMsg } from "./journalText";
import { errMsg } from "./errMsg";
import { MsgKey, MsgParams, t, tOr } from "./i18n";
import { ProtocolMismatchError, checkServerProtocol } from "./protocolVersion";
import { applyServerRun } from "./serverMode";
import { RelayCard, parsePairLink } from "./relayProto";
import { PairStatus, RelayError, RelaySession, RelaySocketFactory, RelayState, RelayStatus, RelayTicket, RelayTiming, TicketResult } from "./relaySession";
import type { RelayStateRec } from "./relayState";

/** wardend from the QR code: the relay it is reached through, its identity key (cards are verified with it) and its encryption key. */
export type WardendLinkRec = {
  relay: string;
  key: string;
  enc: string;
  supervisorId: string;
  host: string;
  pairId: string | null;
  /** The id of the pair frame whose approval is awaited: only a pair.status naming it counts. */
  pairFrame: string | null;
  paired: boolean;
  pairedAt: string | null;
};

/**
 * The link as the user sees it. "connecting" for a paired server: the relay has not said yet
 * whether wardend is connected, or wardend has not answered yet. "unavailable" with lastReason
 * says why a paired server takes no decisions: relay_unreachable (no network or no relay),
 * supervisor_offline (the relay says wardend is not connected to it), untrusted_device (revoked
 * on the server), protocol_mismatch.
 */
export type WardendState = {
  status: "unpaired" | "connecting" | "awaiting-approval" | "connected" | "unavailable" | "rejected";
  relay: string | null;
  host: string | null;
  supervisorId: string | null;
  pairId: string | null;
  mode: string | null; // supervisor mode: observe | deny-list | ticket
  policyMode: string | null; // tripwire | root; which execs need a signature when mode is ticket
  lastError: string | null;
  lastReason: string | null;
  lastOkAt: number | null;
  signed: number;
};

export type PushToken = { platform: "apns" | "fcm"; token: string };

/** readyMs: how long pairing waits for the relay. */
export type WardendTiming = { readyMs: number; relay?: Partial<RelayTiming> };
const TIMING: WardendTiming = { readyMs: 15_000 };

export type WardendPlatform = {
  /** The device identity, or null when the key could not be stored (identityError says why). */
  device: () => { deviceId: string; publicKey: string; sign(payload: string): string } | null;
  identityError: () => string | null;
  /** The device's X25519 private key (identity.ts loadOrCreateEncKey). */
  encPrivate: () => Promise<Uint8Array>;
  requireOwner: (prompt: MsgKey, params?: MsgParams) => Promise<void>;
  socket: RelaySocketFactory;
  random: (n: number) => Uint8Array;
  /** App version for the relay hello. */
  version: string;
  saveLink: (rec: WardendLinkRec) => Promise<void>;
  clearLink: () => Promise<void>;
  loadRelayState: (supervisorId: string) => Promise<RelayStateRec>;
  relayStateWriter: (supervisorId: string, initial: RelayStateRec, onError: (e: unknown) => void) => { onSeq(seq: number, id: string): void };
  state: () => WardendState;
  /** serverHw undefined: keep what is known. */
  setState: (patch: Partial<WardendState>, serverHw?: ServerHardware | null) => void;
  note: (kind: "pairing" | "connect" | "info", body: { summary: string; payload: string | null }, by?: "me") => void;
  log: (line: string) => void;
  removeCards: () => void;
  syncCards: (pending: GatePending[]) => void;
  timing?: Partial<WardendTiming>;
};

let platform: WardendPlatform | null = null;
let timing: WardendTiming = TIMING;
let link: WardendLinkRec | null = null;
let session: RelaySession | null = null;
/** Sessions opened so far: a hook of an older session changes nothing. */
let gen = 0;
/** Pending cards of the server as last heard: a status replaces the list, card and card.done edit it. */
const cards = new Map<string, GatePending>();
/** What the relay said about wardend on the current connection: null until its first `peer` frame. */
let peerOnline: boolean | null = null;
let readyWait: { resolve(): void; reject(e: Error): void } | null = null;
/** A pair.status that arrived before the link of this pairing was stored. */
let early: PairStatus | null = null;
let pairing = false;
let pushToken: (() => Promise<PushToken | null>) | null = null;

/** Called once from controller after its card helpers exist. */
export function bindWardendSession(p: WardendPlatform) {
  closeSession();
  platform = p;
  timing = { ...TIMING, ...p.timing };
  link = null;
  cards.clear();
}

function use(): WardendPlatform {
  if (!platform) throw new Error("wardend session is not bound");
  return platform;
}

export function activeWardendLink(): WardendLinkRec | null {
  return link;
}

/** Bootstrap restores a saved link before the session starts. */
export function adoptWardendLink(l: WardendLinkRec | null) {
  link = l;
}

/** phonePush.ts tells where the registered token is, so that "Forget server" can take it off the relay. */
export function setPushTokenSource(fn: (() => Promise<PushToken | null>) | null) {
  pushToken = fn;
}

export function wardendStateFromLink(l: WardendLinkRec | null) {
  if (!l) return { status: "unpaired" as const, relay: null, host: null, supervisorId: null, pairId: null, lastError: null, lastReason: null };
  return { status: l.paired ? ("connecting" as const) : ("awaiting-approval" as const), relay: l.relay, host: l.host, supervisorId: l.supervisorId, pairId: l.pairId, lastError: null, lastReason: null };
}

/** Host of the relay for the screen: wss://relay.example/x → relay.example. */
export function relayHost(relay: string | null | undefined): string {
  return /^wss:\/\/([^/]+)/.exec(relay ?? "")?.[1] ?? "";
}

/** A card of the relay (the queue item of wardend with supervisorSig, already verified) → the gate's pending record shape. */
export function cardToPending(it: Record<string, unknown>): GatePending {
  const env = (it.envelope && typeof it.envelope === "object" ? it.envelope : {}) as Record<string, unknown>;
  const argv = Array.isArray(env.argv) ? env.argv.map(String) : [];
  const command = argv.join(" ");
  return {
    id: String(it.id ?? ""),
    kind: "exec",
    digest: String(it.digest ?? ""),
    envelope: env,
    meta: (it.meta && typeof it.meta === "object" ? it.meta : {}) as Record<string, unknown>,
    toolName: "wardend.exec",
    toolKind: "exec",
    toolInputKind: null,
    paramsPreview: command.length > 4000 ? `${command.slice(0, 4000)}…` : command,
    command,
    filePath: null,
    agentId: null,
    sessionKey: null,
    runId: null,
    toolCallId: null,
    source: "wardend",
    mode: "enforce",
    createdAt: Number(it.createdAt) || 0,
    expiresAt: Number(it.expiresAt) || 0,
    status: "pending",
    decision: null,
    deviceId: null,
  };
}

/** Connection lost before or instead of an answer: the relay, not a refusal of wardend. */
const NO_ANSWER = new Set(["not_connected", "disconnected", "stopped", "timeout", "relay_unreachable"]);

/** A refusal of wardend or of the relay in words, or the code itself when it is not known. */
function reasonText(code: string | undefined): string {
  return tOr(`wdr.${code ?? ""}`, "") || code || "refused";
}

function errText(e: unknown): string {
  if (e instanceof RelayError) return NO_ANSWER.has(e.code) ? t("err.relayUnreachable") : reasonText(e.code);
  return errMsg(e);
}

function closeSession() {
  gen++;
  peerOnline = null;
  readyWait?.reject(new RelayError("stopped"));
  readyWait = null;
  session?.stop();
  session = null;
}

/** One session per link: the device keys, the stored seq and the handled ids of this supervisor. */
async function openSession(l: WardendLinkRec, trusted: boolean): Promise<RelaySession> {
  const p = use();
  const device = p.device();
  if (!device) throw new Error(p.identityError() ?? t("err.noIdentity"));
  closeSession();
  const my = gen;
  const [encPrivate, saved] = await Promise.all([p.encPrivate(), p.loadRelayState(l.supervisorId)]);
  if (my !== gen) throw new RelayError("stopped");
  const writer = p.relayStateWriter(l.supervisorId, saved, (e) => p.log(`relay state: ${errMsg(e)}`));
  const mine =
    <A extends unknown[]>(fn: (...a: A) => void) =>
    (...a: A) => {
      if (my === gen) fn(...a);
    };
  const s = new RelaySession({
    link: { relay: l.relay, supervisorId: l.supervisorId, key: l.key, enc: l.enc },
    device: { ...device, encPrivate },
    version: p.version,
    seq: saved.seq,
    seen: saved.seen,
    trusted,
    pairFrame: l.pairFrame,
    socket: p.socket,
    random: p.random,
    timing: timing.relay,
    hooks: {
      onState: mine(onRelayState),
      onSeq: (seq, id) => writer.onSeq(seq, id),
      onCard: mine(onCard),
      onCardDone: mine((d: { id: string }) => {
        heard();
        cards.delete(d.id);
        syncCards();
      }),
      onStatus: mine(onStatus),
      onPairStatus: mine(onPairStatus),
      onPeer: mine(onPeer),
      onNotTrusted: mine(onNotTrusted),
      onRefused: mine((reason: string, id?: string) => p.log(`relay: frame ${id?.slice(0, 8) ?? "?"} refused: ${reason}`)),
      onIgnored: mine((kind: string, id: string) => p.log(`relay: frame ${id.slice(0, 8)} of unknown kind ${kind} ignored: update the app`)),
    },
  });
  session = s;
  p.log(`wardend: relay ${relayHost(l.relay)}, channel ${l.supervisorId.slice(0, 12)}…`);
  s.start();
  return s;
}

function onRelayState(st: RelayState, detail?: string) {
  const p = use();
  if (st === "ready") {
    readyWait?.resolve();
    readyWait = null;
    if (!link) return;
    if (!link.paired) {
      p.setState({ lastError: null, lastReason: null });
      // approved while this phone was away and the pair.status is no longer queued: a status answers only a trusted device
      session?.requestStatus().catch(() => {});
      return;
    }
    // the relay says next whether wardend is connected, and the session asks for its status
    p.setState({ status: "connecting", lastError: null, lastReason: null });
    return;
  }
  if (st !== "waiting") return;
  peerOnline = null;
  if (!link) return; // a pairing attempt reports its own failure
  const mismatch = detail === "welcome_invalid";
  const msg = mismatch ? t("err.relayProtocol") : t("err.relayUnreachable");
  if (p.state().lastError !== msg) p.log(`wardend: relay unavailable (${detail ?? "closed"})`);
  p.setState({ ...(link.paired ? { status: "unavailable" as const } : {}), lastError: msg, lastReason: mismatch ? "protocol_mismatch" : "relay_unreachable" });
}

/** The relay's word on wardend's connection: "server offline" is known at once, without waiting for an answer that does not come. */
function onPeer(online: boolean) {
  peerOnline = online;
  if (!link?.paired) return;
  const p = use();
  if (!online) {
    if (p.state().lastReason !== "supervisor_offline") p.log("wardend: the relay answers, the server is not connected to it");
    p.setState({ status: "unavailable", lastError: t("err.supervisorOffline"), lastReason: "supervisor_offline" });
  } else if (p.state().lastReason === "supervisor_offline") {
    // back on the relay: the session asks for its status, the answer makes it "connected"
    p.setState({ status: "connecting", lastError: null, lastReason: null });
  }
}

/** The relay no longer forwards for this device: wardend pair revoke. */
function onNotTrusted() {
  if (!link?.paired) return;
  use().setState({ status: "unavailable", lastError: t("wdr.untrusted_device"), lastReason: "untrusted_device" });
}

/** Something that only this wardend could have boxed arrived: it is connected, unless the relay says the frame waited in the queue of a wardend that is away. */
function heard() {
  if (!link?.paired || peerOnline === false) return;
  const p = use();
  if (p.state().status !== "connected") p.log(`wardend: online (${link.host || relayHost(link.relay)})`);
  p.setState({ status: "connected", lastError: null, lastReason: null, lastOkAt: Date.now() });
}

function syncCards() {
  use().syncCards([...cards.values()]);
}

function onCard(c: RelayCard) {
  heard();
  cards.set(c.id, cardToPending(c));
  syncCards();
}

function onStatus(st: RelayStatus) {
  const p = use();
  if (!link) return;
  // a status answers only a trusted device: the approval itself was missed
  if (!link.paired) markPaired();
  const pc = checkServerProtocol(st);
  if (!pc.ok) {
    // different protocol version: this server's cards are not signed until the server or the app is updated
    cards.clear();
    p.removeCards();
    p.setState({ status: "unavailable", lastError: new ProtocolMismatchError(pc.code, "wardend", pc.protocol).message, lastReason: "protocol_mismatch" });
    return;
  }
  heard();
  const host = typeof st.host === "string" && st.host ? st.host.slice(0, 64) : null;
  p.setState({ ...applyServerRun(st), ...(host ? { host } : {}) }, parseServerHardware(st));
  cards.clear();
  for (const c of st.pending) cards.set(c.id, cardToPending(c));
  syncCards();
}

function onPairStatus(st: PairStatus) {
  if (pairing && !link) {
    early = st;
    return;
  }
  if (!link || link.paired) return;
  if (st.status === "approved") markPaired();
  else if (st.status === "rejected" || st.status === "refused") void pairingEnded(st.status === "rejected");
}

function markPaired() {
  const p = use();
  if (!link || link.paired) return;
  const rec: WardendLinkRec = { ...link, pairFrame: null, paired: true, pairedAt: new Date().toISOString() };
  link = rec;
  p.saveLink(rec).catch((e) => p.log(`wardend: link not saved: ${errMsg(e)}`));
  p.note("connect", journalMsg("j.pairApproved", { host: rec.host || relayHost(rec.relay) }, { relay: rec.relay, supervisorId: rec.supervisorId }));
  p.log(`wardend: pairing confirmed (${rec.host || rec.supervisorId.slice(0, 12)})`);
  p.setState({ ...wardendStateFromLink(rec), pairId: null });
  if (peerOnline === false) onPeer(false);
}

/** The request was rejected on the server, or it no longer knows it. */
async function pairingEnded(rejected: boolean) {
  const p = use();
  const old = link;
  if (!old) return;
  const why = rejected ? t("err.pairRejected") : t("err.pairExpired");
  // the session acks this answer after the hook returns: closed before that, the relay would deliver it again to the next pairing
  const s = session;
  void Promise.resolve().then(() => {
    if (session === s) closeSession();
  });
  link = null;
  p.setState({ ...wardendStateFromLink(null), status: rejected ? "rejected" : "unpaired", lastError: why });
  p.note("pairing", { summary: `wardend: ${why}`, payload: null });
  await p.clearLink().catch(() => {});
}

function whenReady(s: RelaySession): Promise<void> {
  if (s.state === "ready") return Promise.resolve();
  return new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      readyWait = null;
      reject(new RelayError("relay_unreachable"));
    }, timing.readyMs);
    readyWait = {
      resolve: () => {
        clearTimeout(timer);
        resolve();
      },
      reject: (e) => {
        clearTimeout(timer);
        reject(e);
      },
    };
  });
}

/**
 * Pairing via the link from the QR: connect to the relay named in it, send our keys signed
 * together with the code in a box only this wardend opens, and wait for `wardend pair approve`
 * on the server. Its answers are boxed with the key from the QR: the relay can neither read the
 * code nor pose as the server.
 */
export async function pairWithWardend(linkText: string, deviceName: string): Promise<void> {
  const p = use();
  if (!p.device()) throw new Error(p.identityError() ?? t("err.noIdentity"));
  const l = parsePairLink(linkText);
  await p.requireOwner("owner.pair", { host: l.host || relayHost(l.relay) });
  const prev = link;
  const fresh: WardendLinkRec = { relay: l.relay, key: l.key, enc: l.enc, supervisorId: l.supervisorId, host: l.host, pairId: null, pairFrame: null, paired: false, pairedAt: null };
  pairing = true;
  early = null;
  link = null;
  cards.clear();
  p.removeCards();
  p.setState({ status: "connecting", lastError: null, lastReason: null });
  try {
    const s = await openSession(fresh, false);
    await whenReady(s);
    const st = await s.pair(l.code, deviceName.trim() || "WardenClaw");
    if (st.status === "refused" || st.status === "rejected") throw new Error(reasonText(st.reason));
    const rec: WardendLinkRec = { ...fresh, host: st.host || l.host, pairId: st.id ?? null, pairFrame: st.re };
    await p.saveLink(rec);
    link = rec;
    p.setState({ ...wardendStateFromLink(rec), signed: 0, mode: null, policyMode: null }, null);
    p.note("pairing", journalMsg("j.pairRequested", { id: st.id ?? "", host: rec.host || relayHost(rec.relay), fp: st.fingerprint ?? "" }, { relay: rec.relay, supervisorId: rec.supervisorId, pairId: st.id ?? null, status: st.status }));
    p.log(`wardend: pairing request ${st.id ?? "?"} (${st.status}), fingerprint ${st.fingerprint ?? "?"}`);
    const next: PairStatus | null = st.status === "approved" ? st : early;
    pairing = false;
    if (next) onPairStatus(next);
  } catch (e) {
    const msg = errText(e);
    closeSession();
    link = prev;
    p.setState({ ...wardendStateFromLink(prev), lastError: msg });
    if (prev) startWardend();
    throw new Error(msg);
  } finally {
    pairing = false;
    early = null;
  }
}

/** Open the session of the stored link: paired, or still waiting for `wardend pair approve`. */
export function startWardend() {
  const l = link;
  if (!l || !use().device()) return;
  openSession(l, l.paired).catch((e) => {
    if (!(e instanceof RelayError && e.code === "stopped")) use().log(`wardend: session not started: ${errMsg(e)}`);
  });
}

/**
 * Send a signed ticket and return wardend's answer for that card ({ok, id, decision} or {ok:false,
 * reason}). No answer (relay or wardend away) throws: the decision is not applied, the card stays.
 */
export async function sendWardendTicket(ticket: RelayTicket): Promise<TicketResult> {
  const s = session;
  if (!s || !link?.paired) throw new Error(t("err.noWardend"));
  const my = gen;
  try {
    const r = await s.sendTicket(ticket);
    if (my === gen) heard();
    return r;
  } catch (e) {
    throw new Error(e instanceof RelayError && e.code === "timeout" && s.state === "ready" ? t("err.supervisorOffline") : errText(e));
  }
}

/** This phone's push token goes to the relay: it pushes when a card arrives and the phone has no live connection. */
export async function wardendPushRegister(p: PushToken & { environment: "sandbox" | "production"; topic: string }): Promise<{ supervisorId: string; configured: boolean }> {
  const s = session;
  const l = link;
  if (!s || !l?.paired) throw new Error(t("err.noWardend"));
  try {
    const r = await s.registerPush(p);
    return { supervisorId: l.supervisorId, configured: r.configured };
  } catch (e) {
    throw new Error(errText(e));
  }
}

/** Remove the token from the relay (notifications turned off or the server is being forgotten). Errors do not matter: the relay drops a token that stops working. */
export async function wardendPushUnregister(p: PushToken): Promise<void> {
  if (!session) return;
  await session.unregisterPush(p).catch((e) => use().log(`push: unregister failed: ${errText(e)}`));
}

/**
 * "Forget server": stop talking to wardend (on the server: wardend pair revoke). The resume state
 * of that supervisor (seq, handled ids) stays: the relay keeps counting for this device, and a
 * later pairing with the same server must not get the old frames again.
 */
export async function forgetWardend() {
  const p = use();
  await p.requireOwner("owner.forget");
  const old = link;
  // while the session still exists; the relay answers at once or not at all
  const token = session?.state === "ready" && pushToken ? await pushToken().catch(() => null) : null;
  if (token) await wardendPushUnregister(token);
  closeSession();
  link = null;
  cards.clear();
  await p.clearLink();
  p.removeCards();
  p.setState({ ...wardendStateFromLink(null), mode: null, policyMode: null, lastOkAt: null }, null);
  p.note("info", journalMsg("j.serverForgotten", { host: old?.host || relayHost(old?.relay), id: p.device()?.deviceId.slice(0, 12) ?? "" }), "me");
}

/**
 * Ask wardend for its status again: how many require_hardware rules and which keys the server
 * knows. The "Mode" screen uses it to state what the linked YubiKey actually protects.
 */
export async function refreshServerStatus(): Promise<void> {
  const s = session;
  if (!s || s.state !== "ready" || !link?.paired) return;
  const my = gen;
  await s.requestStatus().catch((e) => {
    if (my === gen && e instanceof RelayError && e.code === "not_trusted") onNotTrusted();
  });
}
