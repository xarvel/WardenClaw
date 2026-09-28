// SPDX-License-Identifier: GPL-3.0-or-later
// Direct connection to wardend: pairing from the QR, the long-poll, and signed push registration.
// The card list and the owner check stay in controller.ts; this file only talks to the server.
import { GatePending } from "./gate";
import { appendEntry } from "./journal";
import { journalMsg } from "./journalText";
import { isNetworkError } from "./netError";
import { errMsg } from "./errMsg";
import { getState, pushLog, setState } from "./store";
import { DeviceIdentity } from "./identity";
import { WardendLinkRec, clearWardendLink, saveWardendLink } from "./settings";
import { WardendClient, WardendHttpError } from "./wardendClient";
import { ProtocolMismatchError } from "./protocolVersion";
import { applyServerRun } from "./serverMode";
import { parseServerHardware } from "./hardware";
import { MsgKey, MsgParams, t } from "./i18n";
import { wardendHttpReason, parsePairLink, supervisorIdFromKey, wardendItemToPending } from "./wardendProto";

/** Long-poll wait; the server returns at most this many milliseconds after the request. Same cap as the gate loop. */
const LONG_POLL_WAIT_MS = 25000;
/** Maximum backoff between reconnect attempts and after errors. */
const MAX_BACKOFF_MS = 30000;
/** Initial backoff for the wardend loop (shorter: direct TCP, faster to detect recovery). */
const WARDEND_BACKOFF_INIT_MS = 2000;
/** Initial poll delay while waiting for pair approval. */
const PAIR_POLL_INIT_MS = 3000;

export type WardendHooks = {
  identity: () => DeviceIdentity | null;
  requireOwner: (prompt: MsgKey, params?: MsgParams) => Promise<void>;
  removeCards: (via: "wardend") => void;
  syncCards: (pending: GatePending[]) => void;
};

let hooks: WardendHooks | null = null;

/** Called once from controller after its card helpers exist. */
export function bindWardendSession(h: WardendHooks) {
  hooks = h;
}

function useHooks(): WardendHooks {
  if (!hooks) throw new Error("wardend session is not bound");
  return hooks;
}

let wardendLink: WardendLinkRec | null = null;
let wardendClient: WardendClient | null = null;
let wardendAbort: AbortController | null = null;
let wardendSeq = 0;
let pairAbort: AbortController | null = null;

// Dev: on Fast Refresh the module re-executes, while the old long-poll stays alive.
type Globals = { __wcWardendAbort?: AbortController | null };
const g = globalThis as unknown as Globals;
if (g.__wcWardendAbort) {
  g.__wcWardendAbort.abort();
  g.__wcWardendAbort = null;
}

export function activeWardendLink(): WardendLinkRec | null {
  return wardendLink;
}

export function activeWardendClient(): WardendClient | null {
  return wardendClient;
}

/** Bootstrap restores a saved link before the loop starts. */
export function adoptWardendLink(link: WardendLinkRec | null) {
  wardendLink = link;
}

export function wardendStateFromLink(link: WardendLinkRec | null) {
  if (!link) return { status: "unpaired" as const, url: null, host: null, supervisorId: null, pairId: null, lastError: null, lastReason: null };
  return { status: link.paired ? ("unavailable" as const) : ("awaiting-approval" as const), url: link.url, host: link.host, supervisorId: link.supervisorId, pairId: link.pairId, lastError: null, lastReason: null };
}

function wardendReason(e: unknown): string {
  if (e instanceof WardendHttpError) return wardendHttpReason(e.reason) ?? `${e.status} ${e.reason}`;
  const m = errMsg(e);
  return isNetworkError(m) ? t("err.serverUnreachable", { msg: m }) : m;
}

/**
 * Pairing via the link from the QR: check that the server at that address answers with the key
 * from the QR, send our public key signed together with the code, and wait for
 * `wardend pair approve` on the server.
 */
export async function pairWithWardend(linkText: string, deviceName: string): Promise<void> {
  const { identity, requireOwner, removeCards } = useHooks();
  const idn = identity();
  if (!idn) throw new Error(getState().identityError ?? t("err.noIdentity"));
  const l = parsePairLink(linkText);
  const supervisorId = supervisorIdFromKey(l.key);
  await requireOwner("owner.pair", { host: l.host || l.url });
  const client = new WardendClient({ baseUrl: l.url, pinnedKey: l.key, identity: idn });
  setState((s) => ({ wardend: { ...s.wardend, status: "checking", lastError: null } }));
  try {
    const ping = await client.ping();
    if (ping.supervisorId !== supervisorId) throw new Error(t("err.wrongSupervisorId"));
    const r = await client.pair(l.code, supervisorId, deviceName.trim() || "WardenClaw");
    pairAbort?.abort();
    stopWardend();
    removeCards("wardend");
    const rec: WardendLinkRec = { url: l.url, key: l.key, supervisorId, host: r.host || l.host, pairId: r.id, paired: r.status === "approved", pairedAt: r.status === "approved" ? new Date().toISOString() : null };
    await saveWardendLink(rec);
    wardendLink = rec;
    setState((s) => ({ wardend: { ...s.wardend, ...wardendStateFromLink(rec), signed: 0, mode: null, policyMode: null }, serverHw: null }));
    appendEntry({ ts: Date.now(), kind: "pairing", approval_id: null, approval_kind: null, ...journalMsg("j.pairRequested", { id: r.id, host: rec.host || rec.url, fp: r.fingerprint }, { url: rec.url, supervisorId, pairId: r.id, status: r.status }), decided_by: null, decision: null, latency_ms: null });
    pushLog(`wardend: pairing request ${r.id} (${r.status}), fingerprint ${r.fingerprint}`);
    if (rec.paired) onWardendPaired();
    else pollPairStatus();
  } catch (e) {
    const msg = wardendReason(e);
    setState((s) => ({ wardend: { ...s.wardend, ...wardendStateFromLink(wardendLink), lastError: msg } }));
    if (wardendLink?.paired) startWardend();
    throw new Error(msg);
  }
}

/** Wait for `wardend pair approve` (poll /v1/pair/status every 3 s, signed with the same key). */
export function pollPairStatus() {
  const link = wardendLink;
  const idn = useHooks().identity();
  if (!idn || !link?.pairId) return;
  pairAbort?.abort();
  const ac = new AbortController();
  pairAbort = ac;
  const client = new WardendClient({ baseUrl: link.url, pinnedKey: link.key, identity: idn });
  (async () => {
    let delay = PAIR_POLL_INIT_MS;
    while (!ac.signal.aborted) {
      try {
        const st = await client.pairStatus(link.pairId as string, ac.signal);
        if (ac.signal.aborted) return;
        setState((s) => ({ wardend: { ...s.wardend, lastError: null } }));
        if (st.status === "approved") {
          const rec = { ...link, paired: true, pairedAt: new Date().toISOString() };
          await saveWardendLink(rec);
          wardendLink = rec;
          onWardendPaired();
          return;
        }
        if (st.status === "rejected" || st.status === "unknown" || st.status === "revoked") {
          const why = st.status === "rejected" ? t("err.pairRejected") : t("err.pairExpired");
          await clearWardendLink();
          wardendLink = null;
          setState((s) => ({ wardend: { ...s.wardend, ...wardendStateFromLink(null), status: st.status === "rejected" ? "rejected" : "unpaired", lastError: why } }));
          appendEntry({ ts: Date.now(), kind: "pairing", approval_id: null, approval_kind: null, summary: `wardend: ${why}`, decided_by: null, decision: null, latency_ms: null, payload: null });
          return;
        }
        delay = PAIR_POLL_INIT_MS;
      } catch (e) {
        if (ac.signal.aborted) return;
        const msg = wardendReason(e);
        setState((s) => ({ wardend: { ...s.wardend, lastError: msg } }));
        delay = Math.min(MAX_BACKOFF_MS, delay * 2);
      }
      await new Promise((r) => setTimeout(r, delay));
    }
  })().catch((e) => pushLog(`wardend: pairing poll crashed: ${errMsg(e)}`));
}

function onWardendPaired() {
  const link = wardendLink;
  if (!link) return;
  appendEntry({ ts: Date.now(), kind: "connect", approval_id: null, approval_kind: null, ...journalMsg("j.pairApproved", { host: link.host || link.url }, { url: link.url, supervisorId: link.supervisorId }), decided_by: null, decision: null, latency_ms: null });
  pushLog(`wardend: pairing confirmed (${link.url})`);
  setState((s) => ({ wardend: { ...s.wardend, ...wardendStateFromLink(link), pairId: null } }));
  startWardend();
}

/** iOS: the phone's APNs token in wardend (/v1/push/register, signed with the device key). */
export async function wardendPushRegister(token: string, topic: string, environment: "sandbox" | "production"): Promise<string> {
  if (!wardendClient || !wardendLink?.paired) throw new Error(t("err.noWardend"));
  await wardendClient.pushRegister(token, topic, environment);
  return wardendLink.supervisorId;
}

/** Remove the token from the server (notifications turned off or the server is being forgotten). Errors do not matter: a token without a device is useless. */
export async function wardendPushUnregister(token?: string): Promise<void> {
  if (!wardendClient) return;
  await wardendClient.pushUnregister(token).catch((e) => pushLog(`push: unregister failed: ${errMsg(e)}`));
}

/** "Forget server": stop talking to wardend (on the server: wardend pair revoke). */
export async function forgetWardend() {
  const { identity, requireOwner, removeCards } = useHooks();
  await requireOwner("owner.forget");
  pairAbort?.abort();
  pairAbort = null;
  // iPhone: remove the APNs token while the client still exists (no waiting for the reply: revoke on the server removes it too)
  if (getState().bg.push.state === "registered") void wardendPushUnregister();
  stopWardend();
  const old = wardendLink;
  await clearWardendLink();
  wardendLink = null;
  removeCards("wardend");
  setState((s) => ({ wardend: { ...s.wardend, ...wardendStateFromLink(null), mode: null, policyMode: null, lastOkAt: null }, serverHw: null }));
  appendEntry({ ts: Date.now(), kind: "info", approval_id: null, approval_kind: null, ...journalMsg("j.serverForgotten", { host: old?.host || old?.url || "", id: identity()?.deviceId.slice(0, 12) ?? "" }), decided_by: "me", decision: null, latency_ms: null });
}

export function startWardend() {
  const idn = useHooks().identity();
  if (!idn || !wardendLink?.paired) return;
  stopWardend();
  const client = new WardendClient({ baseUrl: wardendLink.url, pinnedKey: wardendLink.key, identity: idn });
  wardendClient = client;
  const ac = new AbortController();
  wardendAbort = ac;
  g.__wcWardendAbort = ac;
  pushLog(`wardend: long-poll ${wardendLink.url}/v1/pending`);
  wardendLoop(client, ac.signal).catch((e) => pushLog(`wardend: loop crashed: ${errMsg(e)}`));
}

function stopWardend() {
  if (wardendAbort) {
    wardendAbort.abort();
    wardendAbort = null;
    g.__wcWardendAbort = null;
  }
  wardendClient = null;
  wardendSeq = 0;
}

async function wardendLoop(client: WardendClient, signal: AbortSignal) {
  let backoffMs = WARDEND_BACKOFF_INIT_MS;
  // protocol version: /v1/status before long-poll on every (re)connect, the server may have been updated
  let checked = false;
  while (!signal.aborted) {
    try {
      if (!checked) {
        const st = await client.status(signal); // ProtocolMismatchError if we cannot understand each other
        if (signal.aborted) return;
        if (client === wardendClient) noteServerStatus(st);
        checked = true;
      }
      const res = await client.pending(wardendSeq, LONG_POLL_WAIT_MS, signal);
      if (signal.aborted) return;
      wardendSeq = res.seq;
      backoffMs = WARDEND_BACKOFF_INIT_MS;
      const wasUp = getState().wardend.status === "connected";
      setState((s) => ({ wardend: { ...s.wardend, status: "connected", ...applyServerRun({ mode: res.mode }), host: res.host || s.wardend.host, lastError: null, lastReason: null, lastOkAt: Date.now() } }));
      if (!wasUp) pushLog(`wardend: online (${res.host}, mode ${res.mode}${getState().wardend.policyMode ? `, policy ${getState().wardend.policyMode}` : ""})`);
      useHooks().syncCards(res.pending.map(wardendItemToPending));
    } catch (e) {
      if (signal.aborted) return;
      checked = false;
      const msg = wardendReason(e);
      if (getState().wardend.lastError !== msg) pushLog(`wardend unavailable: ${msg}`);
      setState((s) => ({ wardend: { ...s.wardend, status: "unavailable", lastError: msg, lastReason: e instanceof WardendHttpError ? e.reason : e instanceof ProtocolMismatchError ? "protocol_mismatch" : null } }));
      // different protocol version: this server's cards are not signed until the server or the app is updated
      if (e instanceof ProtocolMismatchError) useHooks().removeCards("wardend");
      // the server does not know us (revoke), the response is unsigned, or the protocol version differs: no point polling more often
      const slow = e instanceof ProtocolMismatchError || (e instanceof WardendHttpError && (e.status === 401 || e.reason === "unsigned_response"));
      await new Promise((r) => setTimeout(r, slow ? MAX_BACKOFF_MS : backoffMs));
      backoffMs = Math.min(MAX_BACKOFF_MS, backoffMs * 2);
    }
  }
}

/** Keep require_hardware and the server's mode from a /v1/status body. */
function noteServerStatus(st: unknown) {
  setState((s) => ({ serverHw: parseServerHardware(st), wardend: { ...s.wardend, ...applyServerRun(st) } }));
}

/**
 * wardend /v1/status: how many require_hardware rules and which keys the server knows. The "Mode"
 * screen uses it to state what the linked YubiKey actually protects (there may be no rules at all).
 */
export async function refreshServerStatus(): Promise<void> {
  const client = wardendClient;
  if (!client || !wardendLink?.paired) return;
  try {
    const st = await client.status();
    if (client !== wardendClient) return;
    noteServerStatus(st);
  } catch (e) {
    pushLog(`wardend: status failed: ${wardendReason(e)}`);
  }
}
