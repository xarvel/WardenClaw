// SPDX-License-Identifier: GPL-3.0-or-later
// OpenClaw adapter: gateway websocket, device token, and the wardenclaw-gate long-poll.
// Cards and the owner check stay in controller.ts; this file only talks to the gateway.
import { ApprovalKind, Card, extractList, normalizeApproval } from "./approvals";
import { GatewayAuth, GatewayConnection, GatewayEvent, GatewayRequestError, HelloOk, TERMINAL_AUTH_CODES, pairingDetails } from "./gateway";
import { GateClient, GateHttpError, GatePending, httpBaseFromGatewayUrl } from "./gate";
import { DeviceIdentity, deleteIdentity, loadOrCreateIdentity } from "./identity";
import { appendEntry } from "./journal";
import { journalMsg } from "./journalText";
import { errMsg } from "./errMsg";
import { getState, pushLog, setState } from "./store";
import { activeWardendLink } from "./wardendSession";
import { decodeSetupCode } from "./setupCode";
import { ProtocolMismatchError } from "./protocolVersion";
import { noteMissed } from "./missed";
import { MsgKey, MsgParams, t } from "./i18n";
import { SK, secureDelete, secureGet, secureSet } from "./secure";
import { saveOpenClawAdapter } from "./settings";

const PAIRING_RETRY_MS = 15000;
/** Long-poll wait; the server returns at most this many milliseconds after the request. Same cap as the wardend loop. */
const LONG_POLL_WAIT_MS = 25000;
/** Maximum backoff between reconnect attempts and after errors. */
const MAX_BACKOFF_MS = 30000;
/** Initial backoff for the gate (plugin) loop. */
const GATE_BACKOFF_INIT_MS = 3000;

type TokenRec = { token: string; scopes: string[]; updatedAt: string };

export type GatewayHooks = {
  identity: () => DeviceIdentity | null;
  setIdentity: (id: DeviceIdentity) => void;
  requireOwner: (prompt: MsgKey, params?: MsgParams) => Promise<void>;
  syncOpenclaw: (pending: GatePending[]) => void;
  addCard: (card: Card | null, origin: string) => void;
  removeCard: (id: string) => void;
  removeCards: (via: "openclaw") => void;
  clearUnshown: (via: "openclaw") => void;
  decision: (id: string) => { decision: string; at: number } | undefined;
  markResolved: (id: string) => void;
};

let hooks: GatewayHooks | null = null;

/** Called once from controller after its card helpers exist. */
export function bindGatewaySession(h: GatewayHooks) {
  hooks = h;
}

function useHooks(): GatewayHooks {
  if (!hooks) throw new Error("gateway session is not bound");
  return hooks;
}

let conn: GatewayConnection | null = null;
let bootstrapToken: string | null = null; // only for the duration of pairing
let retryTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectAttempt = 0;
let stopped = false;
let gateClient: GateClient | null = null;
let gateAbort: AbortController | null = null;
let gateSeq = 0;

/** The live plugin client, or null when the adapter is not polling. */
export function activeGateClient(): GateClient | null {
  return gateClient;
}

/** The live gateway websocket, or null when the adapter is off. */
export function activeGatewayConnection(): GatewayConnection | null {
  return conn;
}

// Dev: on Fast Refresh the module re-executes, while the old connection stays alive and duplicates events.
type Globals = { __wcConn?: GatewayConnection | null; __wcGateAbort?: AbortController | null };
const g = globalThis as unknown as Globals;
if (g.__wcConn) {
  try {
    g.__wcConn.close(1000, "module reload");
  } catch {}
  g.__wcConn = null;
}
if (g.__wcGateAbort) {
  g.__wcGateAbort.abort();
  g.__wcGateAbort = null;
}

async function loadToken(): Promise<TokenRec | null> {
  const raw = await secureGet(SK.token);
  if (!raw) return null;
  try {
    const r = JSON.parse(raw) as TokenRec;
    return r.token ? r : null;
  } catch {
    return null;
  }
}
async function saveToken(rec: TokenRec) {
  await secureSet(SK.token, JSON.stringify(rec));
  setState({ hasToken: true });
}
async function clearToken() {
  await secureDelete(SK.token);
  setState({ hasToken: false });
}

// ---------------------------------------------------------------------------
// OpenClaw adapter (off by default): WS connection to the gateway, its exec/plugin cards
// and the HTTP routes of the wardenclaw-gate plugin. Same device identity.
// ---------------------------------------------------------------------------
export async function setOpenClawAdapter(on: boolean) {
  // plugin tool cards in "Dangerous and roots" mode are signed without biometrics
  if (on && !getState().openclawAdapter) await useHooks().requireOwner("owner.adapter");
  await saveOpenClawAdapter(on);
  setState({ openclawAdapter: on });
  appendEntry({ ts: Date.now(), kind: "info", approval_id: null, approval_kind: null, ...journalMsg(on ? "j.adapterOn" : "j.adapterOff"), decided_by: "me", decision: null, latency_ms: null });
  if (on) {
    stopped = false;
    const t = await loadToken();
    if (t) connectGateway({ deviceToken: t.token });
    else setState({ status: "unpaired" });
    return;
  }
  stopped = true;
  if (retryTimer) clearTimeout(retryTimer);
  retryTimer = null;
  stopGate();
  conn?.close(1000, "adapter off");
  conn = null;
  bootstrapToken = null;
  for (const c of getState().cards) if (c.kind !== "gate" || c.gate?.via === "openclaw") useHooks().removeCard(c.id);
  useHooks().clearUnshown("openclaw");
  setState({ status: "off", statusDetail: "", pairingRequestId: null });
}

/** OpenClaw adapter pairing wizard: URL + setup-code → bootstrap connection. */
export async function startPairing(url: string, setupCode: string) {
  const decoded = decodeSetupCode(setupCode); // throws a clear error
  const cleanUrl = url.trim().replace(/\/+$/, "");
  if (!/^wss?:\/\//.test(cleanUrl)) throw new Error(t("err.wsUrl"));
  await useHooks().requireOwner("owner.gwPair", { url: cleanUrl });
  await secureSet(SK.gatewayUrl, cleanUrl);
  bootstrapToken = decoded.bootstrapToken;
  stopped = false;
  setState({ gatewayUrl: cleanUrl, status: "connecting", statusDetail: t("st.connectingSetupCode"), pairingRequestId: null, lastError: null });
  appendEntry({ ts: Date.now(), kind: "pairing", approval_id: null, approval_kind: null, ...journalMsg("j.gwPairingConnect", { url: cleanUrl }), decided_by: null, decision: null, latency_ms: null });
  connectGateway({ bootstrapToken: decoded.bootstrapToken });
}

/**
 * "Unlink" the OpenClaw adapter: erase the gateway device token. The device key changes only
 * if the phone is not connected to wardend (the same key signs wardend tickets).
 */
export async function unpair() {
  stopped = true;
  if (retryTimer) clearTimeout(retryTimer);
  retryTimer = null;
  stopGate();
  conn?.close(1000, "unpair");
  conn = null;
  bootstrapToken = null;
  await clearToken();
  for (const c of getState().cards) if (c.kind !== "gate" || c.gate?.via === "openclaw") useHooks().removeCard(c.id);
  useHooks().clearUnshown("openclaw");
  const rotate = !activeWardendLink();
  if (rotate) {
    await deleteIdentity();
    useHooks().setIdentity(await loadOrCreateIdentity());
  }
  setState({ status: "unpaired", statusDetail: "", pairingRequestId: null, deviceId: useHooks().identity()?.deviceId ?? "", serverVersion: null, scopes: [] });
  appendEntry({ ts: Date.now(), kind: "info", approval_id: null, approval_kind: null, ...journalMsg(rotate ? "j.adapterUnpairedRotated" : "j.adapterUnpairedKept"), decided_by: null, decision: null, latency_ms: null });
  pushLog(rotate ? "unpaired, new identity created" : "OpenClaw adapter unpaired, key kept");
}

export function reconnectNow() {
  if (!getState().openclawAdapter) return;
  if (retryTimer) clearTimeout(retryTimer);
  retryTimer = null;
  reconnectAttempt = 0;
  stopped = false;
  loadToken().then((t) => {
    if (t) connectGateway({ deviceToken: t.token });
    else if (bootstrapToken) connectGateway({ bootstrapToken });
    else setState({ status: "unpaired" });
  });
}

function scheduleRetry(why: string, delayMs: number) {
  if (stopped || retryTimer) return;
  pushLog(`retry in ${Math.round(delayMs / 1000)} s (${why})`);
  retryTimer = setTimeout(() => {
    retryTimer = null;
    reconnectNow();
  }, delayMs);
}

export function connectGateway(auth: GatewayAuth) {
  if (!useHooks().identity()) return;
  conn?.close(1000, "reconnect");
  const url = getState().gatewayUrl;
  const c = new GatewayConnection({
    url,
    identity: useHooks().identity()!,
    auth,
    handlers: {
      onLog: pushLog,
      onHello: (hello) => onHello(hello, auth),
      onEvent,
      onConnectError: (err) => onConnectError(err, auth),
      onClose: (code, reason, wasConnected) => {
        if (conn !== c) return;
        conn = null;
        stopGate();
        if (stopped) return;
        const st = getState().status;
        if (st === "pairing" || st === "auth-failed" || st === "unpaired") return;
        pushLog(`closed ${code}${reason ? ` ${reason}` : ""}`);
        setState({ status: "reconnecting", statusDetail: wasConnected ? t("st.connLost") : t("st.connFailed") });
        reconnectAttempt += 1;
        scheduleRetry("reconnect", Math.min(MAX_BACKOFF_MS, 1000 * 2 ** Math.min(reconnectAttempt, 5)));
      },
    },
  });
  conn = c;
  g.__wcConn = c;
  c.start();
}

async function onHello(hello: HelloOk, auth: GatewayAuth) {
  reconnectAttempt = 0;
  const a = hello.auth ?? {};
  const scopes = a.scopes ?? [];
  pushLog(`hello-ok: protocol ${hello.protocol}, server ${hello.server?.version ?? "?"}, scopes [${scopes.join(", ")}]${a.deviceToken ? ", device token issued" : ""}`);
  if (a.deviceToken) {
    await saveToken({ token: a.deviceToken, scopes, updatedAt: new Date().toISOString() });
    bootstrapToken = null;
  } else if ("bootstrapToken" in auth) {
    pushLog("gateway did not issue a device token for the setup-code");
  }
  setState({ status: "connected", statusDetail: "", pairingRequestId: null, serverVersion: hello.server?.version ?? null, scopes, lastError: null });
  appendEntry({ ts: Date.now(), kind: "connect", approval_id: null, approval_kind: null, ...journalMsg("j.gwConnected", { url: getState().gatewayUrl, version: hello.server?.version ?? "?" }, { protocol: hello.protocol, scopes, role: a.role }), decided_by: null, decision: null, latency_ms: null });
  if (!scopes.includes("operator.approvals")) pushLog("operator.approvals is missing from scopes: cannot resolve");
  backfill().catch((e) => pushLog(`backfill: ${String(e?.message ?? e)}`));
  const tok = a.deviceToken ?? (await loadToken())?.token ?? null;
  startGate(tok);
}

// ---------------------------------------------------------------------------
// Gate (wardenclaw-gate plugin): long-poll pending over HTTP, signed decisions.
// Lives as long as the WS connection lives: same device token, same key.
// ---------------------------------------------------------------------------
function startGate(deviceToken: string | null) {
  if (!useHooks().identity()) return;
  stopGate();
  const baseUrl = httpBaseFromGatewayUrl(getState().gatewayUrl);
  gateClient = new GateClient({ baseUrl, identity: useHooks().identity()!, deviceToken, onLog: pushLog });
  const ac = new AbortController();
  gateAbort = ac;
  g.__wcGateAbort = ac;
  setState((s) => ({ gate: { ...s.gate, status: "polling", lastError: null } }));
  pushLog(`gate: long-poll ${baseUrl}/wardenclaw/pending`);
  gateLoop(gateClient, ac.signal).catch((e) => pushLog(`gate: loop crashed: ${errMsg(e)}`));
}

function stopGate() {
  if (gateAbort) {
    gateAbort.abort();
    gateAbort = null;
    g.__wcGateAbort = null;
  }
  gateClient = null;
  gateSeq = 0;
  setState((s) => (s.gate.status === "off" ? {} : { gate: { ...s.gate, status: "off" } }));
}

async function gateLoop(client: GateClient, signal: AbortSignal) {
  let backoffMs = GATE_BACKOFF_INIT_MS;
  let checked = false; // plugin protocol version: /wardenclaw/status on every (re)connect
  while (!signal.aborted) {
    try {
      if (!checked) {
        await client.status(signal); // ProtocolMismatchError if we cannot understand each other
        if (signal.aborted) return;
        checked = true;
      }
      const res = await client.pending(gateSeq, LONG_POLL_WAIT_MS, signal);
      if (signal.aborted) return;
      gateSeq = res.seq;
      backoffMs = GATE_BACKOFF_INIT_MS;
      setState((s) => ({ gate: { ...s.gate, status: "polling", mode: res.mode, lastError: null, lastOkAt: Date.now() } }));
      // exec records of "our" wardend also arrive directly: we do not take them from the plugin (relay)
      useHooks().syncOpenclaw(res.pending.filter((p) => p.status === "pending" && !isDirectWardendRecord(p)));
    } catch (e) {
      if (signal.aborted) return;
      checked = false;
      const msg = e instanceof GateHttpError ? `${e.status} ${e.reason}` : errMsg(e);
      const prev = getState().gate;
      if (prev.lastError !== msg) pushLog(`gate unavailable: ${msg}`);
      setState((s) => ({ gate: { ...s.gate, status: "unavailable", lastError: msg } }));
      // different protocol version: plugin cards are not signed until the plugin or the app is updated
      if (e instanceof ProtocolMismatchError) useHooks().removeCards("openclaw");
      // 401/403/404: plugin config or plugin not enabled, different protocol version: no point polling more often.
      const slow = e instanceof ProtocolMismatchError || (e instanceof GateHttpError && [401, 403, 404].includes(e.status));
      await new Promise((r) => setTimeout(r, slow ? MAX_BACKOFF_MS : backoffMs));
      backoffMs = Math.min(MAX_BACKOFF_MS, backoffMs * 2);
    }
  }
}

function isDirectWardendRecord(p: GatePending): boolean {
  const link = activeWardendLink();
  if (!link?.paired || p.kind !== "exec") return false;
  const env = (p.envelope ?? {}) as { requester?: { supervisorId?: unknown } };
  return env.requester?.supervisorId === link.supervisorId;
}

function onConnectError(err: Error, auth: GatewayAuth) {
  const pd = pairingDetails(err);
  if (pd) {
    pushLog(`PAIRING_REQUIRED requestId=${pd.requestId ?? "?"}`);
    setState({ status: "pairing", pairingRequestId: pd.requestId ?? null, statusDetail: pd.hint ?? t("st.awaitApproval") });
    appendEntry({ ts: Date.now(), kind: "pairing", approval_id: null, approval_kind: null, ...journalMsg("j.gwPairingNeeded", { id: pd.requestId ?? "?" }), decided_by: null, decision: null, latency_ms: null });
    scheduleRetry("waiting for pairing approval", PAIRING_RETRY_MS);
    return;
  }
  const code = err instanceof GatewayRequestError ? err.detailCode : undefined;
  pushLog(`connect error: ${err.message}${code ? ` [${code}]` : ""}`);
  if (code && TERMINAL_AUTH_CODES.has(code)) {
    if ("deviceToken" in auth) clearToken();
    bootstrapToken = null;
    setState({ status: "auth-failed", statusDetail: t("st.newSetupCode", { code }), lastError: err.message });
    appendEntry({ ts: Date.now(), kind: "error", approval_id: null, approval_kind: null, ...journalMsg("j.accessDenied", { code }), decided_by: null, decision: null, latency_ms: null });
    return;
  }
  setState({ lastError: err.message });
}

async function backfill() {
  if (!conn) return;
  for (const [method, kind] of [
    ["exec.approval.list", "exec"],
    ["plugin.approval.list", "plugin"],
  ] as const) {
    try {
      const res = await conn.request(method, {});
      const items = extractList(res);
      pushLog(`${method}: ${items.length} pending`);
      for (const it of items) useHooks().addCard(normalizeApproval(it, kind), "backfill");
    } catch (e) {
      pushLog(`${method}: ${errMsg(e)}`);
    }
  }
}

function onEvent(evt: GatewayEvent) {
  const name = evt.event;
  const p = (evt.payload ?? {}) as Record<string, unknown>;
  if (name === "exec.approval.requested" || name === "plugin.approval.requested") {
    useHooks().addCard(normalizeApproval(p, name.startsWith("exec") ? "exec" : "plugin"), "event");
    return;
  }
  if (name === "exec.approval.resolved" || name === "plugin.approval.resolved") {
    const id = (typeof p.id === "string" ? p.id : typeof p.approvalId === "string" ? p.approvalId : null) as string | null;
    if (!id) return;
    const kind: ApprovalKind = name.startsWith("exec") ? "exec" : "plugin";
    const decision = typeof p.decision === "string" ? p.decision : typeof p.status === "string" ? p.status : "?";
    const mine = useHooks().decision(id);
    const card = getState().cards.find((c) => c.id === id);
    useHooks().markResolved(id);
    if (!mine) {
      // The gateway reports a timeout as decision "deny" with resolvedBy=null at the moment of expiry.
      const resolvedBy = p.resolvedBy;
      const evTs = typeof p.ts === "number" ? p.ts : Date.now();
      const isTimeout = /timeout|expired/i.test(decision) || p.reason === "timeout" || (!resolvedBy && !!card?.expiresAtMs && evTs >= card.expiresAtMs - 1500);
      appendEntry({
        ts: Date.now(),
        kind: "resolved",
        approval_id: id,
        approval_kind: kind,
        summary: card?.summary ?? t("j.cardFallback", { id: id.slice(0, 8) }),
        decided_by: isTimeout ? "timeout" : "other",
        decision,
        latency_ms: card ? Date.now() - card.createdAtMs : null,
        payload: JSON.stringify(p),
      });
      pushLog(`${name} ${id.slice(0, 8)} → ${decision} (${isTimeout ? "timeout" : "another operator"})`);
      if (isTimeout && card) noteMissed(card, evTs);
    }
    useHooks().removeCard(id);
    return;
  }
}

export { loadToken as loadGatewayToken };
