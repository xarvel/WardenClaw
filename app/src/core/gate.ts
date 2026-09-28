// SPDX-License-Identifier: GPL-3.0-or-later
// Client of the wardenclaw-gate plugin routes (HTTP variant of the gateway URL).
//   GET  /wardenclaw/pending?since&wait   long-poll, device signature in headers + Bearer device token
//   GET  /wardenclaw/status
//   POST /wardenclaw/decide               {deviceId, payload:{id,digest,decision,ts,nonce}, signature}
// Signed with the same Ed25519 device key as in connect (identity.ts); string format in canonical.ts.
import { randomUUID } from "expo-crypto";
import { DeviceIdentity, signPayload } from "./identity";
import { DecisionPayload, GateDecision, TICKET_EXEC, TicketScope, decisionSigningString, requestSigningString } from "./canonical";
import { HardwareAssertion, HardwareSigner, assertionRequest } from "./hardware";
import { assertServerProtocol } from "./protocolVersion";
export { checkExecPending, type ExecCheck } from "./execEnvelope";

export type GateMode = "observe" | "enforce";

/** toolCallDigest input; null and a missing field differ (null is part of the canonical JSON). */
export type ToolCall = { toolName: string; params: unknown; agentId?: string | null; sessionKey?: string | null; runId?: string | null; toolCallId?: string | null };

export type GatePending = {
  /** "exec": a wardend supervisor entry (seccomp execve gate), came via the plugin relay; id "wd-…". */
  kind?: "exec" | "tool";
  /** Only for kind === "exec": the v1 envelope (signed as digest = sha256(canonicalJson(envelope))). */
  envelope?: unknown;
  /** Only for kind === "exec": wardend policy class (root | delegating), rule, explanation. */
  meta?: Record<string, unknown>;
  /** The whole tool call, exactly what the digest covers (toolCallDigest): the phone recomputes it
   *  itself and shows what it signs. Absent (old plugin, large call): it cannot be allowed. */
  call?: ToolCall;
  id: string;
  digest: string;
  toolName: string;
  toolKind: string | null;
  toolInputKind: string | null;
  paramsPreview: string;
  command: string | null;
  filePath: string | null;
  agentId: string | null;
  sessionKey: string | null;
  runId: string | null;
  toolCallId: string | null;
  source: string;
  mode: GateMode;
  createdAt: number;
  expiresAt: number;
  status: string;
  decision: GateDecision | null;
  deviceId: string | null;
};

export type WardendSummary = { socket: string; connected: boolean; pending: number; lastError: string | null; supervisorId?: string | null; host?: string | null; mode?: string | null };
export type GatePendingResponse = { ok: true; seq: number; mode: GateMode; pending: GatePending[]; now: number; wardend?: WardendSummary | null };
export type GateDecideResponse = { ok: boolean; reason?: string; id?: string; decision?: GateDecision; late?: boolean; status?: string; hardwareRule?: string };

/** Decision body: the device signature and (for high risk) a second YubiKey signature. */
export type SignedDecision = { deviceId: string; payload: DecisionPayload; signature: string; hw?: HardwareAssertion };
export type GateStatus = {
  ok: true;
  mode: GateMode;
  ttlMs: number;
  tools: string[];
  trustedDeviceIds: string[];
  startedAt: number;
  counters: Record<string, number>;
  seenTools: { toolName: string; toolKind: string | null; count: number; lastAt: number }[];
  pending: number;
  journalPublicKey: string | null;
  now: number;
  /** Plugin protocol version and the oldest client it understands (protocolVersion.ts). */
  protocol?: number;
  minClient?: number;
};

export class GateHttpError extends Error {
  constructor(
    public status: number,
    public reason: string,
  ) {
    super(`gate: ${status} ${reason}`);
  }
}

/** ws(s)://host → http(s)://host */
export function httpBaseFromGatewayUrl(wsUrl: string): string {
  return wsUrl.trim().replace(/\/+$/, "").replace(/^wss:\/\//i, "https://").replace(/^ws:\/\//i, "http://");
}

/** The entry the decision is signed for, and the ticket type: tool (plugin) or exec (wardend + supervisorId). */
export type DecisionTarget = { id: string; digest: string; ticket: TicketScope };

/**
 * Sign a decision for a pending entry. Returns the body for POST /wardenclaw/decide and /v1/decide.
 * The ticket type and supervisorId are part of the signed string; risk (0..100) if set (wardend
 * score rules).
 */
export function signDecision(identity: DeviceIdentity, pending: DecisionTarget, decision: GateDecision, now = Date.now(), risk?: number): SignedDecision {
  const payload: DecisionPayload = { type: pending.ticket.type, id: pending.id, digest: pending.digest, decision, ts: now, nonce: randomUUID() };
  if (pending.ticket.type === TICKET_EXEC) payload.supervisorId = pending.ticket.supervisorId;
  if (risk !== undefined) payload.risk = risk;
  const signature = signPayload(identity, decisionSigningString({ deviceId: identity.deviceId, ...payload }));
  return { deviceId: identity.deviceId, payload, signature };
}

/**
 * Device signature + a second key signature over the challenge of THIS ticket (digest, decision,
 * nonce, risk). Order: payload first (fixes ts/nonce), then the touch (the challenge comes from
 * it), then the body.
 */
export async function signDecisionWithHardware(identity: DeviceIdentity, pending: DecisionTarget, decision: GateDecision, hardware: HardwareSigner, risk?: number, now = Date.now()): Promise<SignedDecision> {
  const signed = signDecision(identity, pending, decision, now, risk);
  const hw = await hardware(assertionRequest(identity.deviceId, signed.payload));
  return { ...signed, hw };
}

export type GateClientOptions = {
  baseUrl: string; // http(s)://…
  identity: DeviceIdentity;
  deviceToken: string | null; // Bearer; the plugin checks it against the paired devices store
  onLog?: (line: string) => void;
};

export class GateClient {
  constructor(private readonly opts: GateClientOptions) {}

  get baseUrl() {
    return this.opts.baseUrl;
  }

  private signedHeaders(action: string): Record<string, string> {
    const { identity, deviceToken } = this.opts;
    const ts = Date.now();
    const nonce = randomUUID();
    const h: Record<string, string> = {
      "x-wardenclaw-device": identity.deviceId,
      "x-wardenclaw-ts": String(ts),
      "x-wardenclaw-nonce": nonce,
      "x-wardenclaw-signature": signPayload(identity, requestSigningString({ action, deviceId: identity.deviceId, ts, nonce })),
    };
    if (deviceToken) h.authorization = `Bearer ${deviceToken}`;
    return h;
  }

  private async call<T>(path: string, init: RequestInit & { timeoutMs?: number }, signal?: AbortSignal): Promise<T> {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), init.timeoutMs ?? 15000);
    const onOuter = () => ac.abort();
    signal?.addEventListener("abort", onOuter, { once: true });
    try {
      const res = await fetch(`${this.opts.baseUrl}${path}`, { ...init, signal: ac.signal });
      let body: unknown = null;
      try {
        body = await res.json();
      } catch {}
      const rec = (body ?? {}) as { ok?: boolean; reason?: string };
      if (!res.ok || rec.ok === false) throw new GateHttpError(res.status, rec.reason ?? `HTTP ${res.status}`);
      return body as T;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onOuter);
    }
  }

  /** Long-poll: returns when seq on the server becomes greater than since, or after waitMs. */
  pending(since: number, waitMs = 25000, signal?: AbortSignal): Promise<GatePendingResponse> {
    return this.call<GatePendingResponse>(`/wardenclaw/pending?since=${since}&wait=${waitMs}`, { method: "GET", headers: this.signedHeaders("pending"), timeoutMs: waitMs + 10000 }, signal);
  }

  /** Plugin state; checks the protocol version right here (ProtocolMismatchError), the controller calls it on every connection. */
  async status(signal?: AbortSignal): Promise<GateStatus> {
    const st = await this.call<GateStatus>("/wardenclaw/status", { method: "GET", headers: this.signedHeaders("status") }, signal);
    assertServerProtocol(st, "plugin");
    return st;
  }

  /**
   * Sign and send a decision. Returns the plugin response and what was signed (for the journal).
   * opts.hardware: YubiKey touch (for wardend exec entries with meta.hardware), opts.risk: judge rating.
   * pending.ticket: tool is a plugin tool call, exec is a wardend entry the plugin forwards as is.
   */
  async decide(pending: DecisionTarget, decision: GateDecision, opts: { risk?: number; hardware?: HardwareSigner } = {}) {
    const signed = opts.hardware
      ? await signDecisionWithHardware(this.opts.identity, pending, decision, opts.hardware, opts.risk)
      : signDecision(this.opts.identity, pending, decision, Date.now(), opts.risk);
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this.opts.deviceToken) headers.authorization = `Bearer ${this.opts.deviceToken}`;
    let response: GateDecideResponse;
    try {
      response = await this.call<GateDecideResponse>("/wardenclaw/decide", { method: "POST", headers, body: JSON.stringify(signed) });
    } catch (e) {
      if (e instanceof GateHttpError) response = { ok: false, reason: e.reason };
      else throw e;
    }
    return { signed, response };
  }
}
