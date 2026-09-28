// SPDX-License-Identifier: Apache-2.0
// Gate core: creates pending entries, accepts signed decisions, maintains journal and counters.
import { TICKET_EXEC, TICKET_TOOL, toolCallDigest } from "./canonical.js";
import { PendingStore, summarizeParams } from "./store.js";
import { NonceCache, parseDecisionBody, verifyDecision, verifySignedRequest } from "./verify.js";
import { isRelayId } from "./relay.js";
import { MIN_CLIENT, PROTOCOL } from "./protocol.js";

export class Gate {
  /**
   * @param {{
   *   config: import("./config.js").GateConfig,
   *   directory: { getDevice(id: string): Promise<import("./devices.js").DeviceRecord | null> },
   *   journal: { append(kind: string, data: unknown): unknown, publicKey?: string },
   *   logger: { info(m: string): void, warn(m: string): void, error(m: string): void, debug?: (m: string) => void },
   *   store?: PendingStore,
   *   now?: () => number,
   *   relay?: import("./relay.js").WardendRelay | null,
   * }} deps
   */
  constructor(deps) {
    this.config = deps.config;
    this.directory = deps.directory;
    this.journal = deps.journal;
    this.log = deps.logger;
    this.now = deps.now ?? (() => Date.now());
    this.store = deps.store ?? new PendingStore({ dir: deps.config.stateDir, now: this.now });
    this.nonces = new NonceCache({ windowMs: deps.config.tsWindowMs, now: this.now });
    /** relay to wardend (exec entries "wd-..."); separate nonce cache for pre-verification */
    this.relay = deps.relay ?? null;
    this.relayNonces = new NonceCache({ windowMs: deps.config.tsWindowMs, now: this.now });
    this.startedAt = this.now();
    /** Seen-tool stats: key `${toolName}|${toolKind}` -> count (answers "does the hook see native tools?"). */
    this.seenTools = new Map();
    this.counters = { seen: 0, gated: 0, allowed: 0, denied: 0, expired: 0, aborted: 0, stopped: 0, observed: 0, rejectedDecisions: 0 };
  }

  /**
   * Register a tool call: compute digest, create pending entry, write to journal.
   * @param {{ toolName: string, params: Record<string, unknown>, toolKind?: string, toolInputKind?: string, agentId?: string, sessionKey?: string, runId?: string, toolCallId?: string, source: string }} call
   */
  createPending(call) {
    const digest = toolCallDigest(call);
    const { command, filePath, paramsPreview } = summarizeParams(call.toolName, call.params);
    const rec = this.store.create(
      {
        digest,
        toolName: call.toolName,
        params: call.params,
        toolKind: call.toolKind,
        toolInputKind: call.toolInputKind,
        paramsPreview,
        command,
        filePath,
        agentId: call.agentId,
        sessionKey: call.sessionKey,
        runId: call.runId,
        toolCallId: call.toolCallId,
        source: call.source,
        mode: this.config.mode,
      },
      this.config.ttlMs,
    );
    this.counters.gated += 1;
    this.journal.append("pending", publicRecord(rec));
    return rec;
  }

  /**
   * Wait for a decision (enforce). Returns result for before_tool_call.
   * @param {string} id
   * @param {{ signal?: AbortSignal }} [opts]
   */
  async waitDecision(id, opts = {}) {
    const { outcome, record } = await this.store.waitDecision(id, { signal: opts.signal, timeoutMs: this.config.ttlMs });
    if (outcome === "allow") {
      this.counters.allowed += 1;
      return { allow: true, outcome, record };
    }
    if (outcome === "deny") this.counters.denied += 1;
    else if (outcome === "timeout") {
      this.counters.expired += 1;
      this.journal.append("expired", { id, digest: record?.digest });
    } else if (outcome === "aborted") {
      this.counters.aborted += 1;
      this.journal.append("aborted", { id, digest: record?.digest });
    } else if (outcome === "stopped") {
      this.counters.stopped += 1;
      this.journal.append("stopped", { id, digest: record?.digest });
    }
    return { allow: false, outcome, record, reason: blockReason(outcome, record, this.config.ttlMs) };
  }

  /**
   * Accept a signed decision (HTTP or gateway method).
   * @param {unknown} body
   * @param {{ transport: string, authenticatedDeviceId?: string }} meta
   */
  async decide(body, meta) {
    const entryId = /** @type {any} */ (body)?.payload?.id;
    if (this.relay && isRelayId(entryId)) return this.relayDecide(body, meta);
    const result = await verifyDecision(body, {
      ticketType: TICKET_TOOL,
      now: this.now(),
      trustedDeviceIds: this.config.trustedDeviceIds,
      tsWindowMs: this.config.tsWindowMs,
      directory: this.directory,
      nonces: this.nonces,
      getPending: (id) => this.store.get(id),
    });
    if (!result.ok) {
      this.counters.rejectedDecisions += 1;
      this.journal.append("decision_rejected", { reason: result.reason, transport: meta.transport, deviceId: result.body?.deviceId, id: result.body?.payload.id, digest: result.body?.payload.digest });
      this.log.warn(`[wardenclaw-gate] decision rejected: ${result.reason} (${meta.transport}${result.body ? `, ${result.body.payload.decision} for ${result.body.payload.id.slice(0, 8)}` : ""})`);
      return { ok: false, reason: result.reason };
    }
    const { deviceId, payload, signature } = result.body;
    if (meta.authenticatedDeviceId && meta.authenticatedDeviceId !== deviceId) {
      this.counters.rejectedDecisions += 1;
      this.journal.append("decision_rejected", { reason: "device_mismatch", transport: meta.transport, deviceId, connDeviceId: meta.authenticatedDeviceId });
      return { ok: false, reason: "device_mismatch" };
    }
    const applied = this.store.decide(payload.id, payload.decision, deviceId);
    const rec = applied?.record ?? null;
    const late = applied?.late ?? true;
    this.journal.append("decision", {
      type: payload.type,
      id: payload.id,
      digest: payload.digest,
      decision: payload.decision,
      deviceId,
      publicKey: result.publicKey,
      ts: payload.ts,
      nonce: payload.nonce,
      signature,
      transport: meta.transport,
      late,
      mode: rec?.mode,
      status: rec?.status,
    });
    this.log.info(`[wardenclaw-gate] ${payload.decision.toUpperCase()} ${payload.id.slice(0, 8)} from ${deviceId.slice(0, 12)} (${meta.transport}${late ? ", late" : ""})`);
    return { ok: true, id: payload.id, decision: payload.decision, late, status: rec?.status ?? "unknown" };
  }

  /**
   * Decision for a wardend exec entry: optional pre-verification here, final verification
   * and enforcement in wardend. The plugin never grants permission on its own.
   * @param {unknown} body
   * @param {{ transport: string, authenticatedDeviceId?: string }} meta
   */
  async relayDecide(body, meta) {
    const parsed = parseDecisionBody(body);
    if (!parsed.ok) return { ok: false, reason: parsed.reason };
    const ticket = parsed.value;
    const { payload } = ticket;
    if (meta.authenticatedDeviceId && meta.authenticatedDeviceId !== ticket.deviceId) {
      this.#rejectRelayed("device_mismatch", ticket, meta, { connDeviceId: meta.authenticatedDeviceId });
      return { ok: false, reason: "device_mismatch" };
    }
    // only an exec ticket reaches wardend (type is in the signing string): a decision signed as
    // a tool call is not valid for wardend and must not be forwarded
    if (payload.type !== TICKET_EXEC) {
      this.#rejectRelayed("ticket_type_mismatch", ticket, meta, { type: payload.type });
      return { ok: false, reason: "ticket_type_mismatch", stage: "plugin_relay" };
    }
    // second gate: only entries the plugin itself served to the client as kind "exec"
    if (!this.relay.servedAsExec(payload.id)) {
      this.#rejectRelayed("not_served_as_exec", ticket, meta);
      this.log.warn(`[wardenclaw-gate] relay: decision for ${payload.id.slice(0, 11)} not forwarded: plugin did not serve this entry as exec`);
      return { ok: false, reason: "not_served_as_exec", stage: "plugin_relay" };
    }
    if (this.config.relayPreverify) {
      const pre = await verifyDecision(ticket, {
        ticketType: TICKET_EXEC,
        supervisorId: this.relay.info?.supervisorId ?? undefined,
        now: this.now(),
        trustedDeviceIds: this.config.trustedDeviceIds,
        tsWindowMs: this.config.tsWindowMs,
        directory: this.directory,
        nonces: this.relayNonces,
        getPending: (id) => this.relay?.get(id) ?? null,
      });
      if (!pre.ok) {
        this.#rejectRelayed(pre.reason, ticket, meta);
        return { ok: false, reason: pre.reason, stage: "plugin_preverify" };
      }
    }
    let reply;
    try {
      reply = await this.relay.decide(ticket);
    } catch (e) {
      reply = { ok: false, reason: "wardend_unavailable", detail: String(/** @type {any} */ (e)?.message ?? e) };
    }
    // second signature (hw) and risk are forwarded to wardend as-is; journaled together with wardend response
    this.journal.append("relay_decision", { type: payload.type, supervisorId: payload.supervisorId, id: payload.id, digest: payload.digest, decision: payload.decision, deviceId: ticket.deviceId, ts: payload.ts, nonce: payload.nonce, risk: payload.risk, signature: ticket.signature, hw: ticket.hw, transport: meta.transport, wardend: reply });
    this.log.info(`[wardenclaw-gate] relay ${payload.decision.toUpperCase()} ${payload.id.slice(0, 11)} -> wardend: ${reply?.ok ? "ok" : reply?.reason}`);
    return { ...reply, relayed: true };
  }

  /**
   * Count and journal a decision for a wardend entry that the plugin refused to forward.
   * @param {string} reason
   * @param {import("./verify.js").DecisionBody} ticket
   * @param {{ transport: string }} meta
   * @param {Record<string, unknown>} [extra] fields appended to the journal entry
   */
  #rejectRelayed(reason, ticket, meta, extra = {}) {
    this.counters.rejectedDecisions += 1;
    this.journal.append("relay_rejected", { reason, transport: meta.transport, deviceId: ticket.deviceId, id: ticket.payload.id, digest: ticket.payload.digest, ...extra });
  }

  /**
   * Verify a signed GET request (pending/status).
   * @param {{ action: string, deviceId?: string, ts?: string | number, nonce?: string, signature?: string }} req
   */
  verifyRequest(req) {
    return verifySignedRequest(req, {
      now: this.now(),
      trustedDeviceIds: this.config.trustedDeviceIds,
      tsWindowMs: this.config.tsWindowMs,
      directory: this.directory,
      nonces: this.nonces,
    });
  }

  /** Record that the hook saw a tool call (coverage statistics). */
  recordSeen(toolName, toolKind, { agentId } = {}) {
    this.counters.seen += 1;
    const key = `${toolName}|${toolKind ?? ""}`;
    const stats = this.seenTools.get(key) ?? { toolName, toolKind: toolKind ?? null, count: 0, lastAt: 0, agents: {} };
    stats.count += 1;
    stats.lastAt = this.now();
    if (agentId) stats.agents[agentId] = (stats.agents[agentId] ?? 0) + 1;
    this.seenTools.set(key, stats);
  }

  /** Public pending snapshot for the client. */
  pendingSnapshot() {
    const own = this.store.listPending().map(clientRecord);
    const relayed = this.relay ? this.relay.pendingRecords() : [];
    return { seq: this.store.seq, mode: this.config.mode, pending: [...own, ...relayed], wardend: this.relay ? this.relay.summary() : null };
  }

  status() {
    return {
      protocol: PROTOCOL,
      minClient: MIN_CLIENT,
      mode: this.config.mode,
      ttlMs: this.config.ttlMs,
      tools: this.config.tools,
      trustedDeviceIds: this.config.trustedDeviceIds,
      startedAt: this.startedAt,
      counters: { ...this.counters },
      seenTools: [...this.seenTools.values()],
      pending: this.store.listPending().length,
      journalPublicKey: this.journal.publicKey ?? null,
      wardend: this.relay ? this.relay.summary() : null,
    };
  }

  /**
   * Shutdown (gateway_stop, including plugin reload): waiting calls immediately receive a block
   * (fail-closed) instead of hanging until TTL; their entries are not restored in the new instance,
   * so a phone signature can no longer reach them.
   */
  close() {
    this.relay?.stop();
    const rejected = this.store.close();
    if (rejected) this.log.warn(`[wardenclaw-gate] shutdown: ${rejected} pending call(s) rejected (plugin stopped)`);
  }
}

/**
 * Reason the agent gets when a call is blocked (hook blockReason, /wardenclaw/request response).
 * @param {string} outcome store.waitDecision outcome other than "allow"
 * @param {import("./store.js").PendingRecord | null} record
 * @param {number} ttlMs
 */
function blockReason(outcome, record, ttlMs) {
  switch (outcome) {
    case "deny":
      return `denied by device ${record?.deviceId?.slice(0, 12) ?? "?"}`;
    case "timeout":
      return `no signed decision within ${Math.round(ttlMs / 1000)} s`;
    case "aborted":
      return "call aborted";
    case "stopped":
      return "plugin stopped (reload or gateway shutdown), call rejected without a decision; retry it";
    default:
      return "gate entry not found";
  }
}

/** @param {import("./store.js").PendingRecord} r */
export function publicRecord(r) {
  return {
    id: r.id,
    digest: r.digest,
    toolName: r.toolName,
    toolKind: r.toolKind ?? null,
    toolInputKind: r.toolInputKind ?? null,
    paramsPreview: r.paramsPreview,
    command: r.command ?? null,
    filePath: r.filePath ?? null,
    agentId: r.agentId ?? null,
    sessionKey: r.sessionKey ?? null,
    runId: r.runId ?? null,
    toolCallId: r.toolCallId ?? null,
    source: r.source,
    mode: r.mode,
    createdAt: r.createdAt,
    expiresAt: r.expiresAt,
    status: r.status,
    decision: r.decision ?? null,
    deviceId: r.deviceId ?? null,
  };
}

/** Entries larger than this (JSON params) are not included in the feed: the phone cannot recompute the digest and will not be able to approve. */
export const CLIENT_CALL_MAX_BYTES = 512 * 1024;

/**
 * Client record: publicRecord plus call -- exactly the data covered by digest (toolCallDigest),
 * so the phone can recompute it and display what it is signing (crypto review 2026-09-28, finding 1).
 * call is not written to the journal. undefined fields vanish in JSON, same as in canonicalisation.
 * @param {import("./store.js").PendingRecord} r
 */
export function clientRecord(r) {
  const call = { toolName: r.toolName, params: r.params ?? {}, agentId: r.agentId, sessionKey: r.sessionKey, runId: r.runId, toolCallId: r.toolCallId };
  let size = Infinity;
  try {
    size = Buffer.byteLength(JSON.stringify(call.params) ?? "", "utf8");
  } catch {
    // params that cannot be serialised (BigInt, cycles) count as too large
  }
  return { ...publicRecord(r), kind: "tool", ...(size <= CLIENT_CALL_MAX_BYTES ? { call } : {}) };
}
