// SPDX-License-Identifier: Apache-2.0
// Pending entry store: in-memory + pending.json snapshot in the plugin state dir
// (diagnostic only: not read on startup or reload, params are not written to it).
// Waiting handlers (enforce) and long-poll clients subscribe to changes.
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

/** Settled entries kept in memory for status and late decisions; pending entries are never pruned. */
const DEFAULT_MAX_KEEP = 200;
/** Debounce of the pending.json snapshot: a burst of changes is written once. */
const SAVE_DEBOUNCE_MS = 200;
/** Length limit of paramsPreview on a card. */
export const PREVIEW_MAX_CHARS = 4000;

/**
 * @typedef {{
 *   id: string, digest: string, toolName: string, toolKind?: string, toolInputKind?: string,
 *   params?: Record<string, unknown>,
 *   paramsPreview: string, command?: string, filePath?: string,
 *   agentId?: string, sessionKey?: string, runId?: string, toolCallId?: string,
 *   source: string, mode: "observe" | "enforce",
 *   createdAt: number, expiresAt: number,
 *   status: "pending" | "allowed" | "denied" | "expired" | "aborted" | "stopped",
 *   decision?: "allow" | "deny", decidedAt?: number, deviceId?: string, late?: boolean, seq: number
 * }} PendingRecord
 */

export class PendingStore {
  /**
   * @param {{ dir?: string, maxKeep?: number, now?: () => number }} [opts]
   */
  constructor(opts = {}) {
    this.dir = opts.dir ?? null;
    this.maxKeep = opts.maxKeep ?? DEFAULT_MAX_KEEP;
    this.now = opts.now ?? (() => Date.now());
    /** @type {Map<string, PendingRecord>} */
    this.records = new Map();
    /** @type {Map<string, Set<(r: PendingRecord) => void>>} */
    this.decisionWaiters = new Map();
    /** @type {Set<() => void>} */
    this.changeWaiters = new Set();
    this.seq = 0;
    this.saveTimer = null;
    /** plugin stopped (close): no point waiting for decisions */
    this.closed = false;
    if (this.dir) fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
  }

  /**
   * @param {Omit<PendingRecord, "id" | "createdAt" | "expiresAt" | "status" | "seq">} input
   * @param {number} ttlMs
   */
  create(input, ttlMs) {
    const now = this.now();
    /** @type {PendingRecord} */
    const rec = { ...input, id: randomUUID(), createdAt: now, expiresAt: now + ttlMs, status: "pending", seq: ++this.seq };
    this.records.set(rec.id, rec);
    this.#prune();
    this.#changed();
    return rec;
  }

  get(id) {
    return this.records.get(id) ?? null;
  }

  /** All entries in pending status whose TTL has not expired (expired ones are marked). */
  listPending() {
    this.expireStale();
    return [...this.records.values()].filter((r) => r.status === "pending").sort((a, b) => a.seq - b.seq);
  }

  /** All entries (for debug/status). */
  listAll() {
    return [...this.records.values()].sort((a, b) => a.seq - b.seq);
  }

  expireStale() {
    const now = this.now();
    let changed = false;
    for (const r of this.records.values()) {
      if (r.status === "pending" && r.expiresAt <= now) {
        this.#setStatus(r, "expired");
        changed = true;
        this.#notifyDecision(r);
      }
    }
    if (changed) this.#changed();
  }

  /**
   * Apply a decision. For an entry that is no longer pending (observe, expired), the decision
   * is recorded as late (for the journal) but the status does not change.
   * @param {string} id
   * @param {"allow" | "deny"} decision
   * @param {string} deviceId
   */
  decide(id, decision, deviceId) {
    const r = this.records.get(id);
    if (!r) return null;
    const late = r.status !== "pending";
    if (late) {
      // the entry is already settled: its first decision stays, the late one is only noted
      r.late = true;
      r.decision = r.decision ?? decision;
      r.decidedAt = r.decidedAt ?? this.now();
      r.deviceId = r.deviceId ?? deviceId;
      r.seq = ++this.seq;
    } else {
      r.decision = decision;
      r.decidedAt = this.now();
      r.deviceId = deviceId;
      this.#setStatus(r, decision === "allow" ? "allowed" : "denied");
      this.#notifyDecision(r);
    }
    this.#changed();
    return { record: r, late };
  }

  /** Mark a pending entry as aborted: the waiting call was cancelled through its AbortSignal. */
  markAborted(id) {
    const r = this.records.get(id);
    if (!r || r.status !== "pending") return;
    this.#setStatus(r, "aborted");
    this.#notifyDecision(r);
    this.#changed();
  }

  /**
   * Wait for a decision: resolves with the entry on decide/expire/abort/close.
   * @param {string} id
   * @param {{ signal?: AbortSignal, timeoutMs: number }} opts
   * @returns {Promise<{ outcome: "allow" | "deny" | "timeout" | "aborted" | "stopped" | "missing", record: PendingRecord | null }>}
   */
  waitDecision(id, opts) {
    const r = this.records.get(id);
    if (!r) return Promise.resolve({ outcome: "missing", record: null });
    // store already closed (call arrived in old instance during reload): do not wait for TTL
    if (this.closed && r.status === "pending") this.#setStatus(r, "stopped");
    if (r.status !== "pending") return Promise.resolve({ outcome: outcomeOf(r), record: r });
    return new Promise((resolve) => {
      let done = false;
      const finish = (outcome) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        opts.signal?.removeEventListener("abort", onAbort);
        this.decisionWaiters.get(id)?.delete(onDecision);
        resolve({ outcome, record: this.records.get(id) ?? null });
      };
      const onDecision = (rec) => finish(outcomeOf(rec));
      const onAbort = () => {
        this.markAborted(id);
        finish("aborted");
      };
      const timer = setTimeout(() => {
        const rec = this.records.get(id);
        if (rec && rec.status === "pending") {
          this.#setStatus(rec, "expired");
          this.#changed();
        }
        finish("timeout");
      }, opts.timeoutMs);
      if (!this.decisionWaiters.has(id)) this.decisionWaiters.set(id, new Set());
      this.decisionWaiters.get(id).add(onDecision);
      if (opts.signal) {
        if (opts.signal.aborted) onAbort();
        else opts.signal.addEventListener("abort", onAbort, { once: true });
      }
    });
  }

  /** External change (wardend relay): bump seq and wake long-poll clients. */
  touch() {
    this.seq += 1;
    this.#changed();
  }

  /**
   * Long-poll: wait until seq becomes greater than since (or timeout).
   * @param {number} since
   * @param {number} waitMs
   * @param {AbortSignal} [signal]
   */
  waitChange(since, waitMs, signal) {
    this.expireStale();
    if (this.seq > since) return Promise.resolve(true);
    return new Promise((resolve) => {
      let done = false;
      const finish = (v) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        this.changeWaiters.delete(onChange);
        signal?.removeEventListener("abort", onAbort);
        resolve(v);
      };
      const onChange = () => finish(true);
      const onAbort = () => finish(false);
      const timer = setTimeout(() => finish(false), waitMs);
      this.changeWaiters.add(onChange);
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  }

  #notifyDecision(rec) {
    const ws = this.decisionWaiters.get(rec.id);
    if (!ws) return;
    for (const w of [...ws]) w(rec);
    this.decisionWaiters.delete(rec.id);
  }

  #changed() {
    this.#wakeChangeWaiters();
    this.#scheduleSave();
  }

  #wakeChangeWaiters() {
    for (const w of [...this.changeWaiters]) w();
  }

  #prune() {
    if (this.records.size <= this.maxKeep) return;
    const done = [...this.records.values()].filter((r) => r.status !== "pending").sort((a, b) => a.seq - b.seq);
    for (const r of done) {
      if (this.records.size <= this.maxKeep) break;
      this.records.delete(r.id);
    }
  }

  /**
   * Status change; the new seq lets long-poll clients see it.
   * @param {PendingRecord} r
   * @param {PendingRecord["status"]} status
   */
  #setStatus(r, status) {
    r.status = status;
    r.seq = ++this.seq;
  }

  #scheduleSave() {
    // closed store does not write snapshot: pending.json is managed by the new instance after reload
    if (!this.dir || this.saveTimer || this.closed) return;
    this.saveTimer = setTimeout(() => {
      this.saveTimer = null;
      try {
        const file = path.join(this.dir, "pending.json");
        const tmp = `${file}.tmp`;
        // params (full call, may contain file contents) are kept in memory only
        const records = this.listAll().map(({ params, ...r }) => r);
        fs.writeFileSync(tmp, JSON.stringify({ savedAt: this.now(), seq: this.seq, records }), { mode: 0o600 });
        fs.renameSync(tmp, file);
      } catch {
        // the snapshot is diagnostic only: a failed write must not affect the gate
      }
    }, SAVE_DEBOUNCE_MS);
    this.saveTimer.unref?.();
  }

  /**
   * Plugin shutdown (gateway_stop, including reload): pending entries receive status "stopped",
   * waiting waitDecision calls immediately get outcome "stopped" (hook responds block, fail-closed)
   * instead of hanging until TTL. A decision arriving afterwards is late for the entry and does
   * not allow anything. Long-poll clients wake up. Repeated close is a no-op.
   * @returns {number} number of waiting calls rejected
   */
  close() {
    if (this.saveTimer) {
      clearTimeout(this.saveTimer);
      this.saveTimer = null;
    }
    if (this.closed) return 0;
    this.closed = true;
    let rejected = 0;
    for (const r of this.records.values()) {
      if (r.status !== "pending") continue;
      rejected += this.decisionWaiters.get(r.id)?.size ?? 0;
      this.#setStatus(r, "stopped");
      this.#notifyDecision(r);
    }
    this.#wakeChangeWaiters();
    return rejected;
  }
}

/** @param {PendingRecord} r */
function outcomeOf(r) {
  if (r.status === "allowed") return "allow";
  if (r.status === "denied") return "deny";
  if (r.status === "aborted") return "aborted";
  if (r.status === "stopped") return "stopped";
  return "timeout";
}

/**
 * Brief params summary for the card.
 * @param {string} toolName
 * @param {Record<string, unknown>} params
 */
export function summarizeParams(toolName, params) {
  const p = params && typeof params === "object" ? params : {};
  const str = (v) => (typeof v === "string" ? v : undefined);
  const command = str(p.command) ?? (Array.isArray(p.commandArgv) ? p.commandArgv.join(" ") : undefined) ?? str(p.cmd);
  const filePath = str(p.file_path) ?? str(p.path) ?? str(p.filePath) ?? str(p.notebook_path);
  let preview;
  if (command) preview = command;
  else if (filePath) preview = `${filePath}${typeof p.content === "string" ? ` (${p.content.length} chars)` : ""}`;
  else {
    try {
      preview = JSON.stringify(p);
    } catch {
      preview = String(p);
    }
  }
  return { command, filePath, paramsPreview: clip(preview ?? "", PREVIEW_MAX_CHARS) };
}

/** @param {string} s @param {number} n */
export function clip(s, n) {
  return s.length > n ? `${s.slice(0, n)}…(+${s.length - n})` : s;
}
