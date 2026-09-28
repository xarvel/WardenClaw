// SPDX-License-Identifier: Apache-2.0
// Relay to wardend supervisor (OS-level seccomp execve gate).
//
// The plugin is a dumb transport over the existing gateway tunnel: the app hits
// /wardenclaw/pending and /wardenclaw/decide as usual, while wardend exec entries (id "wd-...")
// appear in the same list and decisions are forwarded to wardend via its unix socket
// (JSON-RPC 2.0, one message per line). SIGNATURE VERIFICATION STAYS IN WARDEND: it decides
// whether to allow the execve. The plugin may verify the signature in advance (relayPreverify)
// as an early rejection only, not as a trust source.
//
// The background loop maintains a long-poll `pending` to wardend and calls onChange() on every
// change (the plugin bumps its store seq, waking waiting long-poll app clients).
//
// The protocol version of wardend is checked via RPC status on each connection and at least once
// every PROTOCOL_RECHECK_MS: on a mismatch, decisions for exec entries are not forwarded
// (response: wardend_protocol_mismatch); the reason is logged and exposed in summary()
// (plugin status, wardend.error).
import fs from "node:fs";
import net from "node:net";
import { MIN_SERVER_PROTOCOL, PROTOCOL, checkServerProtocol } from "./protocol.js";
import { PREVIEW_MAX_CHARS, clip } from "./store.js";

export const RELAY_ID_PREFIX = "wd-";
/** how long to remember that an entry was served as exec after its expiry (wardend and plugin clocks) */
const SERVED_GRACE_MS = 60_000;
/** how often to re-check the protocol version of the connected wardend */
const PROTOCOL_RECHECK_MS = 60_000;
/** long-poll wait asked of wardend, and the RPC timeout that leaves room for its reply */
const LONG_POLL_WAIT_MS = 25_000;
const LONG_POLL_TIMEOUT_MS = 35_000;
/** timeout of decide (and of rpcCall by default) */
const RPC_TIMEOUT_MS = 10_000;
/** timeout of the quick calls: status and a one-off pending */
const QUICK_RPC_TIMEOUT_MS = 5000;
/** pause before the next attempt while wardend is absent or failing */
const RETRY_MS = 2000;
export const PROTOCOL_MISMATCH = "wardend_protocol_mismatch";

/**
 * Human-readable mismatch description for the log and status.
 * @param {ReturnType<typeof checkServerProtocol>} p
 */
function mismatchText(p) {
  if (p.mismatch === "server_too_old") {
    const has = p.protocol === null ? "does not report a protocol version" : `speaks protocol ${p.protocol}`;
    return `wardend ${has}, but the plugin relay requires wardend protocol ${MIN_SERVER_PROTOCOL} or newer: update wardend. Decisions for its requests are not forwarded`;
  }
  return `wardend requires clients on protocol ${p.minClient} or newer, but the plugin speaks protocol ${PROTOCOL}: update the wardenclaw-gate plugin. Decisions for wardend requests are not forwarded`;
}

/** @param {string} id */
export function isRelayId(id) {
  return typeof id === "string" && id.startsWith(RELAY_ID_PREFIX);
}

/**
 * Single JSON-RPC call over a separate connection.
 * @param {string} socketPath
 * @param {string} method
 * @param {unknown} params
 * @param {{ timeoutMs?: number }} [opts]
 */
export function rpcCall(socketPath, method, params, opts = {}) {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection(socketPath);
    let buf = "";
    let settled = false;
    const finish = (err, val) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.destroy();
      err ? reject(err) : resolve(val);
    };
    const timer = setTimeout(() => finish(new Error(`wardend ${method}: timeout`)), opts.timeoutMs ?? RPC_TIMEOUT_MS);
    sock.setEncoding("utf8");
    sock.on("connect", () => sock.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: params ?? {} }) + "\n"));
    sock.on("data", (d) => {
      buf += d;
      const i = buf.indexOf("\n");
      if (i < 0) return;
      try {
        const msg = JSON.parse(buf.slice(0, i));
        if (msg.error) finish(new Error(`wardend ${method}: ${msg.error.message}`));
        else finish(null, msg.result);
      } catch (e) {
        finish(e);
      }
    });
    sock.on("error", (e) => finish(e));
    sock.on("close", () => finish(new Error(`wardend ${method}: connection closed`)));
  });
}

/**
 * wardend exec entry -> plugin pending entry shape (plus envelope fields).
 * Old app versions will see a "wardend.exec" card with the command; new versions will render
 * the envelope (argv/cwd/exe/chain) and recompute the digest before signing.
 * @param {any} entry
 */
export function publicExecRecord(entry) {
  const env = entry?.envelope ?? {};
  const argv = Array.isArray(env.argv) ? env.argv.map(String) : [];
  const command = argv.join(" ");
  return {
    id: String(entry.id),
    kind: "exec",
    digest: String(entry.digest),
    envelope: env,
    meta: entry.meta ?? {},
    toolName: "wardend.exec",
    toolKind: "exec",
    toolInputKind: null,
    paramsPreview: clip(command, PREVIEW_MAX_CHARS),
    command,
    filePath: null,
    agentId: null,
    sessionKey: null,
    runId: null,
    toolCallId: null,
    source: "wardend",
    mode: "enforce",
    createdAt: Number(entry.createdAt) || 0,
    expiresAt: Number(entry.expiresAt) || 0,
    status: "pending",
    decision: null,
    deviceId: null,
  };
}

export class WardendRelay {
  /**
   * @param {{ socketPath: string, logger?: { info(m: string): void, warn(m: string): void }, onChange?: () => void, rpc?: typeof rpcCall, retryMs?: number }} opts
   */
  constructor(opts) {
    this.socketPath = opts.socketPath;
    this.log = opts.logger ?? console;
    this.onChange = opts.onChange ?? (() => {});
    this.rpc = opts.rpc ?? rpcCall;
    this.retryMs = opts.retryMs ?? RETRY_MS;
    /** @type {Map<string, any>} id -> wardend entry */
    this.items = new Map();
    this.seq = 0;
    this.connected = false;
    this.info = null; // {supervisorId, host, mode}
    this.stopped = true;
    this.lastError = null;
    /** @type {Map<string, number>} ids served to the client as exec -> expiry timestamp (ms) */
    this.served = new Map();
    /** last protocol version check for the connected wardend; null means not yet checked since connect */
    this.proto = null;
  }

  available() {
    try {
      return fs.statSync(this.socketPath).isSocket();
    } catch {
      return false;
    }
  }

  start() {
    if (!this.stopped) return;
    this.stopped = false;
    void this.#loop();
  }

  stop() {
    this.stopped = true;
  }

  async #loop() {
    while (!this.stopped) {
      if (!this.available()) {
        this.#setItems([], false);
        await sleep(this.retryMs);
        continue;
      }
      try {
        if (!this.connected || this.#protoStale()) await this.checkProtocol();
        const r = await this.rpc(this.socketPath, "pending", { since: this.seq, wait: LONG_POLL_WAIT_MS }, { timeoutMs: LONG_POLL_TIMEOUT_MS });
        if (!this.connected) this.log.info(`[wardenclaw-gate] relay: wardend connected (${this.socketPath})`);
        this.lastError = null;
        this.#applyPending(r);
      } catch (e) {
        // the same error again (wardend is down, its socket file left behind) is logged once
        const message = String(e?.message ?? e);
        if (this.connected || this.lastError !== message) this.log.warn(`[wardenclaw-gate] relay: ${message}`);
        this.lastError = message;
        this.seq = 0;
        this.proto = null; // re-check version after reconnect: wardend may have been updated
        this.#setItems([], false);
        await sleep(this.retryMs);
      }
    }
  }

  /** Fetch the list once, without the background loop (tests). */
  async refresh() {
    await this.checkProtocol();
    const r = await this.rpc(this.socketPath, "pending", {}, { timeoutMs: QUICK_RPC_TIMEOUT_MS });
    this.#applyPending(r);
    return r;
  }

  /** Take in a wardend `pending` reply: supervisor info, seq for the next long-poll, entries. */
  #applyPending(r) {
    this.info = { supervisorId: r?.supervisorId ?? null, host: r?.host ?? null, mode: r?.mode ?? null };
    this.seq = Number(r?.seq) || 0;
    this.#setItems(Array.isArray(r?.pending) ? r.pending : [], true);
  }

  #setItems(list, connected) {
    const before = [...this.items.keys()].sort().join(",");
    this.items = new Map(list.filter((x) => x && isRelayId(x.id)).map((x) => [x.id, x]));
    const changed = before !== [...this.items.keys()].sort().join(",") || this.connected !== connected;
    this.connected = connected;
    if (changed) this.onChange();
  }

  /** Entries for /wardenclaw/pending. Served ids are remembered: decisions are only forwarded for them. */
  pendingRecords() {
    const out = [...this.items.values()].map(publicExecRecord).sort((a, b) => a.createdAt - b.createdAt);
    const now = Date.now();
    for (const [id, until] of this.served) if (until < now) this.served.delete(id);
    for (const r of out) this.served.set(r.id, Math.max(now, r.expiresAt) + SERVED_GRACE_MS);
    return out;
  }

  /**
   * Whether the plugin served this entry to the client as kind "exec" (pendingRecords). A decision
   * for a "wd-..." entry the plugin never showed as exec (e.g. its id was injected into a tool card
   * or was never in the feed) is not forwarded to wardend.
   * @param {string} id
   */
  servedAsExec(id) {
    const until = this.served.get(id);
    return until !== undefined && until >= Date.now();
  }

  /** digest of a pending entry (for optional pre-verification of the signature in the plugin). */
  get(id) {
    const it = this.items.get(id);
    return it ? { digest: String(it.digest) } : null;
  }

  /**
   * wardend protocol version via RPC status: {protocol, minClient, mismatch, error, errorText,
   * checkedAt}. Mismatch is logged when first detected and when it changes. RPC error throws.
   */
  async checkProtocol() {
    const p = checkServerProtocol(await this.rpc(this.socketPath, "status", {}, { timeoutMs: QUICK_RPC_TIMEOUT_MS }));
    const errorText = p.mismatch ? mismatchText(p) : null;
    if (errorText && errorText !== this.proto?.errorText) this.log.warn(`[wardenclaw-gate] relay: ${errorText}`);
    if (!errorText && this.proto?.errorText) this.log.info(`[wardenclaw-gate] relay: wardend protocol version (${p.protocol}) is compatible again`);
    this.proto = { ...p, error: p.mismatch ? PROTOCOL_MISMATCH : null, errorText, checkedAt: Date.now() };
    return this.proto;
  }

  #protoStale() {
    return !this.proto || Date.now() - this.proto.checkedAt > PROTOCOL_RECHECK_MS;
  }

  /**
   * Forward a signed decision. Returns wardend response {ok, reason?, id?, decision?}; on
   * protocol version mismatch, the decision is not forwarded: {ok: false, reason:
   * "wardend_protocol_mismatch"}.
   */
  async decide(body) {
    const proto = this.#protoStale() ? await this.checkProtocol() : this.proto;
    if (proto.error) return { ok: false, reason: proto.error, detail: proto.errorText };
    const r = await this.rpc(this.socketPath, "decide", body, { timeoutMs: RPC_TIMEOUT_MS });
    // wardend already removed the entry; update the cache immediately without waiting for long-poll
    if (r?.ok) {
      const id = body?.payload?.id;
      if (id && this.items.delete(id)) this.onChange();
    }
    return r ?? { ok: false, reason: "empty_response" };
  }

  /** Relay state for plugin status: protocol and minClient are from the connected wardend. */
  summary() {
    const p = this.proto;
    return {
      socket: this.socketPath,
      connected: this.connected,
      pending: this.items.size,
      lastError: this.lastError,
      ...(this.info ?? {}),
      protocol: p?.protocol ?? null,
      minClient: p?.minClient ?? null,
      error: p?.error ?? null,
      errorText: p?.errorText ?? null,
    };
  }
}

function sleep(ms) {
  return new Promise((r) => {
    const t = setTimeout(r, ms);
    t.unref?.();
  });
}
