// SPDX-License-Identifier: Apache-2.0
// HTTP routes for the plugin (auth: "plugin" -- authentication is done here):
//   GET  /wardenclaw/pending?since=N&wait=MS   long-poll (up to 25 s), device signature in headers
//   GET  /wardenclaw/status                    stats/coverage, device signature in headers
//   POST /wardenclaw/decide                    {deviceId, payload:{id,digest,decision,ts,nonce[,risk]}, signature[, hw]}
//   POST /wardenclaw/request                   external caller (Claude Code PreToolUse), Bearer requestToken
// GET request signature: X-Wardenclaw-Device / -Ts / -Nonce / -Signature, string requestSigningString({action, deviceId, ts, nonce}).
// Additionally (requireDeviceToken): Authorization: Bearer <device-token> -- same token the device
// uses in connect.auth.deviceToken; matched against tokens_json in the gateway storage.
import { secretEquals } from "./crypto.js";

export const LONG_POLL_MAX_MS = 25_000;
const BODY_LIMIT = 256 * 1024;

/** @param {import("node:http").ServerResponse} res */
function sendJson(res, status, body) {
  res.statusCode = status;
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
  return true;
}

/**
 * Every refusal has the same shape: {ok: false, reason}.
 * @param {import("node:http").ServerResponse} res
 * @param {number} status
 * @param {string} reason
 */
function sendError(res, status, reason) {
  return sendJson(res, status, { ok: false, reason });
}

/**
 * Error of readJson (payload too large, invalid json) as a response.
 * @param {import("node:http").ServerResponse} res
 */
function sendBodyError(res, e) {
  return sendError(res, e?.status ?? 400, e?.message ?? "bad_request");
}

/**
 * Runs a long wait with a signal that aborts when the client disconnects.
 * @template T
 * @param {import("node:http").ServerResponse} res
 * @param {(signal: AbortSignal) => Promise<T>} wait
 * @returns {Promise<T>}
 */
async function abortOnClientClose(res, wait) {
  const ac = new AbortController();
  const onClose = () => ac.abort();
  res.on("close", onClose);
  try {
    return await wait(ac.signal);
  } finally {
    res.off("close", onClose);
  }
}

/** The client is gone or the response is already sent: nothing more to write. */
function responseClosed(res) {
  return res.writableEnded || res.destroyed;
}

/** @param {unknown} v */
function optionalString(v) {
  return typeof v === "string" ? v : undefined;
}

/** @param {import("node:http").IncomingMessage} req */
function readJson(req, limit = BODY_LIMIT) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) {
        reject(Object.assign(new Error("payload too large"), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      if (!text.trim()) return resolve(null);
      try {
        resolve(JSON.parse(text));
      } catch {
        reject(Object.assign(new Error("invalid json"), { status: 400 }));
      }
    });
    req.on("error", reject);
  });
}

/** @param {import("node:http").IncomingMessage} req */
function bearer(req) {
  const h = req.headers.authorization;
  if (typeof h !== "string") return null;
  const m = /^Bearer\s+(.+)$/i.exec(h.trim());
  return m ? m[1].trim() : null;
}

/** @param {import("node:http").IncomingMessage} req */
function header(req, name) {
  const v = req.headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

/**
 * @param {{ gate: import("./gate.js").Gate, config: import("./config.js").GateConfig, logger: { warn(m: string): void, info(m: string): void } }} deps
 */
export function createHttpHandlers({ gate, config, logger }) {
  /**
   * Bearer = paired device token (if requireDeviceToken).
   * @param {import("node:http").IncomingMessage} req
   * @param {string} deviceId
   */
  async function checkDeviceToken(req, deviceId) {
    if (!config.requireDeviceToken) return { ok: true };
    const token = bearer(req);
    if (!token) return { ok: false, reason: "device_token_missing" };
    const device = await gate.directory.getDevice(deviceId);
    if (!device) return { ok: false, reason: "unknown_device" };
    if (!device.tokens.length) return { ok: false, reason: "device_token_unavailable" };
    return device.tokens.some((known) => secretEquals(known, token)) ? { ok: true } : { ok: false, reason: "device_token_mismatch" };
  }

  /** Authenticate a signed GET: signature in headers + device token. */
  async function authSignedGet(req, action) {
    const verified = await gate.verifyRequest({
      action,
      deviceId: header(req, "x-wardenclaw-device"),
      ts: header(req, "x-wardenclaw-ts"),
      nonce: header(req, "x-wardenclaw-nonce"),
      signature: header(req, "x-wardenclaw-signature"),
    });
    if (!verified.ok) return verified;
    const token = await checkDeviceToken(req, verified.deviceId);
    if (!token.ok) return token;
    return verified;
  }

  /** @type {(req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => Promise<boolean>} */
  async function pending(req, res) {
    if (req.method !== "GET") return sendError(res, 405, "method_not_allowed");
    const auth = await authSignedGet(req, "pending");
    if (!auth.ok) return sendError(res, 401, auth.reason);
    const url = new URL(req.url ?? "/", "http://localhost");
    const since = Math.max(0, Number(url.searchParams.get("since") ?? 0) || 0);
    const wait = Math.min(LONG_POLL_MAX_MS, Math.max(0, Number(url.searchParams.get("wait") ?? LONG_POLL_MAX_MS) || 0));
    await abortOnClientClose(res, (signal) => gate.store.waitChange(since, wait, signal));
    if (responseClosed(res)) return true;
    return sendJson(res, 200, { ok: true, ...gate.pendingSnapshot(), now: gate.now() });
  }

  async function status(req, res) {
    if (req.method !== "GET") return sendError(res, 405, "method_not_allowed");
    const auth = await authSignedGet(req, "status");
    if (!auth.ok) return sendError(res, 401, auth.reason);
    return sendJson(res, 200, { ok: true, ...gate.status(), now: gate.now() });
  }

  async function decide(req, res) {
    if (req.method !== "POST") return sendError(res, 405, "method_not_allowed");
    let body;
    try {
      body = await readJson(req);
    } catch (e) {
      return sendBodyError(res, e);
    }
    const deviceId = body && typeof body === "object" && typeof body.deviceId === "string" ? body.deviceId : "";
    const token = await checkDeviceToken(req, deviceId);
    if (!token.ok) return sendError(res, 401, token.reason);
    const result = await gate.decide(body, { transport: "http" });
    return sendJson(res, result.ok ? 200 : 403, result);
  }

  /**
   * External caller: creates a pending entry and (enforce) waits for a decision. For the Claude Code PreToolUse hook.
   * Body: {toolName, params, agentId?, sessionKey?, runId?, toolCallId?, source?, wait?: boolean}
   */
  async function request(req, res) {
    if (req.method !== "POST") return sendError(res, 405, "method_not_allowed");
    if (!config.requestToken) return sendError(res, 403, "request_route_disabled");
    const token = bearer(req);
    if (!token || !secretEquals(token, config.requestToken)) return sendError(res, 401, "request_token_invalid");
    let body;
    try {
      body = await readJson(req);
    } catch (e) {
      return sendBodyError(res, e);
    }
    if (!body || typeof body !== "object" || typeof body.toolName !== "string" || !body.toolName) return sendError(res, 400, "tool_name_missing");
    const agentId = optionalString(body.agentId);
    if (agentId && config.exemptAgents.includes(agentId)) return sendJson(res, 200, { ok: true, decision: "exempt", mode: config.mode });
    const rec = gate.createPending({
      toolName: body.toolName,
      params: body.params && typeof body.params === "object" ? body.params : {},
      toolKind: optionalString(body.toolKind),
      agentId,
      sessionKey: optionalString(body.sessionKey),
      runId: optionalString(body.runId),
      toolCallId: optionalString(body.toolCallId),
      source: optionalString(body.source) ?? "external",
    });
    if (config.mode === "observe" || body.wait === false) {
      gate.counters.observed += 1;
      return sendJson(res, 200, { ok: true, id: rec.id, digest: rec.digest, decision: "observe", mode: config.mode, expiresAt: rec.expiresAt });
    }
    const result = await abortOnClientClose(res, (signal) => gate.waitDecision(rec.id, { signal }));
    if (responseClosed(res)) return true;
    return sendJson(res, 200, { ok: true, id: rec.id, digest: rec.digest, decision: result.allow ? "allow" : "deny", outcome: result.outcome, reason: result.reason ?? null, mode: config.mode });
  }

  return { pending, status, decide, request };
}
