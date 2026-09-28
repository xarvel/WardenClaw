// SPDX-License-Identifier: Apache-2.0
// Canonical JSON and digest. Format is FIXED and matches
// app/src/core/canonical.ts: object keys are sorted, undefined
// is dropped, arrays preserve order, numbers/strings as JSON.stringify.
import { createHash } from "node:crypto";

/**
 * @param {unknown} v
 * @returns {string}
 */
export function canonicalJson(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const obj = /** @type {Record<string, unknown>} */ (v);
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

/** @param {string} s */
export function sha256Hex(s) {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

/**
 * Tool call digest: sha256(canonical JSON {toolName, params, agentId, sessionKey, runId, toolCallId}).
 * Missing fields (undefined) are not included in JSON; null is included.
 * @param {{toolName: string, params: unknown, agentId?: string, sessionKey?: string, runId?: string, toolCallId?: string}} call
 */
export function toolCallDigest(call) {
  return sha256Hex(
    canonicalJson({
      toolName: call.toolName,
      params: call.params ?? {},
      agentId: call.agentId,
      sessionKey: call.sessionKey,
      runId: call.runId,
      toolCallId: call.toolCallId,
    }),
  );
}

/** Ticket type: domain of the decision signing string for plugin tool calls. */
export const TICKET_TOOL = "wardenclaw.ticket.tool.v1";
/** Ticket type for wardend exec entries (with supervisorId): the plugin only relays these to wardend. */
export const TICKET_EXEC = "wardenclaw.ticket.exec.v1";

/**
 * String signed by the device for a decision:
 * canonicalJson({type, deviceId, id, digest, decision, ts, nonce[, supervisorId][, risk]}).
 * type separates plugin tool call decisions (TICKET_TOOL, no supervisorId) from wardend exec
 * decisions (TICKET_EXEC, server supervisorId): a signature for one is not valid for the other.
 * risk (0..100, app judge score) is optional; undefined is not included in the string.
 * @param {{type: string, supervisorId?: string, deviceId: string, id: string, digest: string, decision: string, ts: number, nonce: string, risk?: number}} p
 */
export function decisionSigningString(p) {
  return canonicalJson({ type: p.type, supervisorId: p.supervisorId, deviceId: p.deviceId, id: p.id, digest: p.digest, decision: p.decision, ts: p.ts, nonce: p.nonce, risk: p.risk });
}

/**
 * String signed by the device to authenticate GET requests (pending/status).
 * @param {{action: string, deviceId: string, ts: number, nonce: string}} p
 */
export function requestSigningString(p) {
  return canonicalJson({ action: p.action, deviceId: p.deviceId, ts: p.ts, nonce: p.nonce });
}
