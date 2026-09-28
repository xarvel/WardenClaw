// SPDX-License-Identifier: GPL-3.0-or-later
// Canonical JSON and signing strings. The format is FROZEN and matches the plugin
// (plugin/src/canonical.js): object keys are sorted, undefined is dropped, arrays keep their
// order, numbers/strings as JSON.stringify. Change only in sync with the plugin.
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, utf8Encode } from "./bytes";

export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const obj = v as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

export function sha256Hex(s: string): string {
  return bytesToHex(sha256(utf8Encode(s)));
}

/** Tool call digest: the plugin computes it, the app recomputes it from the record's call and does not allow without a match. */
export function toolCallDigest(call: { toolName: string; params: unknown; agentId?: string | null; sessionKey?: string | null; runId?: string | null; toolCallId?: string | null }): string {
  return sha256Hex(canonicalJson({ toolName: call.toolName, params: call.params ?? {}, agentId: call.agentId, sessionKey: call.sessionKey, runId: call.runId, toolCallId: call.toolCallId }));
}

export type GateDecision = "allow" | "deny";

/** Ticket type is the signing string domain: a decision on a gateway plugin tool call. */
export const TICKET_TOOL = "wardenclaw.ticket.tool.v1";
/** Ticket type of a wardend exec record: the signature is also bound to the server's supervisorId. */
export const TICKET_EXEC = "wardenclaw.ticket.exec.v1";

/** What we sign: a tool ticket for the plugin or an exec ticket for a specific wardend. A signature for one does not fit the other. */
export type TicketScope = { type: typeof TICKET_TOOL } | { type: typeof TICKET_EXEC; supervisorId: string };

/** risk (0..100): optional judge score; if present, it is part of the signing string (format: protocol/HARDWARE.md). */
export type DecisionPayload = { type: TicketScope["type"]; supervisorId?: string; id: string; digest: string; decision: GateDecision; ts: number; nonce: string; risk?: number };

/** String the device signs for a decision: canonicalJson({type, deviceId, id, digest, decision, ts, nonce[, supervisorId][, risk]}). */
export function decisionSigningString(p: DecisionPayload & { deviceId: string }): string {
  return canonicalJson({ type: p.type, supervisorId: p.supervisorId, deviceId: p.deviceId, id: p.id, digest: p.digest, decision: p.decision, ts: p.ts, nonce: p.nonce, risk: p.risk });
}

/** String the device signs to authenticate GET requests (pending/status). */
export function requestSigningString(p: { action: string; deviceId: string; ts: number; nonce: string }): string {
  return canonicalJson({ action: p.action, deviceId: p.deviceId, ts: p.ts, nonce: p.nonce });
}

/** Request with a JSON body (push.register, push.unregister): the signature covers the body too (protocol/README.md, section 5). */
export function requestBodySigningString(p: { action: string; deviceId: string; ts: number; nonce: string; body: Record<string, unknown> }): string {
  return canonicalJson({ action: p.action, body: p.body, deviceId: p.deviceId, ts: p.ts, nonce: p.nonce });
}
