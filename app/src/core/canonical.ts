// SPDX-License-Identifier: GPL-3.0-or-later
// Canonical JSON and signing strings. The format is FROZEN (protocol/README.md): object keys are
// sorted, undefined is dropped, arrays keep their order, numbers/strings as JSON.stringify. Change
// only in sync with wardend and the vectors in protocol/vectors.
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

export type GateDecision = "allow" | "deny";

/** Ticket type is the signing string domain: a wardend exec record; the signature is also bound to the server's supervisorId. */
export const TICKET_EXEC = "wardenclaw.ticket.exec.v1";

/** What we sign: an exec ticket for a specific wardend. A signature for one server does not fit another. */
export type TicketScope = { type: typeof TICKET_EXEC; supervisorId: string };

/** risk (0..100): optional judge score; if present, it is part of the signing string (format: protocol/HARDWARE.md). */
export type DecisionPayload = { type: TicketScope["type"]; supervisorId: string; id: string; digest: string; decision: GateDecision; ts: number; nonce: string; risk?: number };

/** String the device signs for a decision: canonicalJson({type, supervisorId, deviceId, id, digest, decision, ts, nonce[, risk]}). */
export function decisionSigningString(p: DecisionPayload & { deviceId: string }): string {
  return canonicalJson({ type: p.type, supervisorId: p.supervisorId, deviceId: p.deviceId, id: p.id, digest: p.digest, decision: p.decision, ts: p.ts, nonce: p.nonce, risk: p.risk });
}
