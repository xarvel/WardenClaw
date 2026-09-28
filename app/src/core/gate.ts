// SPDX-License-Identifier: GPL-3.0-or-later
// Pending records of wardend's exec gate and the signed decision (ticket) the phone answers with:
//   {deviceId, payload:{type,supervisorId,id,digest,decision,ts,nonce[,risk]}, signature[, hw]}
// Signed with the Ed25519 device key (identity.ts); string format in canonical.ts.
import { randomUUID } from "expo-crypto";
import { DeviceIdentity, signPayload } from "./identity";
import { DecisionPayload, GateDecision, TicketScope, decisionSigningString } from "./canonical";
import { HardwareAssertion, HardwareSigner, assertionRequest } from "./hardware";
export { checkExecPending, type ExecCheck } from "./execEnvelope";

export type GatePending = {
  /** A wardend supervisor record (seccomp execve gate); id "wd-…". */
  kind: "exec";
  /** The v1 envelope (signed as digest = sha256(canonicalJson(envelope))). */
  envelope?: unknown;
  /** wardend policy class (root | delegating), rule, explanation. Not signed. */
  meta?: Record<string, unknown>;
  id: string;
  digest: string;
  createdAt: number;
  expiresAt: number;
};

export type GateDecideResponse = { ok: boolean; reason?: string; id?: string; decision?: GateDecision; late?: boolean; status?: string; hardwareRule?: string };

/** Decision body: the device signature and (for high risk) a second YubiKey signature. */
export type SignedDecision = { deviceId: string; payload: DecisionPayload; signature: string; hw?: HardwareAssertion };
/** The entry the decision is signed for, and the ticket scope (exec + supervisorId). */
export type DecisionTarget = { id: string; digest: string; ticket: TicketScope };

/**
 * Sign a decision for a pending entry. Returns the ticket sent to wardend through the relay.
 * The ticket type and supervisorId are part of the signed string; risk (0..100) if set (wardend
 * score rules).
 */
export function signDecision(identity: DeviceIdentity, pending: DecisionTarget, decision: GateDecision, now = Date.now(), risk?: number): SignedDecision {
  const payload: DecisionPayload = { type: pending.ticket.type, supervisorId: pending.ticket.supervisorId, id: pending.id, digest: pending.digest, decision, ts: now, nonce: randomUUID() };
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
