// SPDX-License-Identifier: Apache-2.0
// Verification of signed device decisions and signed GET requests.
import { decisionSigningString, requestSigningString, TICKET_EXEC, TICKET_TOOL } from "./canonical.js";
import { publicKeyMatchesDeviceId, verifyEd25519 } from "./crypto.js";
import { HARDWARE_KEY } from "./features.js";

/** deviceId, supervisorId, digest: lowercase hex of 32 bytes */
const HEX64 = /^[0-9a-f]{64}$/;
const NONCE_MIN_LENGTH = 8;
const NONCE_MAX_LENGTH = 128;
/** app judge score range, inclusive */
const RISK_MAX = 100;
/** fields of the hw assertion: base64 or base64url, bounded in length */
const HW_FIELD_MAX_LENGTH = 8192;
const HW_FIELD_CHARS = /^[A-Za-z0-9_\-+/=]+$/;
/** above this many remembered nonces, claim() first drops the expired ones */
const NONCE_SWEEP_THRESHOLD = 5000;

/** @param {unknown} v */
function isHex64(v) {
  return typeof v === "string" && HEX64.test(v);
}

/** @param {unknown} v */
function isValidNonce(v) {
  return typeof v === "string" && v.length >= NONCE_MIN_LENGTH && v.length <= NONCE_MAX_LENGTH;
}

/** Nonce cache: uniqueness within a window (2 x tsWindowMs), per device. */
export class NonceCache {
  /** @param {{ windowMs: number, now?: () => number }} opts */
  constructor(opts) {
    this.windowMs = opts.windowMs;
    this.now = opts.now ?? (() => Date.now());
    /** @type {Map<string, number>} key = deviceId + "\n" + nonce -> expiresAt */
    this.seen = new Map();
  }
  /** Returns true if the nonce is new (and is now claimed). */
  claim(deviceId, nonce) {
    const now = this.now();
    if (this.seen.size > NONCE_SWEEP_THRESHOLD) this.sweep(now);
    const key = `${deviceId}\n${nonce}`;
    const exp = this.seen.get(key);
    if (exp !== undefined && exp > now) return false;
    this.seen.set(key, now + 2 * this.windowMs);
    return true;
  }
  sweep(now = this.now()) {
    for (const [k, exp] of this.seen) if (exp <= now) this.seen.delete(k);
  }
}

/**
 * @typedef {{ credentialId: string, clientDataJSON: string, authenticatorData: string, signature: string }} HardwareAssertion
 * @typedef {{ deviceId: string, payload: { type: string, supervisorId?: string, id: string, digest: string, decision: "allow" | "deny", ts: number, nonce: string, risk?: number }, signature: string, hw?: HardwareAssertion }} DecisionBody
 */

const HW_FIELDS = ["credentialId", "clientDataJSON", "authenticatorData", "signature"];

/**
 * Second factor (FIDO2 assertion YubiKey): the plugin does NOT verify it -- only the form is
 * checked, then it is forwarded to wardend as-is (relay). Key, challenge, and signCount
 * verification happens in wardend.
 * @param {unknown} v
 * @returns {HardwareAssertion | null}
 */
function parseHardware(v) {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const o = /** @type {Record<string, unknown>} */ (v);
  const out = /** @type {Record<string, string>} */ ({});
  for (const k of HW_FIELDS) {
    const x = o[k];
    if (typeof x !== "string" || !x || x.length > HW_FIELD_MAX_LENGTH || !HW_FIELD_CHARS.test(x)) return null;
    out[k] = x;
  }
  return /** @type {HardwareAssertion} */ (out);
}

/**
 * Parse the decision body without trusting types.
 * @param {unknown} body
 * @returns {{ ok: true, value: DecisionBody } | { ok: false, reason: string }}
 */
export function parseDecisionBody(body) {
  const b = body && typeof body === "object" ? /** @type {Record<string, unknown>} */ (body) : null;
  if (!b) return { ok: false, reason: "body_not_object" };
  const p = b.payload && typeof b.payload === "object" ? /** @type {Record<string, unknown>} */ (b.payload) : null;
  if (!p) return { ok: false, reason: "payload_missing" };
  if (!isHex64(b.deviceId)) return { ok: false, reason: "device_id_invalid" };
  if (typeof b.signature !== "string" || !b.signature) return { ok: false, reason: "signature_missing" };
  if (p.type !== TICKET_TOOL && p.type !== TICKET_EXEC) return { ok: false, reason: "type_invalid" };
  // supervisorId is only present in wardend exec tickets
  const supervisorIdValid = p.type === TICKET_EXEC ? isHex64(p.supervisorId) : p.supervisorId === undefined;
  if (!supervisorIdValid) return { ok: false, reason: "supervisor_id_invalid" };
  if (typeof p.id !== "string" || !p.id) return { ok: false, reason: "id_missing" };
  if (!isHex64(p.digest)) return { ok: false, reason: "digest_invalid" };
  if (p.decision !== "allow" && p.decision !== "deny") return { ok: false, reason: "decision_invalid" };
  if (typeof p.ts !== "number" || !Number.isFinite(p.ts)) return { ok: false, reason: "ts_invalid" };
  if (!isValidNonce(p.nonce)) return { ok: false, reason: "nonce_invalid" };
  if (p.risk !== undefined && !(Number.isInteger(p.risk) && p.risk >= 0 && p.risk <= RISK_MAX)) return { ok: false, reason: "risk_invalid" };
  let hw;
  if (b.hw !== undefined) {
    // second factor is disabled (features.js): YubiKey signature is not silently dropped
    if (!HARDWARE_KEY) return { ok: false, reason: "hw_not_in_release" };
    const h = parseHardware(b.hw);
    if (!h) return { ok: false, reason: "hw_invalid" };
    hw = h;
  }
  /** @type {DecisionBody} */
  const value = { deviceId: b.deviceId, payload: { type: p.type, id: p.id, digest: p.digest, decision: p.decision, ts: p.ts, nonce: p.nonce }, signature: b.signature };
  if (p.type === TICKET_EXEC) value.payload.supervisorId = /** @type {string} */ (p.supervisorId);
  if (p.risk !== undefined) value.payload.risk = /** @type {number} */ (p.risk);
  if (hw) value.hw = hw;
  return { ok: true, value };
}

/**
 * Full decision verification. Order matters: nonce is claimed only AFTER signature verification,
 * otherwise an unauthenticated request could burn someone else's nonce.
 * Only tickets of type ctx.ticketType are accepted (default TICKET_TOOL: plugin tool call decisions);
 * ctx.supervisorId, if provided, must match the supervisorId in the ticket.
 * @param {unknown} body
 * @param {{
 *   ticketType?: string,
 *   supervisorId?: string,
 *   now: number,
 *   trustedDeviceIds: string[],
 *   tsWindowMs: number,
 *   directory: { getDevice(id: string): Promise<{ publicKey: string } | null> },
 *   nonces: NonceCache,
 *   getPending: (id: string) => { digest: string } | null,
 * }} ctx
 * @returns {Promise<{ ok: true, body: DecisionBody, publicKey: string } | { ok: false, reason: string, body?: DecisionBody }>}
 */
export async function verifyDecision(body, ctx) {
  const parsed = parseDecisionBody(body);
  if (!parsed.ok) return { ok: false, reason: parsed.reason };
  const b = parsed.value;
  if (b.payload.type !== (ctx.ticketType ?? TICKET_TOOL)) return { ok: false, reason: "ticket_type_mismatch", body: b };
  if (ctx.supervisorId !== undefined && b.payload.supervisorId !== ctx.supervisorId) return { ok: false, reason: "supervisor_mismatch", body: b };
  if (!ctx.trustedDeviceIds.includes(b.deviceId)) return { ok: false, reason: "untrusted_device", body: b };
  const device = await ctx.directory.getDevice(b.deviceId);
  if (!device) return { ok: false, reason: "unknown_device", body: b };
  // key does not belong to this device (sha256(key) != deviceId): gateway DB substitution or config error
  if (!publicKeyMatchesDeviceId(device.publicKey, b.deviceId)) return { ok: false, reason: "pubkey_id_mismatch", body: b };
  if (Math.abs(ctx.now - b.payload.ts) > ctx.tsWindowMs) return { ok: false, reason: "stale_timestamp", body: b };
  const msg = decisionSigningString({ deviceId: b.deviceId, ...b.payload });
  if (!verifyEd25519(msg, b.signature, device.publicKey)) return { ok: false, reason: "bad_signature", body: b };
  if (!ctx.nonces.claim(b.deviceId, b.payload.nonce)) return { ok: false, reason: "nonce_reused", body: b };
  const pending = ctx.getPending(b.payload.id);
  if (!pending) return { ok: false, reason: "unknown_pending", body: b };
  if (pending.digest !== b.payload.digest) return { ok: false, reason: "digest_mismatch", body: b };
  return { ok: true, body: b, publicKey: device.publicKey };
}

/**
 * Verify a signed request (GET pending/status): from headers or query.
 * @param {{ action: string, deviceId?: string, ts?: string | number, nonce?: string, signature?: string }} req
 * @param {{ now: number, trustedDeviceIds: string[], tsWindowMs: number, directory: { getDevice(id: string): Promise<{ publicKey: string } | null> }, nonces: NonceCache }} ctx
 */
export async function verifySignedRequest(req, ctx) {
  const deviceId = typeof req.deviceId === "string" ? req.deviceId : "";
  const ts = typeof req.ts === "number" ? req.ts : Number(req.ts);
  const nonce = typeof req.nonce === "string" ? req.nonce : "";
  const signature = typeof req.signature === "string" ? req.signature : "";
  if (!isHex64(deviceId)) return { ok: false, reason: "device_id_invalid" };
  if (!Number.isFinite(ts)) return { ok: false, reason: "ts_invalid" };
  if (!isValidNonce(nonce)) return { ok: false, reason: "nonce_invalid" };
  if (!signature) return { ok: false, reason: "signature_missing" };
  if (!ctx.trustedDeviceIds.includes(deviceId)) return { ok: false, reason: "untrusted_device" };
  const device = await ctx.directory.getDevice(deviceId);
  if (!device) return { ok: false, reason: "unknown_device" };
  if (!publicKeyMatchesDeviceId(device.publicKey, deviceId)) return { ok: false, reason: "pubkey_id_mismatch" };
  if (Math.abs(ctx.now - ts) > ctx.tsWindowMs) return { ok: false, reason: "stale_timestamp" };
  if (!verifyEd25519(requestSigningString({ action: req.action, deviceId, ts, nonce }), signature, device.publicKey)) return { ok: false, reason: "bad_signature" };
  if (!ctx.nonces.claim(deviceId, nonce)) return { ok: false, reason: "nonce_reused" };
  return { ok: true, deviceId, device };
}
