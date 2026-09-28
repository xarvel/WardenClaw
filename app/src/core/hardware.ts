// SPDX-License-Identifier: GPL-3.0-or-later
// Second factor: YubiKey (FIDO2) for high risk. Format: protocol/HARDWARE.md, cross-fixture
// protocol/vectors/hw_vectors.json (Go is the reference). Only pure logic here: the ticket
// challenge, clientDataJSON, parsing meta.hardware, the registration blob. NFC: modules/yubikey.
import { sha256 } from "@noble/hashes/sha256";
import { b64url, utf8Encode } from "./bytes";
import { canonicalJson, DecisionPayload } from "./canonical";
import { t } from "./i18n";

export const HW_TYPE = "wardenclaw.hw.v1";
export const HW_ORIGIN = "wardenclaw:app";
export const HW_RP_ID = "wardenclaw";
export const HW_BLOB_PREFIX = "wchw1:";

/** Second signature in the decision body (field hw), all base64url. */
export type HardwareAssertion = { credentialId: string; clientDataJSON: string; authenticatorData: string; signature: string };

/** Bound key (stored in SecureStore; the public part is in the wardend config). */
export type HardwareKey = { credentialId: string; rpId: string; name: string; alg: number; addedAt: string; blob: string; requireUv?: boolean };

/** challenge = sha256(canonicalJson({type:"wardenclaw.hw.v1", ticket, deviceId, id, digest, decision, ts, nonce[, supervisorId][, risk]})): the ticket type is in the ticket field. */
export function hwChallenge(deviceId: string, p: DecisionPayload): Uint8Array {
  return sha256(utf8Encode(canonicalJson({ type: HW_TYPE, ticket: p.type, supervisorId: p.supervisorId, deviceId, id: p.id, digest: p.digest, decision: p.decision, ts: p.ts, nonce: p.nonce, risk: p.risk })));
}

/** clientDataJSON: key order type, challenge, origin (as in Go hwkey.ClientDataJSON). */
export function clientDataJSON(type: "webauthn.get" | "webauthn.create", challenge: Uint8Array): string {
  return JSON.stringify({ type, challenge: b64url.encode(challenge), origin: HW_ORIGIN });
}

export function clientDataHash(json: string): Uint8Array {
  return sha256(utf8Encode(json));
}

/** Everything the native getAssertion needs for this ticket. */
export function assertionRequest(deviceId: string, p: DecisionPayload) {
  const json = clientDataJSON("webauthn.get", hwChallenge(deviceId, p));
  return { clientDataJSON: json, clientDataHash: b64url.encode(clientDataHash(json)) };
}

export type HardwareMeta = {
  required: boolean;
  rule: string | null;
  escalated: boolean;
  minScore: number | null;
  credentials: { id: string; name: string; alg: string }[];
};

/** meta.hardware of a wardend pending record (via relay). Garbage → null. */
export function parseHardwareMeta(meta: unknown): HardwareMeta | null {
  const h = meta && typeof meta === "object" ? (meta as Record<string, unknown>).hardware : null;
  if (!h || typeof h !== "object") return null;
  const o = h as Record<string, unknown>;
  const ms = typeof o.minScore === "number" && Number.isInteger(o.minScore) && o.minScore >= 0 && o.minScore <= 100 ? o.minScore : null;
  const creds = Array.isArray(o.credentials)
    ? o.credentials
        .filter((c): c is Record<string, unknown> => !!c && typeof c === "object")
        .map((c) => ({ id: String(c.id ?? ""), name: String(c.name ?? ""), alg: String(c.alg ?? "") }))
        .filter((c) => c.id)
    : [];
  return { required: o.required === true, rule: typeof o.rule === "string" ? o.rule : null, escalated: o.escalated === true, minScore: ms, credentials: creds };
}

/**
 * Whether "Allow" needs a key tap. A static wardend rule (required): always; a score rule
 * (minScore): if our own risk score ≥ the threshold. Without meta (plugin records): no.
 */
export function needsHardware(meta: HardwareMeta | null, risk: number | null): { need: boolean; why: string } {
  if (!meta) return { need: false, why: "" };
  if (meta.required) return { need: true, why: t(meta.escalated ? "hwr.ruleEscalated" : "hwr.rule", { rule: meta.rule ?? "?" }) };
  if (meta.minScore !== null && risk !== null && risk >= meta.minScore) return { need: true, why: t("hwr.risk", { risk, min: meta.minScore }) };
  return { need: false, why: "" };
}

/** Key to sign with: our own bound key, if wardend knows it (or the list did not arrive). */
export function pickCredential(meta: HardwareMeta | null, key: HardwareKey | null): { ok: true; key: HardwareKey } | { ok: false; reason: string } {
  if (!key) return { ok: false, reason: t("hwr.notBound") };
  if (meta && meta.credentials.length > 0 && !meta.credentials.some((c) => c.id === key.credentialId)) {
    return { ok: false, reason: t("hwr.unknownKey") };
  }
  if (meta && meta.credentials.length === 0) return { ok: false, reason: t("hwr.noneRegistered") };
  return { ok: true, key };
}

/** Blob for `wardend hw-register`: wchw1:<base64url(JSON)>. */
export function registrationBlob(r: { credentialId: string; attestationObject: string; clientDataJSON: string; rpId: string; name: string }): string {
  const json = JSON.stringify({ credentialId: r.credentialId, attestationObject: r.attestationObject, clientDataJSON: b64url.encode(utf8Encode(r.clientDataJSON)), rpId: r.rpId, name: r.name });
  return HW_BLOB_PREFIX + b64url.encode(utf8Encode(json));
}

export function coseAlgName(alg: number): string {
  return alg === -8 ? "EdDSA" : alg === -7 ? "ES256" : `COSE ${alg}`;
}

/**
 * Risk that may be signed into payload.risk: only a real score (model, blocklist, injection).
 * "Manual mode"/"no model" put 100 in as a placeholder: we do not sign that, otherwise wardend
 * score rules would require the key for everything.
 */
export function signableRisk(v: { risk: number | null; source: string } | null | undefined): number | undefined {
  if (!v || v.risk === null || !["model", "blocklist", "injection"].includes(v.source)) return undefined;
  const r = Math.round(v.risk);
  return Number.isInteger(r) && r >= 0 && r <= 100 ? r : undefined;
}

/** Function that gets a signature over this challenge from the key (UI: "Tap the YubiKey"). */
export type HardwareSigner = (req: { clientDataJSON: string; clientDataHash: string }) => Promise<HardwareAssertion>;

/** wardend refusals after which the card stays: the key can be tapped again. */
export function isRetryableHardwareReason(reason: string | undefined | null): boolean {
  return !!reason && (reason.startsWith("hw_") || reason === "hardware_required" || reason === "stale_timestamp");
}

/**
 * wardend score rule (minScore) for this card: none: there is no such rule, or the key is needed
 * anyway by a static one; waiting: the score is still being computed; silent: there is no signable
 * score (manual mode, no model, error), the rule will not fire; armed: there is a score, but it is
 * below the threshold.
 */
export function scoreRuleState(meta: HardwareMeta | null, risk: number | null | undefined, pending: boolean): "none" | "waiting" | "silent" | "armed" | "triggered" {
  if (!meta || meta.required || meta.minScore === null) return "none";
  if (risk !== null && risk !== undefined) return risk >= meta.minScore ? "triggered" : "armed";
  return pending ? "waiting" : "silent";
}

/** require_hardware rule from /v1/status: id, the policy author's note, score threshold. The server does not return the argv matchers. */
export type ServerHardwareRule = { id: string; note: string; minScore: number | null };

/**
 * What the server says about the second factor in /v1/status: the number of require_hardware
 * rules, the rules themselves (ruleList: from a wardend with the requireHardware field, null from
 * an old one) and the keys it knows.
 */
export type ServerHardware = { rules: number | null; ruleList: ServerHardwareRule[] | null; keys: { id: string; name: string }[] | null };

export function parseServerHardware(status: unknown): ServerHardware {
  const s = status && typeof status === "object" ? (status as Record<string, unknown>) : {};
  const ruleList = Array.isArray(s.requireHardware)
    ? s.requireHardware
        .filter((r): r is Record<string, unknown> => !!r && typeof r === "object")
        .map((r) => ({
          id: String(r.id ?? ""),
          note: typeof r.note === "string" ? r.note : "",
          minScore: typeof r.minScore === "number" && Number.isInteger(r.minScore) ? r.minScore : null,
        }))
        .filter((r) => r.id)
    : null;
  const n = s.requireHardwareRules;
  const rules = typeof n === "number" && Number.isInteger(n) && n >= 0 ? n : ruleList ? ruleList.length : null;
  const keys = Array.isArray(s.hardwareKeys)
    ? s.hardwareKeys
        .filter((k): k is Record<string, unknown> => !!k && typeof k === "object")
        .map((k) => ({ id: String(k.id ?? ""), name: String(k.name ?? "") }))
        .filter((k) => k.id)
    : null;
  return { rules, ruleList, keys };
}

/**
 * What the bound key actually protects, in plain words ("Mode" screen, YubiKey block).
 * unknown: the server status was not received (no connection, or an old wardend without these
 * fields). named: the rules by name (note or id), if the server returned them; otherwise only the
 * count is left.
 */
export function hardwareCoverage(
  server: ServerHardware | null,
  credentialId: string | null,
): { rules: "unknown" | "none" | "some"; count: number; named: { label: string; minScore: number | null }[] | null; keyKnown: boolean | null } {
  const rules = !server || server.rules === null ? "unknown" : server.rules === 0 ? "none" : "some";
  const keyKnown = !server || !server.keys || !credentialId ? null : server.keys.some((k) => k.id === credentialId);
  const named = rules === "some" && server?.ruleList?.length ? server.ruleList.map((r) => ({ label: r.note || r.id, minScore: r.minScore })) : null;
  return { rules, count: server?.rules ?? 0, named, keyKnown };
}
