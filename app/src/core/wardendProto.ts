// SPDX-License-Identifier: GPL-3.0-or-later
// Protocol of wardend's own transport (no Expo/RN, tested in node).
// Signing string format: daemon/envelope/transport.go, cross-fixture protocol/vectors/transport_vectors.json.
//
//   QR / link:     wardenclaw://pair?code=…&host=…&key=<supervisor key b64url>&url=<endpoint>&v=1
//   Request:       X-Wardenclaw-Device/-Ts/-Nonce/-Signature over wardendRequestSigningString: type
//                  "wardenclaw.req.v1" and this wardend's supervisorId (not the wardenclaw-gate plugin format)
//   Pairing:       POST /v1/pair, signed by the new key over pairSigningString (with code and supervisorId)
//   Response:      X-Wardend-Signature = Ed25519(key from the QR, response string), bound to the request:
//                  responseSigningString({action, deviceId, nonce[, id, digest]}, status, body) for an
//                  authenticated request, pingSigningString(nonce) for ping, unauthSigningString(action)
//                  for a rejection before the request signature is checked (not bound to the request,
//                  checkResponse → "unbound")
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { sha256 } from "@noble/hashes/sha256";
import { canonicalJson } from "./canonical";
import { b64url, bytesToHex, utf8Encode } from "./bytes";
import type { GatePending } from "./gate";
import { t, tOr } from "./i18n";

ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

export const REQ_TYPE = "wardenclaw.req.v1";
export const PAIR_TYPE = "wardenclaw.pair.v1";
export const RESP_TYPE = "wardenclaw.resp.v1";
export const PING_TYPE = "wardenclaw.ping.v1";
export const UNAUTH_TYPE = "wardenclaw.resp.unauth.v1";

export type PairLink = { url: string; key: string; code: string; host: string };

function parseQuery(q: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of q.split("&")) {
    if (!part) continue;
    const i = part.indexOf("=");
    const k = decodeURIComponent((i < 0 ? part : part.slice(0, i)).replace(/\+/g, " "));
    const v = i < 0 ? "" : decodeURIComponent(part.slice(i + 1).replace(/\+/g, " "));
    out[k] = v;
  }
  return out;
}

/** Parse a pairing link (from a QR or pasted by hand). Throws a readable error. */
export function parsePairLink(input: string): PairLink {
  const s = input.trim();
  const m = /^wardenclaw:\/\/pair\/?\?(.*)$/i.exec(s);
  if (!m) throw new Error(t("link.notWardend"));
  let q: Record<string, string>;
  try {
    q = parseQuery(m[1]);
  } catch {
    throw new Error(t("link.corrupt"));
  }
  if (q.v !== "1") throw new Error(t("link.version"));
  const url = (q.url ?? "").trim().replace(/\/+$/, "");
  if (!/^https?:\/\/[^\s/]+/i.test(url)) throw new Error(t("link.noAddress"));
  const key = (q.key ?? "").trim();
  let raw: Uint8Array;
  try {
    raw = b64url.decode(key);
  } catch {
    throw new Error(t("link.badKey"));
  }
  if (raw.length !== 32) throw new Error(t("link.badKey"));
  const code = normalizeCode(q.code ?? "");
  if (code.length < 6) throw new Error(t("link.noCode"));
  return { url, key, code, host: (q.host ?? "").slice(0, 64) };
}

export function normalizeCode(s: string): string {
  return s.replace(/[-\s]/g, "").toUpperCase();
}

/** supervisorId = sha256(raw key) hex: this is how wardend signs envelopes (requester.supervisorId). */
export function supervisorIdFromKey(keyB64: string): string {
  return bytesToHex(sha256(b64url.decode(keyB64)));
}

/** Fingerprint for checking by eye: the first 16 hex chars in groups of 4 (like `wardend pair list`). */
export function fingerprint(id: string): string {
  const d = id.slice(0, 16);
  return d.length < 16 ? id : `${d.slice(0, 4)} ${d.slice(4, 8)} ${d.slice(8, 12)} ${d.slice(12, 16)}`;
}

/**
 * canonicalJson({type:"wardenclaw.req.v1", supervisorId, action, deviceId, ts, nonce[, body]}): signature of a request
 * to wardend. A request signed for the plugin (a string without a type) or for another
 * wardend does not pass.
 */
export function wardendRequestSigningString(p: { supervisorId: string; action: string; deviceId: string; ts: number; nonce: string; body?: Record<string, unknown> }): string {
  const m: Record<string, unknown> = { type: REQ_TYPE, supervisorId: p.supervisorId, action: p.action, deviceId: p.deviceId, ts: p.ts, nonce: p.nonce };
  if (p.body !== undefined) m.body = p.body;
  return canonicalJson(m);
}

export type PairPayload = { code: string; deviceId: string; pubkey: string; name: string; supervisorId: string; ts: number; nonce: string };

export function pairSigningString(p: PairPayload): string {
  return canonicalJson({ type: PAIR_TYPE, code: p.code, deviceId: p.deviceId, pubkey: p.pubkey, name: p.name, supervisorId: p.supervisorId, ts: p.ts, nonce: p.nonce });
}

/** The request the response is bound to: action ("pending", "status", "decide", "pair", "pair.status", "push.register", "push.unregister"), the request's deviceId and nonce; for decide, the ticket's id and digest. */
export type ResponseContext = { action: string; deviceId: string; nonce: string; id?: string; digest?: string };

const bodySha256 = (bodyText: string) => bytesToHex(sha256(utf8Encode(bodyText)));

/** canonicalJson({type:"wardenclaw.resp.v1", action, deviceId, nonce, status, bodySha256[, id, digest]}): response to an authenticated request. */
export function responseSigningString(ctx: ResponseContext, status: number, bodyText: string): string {
  const m: Record<string, unknown> = { type: RESP_TYPE, action: ctx.action, deviceId: ctx.deviceId, nonce: ctx.nonce, status, bodySha256: bodySha256(bodyText) };
  if (ctx.id || ctx.digest) {
    m.id = ctx.id ?? "";
    m.digest = ctx.digest ?? "";
  }
  return canonicalJson(m);
}

/** canonicalJson({type:"wardenclaw.ping.v1", nonce, status, bodySha256}): /v1/ping response; it cannot pass for any other response. */
export function pingSigningString(nonce: string, status: number, bodyText: string): string {
  return canonicalJson({ type: PING_TYPE, nonce, status, bodySha256: bodySha256(bodyText) });
}

/** canonicalJson({type:"wardenclaw.resp.unauth.v1", action, status, bodySha256}): rejection before the request signature is checked (no nonce or deviceId). */
export function unauthSigningString(action: string, status: number, bodyText: string): string {
  return canonicalJson({ type: UNAUTH_TYPE, action, status, bodySha256: bodySha256(bodyText) });
}

/** Which response we expect: a ping with our nonce or a response to our request. */
export type ResponseExpectation = { ping: true; nonce: string } | { ping?: false; ctx: ResponseContext };

/**
 * What the response is for our request:
 * "bound": signed with the key from the QR and bound to this request (for ping, to its nonce);
 * "unbound": a signed wardend rejection before the request signature is checked (same action, body {ok:false}):
 *   a middleman gets one for any request, so it is not a response to ours (neither success nor a final rejection);
 * "invalid": everything else (including a response to another request or a ping instead of a response).
 */
export function checkResponse(pinnedKeyB64: string, want: ResponseExpectation, status: number, bodyText: string, signatureB64: string | null): "bound" | "unbound" | "invalid" {
  if (!signatureB64) return "invalid";
  try {
    const sig = b64url.decode(signatureB64);
    const pub = b64url.decode(pinnedKeyB64);
    if (sig.length !== 64 || pub.length !== 32) return "invalid";
    const msg = want.ping ? pingSigningString(want.nonce, status, bodyText) : responseSigningString(want.ctx, status, bodyText);
    if (ed.verify(sig, utf8Encode(msg), pub)) return "bound";
    if (want.ping || !isRejectionBody(bodyText)) return "invalid";
    return ed.verify(sig, utf8Encode(unauthSigningString(want.ctx.action, status, bodyText)), pub) ? "unbound" : "invalid";
  } catch {
    return "invalid";
  }
}

/** The body of the signed decide response is about our ticket: the same id, and with ok:true the same decision. */
export function decideResponseMatches(body: unknown, sent: { id: string; decision: string }): boolean {
  if (!body || typeof body !== "object") return false;
  const b = body as { ok?: unknown; id?: unknown; decision?: unknown };
  return b.id === sent.id && (b.ok !== true || b.decision === sent.decision);
}

function isRejectionBody(bodyText: string): boolean {
  try {
    const b = JSON.parse(bodyText) as { ok?: unknown } | null;
    return !!b && typeof b === "object" && b.ok === false;
  } catch {
    return false;
  }
}

/** wardend queue item → the gate's pending record shape (like publicExecRecord in the plugin). */
export function wardendItemToPending(it: Record<string, unknown>): GatePending {
  const env = (it.envelope && typeof it.envelope === "object" ? it.envelope : {}) as Record<string, unknown>;
  const argv = Array.isArray(env.argv) ? env.argv.map(String) : [];
  const command = argv.join(" ");
  return {
    id: String(it.id ?? ""),
    kind: "exec",
    digest: String(it.digest ?? ""),
    envelope: env,
    meta: (it.meta && typeof it.meta === "object" ? it.meta : {}) as Record<string, unknown>,
    toolName: "wardend.exec",
    toolKind: "exec",
    toolInputKind: null,
    paramsPreview: command.length > 4000 ? `${command.slice(0, 4000)}…` : command,
    command,
    filePath: null,
    agentId: null,
    sessionKey: null,
    runId: null,
    toolCallId: null,
    source: "wardend",
    mode: "enforce",
    createdAt: Number(it.createdAt) || 0,
    expiresAt: Number(it.expiresAt) || 0,
    status: "pending",
    decision: null,
    deviceId: null,
  };
}

/** Readable wardend (HTTP) rejection reason in the current language, or undefined if the code is unknown. */
export function wardendHttpReason(reason: string): string | undefined {
  const s = tOr(`wdr.${reason}`, "");
  return s || undefined;
}
