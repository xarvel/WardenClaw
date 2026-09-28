// SPDX-License-Identifier: GPL-3.0-or-later
// Frames of the relay transport (protocol/README.md; no Expo/RN, tested in node). Mirrors
// relay/src/frames.ts and daemon/relay.go; cross-fixture protocol/vectors/relay_vectors.json.
//
//   QR / link:  wardenclaw://pair?v=1&relay=wss://…/v1/ws&sid=<supervisorId>&key=<Ed25519 b64url>
//               &enc=<X25519 b64url>&code=…&host=…
//   hello:      sig over canonicalJson({type:"wardenclaw.relay.hello.v1", role, key, enc, ts, nonce, client})
//   pairing:    {payload:{code, deviceId, pubkey, enc, name, supervisorId, ts, nonce}, signature},
//               signature over canonicalJson({type:"wardenclaw.pair.v1", …payload})
//   card:       supervisorSig over canonicalJson({type:"wardenclaw.card.v1", id, digest, createdAt, expiresAt})
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { sha256 } from "@noble/hashes/sha256";
import { canonicalJson } from "./canonical";
import { b64url, bytesToHex, utf8Encode } from "./bytes";
import { t } from "./i18n";
import { PROTOCOL } from "./protocolVersion";

ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

export const HELLO_TYPE = "wardenclaw.relay.hello.v1";
export const PAIR_TYPE = "wardenclaw.pair.v1";
export const CARD_TYPE = "wardenclaw.card.v1";
export const CLIENT_NAME = "wardenclaw-app";
/** A frame larger than this is refused by the relay (section 2). */
export const FRAME_MAX_BYTES = 65_536;
/** exp of a ticket: ts + 10 min (section 5). */
export const TICKET_TTL_MS = 10 * 60_000;
/** The sender stays this far under the relay's queue TTL, or the clamped exp breaks the AAD (section 7). */
export const TTL_MARGIN_MS = 60_000;

export const ID_RE = /^[0-9a-f]{64}$/;
export const MSG_ID_RE = /^[0-9a-f]{32}$/;

/** Kinds a device receives and kinds it sends. A msg of another kind that opens with the supervisor's box is acked and ignored (protocol/README.md section 5.5). */
export const KINDS_IN = ["card", "card.done", "ticket.result", "status", "pair.status"] as const;
export const KINDS_OUT = ["ticket", "status.req"] as const;
export type KindIn = (typeof KINDS_IN)[number];
export type KindOut = (typeof KINDS_OUT)[number];

export type RelayClient = { name: string; version: string; protocol: number };

export type Hello = { type: "hello"; role: "device"; key: string; enc: string; ts: number; nonce: string; client: RelayClient; sig: string };

/** An envelope frame as the relay forwards it: `from` and `seq` are the relay's. */
export type Envelope = { type: "msg" | "pair"; id: string; to: string; from: string; seq: number; ts: number; exp: number; body: string; kind: string };

/** What the sender puts on the wire: no `from`, no `seq`; a pair frame has no `kind` (the relay sets it). */
export type OutEnvelope = { type: "msg"; id: string; to: string; ts: number; exp: number; body: string; kind: KindOut } | { type: "pair"; id: string; to: string; ts: number; exp: number; body: string };

export type Limits = { frame: number; queue: number; ttl: number };

/** Error codes of the relay (sections 3, 5, 10) the session reacts to; others are reported as they come. */
export const ERR = {
  notTrusted: "not_trusted",
  rateLimited: "rate_limited",
  expired: "expired",
  queueFull: "queue_full",
  tooLarge: "too_large",
  toInvalid: "to_invalid",
} as const;

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isStr = (v: unknown, max = 4096): v is string => typeof v === "string" && v.length > 0 && v.length <= max;
const isInt = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v);

/** Parses one text frame; null when it is not a JSON object with a string type. */
export function parseFrame(raw: string): Record<string, unknown> | null {
  if (raw.length > FRAME_MAX_BYTES) return null;
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return null;
  }
  return isObj(v) && isStr(v.type, 64) ? v : null;
}

/** Parses a decrypted payload: a JSON object or null. */
export function parsePlaintext(text: string): Record<string, unknown> | null {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    return null;
  }
  return isObj(v) ? v : null;
}

export function helloSigningString(h: Omit<Hello, "type" | "sig">): string {
  return canonicalJson({ type: HELLO_TYPE, role: h.role, key: h.key, enc: h.enc, ts: h.ts, nonce: h.nonce, client: { name: h.client.name, version: h.client.version, protocol: h.client.protocol } });
}

/** The signed hello of a device; `sign` is the device's Ed25519 signature (b64url) over a string. */
export function buildHello(p: { key: string; enc: string; ts: number; nonce: string; version: string }, sign: (s: string) => string): Hello {
  const h = { role: "device" as const, key: p.key, enc: p.enc, ts: p.ts, nonce: p.nonce, client: { name: CLIENT_NAME, version: p.version, protocol: PROTOCOL } };
  return { type: "hello", ...h, sig: sign(helloSigningString(h)) };
}

/** {type:"challenge", nonce, ts}: the nonce, or null when the frame is malformed. */
export function challengeNonce(f: Record<string, unknown>): string | null {
  return f.type === "challenge" && isStr(f.nonce, 128) && /^[A-Za-z0-9_-]+$/.test(f.nonce) ? f.nonce : null;
}

/** {type:"welcome", id, role, protocol, ts, limits}: the limits when the relay bound us as this device, else null. */
export function welcomeLimits(f: Record<string, unknown>, deviceId: string): Limits | null {
  if (f.type !== "welcome" || f.id !== deviceId || f.role !== "device" || f.protocol !== PROTOCOL) return null;
  const l = f.limits;
  if (!isObj(l) || !isInt(l.frame) || !isInt(l.queue) || !isInt(l.ttl) || l.ttl <= 0) return null;
  return { frame: l.frame, queue: l.queue, ttl: l.ttl };
}

/** Member order as wardend marshals it: the plaintext of a pair frame matches the vectors byte for byte. */
export type PairPayload = { code: string; deviceId: string; pubkey: string; enc: string; name: string; supervisorId: string; ts: number; nonce: string };

export function pairSigningString(p: PairPayload): string {
  return canonicalJson({ type: PAIR_TYPE, code: p.code, deviceId: p.deviceId, pubkey: p.pubkey, enc: p.enc, name: p.name, supervisorId: p.supervisorId, ts: p.ts, nonce: p.nonce });
}

/** {payload, signature}: the plaintext of a pair frame. */
export function pairPlaintext(p: PairPayload, sign: (s: string) => string): string {
  const payload: PairPayload = { code: p.code, deviceId: p.deviceId, pubkey: p.pubkey, enc: p.enc, name: p.name, supervisorId: p.supervisorId, ts: p.ts, nonce: p.nonce };
  return JSON.stringify({ payload, signature: sign(pairSigningString(payload)) });
}

export function cardSigningString(c: { id: string; digest: string; createdAt: number; expiresAt: number }): string {
  return canonicalJson({ type: CARD_TYPE, id: c.id, digest: c.digest, createdAt: c.createdAt, expiresAt: c.expiresAt });
}

export function verifySig(keyB64: string, message: string, sigB64: string): boolean {
  try {
    const sig = b64url.decode(sigB64);
    const key = b64url.decode(keyB64);
    return sig.length === 64 && key.length === 32 && ed.verify(sig, utf8Encode(message), key);
  } catch {
    return false;
  }
}

/** A pending item as it travels in `card` and in the list of `status`. */
export type RelayCard = Record<string, unknown> & { id: string; digest: string; createdAt: number; expiresAt: number; supervisorSig: string };

/**
 * A card is shown only with the supervisor's signature over its id, digest and times, made with
 * the key of the QR. Returns the reason it is refused, or null when it holds.
 */
export function checkCard(c: Record<string, unknown>, supervisorKeyB64: string, now: number): "card_invalid" | "card_bad_signature" | "card_expired" | null {
  if (!isStr(c.id, 128) || !isStr(c.digest, 128) || !isInt(c.createdAt) || !isInt(c.expiresAt) || !isStr(c.supervisorSig, 128)) return "card_invalid";
  if (!verifySig(supervisorKeyB64, cardSigningString({ id: c.id, digest: c.digest, createdAt: c.createdAt, expiresAt: c.expiresAt }), c.supervisorSig)) return "card_bad_signature";
  if (c.expiresAt <= now) return "card_expired";
  return null;
}

/**
 * An envelope frame the relay forwarded to this device: every routing member is checked before
 * the body is touched. Returns the frame or the reason it is refused.
 */
export function incomingEnvelope(f: Record<string, unknown>, me: { deviceId: string; supervisorId: string }, now: number): Envelope | string {
  if (f.type !== "msg") return "type_invalid";
  if (!isStr(f.id, 32) || !MSG_ID_RE.test(f.id)) return "id_invalid";
  if (f.to !== me.deviceId) return "to_invalid";
  if (f.from !== me.supervisorId) return "from_invalid";
  if (!isInt(f.seq) || f.seq < 1) return "seq_invalid";
  if (!isInt(f.ts)) return "ts_invalid";
  if (!isInt(f.exp)) return "exp_invalid";
  if (!isStr(f.kind, 32)) return "kind_invalid";
  if (!isStr(f.body, 100_000) || !/^[A-Za-z0-9_-]+$/.test(f.body)) return "body_invalid";
  if (f.exp <= now) return "expired";
  return { type: "msg", id: f.id, to: f.to as string, from: f.from as string, seq: f.seq, ts: f.ts, exp: f.exp, body: f.body, kind: f.kind };
}

/** exp of an outgoing frame: the wanted lifetime, kept a minute under the relay's queue TTL. */
export function outgoingExp(now: number, wantMs: number, limits: Limits): number {
  return now + Math.max(1000, Math.min(wantMs, limits.ttl - TTL_MARGIN_MS));
}

export type PairLink = { relay: string; supervisorId: string; key: string; enc: string; code: string; host: string };

function parseQuery(q: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of q.split("&")) {
    if (!part) continue;
    const i = part.indexOf("=");
    const k = decodeURIComponent((i < 0 ? part : part.slice(0, i)).replace(/\+/g, " "));
    if (k in out) throw new Error("duplicate");
    out[k] = i < 0 ? "" : decodeURIComponent(part.slice(i + 1).replace(/\+/g, " "));
  }
  return out;
}

function key32(s: string): boolean {
  if (!/^[A-Za-z0-9_-]{43}$/.test(s)) return false;
  return b64url.decode(s).length === 32;
}

export function normalizeCode(s: string): string {
  return s.replace(/[-\s]/g, "").toUpperCase();
}

/**
 * Parse a pairing link (from the QR of `wardend pair start` or pasted by hand). Throws a
 * readable error. `sid` must be the hash of `key`: the QR binds the supervisor's id, its identity
 * key and its encryption key, and a link that disagrees with itself is refused.
 */
export function parsePairLink(input: string): PairLink {
  const m = /^wardenclaw:\/\/pair\/?\?(.*)$/i.exec(input.trim());
  if (!m) throw new Error(t("link.notWardend"));
  let q: Record<string, string>;
  try {
    q = parseQuery(m[1]);
  } catch {
    throw new Error(t("link.corrupt"));
  }
  if (q.v !== "1") throw new Error(t("link.version"));
  const relay = (q.relay ?? "").trim().replace(/\/+$/, "");
  if (!/^wss:\/\/[A-Za-z0-9.-]+(:\d{1,5})?(\/[A-Za-z0-9._~\/-]*)?$/.test(relay)) throw new Error(t("link.noAddress"));
  const key = q.key ?? "";
  const enc = q.enc ?? "";
  if (!key32(key) || !key32(enc)) throw new Error(t("link.badKey"));
  const supervisorId = q.sid ?? "";
  if (!ID_RE.test(supervisorId) || bytesToHex(sha256(b64url.decode(key))) !== supervisorId) throw new Error(t("link.badKey"));
  const code = normalizeCode(q.code ?? "");
  if (!/^[A-Z0-9]{6,32}$/.test(code)) throw new Error(t("link.noCode"));
  return { relay, supervisorId, key, enc, code, host: (q.host ?? "").slice(0, 64) };
}

/** Fingerprint for checking by eye: the first 16 hex chars in groups of 4 (like `wardend pair list`). */
export function fingerprint(id: string): string {
  const d = id.slice(0, 16);
  return d.length < 16 ? id : `${d.slice(0, 4)} ${d.slice(4, 8)} ${d.slice(8, 12)} ${d.slice(12, 16)}`;
}

/** The WebSocket URL of a channel: <relay>/<supervisorId>. */
export function channelUrl(relay: string, supervisorId: string): string {
  return `${relay.replace(/\/+$/, "")}/${supervisorId}`;
}
