// SPDX-License-Identifier: AGPL-3.0-or-later
// Frames of protocol/README.md section 5.2: the shapes the relay reads and the checks it makes
// before storing anything. Envelope frames (msg, pair) are stored as they came, with `from` and
// `seq` set by the relay; their `body` is opaque.

export const PROTOCOL = 1;
export const HELLO_TYPE = "wardenclaw.relay.hello.v1";
export const REQ_TYPE = "wardenclaw.req.v1";
export const CHALLENGE_TTL_MS = 60_000;
export const TS_WINDOW_MS = 120_000;
export const PAIRING_MAX_MS = 15 * 60_000;
export const SEEN_TTL_MS = 24 * 3_600_000;
export const IDLE_CLOSE_MS = 90_000;

export type Role = "supervisor" | "device";

export const ID_RE = /^[0-9a-f]{64}$/;
export const MSG_ID_RE = /^[0-9a-f]{32}$/;
export const KINDS = new Set(["card", "card.done", "ticket", "ticket.result", "status", "status.req", "pair.status"]);
export const PUSH_KINDS = new Set(["card", "card.done"]);
export const PLATFORMS = new Set(["apns", "fcm"]);

export interface Hello {
  type: "hello";
  role: Role;
  key: string;
  enc: string;
  ts: number;
  nonce: string;
  client: { name: string; version: string; protocol: number };
  sig: string;
}

/** An envelope frame as stored: everything the sender set plus from and seq. */
export interface Envelope {
  type: "msg" | "pair";
  id: string;
  to: string;
  from: string;
  seq: number;
  ts: number;
  exp: number;
  body: string;
  kind: string;
}

export interface Limits {
  frameMaxBytes: number;
  queueMax: number;
  queueTtlMs: number;
}

export function limitsFrom(env: Record<string, string | undefined>): Limits {
  const n = (v: string | undefined, d: number) => {
    const x = Number(v);
    return Number.isFinite(x) && x > 0 ? x : d;
  };
  return { frameMaxBytes: n(env.FRAME_MAX_BYTES, 65_536), queueMax: n(env.QUEUE_MAX, 200), queueTtlMs: n(env.QUEUE_TTL_MS, SEEN_TTL_MS) };
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isStr = (v: unknown, max = 4096): v is string => typeof v === "string" && v.length > 0 && v.length <= max;
const isInt = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v);

/** Parses one text frame; null when it is not a JSON object with a string type. */
export function parseFrame(raw: string): Record<string, unknown> | null {
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return null;
  }
  return isObj(v) && isStr(v.type, 64) ? v : null;
}

export function helloOf(f: Record<string, unknown>): Hello | string {
  if (f.role !== "supervisor" && f.role !== "device") return "role_invalid";
  if (!isStr(f.key, 64) || !isStr(f.enc, 64)) return "key_invalid";
  if (!isInt(f.ts)) return "ts_invalid";
  if (!isStr(f.nonce, 128)) return "nonce_invalid";
  if (!isStr(f.sig, 128)) return "signature_missing";
  const c = f.client;
  if (!isObj(c) || !isStr(c.name, 64) || !isStr(c.version, 64) || !isInt(c.protocol)) return "client_invalid";
  if (c.protocol !== PROTOCOL) return "protocol_mismatch";
  return { type: "hello", role: f.role, key: f.key, enc: f.enc, ts: f.ts, nonce: f.nonce, sig: f.sig, client: { name: c.name, version: c.version, protocol: c.protocol } };
}

/** The sender's part of an envelope frame; `from` and `seq` are ignored and set by the relay. */
export function envelopeOf(f: Record<string, unknown>, now: number, ttlMs: number): Omit<Envelope, "from" | "seq"> | string {
  if (f.type !== "msg" && f.type !== "pair") return "type_invalid";
  if (!isStr(f.id, 32) || !MSG_ID_RE.test(f.id)) return "id_invalid";
  if (!isStr(f.to, 64) || !ID_RE.test(f.to)) return "to_invalid";
  if (!isInt(f.ts)) return "ts_invalid";
  if (!isInt(f.exp)) return "exp_invalid";
  if (f.exp <= now) return "expired";
  if (!isStr(f.body, 100_000)) return "body_invalid";
  const kind = f.type === "pair" ? "pair" : f.kind;
  if (f.type === "msg" && (!isStr(kind, 32) || !KINDS.has(kind))) return "kind_invalid";
  return { type: f.type, id: f.id, to: f.to, ts: f.ts, exp: Math.min(f.exp, now + ttlMs), body: f.body, kind: kind as string };
}

export function pad(seq: number): string {
  return seq.toString().padStart(12, "0");
}
