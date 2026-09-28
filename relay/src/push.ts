// SPDX-License-Identifier: AGPL-3.0-or-later
// Push notifications from the relay (protocol/README.md section 8): APNs with a token-based JWT
// (ES256, WebCrypto; Cloudflare's edge speaks HTTP/2 to Apple), FCM HTTP v1 with a service
// account (RS256 JWT exchanged for an access token). Best effort: a failure is reported to the
// caller and the frame stays queued.

import { b64urlEncode } from "./crypto";

export interface PushToken {
  platform: "apns" | "fcm";
  token: string;
  environment: "sandbox" | "production";
  topic: string;
  registeredAt: number;
}

export interface PushEnv {
  APNS_KEY_P8?: string;
  APNS_KEY_ID?: string;
  APNS_TEAM_ID?: string;
  APNS_TOPIC?: string;
  FCM_SERVICE_ACCOUNT?: string;
}

export interface PushResult {
  ok: boolean;
  status: number;
  reason: string;
  /** the token is dead: delete it */
  unregister: boolean;
}

/** What a notification carries of a frame: every routing member the AAD of its box covers
 * (protocol/README.md section 11; `from` is `sid`, only a supervisor's frames are pushed), so the receiver
 * can open `body` from the notification alone. */
export interface PushPayload {
  sid: string;
  id: string;
  to: string;
  kind: string;
  exp: number;
  /** the frame's ciphertext when it fits (≤ 3 KiB), else absent */
  body?: string;
}

export const PUSH_BODY_MAX = 3072;

export function pushPayload(sid: string, f: { id: string; to: string; kind: string; exp: number; body: string }): PushPayload {
  return { sid, id: f.id, to: f.to, kind: f.kind, exp: f.exp, ...(f.body.length <= PUSH_BODY_MAX ? { body: f.body } : {}) };
}

/** The FCM data message: the same members, all strings (FCM data values are strings), `exp` in decimal. */
export function fcmData(p: PushPayload): Record<string, string> {
  return { sid: p.sid, id: p.id, to: p.to, kind: p.kind, exp: String(p.exp), ...(p.body ? { body: p.body } : {}) };
}

const te = new TextEncoder();
const b64url = (s: string) => b64urlEncode(te.encode(s));

function pemToDer(pem: string): Uint8Array {
  const b64 = pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** JWT cache: one per (issuer, key), renewed after 50 minutes (APNs allows 60, Google 60). */
const jwts = new Map<string, { value: string; at: number }>();
const JWT_TTL_MS = 50 * 60_000;

async function signJwt(kind: "ES256" | "RS256", pkcs8Pem: string, header: Record<string, unknown>, claims: Record<string, unknown>): Promise<string> {
  const alg = kind === "ES256" ? { name: "ECDSA", namedCurve: "P-256" } : { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  const key = await crypto.subtle.importKey("pkcs8", pemToDer(pkcs8Pem), alg, false, ["sign"]);
  const input = `${b64url(JSON.stringify({ alg: kind, typ: "JWT", ...header }))}.${b64url(JSON.stringify(claims))}`;
  const sigAlg = kind === "ES256" ? { name: "ECDSA", hash: "SHA-256" } : { name: "RSASSA-PKCS1-v1_5" };
  const sig = new Uint8Array(await crypto.subtle.sign(sigAlg, key, te.encode(input)));
  return `${input}.${b64urlEncode(sig)}`;
}

export function apnsConfigured(env: PushEnv): boolean {
  return !!(env.APNS_KEY_P8 && env.APNS_KEY_ID && env.APNS_TEAM_ID && env.APNS_TOPIC);
}

export function fcmConfigured(env: PushEnv): boolean {
  return !!env.FCM_SERVICE_ACCOUNT;
}

async function apnsBearer(env: PushEnv, now: number): Promise<string> {
  const k = `apns:${env.APNS_KEY_ID}`;
  const c = jwts.get(k);
  if (c && now - c.at < JWT_TTL_MS) return c.value;
  const jwt = await signJwt("ES256", env.APNS_KEY_P8 as string, { kid: env.APNS_KEY_ID }, { iss: env.APNS_TEAM_ID, iat: Math.floor(now / 1000) });
  jwts.set(k, { value: jwt, at: now });
  return jwt;
}

export function apnsPayload(p: PushPayload): string {
  return JSON.stringify({
    aps: { alert: { title: "Approval request", body: "Open to review" }, sound: "default", "interruption-level": "time-sensitive", "mutable-content": 1, category: "WARDENCLAW_CARD" },
    relay: p,
  });
}

export async function sendApns(env: PushEnv, t: PushToken, p: PushPayload, exp: number, now = Date.now()): Promise<PushResult> {
  const host = t.environment === "sandbox" ? "https://api.sandbox.push.apple.com" : "https://api.push.apple.com";
  const topic = env.APNS_TOPIC as string;
  if (t.topic && t.topic !== topic) return { ok: false, status: 0, reason: "topic_mismatch", unregister: true };
  const headers: Record<string, string> = {
    authorization: `bearer ${await apnsBearer(env, now)}`,
    "apns-topic": topic,
    "apns-push-type": "alert",
    "apns-priority": "10",
    "apns-expiration": String(Math.max(0, Math.floor(exp / 1000))),
    "apns-collapse-id": p.id.slice(0, 32),
    "content-type": "application/json",
  };
  let res: Response;
  try {
    res = await fetch(`${host}/3/device/${t.token}`, { method: "POST", headers, body: apnsPayload(p) });
  } catch (e) {
    return { ok: false, status: 0, reason: `fetch: ${(e as Error).message}`, unregister: false };
  }
  if (res.status === 200) return { ok: true, status: 200, reason: "", unregister: false };
  let reason = `HTTP ${res.status}`;
  try {
    const j = (await res.json()) as { reason?: string };
    if (j.reason) reason = j.reason;
  } catch {}
  if (reason === "ExpiredProviderToken") jwts.delete(`apns:${env.APNS_KEY_ID}`);
  return { ok: false, status: res.status, reason, unregister: res.status === 410 || reason === "BadDeviceToken" || reason === "Unregistered" || reason === "DeviceTokenNotForTopic" };
}

interface ServiceAccount {
  project_id: string;
  client_email: string;
  private_key: string;
  token_uri?: string;
}

async function fcmBearer(env: PushEnv, sa: ServiceAccount, now: number): Promise<string> {
  const k = `fcm:${sa.client_email}`;
  const c = jwts.get(k);
  if (c && now - c.at < JWT_TTL_MS) return c.value;
  const iat = Math.floor(now / 1000);
  const uri = sa.token_uri || "https://oauth2.googleapis.com/token";
  const assertion = await signJwt("RS256", sa.private_key, {}, { iss: sa.client_email, scope: "https://www.googleapis.com/auth/firebase.messaging", aud: uri, iat, exp: iat + 3600 });
  const res = await fetch(uri, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: `grant_type=${encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer")}&assertion=${assertion}` });
  if (!res.ok) throw new Error(`oauth ${res.status}`);
  const j = (await res.json()) as { access_token?: string };
  if (!j.access_token) throw new Error("oauth: no access_token");
  jwts.set(k, { value: j.access_token, at: now });
  return j.access_token;
}

export async function sendFcm(env: PushEnv, t: PushToken, p: PushPayload, exp: number, now = Date.now()): Promise<PushResult> {
  let sa: ServiceAccount;
  try {
    sa = JSON.parse(env.FCM_SERVICE_ACCOUNT as string) as ServiceAccount;
  } catch {
    return { ok: false, status: 0, reason: "service_account_invalid", unregister: false };
  }
  let bearer: string;
  try {
    bearer = await fcmBearer(env, sa, now);
  } catch (e) {
    return { ok: false, status: 0, reason: (e as Error).message, unregister: false };
  }
  const ttl = Math.max(0, Math.floor((exp - now) / 1000));
  const msg = {
    message: {
      token: t.token,
      android: { priority: "high", ttl: `${ttl}s` },
      data: fcmData(p),
    },
  };
  let res: Response;
  try {
    res = await fetch(`https://fcm.googleapis.com/v1/projects/${sa.project_id}/messages:send`, { method: "POST", headers: { authorization: `Bearer ${bearer}`, "content-type": "application/json" }, body: JSON.stringify(msg) });
  } catch (e) {
    return { ok: false, status: 0, reason: `fetch: ${(e as Error).message}`, unregister: false };
  }
  if (res.ok) return { ok: true, status: res.status, reason: "", unregister: false };
  let reason = `HTTP ${res.status}`;
  try {
    const j = (await res.json()) as { error?: { status?: string; details?: { errorCode?: string }[] } };
    reason = j.error?.details?.find((d) => d.errorCode)?.errorCode || j.error?.status || reason;
  } catch {}
  if (res.status === 401) jwts.delete(`fcm:${sa.client_email}`);
  return { ok: false, status: res.status, reason, unregister: reason === "UNREGISTERED" || res.status === 404 };
}

export async function sendPush(env: PushEnv, t: PushToken, p: PushPayload, exp: number): Promise<PushResult> {
  if (t.platform === "apns") return apnsConfigured(env) ? sendApns(env, t, p, exp) : { ok: false, status: 0, reason: "push_not_configured", unregister: false };
  return fcmConfigured(env) ? sendFcm(env, t, p, exp) : { ok: false, status: 0, reason: "push_not_configured", unregister: false };
}
