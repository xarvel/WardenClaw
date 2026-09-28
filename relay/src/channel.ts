// SPDX-License-Identifier: AGPL-3.0-or-later
// One Durable Object per supervisor channel (protocol/README.md sections 5.3, 5.4, 5.5, 6, 8, 12, 13). It holds the
// supervisor's socket and the sockets of its devices (WebSocket hibernation: the object sleeps
// between frames, sessions live in the sockets' attachments), the queues of undelivered frames,
// the push tokens and the dedupe set. Everything a frame carries in `body` is opaque here.
//
// Storage keys:
//   sid                       the channel's supervisorId (from the URL, checked against hellos)
//   devices                   string[]: trusted device ids, as the supervisor last sent them
//   pairing                   {until}: an open pairing window
//   enc:<id>                  the X25519 key a party announced in its hello (informational)
//   key:<deviceId>            the Ed25519 key of a device that authenticated here (for /v1/frames)
//   seq:<to>:<from>           last sequence number assigned in that direction
//   q:<to>:<from>:<seq12>     an undelivered Envelope
//   qid:<id>                  the q: key of that frame (ack, dedupe, /v1/frames)
//   seen:<id>                 exp of a frame the relay accepted (dedupe after delivery)
//   push:<deviceId>:<platform>:<token>   PushToken
//   nonce:<nonce>             exp of a used /v1/frames request nonce

import { canonicalJson } from "./canonical";
import { idOfKey, randomB64url, verifyEd25519 } from "./crypto";
import {
  CHALLENGE_TTL_MS, HELLO_TYPE, ID_RE, IDLE_CLOSE_MS, KINDS, PAIRING_MAX_MS, PLATFORMS, PROTOCOL, PUSH_KINDS, REQ_TYPE, SEEN_TTL_MS, TS_WINDOW_MS,
  envelopeOf, helloOf, limitsFrom, pad, parseFrame,
  type Envelope, type Limits, type Role,
} from "./frames";
import { pushPayload, sendPush, type PushEnv, type PushToken } from "./push";

export interface Env extends PushEnv {
  CHANNEL: DurableObjectNamespace;
  FRAME_MAX_BYTES?: string;
  QUEUE_MAX?: string;
  QUEUE_TTL_MS?: string;
}

interface Session {
  authed: boolean;
  role?: Role;
  id?: string;
  challenge?: string;
  challengeTs?: number;
  /** token bucket: frames the connection may send now, and when it was last refilled */
  tokens: number;
  refill: number;
  /** refused frames in a row */
  strikes: number;
  lastSeen: number;
  /** the socket is closing: it no longer counts for presence */
  gone?: boolean;
  /** the frame being handled, named in an error frame: `id` of an envelope, `what` (the type) of
   *  any other frame. Never stored in the attachment. */
  ref?: { id: string } | { what: string };
}

const RATE_PER_MIN = 60;
const RATE_BURST = 20;
const CLOSE_SUPERSEDED = 4001;
const CLOSE_RATE = 4008;
const CLOSE_PROTOCOL = 4002;
/** Housekeeping of a channel nobody is connected to: expired frames, marks and nonces. */
const ALARM_MS = 10 * 60_000;
/** While a socket is open the alarm also looks for silent connections; one that is silent for
 *  IDLE_CLOSE_MS is closed by the next sweep, so within IDLE_CLOSE_MS + SWEEP_MS. */
const SWEEP_MS = 60_000;

export class Channel implements DurableObject {
  private readonly limits: Limits;
  private sid: string | null = null;

  constructor(private readonly ctx: DurableObjectState, private readonly env: Env) {
    this.limits = limitsFrom(env as unknown as Record<string, string | undefined>);
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair(JSON.stringify({ type: "ping" }), JSON.stringify({ type: "pong" })));
  }

  // ---- HTTP: the socket upgrade and the side door ------------------------------------------

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const sid = url.searchParams.get("sid") || "";
    if (!ID_RE.test(sid)) return json({ ok: false, reason: "sid_invalid" }, 400);
    await this.bindSid(sid);
    if (url.pathname === "/ws") return this.upgrade(req);
    if (url.pathname === "/frame") return this.frameByHttp(req, url.searchParams.get("id") || "");
    return json({ ok: false, reason: "not_found" }, 404);
  }

  private async bindSid(sid: string) {
    if (this.sid === sid) return;
    const stored = await this.ctx.storage.get<string>("sid");
    if (stored && stored !== sid) throw new Error("channel bound to another supervisor");
    if (!stored) await this.ctx.storage.put("sid", sid);
    this.sid = sid;
    if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(Date.now() + ALARM_MS);
  }

  private async upgrade(req: Request): Promise<Response> {
    if (req.headers.get("Upgrade")?.toLowerCase() !== "websocket") return json({ ok: false, reason: "upgrade_required" }, 426);
    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];
    const now = Date.now();
    const s: Session = { authed: false, challenge: randomB64url(32), challengeTs: now, tokens: RATE_BURST, refill: now, strikes: 0, lastSeen: now };
    this.ctx.acceptWebSocket(server, ["pending"]);
    server.serializeAttachment(s);
    const alarm = await this.ctx.storage.getAlarm();
    if (alarm === null || alarm > now + SWEEP_MS) await this.ctx.storage.setAlarm(now + SWEEP_MS);
    server.send(JSON.stringify({ type: "challenge", nonce: s.challenge, ts: now }));
    return new Response(null, { status: 101, webSocket: client });
  }

  // ---- WebSocket events ---------------------------------------------------------------------

  async webSocketMessage(ws: WebSocket, raw: string | ArrayBuffer): Promise<void> {
    const s = ws.deserializeAttachment() as Session;
    const now = Date.now();
    s.lastSeen = now;
    s.ref = undefined;
    if (typeof raw !== "string" || raw.length > this.limits.frameMaxBytes) {
      this.fail(ws, s, "too_large", true, 1009);
      return;
    }
    const f = parseFrame(raw);
    if (f) s.ref = (f.type === "msg" || f.type === "pair") && typeof f.id === "string" && f.id.length <= 64 ? { id: f.id } : { what: f.type as string };
    if (!this.rate(s, now)) {
      s.strikes++;
      if (s.strikes >= 3) {
        s.ref = undefined;
        ws.serializeAttachment(s);
        ws.close(CLOSE_RATE, "rate_limited");
        return;
      }
      this.fail(ws, s, "rate_limited");
      return;
    }
    s.strikes = 0;
    if (!f) {
      this.fail(ws, s, "frame_invalid", !s.authed);
      return;
    }
    if (!s.authed) {
      if (f.type !== "hello") {
        this.fail(ws, s, "hello_expected", true);
        return;
      }
      await this.hello(ws, s, f, now);
      return;
    }
    switch (f.type) {
      case "ping":
        ws.send(JSON.stringify({ type: "pong", ts: now }));
        break;
      case "pong":
        break;
      case "devices":
        await this.devicesFrame(ws, s, f);
        break;
      case "pairing":
        await this.pairingFrame(ws, s, f, now);
        break;
      case "msg":
      case "pair":
        await this.envelopeFrame(ws, s, f, now);
        break;
      case "ack":
        await this.ackFrame(ws, s, f);
        break;
      case "resume":
        await this.resumeFrame(ws, s, f, now);
        break;
      case "push.register":
        await this.pushRegister(ws, s, f, now);
        break;
      case "push.unregister":
        await this.pushUnregister(ws, s, f);
        break;
      default:
        // unknown types are ignored (forward compatibility)
        break;
    }
    s.ref = undefined;
    ws.serializeAttachment(s);
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean): Promise<void> {
    void code;
    void reason;
    void wasClean;
    this.left(ws);
    try {
      ws.close(1000);
    } catch {}
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    this.left(ws);
    try {
      ws.close(1011);
    } catch {}
  }

  async alarm(): Promise<void> {
    const now = Date.now();
    await this.expire(now);
    let open = 0;
    for (const ws of this.ctx.getWebSockets()) {
      const s = ws.deserializeAttachment() as Session | null;
      // a ping answered by the auto-response does not wake the object and does not reach
      // webSocketMessage: the runtime keeps its time, and it counts as a sign of life
      const auto = this.ctx.getWebSocketAutoResponseTimestamp(ws)?.getTime() ?? 0;
      if (s && now - Math.max(s.lastSeen, auto) > IDLE_CLOSE_MS) {
        this.left(ws);
        try {
          ws.close(1001, "idle");
        } catch {}
      } else {
        open++;
      }
    }
    await this.ctx.storage.setAlarm(now + (open > 0 ? SWEEP_MS : ALARM_MS));
  }

  // ---- hello --------------------------------------------------------------------------------

  private async hello(ws: WebSocket, s: Session, f: Record<string, unknown>, now: number) {
    const h = helloOf(f);
    if (typeof h === "string") {
      this.fail(ws, s, h, true);
      return;
    }
    if (!s.challenge || h.nonce !== s.challenge || now - (s.challengeTs ?? 0) > CHALLENGE_TTL_MS) {
      this.fail(ws, s, "challenge_invalid", true);
      return;
    }
    if (Math.abs(now - h.ts) > TS_WINDOW_MS) {
      this.fail(ws, s, "stale_timestamp", true);
      return;
    }
    const id = await idOfKey(h.key);
    if (!id) {
      this.fail(ws, s, "key_invalid", true);
      return;
    }
    const msg = canonicalJson({ type: HELLO_TYPE, role: h.role, key: h.key, enc: h.enc, ts: h.ts, nonce: h.nonce, client: h.client });
    if (!(await verifyEd25519(h.key, msg, h.sig))) {
      this.fail(ws, s, "bad_signature", true);
      return;
    }
    if (h.role === "supervisor" && id !== this.sid) {
      this.fail(ws, s, "not_this_channel", true);
      return;
    }
    s.authed = true;
    s.role = h.role;
    s.id = id;
    s.challenge = undefined;
    ws.serializeAttachment(s);
    // the hibernation tags are fixed at accept time, so the id is found via attachments
    const puts: Record<string, unknown> = { [`enc:${id}`]: h.enc };
    if (h.role === "device") puts[`key:${id}`] = h.key;
    await this.ctx.storage.put(puts);
    if (h.role === "supervisor") {
      for (const other of this.ctx.getWebSockets()) {
        if (other === ws) continue;
        const os = other.deserializeAttachment() as Session | null;
        if (os?.authed && os.role === "supervisor") {
          // superseded, not gone: the devices hear nothing of the old socket
          os.gone = true;
          other.serializeAttachment(os);
          try {
            other.close(CLOSE_SUPERSEDED, "superseded");
          } catch {}
        }
      }
    }
    ws.send(JSON.stringify({ type: "welcome", id, role: h.role, protocol: PROTOCOL, ts: now, limits: { frame: this.limits.frameMaxBytes, queue: this.limits.queueMax, ttl: this.limits.queueTtlMs } }));
    if (h.role === "device") ws.send(JSON.stringify({ type: "peer", online: this.supervisorOnline() }));
    else this.tellDevices(true);
  }

  // ---- presence: devices are told whether the supervisor is connected -----------------------

  /** Derived from the sockets, so it survives hibernation; `gone` marks one that is being closed. */
  private supervisorOnline(): boolean {
    for (const ws of this.ctx.getWebSockets()) {
      const s = ws.deserializeAttachment() as Session | null;
      if (s?.authed && s.role === "supervisor" && !s.gone) return true;
    }
    return false;
  }

  private tellDevices(online: boolean) {
    const frame = JSON.stringify({ type: "peer", online });
    for (const ws of this.ctx.getWebSockets()) {
      const s = ws.deserializeAttachment() as Session | null;
      if (!s?.authed || s.role !== "device" || s.gone) continue;
      try {
        ws.send(frame);
      } catch {}
    }
  }

  /** A socket is closing: when it was the supervisor's last one, the devices hear `online: false` (once per socket). */
  private left(ws: WebSocket) {
    const s = ws.deserializeAttachment() as Session | null;
    if (!s || s.gone) return;
    s.gone = true;
    try {
      ws.serializeAttachment(s);
    } catch {}
    if (s.authed && s.role === "supervisor" && !this.supervisorOnline()) this.tellDevices(false);
  }

  // ---- supervisor-only frames ---------------------------------------------------------------

  private async devicesFrame(ws: WebSocket, s: Session, f: Record<string, unknown>) {
    if (s.role !== "supervisor") {
      this.fail(ws, s, "supervisor_only");
      return;
    }
    const ids = Array.isArray(f.ids) ? f.ids.filter((x): x is string => typeof x === "string" && ID_RE.test(x)) : null;
    if (!ids || ids.length > 64) {
      this.fail(ws, s, "ids_invalid");
      return;
    }
    await this.ctx.storage.put("devices", ids);
    ws.send(JSON.stringify({ type: "ack", what: "devices", count: ids.length }));
  }

  private async pairingFrame(ws: WebSocket, s: Session, f: Record<string, unknown>, now: number) {
    if (s.role !== "supervisor") {
      this.fail(ws, s, "supervisor_only");
      return;
    }
    if (f.open === true) {
      const until = typeof f.until === "number" && Number.isSafeInteger(f.until) ? Math.min(f.until, now + PAIRING_MAX_MS) : now + PAIRING_MAX_MS;
      if (until <= now) {
        this.fail(ws, s, "until_invalid");
        return;
      }
      await this.ctx.storage.put("pairing", { until });
      ws.send(JSON.stringify({ type: "ack", what: "pairing", until }));
    } else {
      await this.ctx.storage.delete("pairing");
      ws.send(JSON.stringify({ type: "ack", what: "pairing", until: 0 }));
    }
  }

  // ---- envelope frames: accept, queue, deliver, push ----------------------------------------

  private async envelopeFrame(ws: WebSocket, s: Session, f: Record<string, unknown>, now: number) {
    const e = envelopeOf(f, now, this.limits.queueTtlMs);
    if (typeof e === "string") {
      this.fail(ws, s, e);
      return;
    }
    const from = s.id as string;
    if (s.role === "device") {
      if (e.to !== this.sid) {
        this.fail(ws, s, "to_invalid");
        return;
      }
      if (e.type === "pair") {
        const p = await this.ctx.storage.get<{ until: number }>("pairing");
        if (!p || p.until <= now) {
          this.fail(ws, s, "pairing_closed");
          return;
        }
      } else if (!(await this.trusted(from))) {
        this.fail(ws, s, "not_trusted");
        return;
      }
    } else {
      // a supervisor may write to any device on its own channel (pair.status goes to a device
      // that is not trusted yet)
      if (e.type === "pair") {
        this.fail(ws, s, "type_invalid");
        return;
      }
    }
    // dedupe: the same id acked again, never stored twice
    const known = await this.ctx.storage.get<string>(`qid:${e.id}`);
    const seen = await this.ctx.storage.get<number>(`seen:${e.id}`);
    if (known || seen) {
      const seq = known ? Number(known.split(":").pop()) : 0;
      ws.send(JSON.stringify({ type: "ack", id: e.id, seq, duplicate: true }));
      return;
    }
    const queued = await this.ctx.storage.list({ prefix: `q:${e.to}:`, limit: this.limits.queueMax });
    if (queued.size >= this.limits.queueMax) {
      this.fail(ws, s, "queue_full");
      return;
    }
    const seqKey = `seq:${e.to}:${from}`;
    const seq = ((await this.ctx.storage.get<number>(seqKey)) ?? 0) + 1;
    const env: Envelope = { ...e, from, seq };
    const qKey = `q:${e.to}:${from}:${pad(seq)}`;
    await this.ctx.storage.put({ [seqKey]: seq, [qKey]: env, [`qid:${e.id}`]: qKey, [`seen:${e.id}`]: Math.min(e.exp, now + SEEN_TTL_MS) + SEEN_TTL_MS });
    ws.send(JSON.stringify({ type: "ack", id: e.id, seq }));
    const delivered = this.deliver(env);
    if (!delivered && s.role === "supervisor" && PUSH_KINDS.has(env.kind)) {
      this.ctx.waitUntil(this.push(env));
    }
  }

  /** Sends the frame to every live, authenticated socket of `to`; true if at least one got it. */
  private deliver(env: Envelope): boolean {
    let n = 0;
    for (const ws of this.ctx.getWebSockets()) {
      const s = ws.deserializeAttachment() as Session | null;
      if (!s?.authed || s.id !== env.to) continue;
      try {
        ws.send(JSON.stringify(env));
        n++;
      } catch {}
    }
    return n > 0;
  }

  private async push(env: Envelope) {
    const tokens = await this.ctx.storage.list<PushToken>({ prefix: `push:${env.to}:` });
    if (tokens.size === 0) return;
    const payload = pushPayload(this.sid as string, env);
    for (const [key, t] of tokens) {
      const r = await sendPush(this.env, t, payload, env.exp);
      if (r.unregister) await this.ctx.storage.delete(key);
      if (!r.ok) console.log(JSON.stringify({ event: "push_failed", sid: this.sid, platform: t.platform, status: r.status, reason: r.reason }));
    }
  }

  private async ackFrame(ws: WebSocket, s: Session, f: Record<string, unknown>) {
    if (typeof f.id !== "string") return;
    const qKey = await this.ctx.storage.get<string>(`qid:${f.id}`);
    if (!qKey) return;
    // only the recipient may ack: q:<to>:<from>:<seq>
    if (qKey.split(":")[1] !== s.id) {
      this.fail(ws, s, "not_recipient");
      return;
    }
    await this.ctx.storage.delete([qKey, `qid:${f.id}`]);
  }

  private async resumeFrame(ws: WebSocket, s: Session, f: Record<string, unknown>, now: number) {
    const since = typeof f.seq === "number" && Number.isSafeInteger(f.seq) && f.seq >= 0 ? f.seq : 0;
    let prefix: string;
    if (s.role === "device") {
      prefix = `q:${s.id}:${this.sid}:`;
    } else {
      const dev = typeof f.device === "string" && ID_RE.test(f.device) ? f.device : "";
      prefix = dev ? `q:${this.sid}:${dev}:` : `q:${this.sid}:`;
    }
    const items = await this.ctx.storage.list<Envelope>({ prefix });
    const out: Envelope[] = [];
    for (const [, env] of items) {
      if (env.exp <= now) continue;
      if (prefix.split(":").length === 4 && env.seq <= since) continue;
      out.push(env);
    }
    out.sort((a, b) => (a.from === b.from ? a.seq - b.seq : a.from < b.from ? -1 : 1));
    for (const env of out) ws.send(JSON.stringify(env));
    ws.send(JSON.stringify({ type: "resumed", count: out.length }));
  }

  // ---- push tokens --------------------------------------------------------------------------

  private async pushRegister(ws: WebSocket, s: Session, f: Record<string, unknown>, now: number) {
    if (s.role !== "device") {
      this.fail(ws, s, "device_only");
      return;
    }
    const platform = f.platform;
    const token = typeof f.token === "string" ? f.token.trim() : "";
    if (typeof platform !== "string" || !PLATFORMS.has(platform)) {
      this.fail(ws, s, "platform_unsupported");
      return;
    }
    if (!/^[A-Za-z0-9:_-]{16,512}$/.test(token)) {
      this.fail(ws, s, "token_invalid");
      return;
    }
    const environment = f.environment === "sandbox" ? "sandbox" : "production";
    const topic = typeof f.topic === "string" && f.topic.length <= 128 ? f.topic : "";
    const existing = await this.ctx.storage.list({ prefix: `push:${s.id}:` });
    if (existing.size >= 8 && !existing.has(`push:${s.id}:${platform}:${token}`)) {
      this.fail(ws, s, "too_many_tokens");
      return;
    }
    const t: PushToken = { platform: platform as PushToken["platform"], token, environment, topic, registeredAt: now };
    await this.ctx.storage.put(`push:${s.id}:${platform}:${token}`, t);
    ws.send(JSON.stringify({ type: "ack", what: "push.register", configured: platform === "apns" ? !!this.env.APNS_KEY_P8 : !!this.env.FCM_SERVICE_ACCOUNT }));
  }

  private async pushUnregister(ws: WebSocket, s: Session, f: Record<string, unknown>) {
    if (s.role !== "device") {
      this.fail(ws, s, "device_only");
      return;
    }
    const platform = typeof f.platform === "string" ? f.platform : "";
    const token = typeof f.token === "string" ? f.token.trim() : "";
    const n = await this.ctx.storage.delete(`push:${s.id}:${platform}:${token}`);
    ws.send(JSON.stringify({ type: "ack", what: "push.unregister", removed: n ? 1 : 0 }));
  }

  // ---- the side door: GET /v1/frames/<sid>/<id> ---------------------------------------------

  private async frameByHttp(req: Request, id: string): Promise<Response> {
    const dev = (req.headers.get("X-Wardenclaw-Device") || "").toLowerCase();
    const nonce = req.headers.get("X-Wardenclaw-Nonce") || "";
    const sig = req.headers.get("X-Wardenclaw-Signature") || "";
    const ts = Number(req.headers.get("X-Wardenclaw-Ts"));
    const now = Date.now();
    const reject = (reason: string, status = 401) => json({ ok: false, reason }, status);
    if (!ID_RE.test(dev)) return reject("device_id_invalid");
    if (!Number.isSafeInteger(ts)) return reject("ts_invalid");
    if (nonce.length < 8 || nonce.length > 128) return reject("nonce_invalid");
    if (!sig) return reject("signature_missing");
    if (Math.abs(now - ts) > TS_WINDOW_MS) return reject("stale_timestamp");
    const key = await this.ctx.storage.get<string>(`key:${dev}`);
    if (!key) return reject("device_unknown");
    const msg = canonicalJson({ type: REQ_TYPE, supervisorId: "relay", action: "relay.frame", deviceId: dev, ts, nonce });
    if (!(await verifyEd25519(key, msg, sig))) return reject("bad_signature");
    if (await this.ctx.storage.get(`nonce:${nonce}`)) return reject("nonce_reused");
    await this.ctx.storage.put(`nonce:${nonce}`, now + TS_WINDOW_MS * 2);
    const qKey = await this.ctx.storage.get<string>(`qid:${id}`);
    const env = qKey ? await this.ctx.storage.get<Envelope>(qKey) : undefined;
    if (!env || env.to !== dev || env.exp <= now) return json({ ok: false, reason: "not_found" }, 404);
    return json({ ok: true, frame: env });
  }

  // ---- helpers ------------------------------------------------------------------------------

  private async trusted(deviceId: string): Promise<boolean> {
    const ids = (await this.ctx.storage.get<string[]>("devices")) ?? [];
    return ids.includes(deviceId);
  }

  /** Token bucket: RATE_PER_MIN frames per minute sustained, RATE_BURST at once. */
  private rate(s: Session, now: number): boolean {
    // a socket accepted by an older version of this object has no bucket yet
    if (typeof s.tokens !== "number" || typeof s.refill !== "number") {
      s.tokens = RATE_BURST;
      s.refill = now;
    }
    s.tokens = Math.min(RATE_BURST, s.tokens + (Math.max(0, now - s.refill) * RATE_PER_MIN) / 60_000);
    s.refill = now;
    if (s.tokens < 1) return false;
    s.tokens -= 1;
    return true;
  }

  /** Answers the frame being handled with an error that names it (`id` or `what`). */
  private fail(ws: WebSocket, s: Session, code: string, close = false, closeCode = CLOSE_PROTOCOL) {
    const ref = s.ref ?? {};
    s.ref = undefined;
    try {
      ws.send(JSON.stringify({ type: "error", code, close, ...ref }));
      if (close) ws.close(closeCode, code);
    } catch {}
    ws.serializeAttachment(s);
  }

  /** Deletes expired queue entries, dedupe marks and request nonces. */
  private async expire(now: number) {
    const dead: string[] = [];
    for (const [k, env] of await this.ctx.storage.list<Envelope>({ prefix: "q:" })) {
      if (env.exp <= now) dead.push(k, `qid:${env.id}`);
    }
    for (const [k, exp] of await this.ctx.storage.list<number>({ prefix: "seen:" })) if (exp <= now) dead.push(k);
    for (const [k, exp] of await this.ctx.storage.list<number>({ prefix: "nonce:" })) if (exp <= now) dead.push(k);
    const p = await this.ctx.storage.get<{ until: number }>("pairing");
    if (p && p.until <= now) dead.push("pairing");
    for (let i = 0; i < dead.length; i += 128) await this.ctx.storage.delete(dead.slice(i, i + 128));
  }
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
}

export { KINDS };
