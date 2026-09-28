// SPDX-License-Identifier: GPL-3.0-or-later
// The device's session with one supervisor over the relay (protocol/README.md; no Expo/RN, tested
// in node with a fake relay socket). One session = one channel = one WebSocket at a time:
//
//   challenge → signed hello → welcome → peer{online} → resume{seq} → resumed → status.req (when paired)
//   pair():        pair frame (payload boxed, the enc key in front) → pair.status naming that frame (`re`)
//   peer:          the relay says whether the supervisor is connected; when it comes back, status.req
//   incoming msg:  routing checked, deduped by id, box opened, payload checked, hook, ack
//   sendTicket():  ticket msg → relay ack → ticket.result for that card
//
// Fail closed: a frame that does not open, is expired, or carries a card without the
// supervisor's signature is reported through onRefused and never acked; nothing of it reaches
// the hooks. A frame of an unknown kind that opens is acked and ignored (onIgnored). The socket and the randomness are injected (React Native passes the
// global WebSocket and expo-crypto, the tests a fake).
import { b64url, bytesToHex, utf8Decode, utf8Encode } from "./bytes";
import { boxAad, boxKey, boxOpen, boxSeal, encKeyPair, pairBody, NONCE_LEN } from "./relayBox";
import {
  KINDS_IN,
  ERR,
  TICKET_TTL_MS,
  buildHello,
  challengeNonce,
  channelUrl,
  checkCard,
  incomingEnvelope,
  outgoingExp,
  pairPlaintext,
  parseFrame,
  parsePlaintext,
  welcomeLimits,
  type KindOut,
  type Limits,
  type OutEnvelope,
  type RelayCard,
} from "./relayProto";

/** The part of a WebSocket the session uses. */
export type RelaySocket = {
  send(data: string): void;
  close(code?: number, reason?: string): void;
  onopen: (() => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onclose: ((ev: { code?: number; reason?: string }) => void) | null;
  onerror: ((ev: unknown) => void) | null;
};
export type RelaySocketFactory = (url: string) => RelaySocket;

/** idle: not started; connecting: socket opening or hello sent; ready: welcomed; waiting: backoff before the next attempt. */
export type RelayState = "idle" | "connecting" | "ready" | "waiting" | "stopped";

/** `re`: the id of the pair frame this answers; `id`: the supervisor's name for the request (`wardend pair approve <id>`). */
export type PairStatus = { status: "pending" | "approved" | "rejected" | "refused"; re: string; id?: string; reason?: string; fingerprint?: string; supervisorId?: string; host?: string; expiresAt?: number };
export type TicketResult = { ok: boolean; id: string; decision?: string; reason?: string };
export type CardDone = { id: string; outcome: string };
/** wardend's status (mode, policy, hardware rules) with the full, verified pending list. */
export type RelayStatus = Record<string, unknown> & { pending: RelayCard[] };

/** A decision ticket of README section 4, built and signed by the caller (decide.ts). */
export type RelayTicket = { deviceId: string; payload: { id: string; decision: string } & Record<string, unknown>; signature: string; hw?: unknown };

export type RelayHooks = {
  onState?(state: RelayState, detail?: string): void;
  /** A frame was handled and acked: persist the last acked seq (the `seq` of the next session) and the frame's id (relayState.ts). */
  onSeq?(seq: number, frameId: string): void;
  onCard?(card: RelayCard): void;
  onCardDone?(done: CardDone): void;
  onStatus?(status: RelayStatus): void;
  onPairStatus?(st: PairStatus): void;
  /** The relay says whether the supervisor is connected to it: after every welcome and when that changes. */
  onPeer?(online: boolean): void;
  /** The relay refused the status request of a device that was trusted: revoked on the supervisor. */
  onNotTrusted?(): void;
  /** A frame was refused (reason: relay_tamper, expired, card_bad_signature, kind_invalid, …). */
  onRefused?(reason: string, frameId?: string): void;
  /** A frame of a kind this app does not know came from the supervisor: acked, not delivered. Log it. */
  onIgnored?(kind: string, frameId: string): void;
};

/**
 * rateBurst / rateEveryMs: the outgoing budget, a token bucket kept below the relay's limit of 20
 * frames at once and one more per second (protocol/README.md section 13), the numbers of wardend's client.
 * rateRetryMs: the pause before a frame the relay refused as rate_limited goes out again.
 */
export type RelayTiming = { pingMs: number; idleMs: number; backoffMinMs: number; backoffMaxMs: number; replyMs: number; retryMs: number; rateBurst: number; rateEveryMs: number; rateRetryMs: number };
const TIMING: RelayTiming = { pingMs: 30_000, idleMs: 75_000, backoffMinMs: 1000, backoffMaxMs: 60_000, replyMs: 20_000, retryMs: 500, rateBurst: 15, rateEveryMs: 1200, rateRetryMs: 3000 };
/** A frame refused as rate_limited is sent again (the same frame, the same id) this many times. */
const RATE_RETRIES = 2;

export type RelaySessionOptions = {
  /** From the pair link: the relay base URL and the supervisor's id, identity key and encryption key. */
  link: { relay: string; supervisorId: string; key: string; enc: string };
  /** The device: identity (identity.ts) and its X25519 private key. */
  device: { deviceId: string; publicKey: string; sign(payload: string): string; encPrivate: Uint8Array };
  /** App version for the hello. */
  version: string;
  /** The last seq acked in an earlier session with this supervisor, 0 for none. */
  seq: number;
  /** Ids of the last frames handled in earlier sessions (relayState.ts): delivered again, they are acked and not shown twice. */
  seen?: readonly string[];
  /** The supervisor already approved this device: status is asked after every connect. */
  trusted: boolean;
  /** The id of the pair frame an earlier session sent and whose approval is still awaited. */
  pairFrame?: string | null;
  socket: RelaySocketFactory;
  random(n: number): Uint8Array;
  now?(): number;
  hooks?: RelayHooks;
  timing?: Partial<RelayTiming>;
};

export class RelayError extends Error {
  constructor(public code: string) {
    super(`relay: ${code}`);
  }
}

type Waiter<T> = { resolve(v: T): void; reject(e: Error): void; timer: ReturnType<typeof setTimeout> };

const SEEN_MAX = 1000;

export class RelaySession {
  private readonly o: RelaySessionOptions;
  private readonly timing: RelayTiming;
  private readonly hooks: RelayHooks;
  private readonly key: Uint8Array;
  private readonly encPub: Uint8Array;
  private ws: RelaySocket | null = null;
  private gen = 0;
  private stateNow: RelayState = "idle";
  private limits: Limits | null = null;
  private seq: number;
  private trusted: boolean;
  private attempt = 0;
  private lastHeard = 0;
  private helloSent = false;
  private tokens = 0;
  private refilled = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private pinger: ReturnType<typeof setTimeout> | null = null;
  private readonly seen = new Set<string>();
  private readonly sent = new Map<string, Waiter<number>>();
  private readonly tickets = new Map<string, Waiter<TicketResult> & { decision: string }>();
  private readonly asked = new Map<string, Waiter<Record<string, unknown>>>();
  private pairing: Waiter<PairStatus> | null = null;
  /** The pair frame whose answers count; a pair.status for another one is acked and dropped. */
  private pairFrame: string | null;
  /** What the relay last said about the supervisor on this connection; null until it says. */
  private peer: boolean | null = null;

  constructor(o: RelaySessionOptions) {
    this.pairFrame = o.pairFrame ?? null;
    this.o = o;
    this.timing = { ...TIMING, ...o.timing };
    this.hooks = o.hooks ?? {};
    this.seq = o.seq;
    for (const id of o.seen ?? []) this.seen.add(id);
    this.trusted = o.trusted;
    this.encPub = encKeyPair(o.device.encPrivate).publicKey;
    this.key = boxKey(o.device.encPrivate, b64url.decode(o.link.enc), o.link.supervisorId, o.device.deviceId);
  }

  get state(): RelayState {
    return this.stateNow;
  }
  get lastSeq(): number {
    return this.seq;
  }
  get isTrusted(): boolean {
    return this.trusted;
  }

  /** Connects and keeps the connection (reconnects with backoff) until stop(). */
  start() {
    if (this.stateNow !== "idle" && this.stateNow !== "stopped") return;
    this.attempt = 0;
    this.connect();
  }

  /** Closes the connection and stops reconnecting; everything waiting for an answer fails with `stopped`. */
  stop() {
    this.gen++;
    this.clearTimers();
    const ws = this.ws;
    this.ws = null;
    try {
      ws?.close(1000, "stopped");
    } catch {}
    this.failAll("stopped");
    this.setState("stopped");
  }

  /**
   * Sends the pairing request for this code and resolves with the supervisor's first answer
   * (pending or refused; approved/rejected follow through onPairStatus, maybe in a later session).
   */
  pair(code: string, name: string): Promise<PairStatus> {
    const { device, link } = this.o;
    if (this.pairing) return Promise.reject(new RelayError("pair_in_progress"));
    const ts = this.now();
    const plaintext = pairPlaintext({ code, deviceId: device.deviceId, pubkey: device.publicKey, enc: b64url.encode(this.encPub), name, supervisorId: link.supervisorId, ts, nonce: uuid(this.o.random(16)) }, device.sign);
    const id = bytesToHex(this.o.random(16));
    return new Promise<PairStatus>((resolve, reject) => {
      const w: Waiter<PairStatus> = { resolve, reject, timer: setTimeout(() => this.endPairing(new RelayError("timeout")), this.timing.replyMs) };
      this.pairing = w;
      this.pairFrame = id;
      this.post("pair", plaintext, 2 * 60_000, id).catch((e) => this.endPairing(e));
    });
  }

  /** Sends a decision ticket and resolves with the supervisor's ticket.result for that card. */
  sendTicket(ticket: RelayTicket): Promise<TicketResult> {
    const id = ticket.payload.id;
    if (this.tickets.has(id)) return Promise.reject(new RelayError("ticket_in_progress"));
    return new Promise<TicketResult>((resolve, reject) => {
      const fail = (e: Error) => {
        const w = this.tickets.get(id);
        if (!w) return;
        clearTimeout(w.timer);
        this.tickets.delete(id);
        reject(e);
      };
      this.tickets.set(id, { resolve, reject, decision: ticket.payload.decision, timer: setTimeout(() => fail(new RelayError("timeout")), this.timing.replyMs) });
      this.post("ticket", JSON.stringify(ticket), TICKET_TTL_MS).catch(fail);
    });
  }

  /** The status request the session sends by itself: after a connect, an approval, a gap, the supervisor's return. */
  private resync() {
    this.requestStatus().catch((e) => {
      if (e instanceof RelayError && e.code === ERR.notTrusted) this.hooks.onNotTrusted?.();
    });
  }

  /** Asks the supervisor for the full state (status.req); the answer comes through onStatus. */
  async requestStatus(): Promise<void> {
    for (let i = 0; ; i++) {
      try {
        await this.post("status.req", "{}", 60_000);
        return;
      } catch (e) {
        // right after approval the relay may not have the new device list yet
        const code = e instanceof RelayError ? e.code : "";
        if (code !== ERR.notTrusted || i >= 5) throw e;
        await new Promise((r) => setTimeout(r, this.timing.retryMs * (i + 1)));
      }
    }
  }

  /**
   * Registers a push token with the relay (section 8): it pushes when a card arrives and this
   * device has no live connection. `configured` is false when the relay has no credentials for
   * that platform.
   */
  async registerPush(p: { platform: "apns" | "fcm"; token: string; environment: "sandbox" | "production"; topic: string }): Promise<{ configured: boolean }> {
    const a = await this.ask({ type: "push.register", platform: p.platform, token: p.token, environment: p.environment, topic: p.topic });
    return { configured: a.configured === true };
  }

  async unregisterPush(p: { platform: "apns" | "fcm"; token: string }): Promise<void> {
    await this.ask({ type: "push.unregister", platform: p.platform, token: p.token });
  }

  /** A relay frame that is answered with {type:"ack", what} or {type:"error", what}; one of a type at a time. */
  private ask(frame: { type: string } & Record<string, unknown>): Promise<Record<string, unknown>> {
    const what = frame.type;
    if (this.stateNow !== "ready") return Promise.reject(new RelayError("not_connected"));
    if (this.asked.has(what)) return Promise.reject(new RelayError("in_progress"));
    // the slot is taken for the whole request, the wait for the budget included
    const hold: Waiter<Record<string, unknown>> = { resolve: () => {}, reject: () => {}, timer: setTimeout(() => {}, 0) };
    this.asked.set(what, hold);
    const wait = () =>
      new Promise<Record<string, unknown>>((resolve, reject) => {
        const timer = setTimeout(() => {
          this.asked.delete(what);
          reject(new RelayError("timeout"));
        }, this.timing.replyMs);
        this.asked.set(what, { resolve, reject, timer });
      });
    return this.paced(frame, wait).finally(() => {
      const w = this.asked.get(what);
      if (w) clearTimeout(w.timer);
      this.asked.delete(what);
    });
  }

  private now(): number {
    return this.o.now ? this.o.now() : Date.now();
  }

  private setState(s: RelayState, detail?: string) {
    if (this.stateNow === s && !detail) return;
    this.stateNow = s;
    this.hooks.onState?.(s, detail);
  }

  private clearTimers() {
    if (this.timer) clearTimeout(this.timer);
    if (this.pinger) clearTimeout(this.pinger);
    this.timer = this.pinger = null;
  }

  private connect() {
    const gen = ++this.gen;
    this.clearTimers();
    this.limits = null;
    this.peer = null;
    this.helloSent = false;
    // the relay counts per connection: a new one starts with a full budget
    this.tokens = this.timing.rateBurst;
    this.refilled = this.now();
    this.setState("connecting");
    let ws: RelaySocket;
    try {
      ws = this.o.socket(channelUrl(this.o.link.relay, this.o.link.supervisorId));
    } catch {
      this.retry("socket_failed");
      return;
    }
    this.ws = ws;
    this.lastHeard = this.now();
    ws.onopen = () => {};
    ws.onerror = () => {};
    ws.onmessage = (ev) => {
      if (gen !== this.gen) return;
      this.lastHeard = this.now();
      if (typeof ev.data !== "string") return this.refuse("frame_invalid");
      const f = parseFrame(ev.data);
      if (!f) return this.refuse("frame_invalid");
      this.onFrame(f);
    };
    ws.onclose = (ev) => {
      if (gen !== this.gen) return;
      this.ws = null;
      this.retry(ev?.reason || (ev?.code ? `closed_${ev.code}` : "closed"));
    };
    this.keepalive(gen);
  }

  /** The connection is gone: what waited for an answer fails, the next attempt is scheduled. */
  private retry(detail: string) {
    this.gen++;
    this.clearTimers();
    this.failAll("disconnected");
    const t = this.timing;
    const ceil = Math.min(t.backoffMaxMs, t.backoffMinMs * 2 ** Math.min(this.attempt, 16));
    this.attempt++;
    // jitter: 50..100% of the step, so phones that lost the relay together do not come back together
    const delay = Math.round(ceil * (0.5 + this.o.random(1)[0] / 510));
    this.setState("waiting", detail);
    this.timer = setTimeout(() => this.connect(), delay);
  }

  private drop(detail: string) {
    const ws = this.ws;
    this.ws = null;
    this.gen++;
    try {
      ws?.close(4000, detail);
    } catch {}
    this.retry(detail);
  }

  private keepalive(gen: number) {
    this.pinger = setTimeout(() => {
      if (gen !== this.gen) return;
      if (this.now() - this.lastHeard > this.timing.idleMs) return this.drop("idle");
      this.write({ type: "ping", ts: this.now() });
      this.keepalive(gen);
    }, this.timing.pingMs);
  }

  /**
   * Takes one token of the outgoing budget; 0, or how long to wait for one. Without `wait` the
   * token is taken anyway and the budget goes into debt: acks, pongs, pings and the hello must not
   * be late, and the relay counts them too.
   */
  private take(wait: boolean): number {
    const t = this.timing;
    const now = this.now();
    this.tokens = Math.min(t.rateBurst, this.tokens + Math.max(0, now - this.refilled) / t.rateEveryMs);
    this.refilled = now;
    if (this.tokens >= 1 || !wait) {
      this.tokens = Math.max(this.tokens - 1, -t.rateBurst);
      return 0;
    }
    return Math.ceil((1 - this.tokens) * t.rateEveryMs);
  }

  /**
   * A request (ticket, status.req, pair, push registration): waits for a token, writes the frame
   * and waits for the relay's answer through `wait`; a frame refused as rate_limited was not
   * stored and goes out again later. Fails if the connection it started on is gone.
   */
  private async paced<T>(frame: Record<string, unknown>, wait: () => Promise<T>): Promise<T> {
    const gen = this.gen;
    const pause = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
    for (let attempt = 0; ; attempt++) {
      for (let ms = this.take(true); ms > 0; ms = this.take(true)) {
        await pause(ms);
        if (gen !== this.gen || this.stateNow !== "ready") throw new RelayError("disconnected");
      }
      const answer = wait();
      if (!this.send(frame)) {
        answer.catch(() => {});
        throw new RelayError("not_connected");
      }
      try {
        return await answer;
      } catch (e) {
        if (!(e instanceof RelayError) || e.code !== ERR.rateLimited || attempt >= RATE_RETRIES) throw e;
      }
      await pause(this.timing.rateRetryMs);
      if (gen !== this.gen || this.stateNow !== "ready") throw new RelayError("disconnected");
    }
  }

  /** A frame that is not paced (take(false)): see there. */
  private write(frame: Record<string, unknown>): boolean {
    this.take(false);
    return this.send(frame);
  }

  private send(frame: Record<string, unknown>): boolean {
    try {
      if (!this.ws) return false;
      this.ws.send(JSON.stringify(frame));
      return true;
    } catch {
      return false;
    }
  }

  private refuse(reason: string, frameId?: string) {
    this.hooks.onRefused?.(reason, frameId);
  }

  private failAll(code: string) {
    for (const w of this.sent.values()) {
      clearTimeout(w.timer);
      w.reject(new RelayError(code));
    }
    this.sent.clear();
    for (const w of this.tickets.values()) {
      clearTimeout(w.timer);
      w.reject(new RelayError(code));
    }
    this.tickets.clear();
    for (const w of this.asked.values()) {
      clearTimeout(w.timer);
      w.reject(new RelayError(code));
    }
    this.asked.clear();
    this.endPairing(new RelayError(code));
  }

  private endPairing(r: PairStatus | Error) {
    const w = this.pairing;
    if (!w) return;
    this.pairing = null;
    clearTimeout(w.timer);
    if (r instanceof Error) w.reject(r);
    else w.resolve(r);
  }

  /** Boxes a payload for the supervisor, sends it and resolves when the relay stored it. */
  private post(kind: KindOut | "pair", plaintext: string, ttlMs: number, id = bytesToHex(this.o.random(16))): Promise<number> {
    const { device, link } = this.o;
    if (this.stateNow !== "ready" || !this.limits) return Promise.reject(new RelayError("not_connected"));
    const ts = this.now();
    const exp = outgoingExp(ts, ttlMs, this.limits);
    const sealed = boxSeal(this.key, this.o.random(NONCE_LEN), utf8Encode(plaintext), boxAad({ id, from: device.deviceId, to: link.supervisorId, kind, exp }));
    const frame: OutEnvelope = kind === "pair" ? { type: "pair", id, to: link.supervisorId, ts, exp, body: pairBody(this.encPub, sealed) } : { type: "msg", id, to: link.supervisorId, ts, exp, body: sealed, kind };
    const wait = () =>
      new Promise<number>((resolve, reject) => {
        const timer = setTimeout(() => {
          this.sent.delete(id);
          reject(new RelayError("timeout"));
        }, this.timing.replyMs);
        this.sent.set(id, { resolve, reject, timer });
      });
    return this.paced(frame, wait).finally(() => {
      const w = this.sent.get(id);
      if (w) clearTimeout(w.timer);
      this.sent.delete(id);
    });
  }

  private onFrame(f: Record<string, unknown>) {
    switch (f.type) {
      case "challenge": {
        const nonce = challengeNonce(f);
        if (!nonce || this.helloSent) return this.refuse("challenge_invalid");
        this.helloSent = true;
        const { device } = this.o;
        this.write(buildHello({ key: device.publicKey, enc: b64url.encode(this.encPub), ts: this.now(), nonce, version: this.o.version }, device.sign));
        return;
      }
      case "welcome": {
        const limits = this.helloSent && !this.limits ? welcomeLimits(f, this.o.device.deviceId) : null;
        if (!limits) return this.drop("welcome_invalid");
        this.limits = limits;
        this.attempt = 0;
        this.setState("ready");
        this.write({ type: "resume", seq: this.seq });
        return;
      }
      case "resumed":
        if (this.trusted) this.resync();
        return;
      case "peer": {
        if (this.stateNow !== "ready" || typeof f.online !== "boolean") return;
        const was = this.peer;
        this.peer = f.online;
        this.hooks.onPeer?.(f.online);
        // it was away and is back: what it decided meanwhile is in its status
        if (f.online && was === false && this.trusted) this.resync();
        return;
      }
      case "msg":
        if (this.stateNow === "ready") this.onMsg(f);
        return;
      case "ack": {
        const q = typeof f.what === "string" ? this.asked.get(f.what) : undefined;
        if (q) {
          this.asked.delete(f.what as string);
          clearTimeout(q.timer);
          q.resolve(f);
          return;
        }
        const w = typeof f.id === "string" ? this.sent.get(f.id) : undefined;
        if (!w) return;
        this.sent.delete(f.id as string);
        clearTimeout(w.timer);
        w.resolve(typeof f.seq === "number" ? f.seq : 0);
        return;
      }
      case "error": {
        const code = typeof f.code === "string" && f.code ? f.code : "error";
        const w = typeof f.id === "string" ? this.sent.get(f.id) : undefined;
        if (w) {
          this.sent.delete(f.id as string);
          clearTimeout(w.timer);
          w.reject(new RelayError(code));
        }
        const q = typeof f.what === "string" ? this.asked.get(f.what) : undefined;
        if (q) {
          this.asked.delete(f.what as string);
          clearTimeout(q.timer);
          q.reject(new RelayError(code));
        }
        if (f.close === true) this.drop(code);
        return;
      }
      case "ping":
        this.write(typeof f.ts === "number" ? { type: "pong", ts: f.ts } : { type: "pong" });
        return;
      default:
        return; // pong and types of a later protocol
    }
  }

  private onMsg(f: Record<string, unknown>) {
    const { device, link } = this.o;
    const now = this.now();
    const e = incomingEnvelope(f, { deviceId: device.deviceId, supervisorId: link.supervisorId }, now);
    const fid = typeof f.id === "string" ? f.id : undefined;
    if (typeof e === "string") return this.refuse(e, fid);
    const ack = () => this.write({ type: "ack", id: e.id, seq: e.seq });
    if (this.seen.has(e.id)) {
      ack();
      return;
    }
    let text: string;
    try {
      text = utf8Decode(boxOpen(this.key, e.body, boxAad(e)));
    } catch {
      return this.refuse("relay_tamper", e.id);
    }
    // a kind of a later protocol, boxed by the supervisor: acked like a handled frame, so it does
    // not come again with every resume until its exp; the plaintext is not looked at
    const known = (KINDS_IN as readonly string[]).includes(e.kind);
    const p = known ? parsePlaintext(text) : {};
    if (!p) return this.refuse("plaintext_invalid", e.id);
    const str = (v: unknown): v is string => typeof v === "string" && v.length > 0;

    switch (e.kind) {
      case "card": {
        const bad = checkCard(p, link.key, now);
        if (bad) return this.refuse(bad, e.id);
        this.hooks.onCard?.(p as RelayCard);
        break;
      }
      case "card.done":
        if (!str(p.id) || !str(p.outcome)) return this.refuse("plaintext_invalid", e.id);
        this.hooks.onCardDone?.({ id: p.id, outcome: p.outcome });
        break;
      case "status": {
        if (!Array.isArray(p.pending) || (p.supervisorId !== undefined && p.supervisorId !== link.supervisorId)) return this.refuse("plaintext_invalid", e.id);
        const pending: RelayCard[] = [];
        for (const it of p.pending) {
          const bad = typeof it === "object" && it !== null && !Array.isArray(it) ? checkCard(it as Record<string, unknown>, link.key, now) : "card_invalid";
          if (bad === "card_expired") continue; // gone between the supervisor and here: not shown
          if (bad) return this.refuse(bad, e.id);
          pending.push(it as RelayCard);
        }
        this.hooks.onStatus?.({ ...p, pending });
        break;
      }
      case "pair.status": {
        const s = p.status;
        if ((s !== "pending" && s !== "approved" && s !== "rejected" && s !== "refused") || (p.supervisorId !== undefined && p.supervisorId !== link.supervisorId)) return this.refuse("plaintext_invalid", e.id);
        // the answer to an earlier request (or to nobody's): handled, so that it does not come again
        if (!this.pairFrame || p.re !== this.pairFrame) break;
        const st = p as PairStatus;
        if (s === "approved" && !this.trusted) {
          this.trusted = true;
          this.resync();
        }
        this.hooks.onPairStatus?.(st);
        this.endPairing(st);
        break;
      }
      case "ticket.result": {
        if (!str(p.id) || typeof p.ok !== "boolean") return this.refuse("plaintext_invalid", e.id);
        const w = this.tickets.get(p.id);
        if (w) {
          // an ok for another decision than the one sent is not an answer to this ticket
          if (p.ok && p.decision !== w.decision) return this.refuse("ticket_result_mismatch", e.id);
          this.tickets.delete(p.id);
          clearTimeout(w.timer);
          w.resolve(p as TicketResult);
        }
        break;
      }
      default:
        this.hooks.onIgnored?.(e.kind, e.id);
    }

    this.seen.add(e.id);
    if (this.seen.size > SEEN_MAX) this.seen.delete(this.seen.values().next().value as string);
    ack();
    // a gap: frames expired or were dropped on the way, the supervisor has the truth
    const gap = e.seq > this.seq + 1 && e.kind !== "status";
    if (e.seq > this.seq) this.seq = e.seq;
    this.hooks.onSeq?.(this.seq, e.id);
    if (gap && this.trusted) this.resync();
  }
}

/** A version-4 UUID from 16 random bytes: the nonce of a pairing payload. */
function uuid(r: Uint8Array): string {
  const b = Uint8Array.from(r);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = bytesToHex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
