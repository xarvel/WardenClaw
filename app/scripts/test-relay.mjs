// SPDX-License-Identifier: GPL-3.0-or-later
// Tests of the relay transport core (src/core/relayBox.ts, relayProto.ts, relaySession.ts), loaded
// by test-core.mjs after it compiled src/core into .test-build/. Covers every member of
// protocol/vectors/relay_vectors.json (byte for byte with wardend, daemon/relayvectors_test.go)
// and the device session against an in-memory relay that also plays the supervisor.
import { createRequire } from "node:module";
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const out = path.join(root, ".test-build");
const require = createRequire(path.join(out, "core/x.js"));
const box = require(path.join(out, "core/relayBox.js"));
const proto = require(path.join(out, "core/relayProto.js"));
const { RelaySession, RelayError } = require(path.join(out, "core/relaySession.js"));
const state = require(path.join(out, "core/relayState.js"));
const { b64url, hexToBytes, bytesToHex, utf8Encode, utf8Decode } = require(path.join(out, "core/bytes.js"));
const { canonicalJson } = require(path.join(out, "core/canonical.js"));
const ed = require("@noble/ed25519");
const rv = JSON.parse(fs.readFileSync(path.join(root, "../protocol/vectors/relay_vectors.json"), "utf8"));

const sign = (seedHex) => (s) => b64url.encode(ed.sign(utf8Encode(s), hexToBytes(seedHex)));
const supEncPriv = hexToBytes(rv.supervisor.encPrivate);
const devEncPriv = hexToBytes(rv.device.encPrivate);

test("relay_vectors: box key, salt and shared secret from both ends", () => {
  assert.equal(b64url.encode(box.encKeyPair(devEncPriv).publicKey), rv.device.enc);
  assert.equal(b64url.encode(box.encKeyPair(supEncPriv).publicKey), rv.supervisor.enc);
  assert.equal(bytesToHex(box.boxShared(devEncPriv, b64url.decode(rv.supervisor.enc))), rv.boxKey.shared);
  assert.equal(bytesToHex(box.boxShared(supEncPriv, b64url.decode(rv.device.enc))), rv.boxKey.shared);
  assert.equal(bytesToHex(box.boxSalt(rv.supervisor.id, rv.device.id)), rv.boxKey.salt);
  assert.equal(box.BOX_INFO, rv.boxKey.info);
  assert.equal(bytesToHex(box.boxKey(devEncPriv, b64url.decode(rv.supervisor.enc), rv.supervisor.id, rv.device.id)), rv.boxKey.key);
  assert.equal(bytesToHex(box.boxKey(supEncPriv, b64url.decode(rv.device.enc), rv.supervisor.id, rv.device.id)), rv.boxKey.key);
  assert.throws(() => box.boxShared(devEncPriv, new Uint8Array(32)), "a low-order public key gives no key");
});

test("relay_vectors: msg aad, seal with the fixed nonce, open; a rewritten routing member does not open", () => {
  const key = hexToBytes(rv.boxKey.key);
  const f = rv.msg.frame;
  assert.equal(box.boxAad(f), rv.msg.aad);
  assert.equal(box.boxSeal(key, hexToBytes(rv.msg.nonce), utf8Encode(rv.msg.plaintext), rv.msg.aad), f.body);
  assert.equal(utf8Decode(box.boxOpen(key, f.body, box.boxAad(f))), rv.msg.plaintext);
  for (const change of [{ exp: f.exp + 1 }, { to: rv.supervisor.id }, { from: rv.device.id }, { kind: "card" }, { id: "00".repeat(16) }]) {
    assert.throws(() => box.boxOpen(key, f.body, box.boxAad({ ...f, ...change })), JSON.stringify(change));
  }
  const raw = b64url.decode(f.body);
  raw[raw.length - 1] ^= 1;
  assert.throws(() => box.boxOpen(key, b64url.encode(raw), rv.msg.aad));
  assert.throws(() => box.boxOpen(key, "AAAA", rv.msg.aad));
  assert.throws(() => box.boxOpen(key, f.body + "=", rv.msg.aad));
});

test("relay_vectors: a push notification alone gives the aad and opens the box (APNs and FCM members)", () => {
  const key = hexToBytes(rv.boxKey.key);
  const a = rv.push.apns;
  const f = rv.push.fcm;
  for (const n of [a, { ...f, exp: Number(f.exp) }]) {
    const aad = box.boxAad({ id: n.id, from: n.sid, to: n.to, kind: n.kind, exp: n.exp });
    assert.equal(aad, rv.msg.aad);
    assert.equal(utf8Decode(box.boxOpen(key, n.body, aad)), rv.msg.plaintext);
  }
  assert.equal(typeof f.exp, "string");
  assert.throws(() => box.boxOpen(key, a.body, box.boxAad({ id: a.id, from: a.sid, to: a.to, kind: a.kind, exp: a.exp + 1 })));
});

test("relay_vectors: hello signing string and signature (device and supervisor)", () => {
  for (const [who, party] of [["device", rv.device], ["supervisor", rv.supervisor]]) {
    const h = rv.hello[who];
    assert.equal(proto.helloSigningString(h.frame), h.signingString, who);
    assert.ok(proto.verifySig(party.key, h.signingString, h.frame.sig), who);
    assert.equal(sign(party.seed)(h.signingString), h.frame.sig, who);
  }
  const f = rv.hello.device.frame;
  assert.deepEqual(proto.buildHello({ key: f.key, enc: f.enc, ts: f.ts, nonce: f.nonce, version: f.client.version }, sign(rv.device.seed)), f);
  assert.equal(f.client.protocol, 1);
});

test("relay_vectors: pair payload, signing string, plaintext, aad and the body layout of a pair frame", () => {
  const p = rv.pair;
  assert.equal(proto.pairSigningString(p.payload), p.signingString);
  assert.equal(sign(rv.device.seed)(p.signingString), p.signature);
  assert.equal(proto.pairPlaintext(p.payload, sign(rv.device.seed)), p.plaintext);
  assert.equal(box.boxAad(p.frame), p.aad);
  const key = hexToBytes(rv.boxKey.key);
  const sealed = box.boxSeal(key, hexToBytes(p.nonce), utf8Encode(p.plaintext), p.aad);
  assert.equal(box.pairBody(b64url.decode(rv.device.enc), sealed), p.frame.body);
  // the supervisor's side: the key in front, then the ordinary box
  const split = box.splitPairBody(p.frame.body);
  assert.equal(b64url.encode(split.enc), rv.device.enc);
  const supKey = box.boxKey(supEncPriv, split.enc, rv.supervisor.id, p.frame.from);
  assert.equal(utf8Decode(box.boxOpen(supKey, split.sealedBody, p.aad)), p.plaintext);
});

test("relay_vectors: card signing string and supervisorSig; checkCard", () => {
  const c = rv.card;
  assert.equal(proto.cardSigningString(c), c.signingString);
  assert.ok(proto.verifySig(rv.supervisor.key, c.signingString, c.supervisorSig));
  const card = { id: c.id, digest: c.digest, createdAt: c.createdAt, expiresAt: c.expiresAt, supervisorSig: c.supervisorSig };
  assert.equal(proto.checkCard(card, rv.supervisor.key, c.createdAt), null);
  assert.equal(proto.checkCard(card, rv.supervisor.key, c.expiresAt), "card_expired");
  assert.equal(proto.checkCard(card, rv.device.key, c.createdAt), "card_bad_signature");
  assert.equal(proto.checkCard({ ...card, digest: "00" + c.digest.slice(2) }, rv.supervisor.key, c.createdAt), "card_bad_signature");
  assert.equal(proto.checkCard({ ...card, expiresAt: c.expiresAt + 1 }, rv.supervisor.key, c.createdAt), "card_bad_signature");
  assert.equal(proto.checkCard({ ...card, supervisorSig: undefined }, rv.supervisor.key, c.createdAt), "card_invalid");
});

test("relay_vectors: pair link; strict validation", () => {
  const l = rv.link;
  assert.deepEqual(proto.parsePairLink(l.text), { relay: l.relay, supervisorId: l.sid, key: l.key, enc: l.enc, code: l.code, host: l.host });
  assert.equal(proto.channelUrl(l.relay, l.sid), `${l.relay}/${l.sid}`);
  const q = { v: "1", relay: l.relay, sid: l.sid, key: l.key, enc: l.enc, code: l.code, host: l.host };
  const link = (o) => "wardenclaw://pair?" + Object.entries({ ...q, ...o }).filter(([, v]) => v !== undefined).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");
  assert.equal(proto.parsePairLink(link({})).supervisorId, l.sid);
  assert.equal(proto.parsePairLink(link({ code: "k7q4-m2xd" })).code, l.code);
  const bad = {
    "another version": { v: "2" },
    "no version": { v: undefined },
    "plain ws": { relay: "ws://relay.wardenclaw.dev/v1/ws" },
    "https relay": { relay: "https://relay.wardenclaw.dev/v1/ws" },
    "relay with a query": { relay: "wss://relay.wardenclaw.dev/v1/ws?x=1" },
    "relay with userinfo": { relay: "wss://a@relay.wardenclaw.dev/v1/ws" },
    "no relay": { relay: undefined },
    "sid of another key": { sid: rv.device.id },
    "sid not hex": { sid: l.sid.toUpperCase() },
    "short key": { key: l.key.slice(0, 42) },
    "padded key": { key: l.key + "=" },
    "no enc": { enc: undefined },
    "enc not base64url": { enc: l.enc.slice(0, 42) + "*" },
    "short code": { code: "ABC" },
    "no code": { code: undefined },
  };
  for (const [name, o] of Object.entries(bad)) assert.throws(() => proto.parsePairLink(link(o)), name);
  assert.throws(() => proto.parsePairLink(link({}) + "&sid=" + rv.device.id), "a member given twice");
  assert.throws(() => proto.parsePairLink("https://example.com/pair?v=1"));
});

test("relayProto: incoming envelope checks, exp kept under the relay TTL", () => {
  const me = { deviceId: rv.device.id, supervisorId: rv.supervisor.id };
  const f = rv.msg.frame;
  assert.deepEqual(proto.incomingEnvelope(f, me, f.ts), f);
  assert.deepEqual(proto.incomingEnvelope({ ...f, kind: "later.kind" }, me, f.ts), { ...f, kind: "later.kind" });
  const cases = { expired: { exp: f.ts }, to_invalid: { to: rv.supervisor.id }, from_invalid: { from: rv.device.id }, kind_invalid: { kind: "" }, id_invalid: { id: "x" }, seq_invalid: { seq: 0 }, type_invalid: { type: "pair" }, body_invalid: { body: "a+b" }, exp_invalid: { exp: "1" } };
  for (const [reason, o] of Object.entries(cases)) assert.equal(proto.incomingEnvelope({ ...f, ...o }, me, f.ts), reason);
  const limits = { frame: 65536, queue: 200, ttl: 300_000 };
  assert.equal(proto.outgoingExp(1000, proto.TICKET_TTL_MS, limits), 1000 + 240_000);
  assert.equal(proto.outgoingExp(1000, 60_000, limits), 61_000);
  assert.equal(proto.parseFrame("[1]"), null);
  assert.equal(proto.parseFrame("{"), null);
  assert.equal(proto.welcomeLimits({ type: "welcome", id: rv.supervisor.id, role: "device", limits }, rv.device.id), null);
  assert.equal(proto.welcomeLimits({ type: "welcome", id: rv.device.id, role: "supervisor", limits }, rv.device.id), null);
});

// ---- the session against an in-memory relay ----

/** The relay and the supervisor in one object: it authenticates the hello, numbers and queues frames as relay/src/channel.ts does, and boxes payloads with the supervisor's keys of the vectors. */
export class FakeRelay {
  sockets = [];
  queue = []; // undelivered frames for the device
  seq = 0;
  inSeq = 0;
  acks = []; // ids the device acked
  got = []; // envelope frames of the device, as stored
  resumes = [];
  hellos = [];
  push_ = []; // push.register / push.unregister frames
  refuseTimes = 0; // how many envelope frames in a row get refuseNext (0: one)
  refusedFrames = [];
  peerOnline = null; // what the relay says about the supervisor; null: a relay that says nothing
  key = hexToBytes(rv.boxKey.key);
  factory = (url) => {
    const relay = this;
    const s = {
      url,
      open: true,
      onopen: null,
      onmessage: null,
      onclose: null,
      onerror: null,
      send(data) {
        if (!this.open) throw new Error("closed");
        queueMicrotask(() => relay.fromDevice(this, JSON.parse(data)));
      },
      close(code, reason) {
        if (!this.open) return;
        this.open = false;
        queueMicrotask(() => this.onclose?.({ code, reason }));
      },
    };
    this.sockets.push(s);
    queueMicrotask(() => {
      s.onopen?.();
      s.nonce = b64url.encode(crypto.randomBytes(32));
      this.toDevice(s, { type: "challenge", nonce: s.nonce, ts: Date.now() });
    });
    return s;
  };
  live() {
    return this.sockets.find((s) => s.open && s.welcomed);
  }
  toDevice(s, f) {
    if (s.open) queueMicrotask(() => s.open && s.onmessage?.({ data: JSON.stringify(f) }));
  }
  /** The supervisor's connection to the relay opens or closes. */
  setPeer(online) {
    this.peerOnline = online;
    const s = this.live();
    if (s) this.toDevice(s, { type: "peer", online });
  }
  /** The relay drops the connection (network loss). */
  cut() {
    for (const s of this.sockets) s.close(1006, "");
  }
  fromDevice(s, f) {
    if (f.type === "hello") {
      this.hellos.push(f);
      assert.equal(f.nonce, s.nonce);
      assert.ok(proto.verifySig(f.key, proto.helloSigningString(f), f.sig), "hello signature");
      assert.equal(f.key, rv.device.key);
      s.welcomed = true;
      this.toDevice(s, { type: "welcome", id: rv.device.id, role: "device", protocol: 1, ts: Date.now(), limits: { frame: 65536, queue: 200, ttl: 86_400_000 } });
      if (this.peerOnline !== null) this.toDevice(s, { type: "peer", online: this.peerOnline });
      return;
    }
    if (f.type === "resume") {
      this.resumes.push(f.seq);
      const replay = this.queue.filter((e) => e.seq > f.seq);
      for (const e of replay) this.toDevice(s, e);
      return this.toDevice(s, { type: "resumed", count: replay.length });
    }
    if (f.type === "ack") {
      this.acks.push(f.id);
      this.queue = this.queue.filter((e) => e.id !== f.id);
      return;
    }
    if (f.type === "ping") return this.toDevice(s, { type: "pong", ts: f.ts });
    if (f.type === "push.register" || f.type === "push.unregister") {
      this.push_.push(f);
      if (!f.token) return this.toDevice(s, { type: "error", code: "token_invalid", what: f.type });
      return this.toDevice(s, { type: "ack", what: f.type, configured: f.platform === "apns" });
    }
    if (f.type === "msg" || f.type === "pair") {
      assert.equal(f.to, rv.supervisor.id);
      if (this.refuseNext) {
        const code = this.refuseNext;
        if (--this.refuseTimes <= 0) this.refuseNext = null;
        this.refusedFrames.push(f);
        return this.toDevice(s, { type: "error", code, id: f.id });
      }
      const e = { ...f, from: rv.device.id, seq: ++this.inSeq, kind: f.type === "pair" ? "pair" : f.kind };
      this.got.push(e);
      return this.toDevice(s, { type: "ack", id: f.id, seq: e.seq });
    }
  }
  /** The supervisor opens a frame of the device. */
  open(e) {
    const body = e.type === "pair" ? box.splitPairBody(e.body).sealedBody : e.body;
    return JSON.parse(utf8Decode(box.boxOpen(this.key, body, box.boxAad(e))));
  }
  /** The supervisor sends a payload to the device; `change` rewrites the frame after it was boxed (a relay that tampers). */
  push(kind, payload, { exp = Date.now() + 60_000, change } = {}) {
    const e = { type: "msg", id: crypto.randomBytes(16).toString("hex"), to: rv.device.id, from: rv.supervisor.id, seq: ++this.seq, ts: Date.now(), exp, body: "", kind };
    e.body = box.boxSeal(this.key, crypto.randomBytes(24), utf8Encode(JSON.stringify(payload)), box.boxAad(e));
    const f = { ...e, ...change };
    this.queue.push(f);
    const s = this.live();
    if (s) this.toDevice(s, f);
    return f;
  }
}

export function card(id, o = {}) {
  const now = Date.now();
  const c = { id, kind: "exec", digest: crypto.createHash("sha256").update(id).digest("hex"), envelope: {}, meta: {}, createdAt: now, expiresAt: now + 60_000, ...o };
  return { ...c, supervisorSig: sign(o.signSeed ?? rv.supervisor.seed)(proto.cardSigningString(c)), signSeed: undefined };
}

export async function until(what, cond) {
  for (let i = 0; i < 2000; i++) {
    const v = cond();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 1));
  }
  assert.fail(`timeout: ${what}`);
}

export function ticket(c, decision) {
  const payload = { type: "wardenclaw.ticket.exec.v1", supervisorId: rv.supervisor.id, id: c.id, digest: c.digest, decision, ts: Date.now(), nonce: crypto.randomUUID() };
  return { deviceId: rv.device.id, payload, signature: sign(rv.device.seed)(canonicalJson({ ...payload, deviceId: rv.device.id })) };
}

/** A session with the device of the vectors and a log of everything the hooks saw. */
function newSession(relay, o = {}) {
  const log = { cards: [], done: [], status: [], pair: [], refused: [], ignored: [], seq: [], states: [], peers: [], notTrusted: 0 };
  const s = new RelaySession({
    link: { relay: rv.link.relay, supervisorId: rv.supervisor.id, key: rv.supervisor.key, enc: rv.supervisor.enc },
    device: { deviceId: rv.device.id, publicKey: rv.device.key, sign: sign(rv.device.seed), encPrivate: devEncPriv },
    version: "1.0.0",
    seq: 0,
    trusted: false,
    socket: relay.factory,
    random: (n) => new Uint8Array(crypto.randomBytes(n)),
    timing: { backoffMinMs: 1, backoffMaxMs: 4, replyMs: 400, retryMs: 1, rateEveryMs: 1, rateRetryMs: 1 },
    hooks: {
      onState: (st, d) => log.states.push(d ? `${st}:${d}` : st),
      onSeq: (n, id) => {
        log.seq.push(n);
        o.onSeq?.(n, id);
      },
      onCard: (c) => log.cards.push(c),
      onCardDone: (d) => log.done.push(d),
      onStatus: (st) => log.status.push(st),
      onPairStatus: (p) => log.pair.push(p),
      onPeer: (online) => log.peers.push(online),
      onNotTrusted: () => log.notTrusted++,
      onRefused: (reason, id) => log.refused.push({ reason, id }),
      onIgnored: (kind, id) => log.ignored.push({ kind, id }),
    },
    ...o,
  });
  return { s, log };
}

test("relaySession: hello, pair, approval, status, card, allow ticket, result, card.done", async () => {
  const relay = new FakeRelay();
  const { s, log } = newSession(relay);
  try {
    await assert.rejects(s.requestStatus(), (e) => e instanceof RelayError && e.code === "not_connected");
    s.start();
    await until("ready", () => s.state === "ready");
    assert.equal(relay.sockets[0].url, `${rv.link.relay}/${rv.supervisor.id}`);
    assert.equal(relay.hellos[0].role, "device");
    assert.equal(relay.hellos[0].enc, rv.device.enc);
    await until("resume", () => relay.resumes.length === 1);
    assert.deepEqual(relay.resumes, [0]);

    const pairing = s.pair(rv.link.code, "Test phone");
    const pf = await until("pair frame", () => relay.got.find((e) => e.type === "pair"));
    assert.equal(pf.kind, "pair");
    assert.equal(b64url.encode(box.splitPairBody(pf.body).enc), rv.device.enc, "the enc key in front of the body");
    const req = relay.open(pf);
    assert.deepEqual(Object.keys(req.payload), ["code", "deviceId", "pubkey", "enc", "name", "supervisorId", "ts", "nonce"]);
    assert.equal(req.payload.code, rv.link.code);
    assert.equal(req.payload.enc, rv.device.enc);
    assert.equal(req.payload.deviceId, pf.from);
    assert.equal(req.payload.supervisorId, rv.supervisor.id);
    assert.ok(proto.verifySig(rv.device.key, proto.pairSigningString(req.payload), req.signature));
    // an answer to another request, and one that names none: acked, not delivered
    const stale = relay.push("pair.status", { re: "0".repeat(32), id: "pr-0", status: "approved", supervisorId: rv.supervisor.id, host: "h" });
    const unbound = relay.push("pair.status", { id: "pr-0", status: "rejected", supervisorId: rv.supervisor.id });
    await until("stale answers acked", () => relay.acks.includes(stale.id) && relay.acks.includes(unbound.id));
    assert.deepEqual(log.pair, []);
    assert.equal(s.isTrusted, false);
    relay.push("pair.status", { re: pf.id, id: "pr-1", status: "pending", fingerprint: rv.pair.fingerprint, supervisorId: rv.supervisor.id, host: "h", expiresAt: Date.now() + 60_000 });
    const first = await pairing;
    assert.equal(first.status, "pending");
    assert.equal(first.re, pf.id);
    assert.equal(s.isTrusted, false);
    assert.equal(relay.got.filter((e) => e.kind === "status.req").length, 0, "no status.req before approval");

    // approved; the relay does not have the new device list yet: the status.req is sent again
    relay.refuseNext = "not_trusted";
    relay.push("pair.status", { re: pf.id, id: "pr-1", status: "approved", fingerprint: rv.pair.fingerprint, supervisorId: rv.supervisor.id, host: "h" });
    const sr = await until("status.req", () => relay.got.find((e) => e.kind === "status.req"));
    assert.deepEqual(relay.open(sr), {});
    assert.equal(s.isTrusted, true);
    const c0 = card("wd-" + "0".repeat(32));
    relay.push("status", { supervisorId: rv.supervisor.id, pendingCount: 1, pending: [c0] });
    await until("status", () => log.status.length === 1);
    assert.equal(log.status[0].pending[0].id, c0.id);

    const c1 = card("wd-" + "1".repeat(32));
    const cf = relay.push("card", c1);
    await until("card", () => log.cards.length === 1);
    assert.equal(log.cards[0].digest, c1.digest);
    await until("card acked", () => relay.acks.includes(cf.id));

    const result = s.sendTicket(ticket(c1, "allow"));
    const tf = await until("ticket frame", () => relay.got.find((e) => e.kind === "ticket"));
    assert.ok(tf.exp - tf.ts <= proto.TICKET_TTL_MS);
    const tk = relay.open(tf);
    assert.equal(tk.deviceId, rv.device.id);
    assert.equal(tk.payload.id, c1.id);
    assert.equal(tk.payload.decision, "allow");
    relay.push("ticket.result", { ok: true, id: c1.id, decision: "allow" });
    assert.deepEqual(await result, { ok: true, id: c1.id, decision: "allow" });
    relay.push("card.done", { id: c1.id, outcome: "approved" });
    await until("card.done", () => log.done.length === 1);
    assert.deepEqual(log.done[0], { id: c1.id, outcome: "approved" });
    await until("everything acked", () => relay.queue.length === 0);
    assert.equal(s.lastSeq, relay.seq);
    assert.equal(log.seq.at(-1), relay.seq);
    assert.deepEqual(log.refused, []);
    assert.deepEqual(log.pair.map((p) => p.status), ["pending", "approved"]);
  } finally {
    s.stop();
  }
  assert.equal(s.state, "stopped");
});

test("relaySession: deny ticket; a refused ticket; a result for another decision; a refused pairing", async () => {
  const relay = new FakeRelay();
  const { s, log } = newSession(relay, { trusted: true });
  try {
    s.start();
    await until("status.req after resume", () => relay.got.some((e) => e.kind === "status.req"));
    const c = card("wd-" + "2".repeat(32));
    relay.push("card", c);
    await until("card", () => log.cards.length === 1);

    let r = s.sendTicket(ticket(c, "deny"));
    await assert.rejects(s.sendTicket(ticket(c, "deny")), (e) => e.code === "ticket_in_progress");
    await until("ticket", () => relay.got.some((e) => e.kind === "ticket"));
    relay.push("ticket.result", { ok: true, id: c.id, decision: "deny" });
    assert.equal((await r).decision, "deny");

    r = s.sendTicket(ticket(c, "allow"));
    await until("second ticket", () => relay.got.filter((e) => e.kind === "ticket").length === 2);
    relay.push("ticket.result", { ok: false, id: c.id, reason: "nonce_reused" });
    assert.deepEqual(await r, { ok: false, id: c.id, reason: "nonce_reused" });

    // the supervisor says ok for deny while allow was sent: not an answer, the ticket times out
    r = s.sendTicket(ticket(c, "allow"));
    await until("third ticket", () => relay.got.filter((e) => e.kind === "ticket").length === 3);
    const wrong = relay.push("ticket.result", { ok: true, id: c.id, decision: "deny" });
    await assert.rejects(r, (e) => e.code === "timeout");
    assert.deepEqual(log.refused, [{ reason: "ticket_result_mismatch", id: wrong.id }]);
    assert.ok(!relay.acks.includes(wrong.id));

    // the relay refuses to store a frame: the error names it, the sender is told
    relay.refuseNext = "queue_full";
    await assert.rejects(s.sendTicket(ticket(c, "deny")), (e) => e.code === "queue_full");

    const pairing = s.pair("WRONG234", "phone");
    const pf = await until("pair frame", () => relay.got.find((e) => e.type === "pair"));
    relay.push("pair.status", { re: pf.id, status: "refused", reason: "bad_code", supervisorId: rv.supervisor.id, host: "h" });
    assert.deepEqual({ status: (await pairing).status, reason: log.pair.at(-1).reason }, { status: "refused", reason: "bad_code" });
  } finally {
    s.stop();
  }
});

test("relaySession: fail closed: tampered box, expired frame, bad card signature, rewritten kind, foreign frame", async () => {
  const relay = new FakeRelay();
  const { s, log } = newSession(relay, { trusted: true });
  try {
    s.start();
    await until("ready", () => s.state === "ready" && relay.resumes.length === 1);
    const good = card("wd-" + "3".repeat(32));
    const refusedFor = (f) => log.refused.find((r) => r.id === f.id)?.reason;

    const exp = Date.now() + 60_000;
    const rewritten = relay.push("card", good, { exp, change: { exp: exp + 1 } });
    await until("rewritten exp", () => refusedFor(rewritten));
    assert.equal(refusedFor(rewritten), "relay_tamper");

    const flipped = relay.push("card", good, { change: {} });
    flipped.body = flipped.body.slice(0, -2) + (flipped.body.endsWith("AA") ? "BB" : "AA");
    const rekind = relay.push("card.done", { id: good.id, outcome: "approved" }, { change: { kind: "card" } });
    const expired = relay.push("card", good, { exp: Date.now() - 1 });
    const expiredCard = relay.push("card", card("wd-" + "4".repeat(32), { expiresAt: Date.now() - 1 }));
    const forged = relay.push("card", card("wd-" + "5".repeat(32), { signSeed: rv.device.seed }));
    const moved = relay.push("card", { ...good, digest: "ab".repeat(32) });
    const unsigned = relay.push("card", { ...good, supervisorSig: undefined });
    const badStatus = relay.push("status", { supervisorId: rv.supervisor.id, pending: [good, card("wd-" + "6".repeat(32), { signSeed: rv.device.seed })] });
    const unknown = relay.push("card.new", good, { change: { kind: "card.newer" } });
    const foreign = relay.push("card", good, { change: { from: rv.device.id } });
    const notJson = relay.push("card.done", [1]);
    await until("all refused", () => log.refused.length === 12);
    assert.equal(refusedFor(flipped), "relay_tamper");
    assert.equal(refusedFor(rekind), "relay_tamper");
    assert.equal(refusedFor(expired), "expired");
    assert.equal(refusedFor(expiredCard), "card_expired");
    assert.equal(refusedFor(forged), "card_bad_signature");
    assert.equal(refusedFor(moved), "card_bad_signature");
    assert.equal(refusedFor(unsigned), "card_invalid");
    assert.equal(refusedFor(badStatus), "card_bad_signature");
    assert.equal(refusedFor(unknown), "relay_tamper");
    assert.equal(refusedFor(foreign), "from_invalid");
    assert.equal(refusedFor(notJson), "plaintext_invalid");
    // nothing of it reached the app, nothing was acked, the seq did not move
    assert.deepEqual([log.cards, log.done, log.status, log.seq], [[], [], [], []]);
    assert.deepEqual(relay.acks, []);
    assert.equal(s.lastSeq, 0);

    // a good card after all that still comes through; the gap in seq asks for the full state
    const before = relay.got.filter((e) => e.kind === "status.req").length;
    const ok = relay.push("card", good);
    await until("good card", () => log.cards.length === 1);
    await until("acked", () => relay.acks.includes(ok.id));
    await until("status.req after the gap", () => relay.got.filter((e) => e.kind === "status.req").length === before + 1);
  } finally {
    s.stop();
  }
});

test("relaySession: a kind of a later protocol from the supervisor is acked and ignored, not delivered", async () => {
  const relay = new FakeRelay();
  const { s, log } = newSession(relay, { trusted: true });
  try {
    s.start();
    await until("ready", () => s.state === "ready" && relay.resumes.length === 1);
    const later = relay.push("card.v9", { anything: 1 });
    const notJson = relay.push("later.kind", [1, 2]);
    await until("both acked", () => relay.acks.includes(later.id) && relay.acks.includes(notJson.id));
    assert.deepEqual(log.ignored, [{ kind: "card.v9", id: later.id }, { kind: "later.kind", id: notJson.id }]);
    assert.deepEqual([log.cards, log.done, log.status, log.refused], [[], [], [], []]);
    assert.equal(s.lastSeq, notJson.seq);
    assert.deepEqual(relay.queue, []);
    // the same kind not boxed by the supervisor's key is a tampered frame like any other
    const forged = relay.push("card.v9", {}, { change: {} });
    forged.body = forged.body.slice(0, -2) + (forged.body.endsWith("AA") ? "BB" : "AA");
    await until("refused", () => log.refused.length === 1);
    assert.deepEqual(log.refused, [{ reason: "relay_tamper", id: forged.id }]);
    assert.equal(relay.acks.includes(forged.id), false);
    // a card after it is delivered as usual
    const c = relay.push("card", card("wd-" + "7".repeat(32)));
    await until("card", () => log.cards.length === 1 && relay.acks.includes(c.id));
  } finally {
    s.stop();
  }
});

test("relaySession: resume after reconnect with the stored seq, replay, dedupe by id", async () => {
  const relay = new FakeRelay();
  const { s, log } = newSession(relay, { trusted: true });
  let s2;
  try {
    s.start();
    await until("ready", () => s.state === "ready" && relay.resumes.length === 1);
    const a = relay.push("card", card("wd-" + "a".repeat(32)));
    await until("first card acked", () => relay.acks.includes(a.id));
    assert.equal(s.lastSeq, 1);

    // the same frame again (the relay did not see the ack): acked again, not shown again
    relay.toDevice(relay.live(), a);
    await until("second ack", () => relay.acks.filter((id) => id === a.id).length === 2);
    assert.equal(log.cards.length, 1);

    // the connection drops; a card and its end wait on the relay and come with the resume
    const pendingTicket = s.sendTicket(ticket(card("wd-" + "f".repeat(32)), "allow"));
    relay.cut();
    await assert.rejects(pendingTicket, (e) => e.code === "disconnected");
    const b = relay.push("card", card("wd-" + "b".repeat(32)));
    const d = relay.push("card.done", { id: "wd-" + "a".repeat(32), outcome: "expired" });
    await until("replayed", () => log.cards.length === 2 && log.done.length === 1);
    assert.deepEqual(relay.resumes, [0, 1]);
    assert.ok(log.states.some((x) => x.startsWith("waiting:")), log.states.join(" "));
    await until("acked", () => relay.acks.includes(b.id) && relay.acks.includes(d.id));
    assert.equal(s.lastSeq, 3);
    assert.deepEqual(log.seq, [1, 2, 3]);
    assert.equal(relay.sockets.length, 2);
    s.stop();

    // a new session (the app was restarted) resumes from the persisted seq and gets only what is new
    const c = relay.push("card", card("wd-" + "c".repeat(32)));
    ({ s: s2 } = newSession(relay, { trusted: true, seq: log.seq.at(-1), hooks: { onCard: (x) => log.cards.push(x) } }));
    s2.start();
    await until("third card", () => log.cards.length === 3);
    assert.deepEqual(relay.resumes, [0, 1, 3]);
    assert.equal(log.cards[2].id, "wd-" + "c".repeat(32));
    await until("acked", () => relay.acks.includes(c.id));
  } finally {
    s.stop();
    s2?.stop();
  }
});

test("relaySession: a welcome for another id is not accepted; keepalive pings; a silent relay is dropped", async () => {
  const relay = new FakeRelay();
  const pings = [];
  let silent = false;
  const fromDevice = relay.fromDevice.bind(relay);
  relay.fromDevice = (sock, f) => {
    if (f.type === "ping") {
      pings.push(f);
      if (silent) return;
    }
    if (f.type === "hello" && relay.hellos.length === 0) {
      relay.hellos.push(f);
      return relay.toDevice(sock, { type: "welcome", id: rv.supervisor.id, role: "device", protocol: 1, ts: Date.now(), limits: { frame: 1, queue: 1, ttl: 1 } });
    }
    fromDevice(sock, f);
  };
  const { s, log } = newSession(relay, { timing: { backoffMinMs: 1, backoffMaxMs: 2, replyMs: 200, retryMs: 1, pingMs: 5, idleMs: 30 } });
  try {
    s.start();
    await until("ready on the second attempt", () => s.state === "ready");
    assert.ok(log.states.includes("waiting:welcome_invalid"), log.states.join(" "));
    await until("pings", () => pings.length >= 2);
    assert.ok(Number.isSafeInteger(pings[0].ts));
    const n = relay.sockets.length;
    silent = true;
    await until("dropped as idle", () => log.states.includes("waiting:idle"));
    silent = false;
    await until("connected again", () => relay.sockets.length > n && s.state === "ready");
  } finally {
    s.stop();
  }
});

test("relaySession: push token registered with the relay; the error names the frame", async () => {
  const relay = new FakeRelay();
  const { s } = newSession(relay, { trusted: true });
  try {
    await assert.rejects(s.registerPush({ platform: "apns", token: "aa", environment: "sandbox", topic: "dev.wardenclaw.app" }), (e) => e.code === "not_connected");
    s.start();
    await until("ready", () => s.state === "ready");
    assert.deepEqual(await s.registerPush({ platform: "apns", token: "aa", environment: "sandbox", topic: "dev.wardenclaw.app" }), { configured: true });
    assert.deepEqual(relay.push_[0], { type: "push.register", platform: "apns", token: "aa", environment: "sandbox", topic: "dev.wardenclaw.app" });
    assert.deepEqual(await s.registerPush({ platform: "fcm", token: "bb", environment: "production", topic: "dev.wardenclaw.app" }), { configured: false });
    await assert.rejects(s.registerPush({ platform: "apns", token: "", environment: "sandbox", topic: "t" }), (e) => e.code === "token_invalid");
    await s.unregisterPush({ platform: "apns", token: "aa" });
    assert.deepEqual(relay.push_.at(-1), { type: "push.unregister", platform: "apns", token: "aa" });
  } finally {
    s.stop();
  }
});

test("relaySession: requests wait for the outgoing budget; a frame refused as rate_limited goes out again", async () => {
  const relay = new FakeRelay();
  // 5 at once, one more every 40 ms; the hello and the resume take two
  const { s } = newSession(relay, { trusted: false, timing: { backoffMinMs: 1, backoffMaxMs: 4, replyMs: 2000, retryMs: 1, rateBurst: 5, rateEveryMs: 40, rateRetryMs: 5 } });
  try {
    s.start();
    await until("ready", () => s.state === "ready" && relay.resumes.length === 1);
    const t0 = Date.now();
    const all = Promise.all([1, 2, 3, 4, 5, 6].map(() => s.requestStatus()));
    await new Promise((r) => setTimeout(r, 10));
    assert.equal(relay.got.length, 3, "what the budget allows goes out at once, the rest waits");
    await all;
    assert.equal(relay.got.length, 6);
    assert.ok(Date.now() - t0 >= 100, `three more frames took ${Date.now() - t0} ms`);
    assert.equal(new Set(relay.got.map((e) => e.id)).size, 6);

    // refused twice as rate_limited: the same frame a third time, and the caller sees no error
    await new Promise((r) => setTimeout(r, 250));
    relay.refuseNext = "rate_limited";
    relay.refuseTimes = 2;
    await s.requestStatus();
    assert.equal(relay.refusedFrames.length, 2);
    assert.equal(relay.got.length, 7);
    assert.deepEqual(relay.refusedFrames.map((f) => [f.id, f.exp, f.body]), [1, 2].map(() => [relay.got[6].id, relay.got[6].exp, relay.got[6].body]));

    // a relay that keeps refusing: the error comes out after the retries
    relay.refuseNext = "rate_limited";
    relay.refuseTimes = 3;
    await assert.rejects(s.requestStatus(), (e) => e.code === "rate_limited");
    assert.equal(relay.refusedFrames.length, 5);

    // a wait for the budget does not outlive the connection
    await new Promise((r) => setTimeout(r, 250));
    const burst = [1, 2, 3, 4, 5, 6, 7].map(() => s.requestStatus());
    relay.cut();
    const res = await Promise.allSettled(burst);
    assert.ok(res.some((r) => r.status === "rejected" && r.reason.code === "disconnected"), JSON.stringify(res.map((r) => r.reason?.code ?? "ok")));
  } finally {
    s.stop();
  }
});

// ---- what is kept between launches (relayState.ts) ----

/** AsyncStorage's shape over a Map; `fail` makes the next writes throw. */
export function fakeKv() {
  const m = new Map();
  const kv = { m, fail: 0, writes: 0, getItem: async (k) => m.get(k) ?? null, removeItem: async (k) => void m.delete(k) };
  kv.setItem = async (k, v) => {
    await new Promise((r) => setTimeout(r, 1));
    if (kv.fail > 0) {
      kv.fail--;
      throw new Error("disk");
    }
    kv.writes++;
    m.set(k, v);
  };
  return kv;
}

test("relayState: the device enc key is generated once, read back, and never used unsaved", async () => {
  let stored = null;
  let draws = 0;
  const slot = { get: async () => stored, set: async (v) => void (stored = v) };
  const random = (n) => {
    draws++;
    assert.equal(n, 32);
    return Uint8Array.from(devEncPriv);
  };
  const rec = await state.loadOrCreateEncKey(slot, random, () => rv.msg.frame.ts);
  assert.equal(rec.publicKey, rv.device.enc);
  assert.equal(rec.privateKeyHex, rv.device.encPrivate);
  assert.equal(bytesToHex(state.encPrivate(rec)), rv.device.encPrivate);
  assert.deepEqual(JSON.parse(stored), rec);
  assert.deepEqual(await state.loadOrCreateEncKey(slot, random), rec);
  assert.equal(draws, 1);
  // a store that refuses the entry (iOS without a passcode): no key comes back
  await assert.rejects(state.loadOrCreateEncKey({ get: async () => null, set: async () => Promise.reject(new Error("no passcode")) }, random), /no passcode/);
  // an entry that is not a key of ours is not trusted: a public half that does not belong, garbage, a short key
  for (const bad of [JSON.stringify({ ...rec, publicKey: rv.supervisor.enc }), "{", JSON.stringify({ ...rec, privateKeyHex: "ab" }), JSON.stringify({ publicKey: rec.publicKey })]) {
    assert.equal(state.parseEncKey(bad), null, bad);
  }
  assert.equal(state.parseEncKey(null), null);
});

test("relayState: seq and handled ids per supervisor: load, write, bounds", async () => {
  const kv = fakeKv();
  const sid = rv.supervisor.id;
  assert.deepEqual(await state.loadRelayState(kv, sid), { seq: 0, seen: [] });
  await assert.rejects(state.loadRelayState(kv, "../x"));
  const id = (n) => n.toString(16).padStart(32, "0");
  const errors = [];
  const w = new state.RelayStateWriter(kv, sid, { seq: 0, seen: [] }, (e) => errors.push(e.message));
  for (let n = 1; n <= 100; n++) w.onSeq(n, id(n));
  w.onSeq(40, id(40)); // an older frame again: the seq does not go back, the id is not listed twice
  await w.flush();
  const got = await state.loadRelayState(kv, sid);
  assert.equal(got.seq, 100);
  assert.equal(got.seen.length, state.SEEN_KEPT);
  assert.deepEqual([got.seen[0], got.seen.at(-2), got.seen.at(-1)], [id(37), id(99), id(100)]);
  assert.ok(kv.writes < 20, `101 frames coalesced into ${kv.writes} writes`);
  assert.deepEqual([...kv.m.keys()], [state.relayStateKey(sid)]);
  // another supervisor has its own state
  assert.deepEqual(await state.loadRelayState(kv, rv.device.id), { seq: 0, seen: [] });
  // a failed write is reported and repaired by the next frame
  kv.fail = 1;
  w.onSeq(101, id(101));
  await w.flush();
  assert.deepEqual(errors, ["disk"]);
  assert.equal((await state.loadRelayState(kv, sid)).seq, 100);
  w.onSeq(102, id(102));
  await w.flush();
  assert.equal((await state.loadRelayState(kv, sid)).seq, 102);
  assert.ok((await state.loadRelayState(kv, sid)).seen.includes(id(101)));
  // what is not readable is the empty state, never a guess
  for (const bad of ["{", JSON.stringify({ seq: -1, seen: [] }), JSON.stringify({ seq: 1.5, seen: [] }), JSON.stringify({ seq: 3 })]) {
    kv.m.set(state.relayStateKey(sid), bad);
    assert.deepEqual(await state.loadRelayState(kv, sid), { seq: 0, seen: [] }, bad);
  }
  kv.m.set(state.relayStateKey(sid), JSON.stringify({ seq: 5, seen: ["x", 7, id(1)] }));
  assert.deepEqual(await state.loadRelayState(kv, sid), { seq: 5, seen: [id(1)] });
});

test("relaySession: presence: the relay's peer frames reach the hook; a supervisor that comes back is asked for its status; a revoked device", async () => {
  const relay = new FakeRelay();
  relay.peerOnline = false;
  const { s, log } = newSession(relay, { trusted: true });
  const asked = () => relay.got.filter((e) => e.kind === "status.req").length;
  try {
    s.start();
    await until("status.req after resume", () => asked() === 1);
    assert.deepEqual(log.peers, [false]);
    relay.setPeer(true);
    await until("status.req when the supervisor is back", () => asked() === 2);
    relay.setPeer(true);
    relay.toDevice(relay.live(), { type: "peer", online: "yes" });
    await new Promise((r) => setTimeout(r, 20));
    assert.deepEqual(log.peers, [false, true, true], "a frame without a boolean is not presence");
    assert.equal(asked(), 2, "online after online asks nothing");

    assert.equal(log.notTrusted, 0);
    relay.refuseNext = "not_trusted";
    relay.refuseTimes = 1000;
    relay.cut();
    await until("revoked", () => log.notTrusted === 1);
  } finally {
    s.stop();
  }

  // the request was sent by an earlier session: its frame id comes from storage
  const relay2 = new FakeRelay();
  const later = newSession(relay2, { pairFrame: "ab".repeat(16) });
  try {
    later.s.start();
    await until("ready", () => later.s.state === "ready");
    assert.deepEqual(later.log.peers, [], "a relay that says nothing about the supervisor");
    relay2.push("pair.status", { re: "ab".repeat(16), id: "pr-1", status: "approved", supervisorId: rv.supervisor.id, host: "h" });
    await until("approved", () => later.log.pair.length === 1);
    assert.equal(later.s.isTrusted, true);
  } finally {
    later.s.stop();
  }
});

test("relayState + relaySession: a relaunch resumes from the stored seq and does not show a redelivered card twice", async () => {
  const relay = new FakeRelay();
  const kv = fakeKv();
  const sid = rv.supervisor.id;
  const w1 = new state.RelayStateWriter(kv, sid, await state.loadRelayState(kv, sid));
  const first = newSession(relay, { trusted: true, onSeq: w1.onSeq });
  let second;
  try {
    first.s.start();
    await until("ready", () => first.s.state === "ready" && relay.resumes.length === 1);
    const a = relay.push("card", card("wd-" + "a".repeat(32)));
    const b = relay.push("card", card("wd-" + "b".repeat(32)));
    await until("two cards acked", () => relay.acks.includes(a.id) && relay.acks.includes(b.id));
    first.s.stop();
    await w1.flush();
    assert.deepEqual(await state.loadRelayState(kv, sid), { seq: 2, seen: [a.id, b.id] });

    // the app starts again; the relay never saw the ack of b and sends it once more, then a new card
    const st = await state.loadRelayState(kv, sid);
    const w2 = new state.RelayStateWriter(kv, sid, st);
    relay.queue.push(b);
    second = newSession(relay, { trusted: true, seq: st.seq, seen: st.seen, onSeq: w2.onSeq });
    second.s.start();
    await until("resumed", () => relay.resumes.length === 2);
    assert.deepEqual(relay.resumes, [0, 2]);
    relay.toDevice(relay.live(), b);
    const c = relay.push("card", card("wd-" + "c".repeat(32)));
    await until("the new card", () => second.log.cards.length === 1 && relay.acks.includes(c.id));
    assert.equal(relay.acks.filter((x) => x === b.id).length >= 2, true);
    assert.deepEqual(second.log.cards.map((x) => x.id), ["wd-" + "c".repeat(32)]);
    await w2.flush();
    assert.deepEqual(await state.loadRelayState(kv, sid), { seq: 3, seen: [a.id, b.id, c.id] });
  } finally {
    first.s.stop();
    second?.s.stop();
  }
});
