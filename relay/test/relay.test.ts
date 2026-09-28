// SPDX-License-Identifier: AGPL-3.0-or-later
// The relay end to end inside workerd: a supervisor and devices with real Ed25519 keys, frames,
// queues, acks, resume, pairing window, push (the request to Apple caught by a stubbed fetch),
// the side door.

import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { canonicalJson } from "../src/canonical";
import { randomHex } from "../src/crypto";
import { HELLO_TYPE, REQ_TYPE } from "../src/frames";
import { connect, login, msg, party, sign, sleep, stubFetch, type Party } from "./helpers";

let sup: Party;
let dev: Party;

// fresh keys per test: sockets left open by one test would otherwise count as live devices
beforeEach(async () => {
  sup = await party();
  dev = await party();
});

describe("relay", () => {
  it("answers ping", async () => {
    const res = await SELF.fetch("https://relay/v1/ping");
    expect(res.status).toBe(200);
    const j = (await res.json()) as { ok: boolean; service: string; protocol: number };
    expect(j.ok).toBe(true);
    expect(j.service).toBe("wardenclaw-relay");
    expect(j.protocol).toBe(1);
  });

  it("refuses a supervisor on another channel and a bad signature", async () => {
    const other = await party();
    const s = await connect(other.id);
    const ch = await s.next();
    const hello = { role: "supervisor", key: sup.pub, enc: sup.enc, ts: Date.now(), nonce: ch.nonce as string, client: { name: "t", version: "0", protocol: 1 } };
    s.send({ type: "hello", ...hello, sig: await sign(sup, canonicalJson({ type: HELLO_TYPE, ...hello })) });
    expect(await s.next()).toMatchObject({ type: "error", code: "not_this_channel" });

    const s2 = await connect(sup.id);
    const ch2 = await s2.next();
    const hello2 = { role: "supervisor", key: sup.pub, enc: sup.enc, ts: Date.now(), nonce: ch2.nonce as string, client: { name: "t", version: "0", protocol: 1 } };
    s2.send({ type: "hello", ...hello2, sig: await sign(dev, canonicalJson({ type: HELLO_TYPE, ...hello2 })) });
    expect(await s2.next()).toMatchObject({ type: "error", code: "bad_signature" });

    // another protocol number: refused, nothing is negotiated
    const s4 = await connect(sup.id);
    const ch4 = await s4.next();
    const hello4 = { ...hello2, nonce: ch4.nonce as string, client: { name: "t", version: "0", protocol: 2 } };
    s4.send({ type: "hello", ...hello4, sig: await sign(sup, canonicalJson({ type: HELLO_TYPE, ...hello4 })) });
    expect(await s4.next()).toMatchObject({ type: "error", code: "protocol_mismatch" });

    // a replayed challenge nonce
    const s3 = await connect(sup.id);
    await s3.next();
    s3.send({ type: "hello", ...hello2, sig: await sign(sup, canonicalJson({ type: HELLO_TYPE, ...hello2 })) });
    expect(await s3.next()).toMatchObject({ type: "error", code: "challenge_invalid" });
  });

  it("routes between a supervisor and a trusted device, with acks", async () => {
    const S = await login(sup.id, sup, "supervisor");
    const D = await login(sup.id, dev, "device");

    // not trusted yet
    D.send(msg(sup.id, "status.req"));
    expect(await D.next()).toMatchObject({ type: "error", code: "not_trusted" });

    S.send({ type: "devices", ids: [dev.id] });
    expect(await S.next()).toMatchObject({ type: "ack", what: "devices", count: 1 });

    const m = msg(sup.id, "status.req", "c1");
    D.send(m);
    expect(await D.next()).toMatchObject({ type: "ack", id: m.id, seq: 1 });
    const got = await S.next();
    expect(got).toMatchObject({ type: "msg", id: m.id, from: dev.id, to: sup.id, seq: 1, body: "c1", kind: "status.req" });
    S.send({ type: "ack", id: m.id });

    // the other way
    const c = msg(dev.id, "card", "card-cipher");
    S.send(c);
    expect(await S.next()).toMatchObject({ type: "ack", id: c.id, seq: 1 });
    expect(await D.next()).toMatchObject({ type: "msg", id: c.id, from: sup.id, seq: 1, kind: "card" });
    D.send({ type: "ack", id: c.id });

    // duplicate id: acked again, not delivered again
    D.send(m);
    expect(await D.next()).toMatchObject({ type: "ack", id: m.id, duplicate: true });
    await S.expectNone();

    // an unknown kind and a wrong channel are refused
    D.send(msg(sup.id, "gossip"));
    expect(await D.next()).toMatchObject({ type: "error", code: "kind_invalid" });
    D.send(msg("b".repeat(64), "status.req"));
    expect(await D.next()).toMatchObject({ type: "error", code: "to_invalid" });

    // nothing left to resume on either side
    D.send({ type: "resume", seq: 0 });
    expect(await D.next()).toMatchObject({ type: "resumed", count: 0 });
    S.send({ type: "resume", device: dev.id, seq: 0 });
    expect(await S.next()).toMatchObject({ type: "resumed", count: 0 });
  });

  it("queues for an offline device and replays on resume", async () => {
    const S = await login(sup.id, sup, "supervisor");
    S.send({ type: "devices", ids: [dev.id] });
    await S.next();
    const c1 = msg(dev.id, "card", "one");
    const c2 = msg(dev.id, "card", "two");
    S.send(c1);
    S.send(c2);
    expect(await S.next()).toMatchObject({ type: "ack", id: c1.id });
    expect(await S.next()).toMatchObject({ type: "ack", id: c2.id });

    const D = await login(sup.id, dev, "device");
    D.send({ type: "resume", seq: 0 });
    const a = await D.next();
    const b = await D.next();
    expect([a.body, b.body]).toEqual(["one", "two"]);
    expect((a.seq as number) < (b.seq as number)).toBe(true);
    expect(await D.next()).toMatchObject({ type: "resumed", count: 2 });
    D.send({ type: "ack", id: a.id });
    // resume from a's seq: only b comes back
    D.send({ type: "resume", seq: a.seq });
    expect(await D.next()).toMatchObject({ id: b.id });
    expect(await D.next()).toMatchObject({ type: "resumed", count: 1 });
    D.send({ type: "ack", id: b.id });
  });

  it("forwards pair frames only while the window is open", async () => {
    const S = await login(sup.id, sup, "supervisor");
    const stranger = await party();
    const P = await login(sup.id, stranger, "device");
    const pair = { type: "pair", id: randomHex(16), to: sup.id, ts: Date.now(), exp: Date.now() + 60_000, body: "sealed-code" };
    P.send(pair);
    expect(await P.next()).toMatchObject({ type: "error", code: "pairing_closed" });

    S.send({ type: "pairing", open: true, until: Date.now() + 60_000 });
    expect(await S.next()).toMatchObject({ type: "ack", what: "pairing" });
    P.send({ ...pair, id: randomHex(16) });
    expect(await P.next()).toMatchObject({ type: "ack" });
    const got = await S.next();
    expect(got).toMatchObject({ type: "pair", from: stranger.id, kind: "pair", body: "sealed-code" });
    S.send({ type: "ack", id: got.id });

    // the supervisor may answer a device that is not trusted (pair.status)
    const st = msg(stranger.id, "pair.status", "pending");
    S.send(st);
    expect(await S.next()).toMatchObject({ type: "ack", id: st.id });
    expect(await P.next()).toMatchObject({ kind: "pair.status", body: "pending" });
    P.send({ type: "ack", id: st.id });

    S.send({ type: "pairing", open: false });
    expect(await S.next()).toMatchObject({ type: "ack", what: "pairing", until: 0 });
    P.send({ ...pair, id: randomHex(16) });
    expect(await P.next()).toMatchObject({ type: "error", code: "pairing_closed" });
  });

  it("pushes to Apple when the device is offline, not when it is online", async () => {
    const S = await login(sup.id, sup, "supervisor");
    S.send({ type: "devices", ids: [dev.id] });
    await S.next();
    const D = await login(sup.id, dev, "device");
    const token = "a".repeat(64);
    D.send({ type: "push.register", platform: "apns", token, environment: "production", topic: "com.wardenclaw.app" });
    expect(await D.next()).toMatchObject({ type: "ack", what: "push.register", configured: true });

    const f = stubFetch("https://api.push.apple.com/");
    try {
      // online: delivered over the socket, no push
      const c1 = msg(dev.id, "card", "live");
      S.send(c1);
      await S.next();
      expect(await D.next()).toMatchObject({ id: c1.id });
      D.send({ type: "ack", id: c1.id });
      await sleep(200);
      expect(f.calls).toHaveLength(0);

      // offline: the push goes out, with the ciphertext inside
      D.ws.close(1000, "bye");
      await sleep(300);
      const c2 = msg(dev.id, "card", "sealed");
      S.send(c2);
      expect(await S.next()).toMatchObject({ type: "ack", id: c2.id });
      for (let i = 0; i < 40 && f.calls.length === 0; i++) await sleep(50);
      expect(f.calls).toHaveLength(1);
      const got = f.calls[0]!;
      expect(got.url).toBe(`https://api.push.apple.com/3/device/${token}`);
      const body = JSON.parse(got.body) as { aps: Record<string, unknown>; relay: Record<string, unknown> };
      expect(body.relay).toEqual({ sid: sup.id, id: c2.id, to: dev.id, kind: "card", exp: c2.exp, body: "sealed" });
      expect(body.aps["mutable-content"]).toBe(1);
      expect(got.headers["apns-topic"]).toBe("com.wardenclaw.app");
      expect(got.headers["authorization"]).toMatch(/^bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

      // a ticket from the device never triggers a push; a card.done does
      const D2 = await login(sup.id, dev, "device");
      D2.send({ type: "resume", seq: 0 });
      await D2.next();
      await D2.next();
      D2.send({ type: "ack", id: c2.id });
      D2.ws.close(1000, "bye");
      await sleep(300);
      S.send(msg(dev.id, "status", "st"));
      await S.next();
      await sleep(200);
      expect(f.calls).toHaveLength(1);
      S.send(msg(dev.id, "card.done", "done"));
      await S.next();
      for (let i = 0; i < 40 && f.calls.length === 1; i++) await sleep(50);
      expect(f.calls).toHaveLength(2);
    } finally {
      f.restore();
    }
  });

  it("drops a token Apple reports dead", async () => {
    const S = await login(sup.id, sup, "supervisor");
    S.send({ type: "devices", ids: [dev.id] });
    await S.next();
    const D = await login(sup.id, dev, "device");
    const token = "c".repeat(64);
    D.send({ type: "push.register", platform: "apns", token, environment: "production", topic: "com.wardenclaw.app" });
    await D.next();
    D.ws.close(1000, "bye");
    await sleep(300);
    const f = stubFetch("https://api.push.apple.com/", 410, JSON.stringify({ reason: "Unregistered" }));
    try {
      S.send(msg(dev.id, "card", "x"));
      await S.next();
      for (let i = 0; i < 40 && f.calls.length === 0; i++) await sleep(50);
      expect(f.calls.map((c) => c.url)).toEqual([`https://api.push.apple.com/3/device/${token}`]);
      // the next card finds no token: no request to Apple
      S.send(msg(dev.id, "card", "y"));
      await S.next();
      await sleep(300);
      expect(f.calls).toHaveLength(1);
    } finally {
      f.restore();
    }
  });

  it("serves one queued frame over the signed side door", async () => {
    const S = await login(sup.id, sup, "supervisor");
    S.send({ type: "devices", ids: [dev.id] });
    await S.next();
    const D = await login(sup.id, dev, "device");
    D.ws.close(1000, "bye");
    await sleep(300);
    const c = msg(dev.id, "card", "for-nse");
    S.send(c);
    await S.next();

    const ts = Date.now();
    const nonce = randomHex(16);
    const sig = await sign(dev, canonicalJson({ type: REQ_TYPE, supervisorId: "relay", action: "relay.frame", deviceId: dev.id, ts, nonce }));
    const headers = { "X-Wardenclaw-Device": dev.id, "X-Wardenclaw-Ts": String(ts), "X-Wardenclaw-Nonce": nonce, "X-Wardenclaw-Signature": sig };
    const res = await SELF.fetch(`https://relay/v1/frames/${sup.id}/${c.id}`, { headers });
    expect(res.status).toBe(200);
    const j = (await res.json()) as { ok: boolean; frame: Record<string, unknown> };
    expect(j.frame).toMatchObject({ id: c.id, body: "for-nse", to: dev.id });

    // the nonce is burned
    const again = await SELF.fetch(`https://relay/v1/frames/${sup.id}/${c.id}`, { headers });
    expect(again.status).toBe(401);
    expect(((await again.json()) as { reason: string }).reason).toBe("nonce_reused");

    // a wrong signature
    const bad = await SELF.fetch(`https://relay/v1/frames/${sup.id}/${c.id}`, { headers: { ...headers, "X-Wardenclaw-Nonce": randomHex(16) } });
    expect(bad.status).toBe(401);

    // another device cannot read it
    const other = await party();
    const O = await login(sup.id, other, "device");
    O.ws.close(1000, "bye");
    const n2 = randomHex(16);
    const sig2 = await sign(other, canonicalJson({ type: REQ_TYPE, supervisorId: "relay", action: "relay.frame", deviceId: other.id, ts, nonce: n2 }));
    const notMine = await SELF.fetch(`https://relay/v1/frames/${sup.id}/${c.id}`, { headers: { "X-Wardenclaw-Device": other.id, "X-Wardenclaw-Ts": String(ts), "X-Wardenclaw-Nonce": n2, "X-Wardenclaw-Signature": sig2 } });
    expect(notMine.status).toBe(404);
  });
});
