// SPDX-License-Identifier: AGPL-3.0-or-later
// Error references, the keepalive sweep and the rate limit (protocol/README.md sections 5.3 and 13).

import { env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { login, msg, party, sleep, type Party } from "./helpers";

let sup: Party;
let dev: Party;

beforeEach(async () => {
  sup = await party();
  dev = await party();
});

const channel = (sid: string) => {
  const ns = (env as unknown as { CHANNEL: DurableObjectNamespace }).CHANNEL;
  return ns.get(ns.idFromName(sid));
};

/** Makes every connection of the channel look silent for `ms` longer. */
const age = (sid: string, ms: number) =>
  runInDurableObject(channel(sid), (_obj, state) => {
    for (const ws of state.getWebSockets()) {
      const s = ws.deserializeAttachment() as { lastSeen: number };
      ws.serializeAttachment({ ...s, lastSeen: s.lastSeen - ms });
    }
  });

describe("relay limits", () => {
  it("names the refused frame in an error: id for envelopes, what for the rest", async () => {
    const S = await login(sup.id, sup, "supervisor");
    const D = await login(sup.id, dev, "device");
    const m = msg(sup.id, "ticket");
    D.send(m);
    expect(await D.next()).toEqual({ type: "error", code: "not_trusted", close: false, id: m.id });
    D.send({ type: "pairing", open: true });
    expect(await D.next()).toEqual({ type: "error", code: "supervisor_only", close: false, what: "pairing" });
    S.send({ type: "devices", ids: "all" });
    expect(await S.next()).toEqual({ type: "error", code: "ids_invalid", close: false, what: "devices" });
    // the reference does not leak into the next error
    D.ws.send("not json");
    expect(await D.next()).toEqual({ type: "error", code: "frame_invalid", close: false });
    const p = { type: "pair", id: m.id, to: sup.id, ts: Date.now(), exp: Date.now() + 60_000, body: "x" };
    D.send(p);
    expect(await D.next()).toEqual({ type: "error", code: "pairing_closed", close: false, id: m.id });
  });

  it("closes a silent connection at the sweep, not one kept alive by the auto-response", async () => {
    const S = await login(sup.id, sup, "supervisor");
    const D = await login(sup.id, dev, "device");
    // 80 s of silence: both stay
    await age(sup.id, 80_000);
    expect(await runDurableObjectAlarm(channel(sup.id))).toBe(true);
    S.send({ type: "ping", ts: 1 });
    expect(await S.next()).toMatchObject({ type: "pong" });
    D.send({ type: "ping", ts: 1 });
    expect(await D.next()).toMatchObject({ type: "pong" });
    // 100 s: the supervisor is closed; the device sent the ping the runtime answers by itself,
    // which never reaches the object, and stays
    await age(sup.id, 100_000);
    D.ws.send(JSON.stringify({ type: "ping" }));
    expect(await D.next()).toEqual({ type: "pong" });
    await runDurableObjectAlarm(channel(sup.id));
    await sleep(200);
    expect(S.closed).toMatchObject({ code: 1001 });
    expect(D.closed).toBeNull();
    D.send({ type: "ping", ts: 2 });
    expect(await D.next()).toMatchObject({ type: "pong" });
  });

  it("limits a connection to a burst of 20 frames, names the refused frame, closes after three in a row", async () => {
    const D = await login(sup.id, dev, "device");
    let pongs = 0;
    const errors: Record<string, unknown>[] = [];
    for (let i = 0; i < 40 && !D.closed; i++) {
      D.send({ type: "ping", ts: i });
      const f = await D.next().catch(() => null);
      if (!f) break;
      if (f.type === "pong") pongs++;
      else errors.push(f);
    }
    await sleep(200);
    // the hello took one token of the 20; the bucket refills one per second while this runs
    expect(pongs).toBeGreaterThanOrEqual(19);
    expect(pongs).toBeLessThanOrEqual(24);
    expect(errors[0]).toEqual({ type: "error", code: "rate_limited", close: false, what: "ping" });
    expect(errors.length).toBeLessThanOrEqual(4);
    expect(D.closed).toMatchObject({ code: 4008 });
  });

  it("forgives refused frames once a frame is accepted again", async () => {
    const D = await login(sup.id, dev, "device");
    const spend = (n: number) =>
      runInDurableObject(channel(sup.id), (_obj, state) => {
        for (const ws of state.getWebSockets()) ws.serializeAttachment({ ...(ws.deserializeAttachment() as object), tokens: n, refill: Date.now() });
      });
    for (let round = 0; round < 3; round++) {
      await spend(0);
      D.send({ type: "ping", ts: round });
      const f = await D.next();
      // a slow run may have refilled a token: then the frame was simply accepted
      if (f.type === "error") expect(f).toMatchObject({ code: "rate_limited", what: "ping" });
      await spend(5);
      D.send({ type: "ping", ts: round });
      expect(await D.next()).toMatchObject({ type: "pong" });
    }
    expect(D.closed).toBeNull();
  });
});
