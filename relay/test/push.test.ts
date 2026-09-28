// SPDX-License-Identifier: AGPL-3.0-or-later
// The APNs sender alone: JWT from the test key, headers, payload, token cleanup on Apple's answer.

import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import vectors from "../../protocol/vectors/relay_vectors.json";
import { canonicalJson } from "../src/canonical";
import { apnsPayload, fcmData, pushPayload, PUSH_BODY_MAX, sendApns, type PushEnv } from "../src/push";
import { stubFetch } from "./helpers";

const token = { platform: "apns" as const, token: "b".repeat(64), environment: "production" as const, topic: "com.wardenclaw.app", registeredAt: 0 };
const payload = { sid: "s".repeat(64), id: "m".repeat(32), to: "d".repeat(64), kind: "card", exp: 1790850300000, body: "cipher" };

describe("apns", () => {
  it("signs a JWT with the configured key and posts the payload", async () => {
    const f = stubFetch("https://api.push.apple.com/");
    try {
      const r = await sendApns(env as unknown as PushEnv, token, payload, Date.now() + 60_000);
      expect(r).toMatchObject({ ok: true, status: 200, unregister: false });
      expect(f.calls).toHaveLength(1);
      const c = f.calls[0]!;
      expect(c.url).toBe(`https://api.push.apple.com/3/device/${token.token}`);
      expect(c.headers["apns-topic"]).toBe("com.wardenclaw.app");
      expect(c.headers["apns-push-type"]).toBe("alert");
      const [h, p] = c.headers["authorization"]!.replace(/^bearer /, "").split(".");
      expect(JSON.parse(atob(h!.replace(/-/g, "+").replace(/_/g, "/")))).toMatchObject({ alg: "ES256", kid: "TESTKEYID0" });
      expect(JSON.parse(atob(p!.replace(/-/g, "+").replace(/_/g, "/")))).toMatchObject({ iss: "TESTTEAM00" });
      expect(c.body).toBe(apnsPayload(payload));
    } finally {
      f.restore();
    }
  });

  it("asks for the token to be dropped when Apple says it is dead", async () => {
    const f = stubFetch("https://api.push.apple.com/", 410, JSON.stringify({ reason: "Unregistered" }));
    try {
      const r = await sendApns(env as unknown as PushEnv, token, payload, Date.now() + 60_000);
      expect(r).toMatchObject({ ok: false, status: 410, reason: "Unregistered", unregister: true });
    } finally {
      f.restore();
    }
  });

  it("refuses a token registered for another topic without calling Apple", async () => {
    const f = stubFetch("https://api.push.apple.com/");
    try {
      const r = await sendApns(env as unknown as PushEnv, { ...token, topic: "com.example.other" }, payload, Date.now() + 60_000);
      expect(r).toMatchObject({ ok: false, reason: "topic_mismatch", unregister: true });
      expect(f.calls).toHaveLength(0);
    } finally {
      f.restore();
    }
  });
});

// protocol/vectors/relay_vectors.json, member push: what the relay puts into a notification for
// msg.frame. The box itself is opened from these members by the daemon's TestRelayVectors and the
// app's test-relay.mjs; here: the relay produces exactly them, and they give the aad of the frame.
describe("push payload", () => {
  const frame = vectors.msg.frame;
  const p = pushPayload(vectors.supervisor.id, frame);

  it("carries every routing member the aad covers, for APNs and FCM", () => {
    expect((JSON.parse(apnsPayload(p)) as { relay: unknown }).relay).toEqual(vectors.push.apns);
    expect(fcmData(p)).toEqual(vectors.push.fcm);
    const n = (JSON.parse(apnsPayload(p)) as { relay: { sid: string; id: string; to: string; kind: string; exp: number } }).relay;
    expect(canonicalJson({ type: "wardenclaw.relay.aad.v1", id: n.id, from: n.sid, to: n.to, kind: n.kind, exp: n.exp })).toBe(vectors.msg.aad);
    const d = fcmData(p);
    expect(canonicalJson({ type: "wardenclaw.relay.aad.v1", id: d.id, from: d.sid, to: d.to, kind: d.kind, exp: Number(d.exp) })).toBe(vectors.msg.aad);
  });

  it("leaves a body over 3 KiB out and keeps the routing members", () => {
    const big = pushPayload(vectors.supervisor.id, { ...frame, body: "A".repeat(PUSH_BODY_MAX + 1) });
    expect(big.body).toBeUndefined();
    expect(big).toEqual({ sid: vectors.supervisor.id, id: frame.id, to: frame.to, kind: frame.kind, exp: frame.exp });
    expect(pushPayload(vectors.supervisor.id, { ...frame, body: "A".repeat(PUSH_BODY_MAX) }).body).toHaveLength(PUSH_BODY_MAX);
  });
});
