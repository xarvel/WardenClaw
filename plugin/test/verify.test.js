// SPDX-License-Identifier: Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { makeDevice, makeGate } from "./helpers.js";
import { bufferToB64url, deviceIdOfPublicKey, verifyEd25519 } from "../src/crypto.js";

async function setup() {
  const dev = await makeDevice();
  const other = await makeDevice();
  const g = makeGate({ devices: [dev], config: { mode: "enforce" } });
  const rec = g.gate.createPending({ toolName: "exec", params: { command: "ls" }, agentId: "main", sessionKey: "s", source: "test" });
  const payload = (over = {}) => ({ id: rec.id, digest: rec.digest, decision: "allow", ts: g.now(), nonce: randomUUID(), ...over });
  return { dev, other, ...g, rec, payload };
}

test("verifyEd25519: @noble signature verified by node:crypto with base64url key", async () => {
  const dev = await makeDevice();
  const sig = await dev.sign("hello");
  assert.equal(verifyEd25519("hello", sig, dev.publicKey), true);
  assert.equal(verifyEd25519("hello!", sig, dev.publicKey), false);
  assert.equal(verifyEd25519("hello", sig, (await makeDevice()).publicKey), false);
  assert.equal(verifyEd25519("hello", "not-a-signature", dev.publicKey), false);
  // identity point: crypto/ed25519 accepts a forgery under it; the plugin must not
  const identity = Buffer.alloc(32);
  identity[0] = 1;
  const identityKey = bufferToB64url(identity);
  assert.equal(deviceIdOfPublicKey(identityKey), null);
  const forged = Buffer.alloc(64);
  forged[0] = 1;
  assert.equal(verifyEd25519("hello", bufferToB64url(forged), identityKey), false);
});

test("decide: valid signature from trusted device is accepted and applied", async () => {
  const s = await setup();
  const r = await s.gate.decide(await s.dev.signDecision(s.payload()), { transport: "test" });
  assert.equal(r.ok, true);
  assert.equal(r.decision, "allow");
  assert.equal(r.late, false);
  assert.equal(s.gate.store.get(s.rec.id).status, "allowed");
  const j = s.journal.entries.find((e) => e.kind === "decision");
  assert.ok(j);
  assert.equal(j.data.signature.length > 40, true);
  assert.equal(j.data.deviceId, s.dev.deviceId);
});

test("decide: untrusted device is rejected even with a valid signature", async () => {
  const s = await setup();
  const r = await s.gate.decide(await s.other.signDecision(s.payload()), { transport: "test" });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "untrusted_device");
  assert.equal(s.gate.store.get(s.rec.id).status, "pending");
});

test("decide: signature with foreign key under trusted deviceId is rejected", async () => {
  const s = await setup();
  const body = await s.other.signDecision(s.payload());
  body.deviceId = s.dev.deviceId;
  const r = await s.gate.decide(body, { transport: "test" });
  assert.equal(r.reason, "bad_signature");
});

test("decide: changing payload after signing breaks the signature", async () => {
  const s = await setup();
  const body = await s.dev.signDecision(s.payload({ decision: "deny" }));
  body.payload.decision = "allow";
  const r = await s.gate.decide(body, { transport: "test" });
  assert.equal(r.reason, "bad_signature");
  assert.equal(s.gate.store.get(s.rec.id).status, "pending");
});

test("decide: timestamp window +-60 s", async () => {
  const s = await setup();
  assert.equal((await s.gate.decide(await s.dev.signDecision(s.payload({ ts: s.now() - 61_000 })), { transport: "t" })).reason, "stale_timestamp");
  assert.equal((await s.gate.decide(await s.dev.signDecision(s.payload({ ts: s.now() + 61_000 })), { transport: "t" })).reason, "stale_timestamp");
  assert.equal((await s.gate.decide(await s.dev.signDecision(s.payload({ ts: s.now() - 59_000 })), { transport: "t" })).ok, true);
});

test("decide: nonce is not reused; signature is verified before nonce is claimed", async () => {
  const s = await setup();
  const nonce = randomUUID();
  // A bad signature with this nonce must not "burn" it.
  const bad = await s.other.signDecision(s.payload({ nonce }));
  bad.deviceId = s.dev.deviceId;
  assert.equal((await s.gate.decide(bad, { transport: "t" })).reason, "bad_signature");
  const good = await s.dev.signDecision(s.payload({ nonce }));
  assert.equal((await s.gate.decide(good, { transport: "t" })).ok, true);
  // Replaying the same body -> nonce_reused (and not "late", because it is rejected before the store).
  const again = await s.gate.decide(good, { transport: "t" });
  assert.equal(again.reason, "nonce_reused");
});

test("decide: digest must match the frozen entry; unknown id is rejected", async () => {
  const s = await setup();
  const wrongDigest = "0".repeat(64);
  assert.equal((await s.gate.decide(await s.dev.signDecision(s.payload({ digest: wrongDigest })), { transport: "t" })).reason, "digest_mismatch");
  assert.equal((await s.gate.decide(await s.dev.signDecision(s.payload({ id: randomUUID() })), { transport: "t" })).reason, "unknown_pending");
});

test("decide: malformed bodies are rejected", async () => {
  const s = await setup();
  for (const body of [null, 1, "x", {}, { deviceId: "short", payload: {}, signature: "s" }, { deviceId: s.dev.deviceId, payload: { id: "i", digest: "x", decision: "allow", ts: 1, nonce: "n" }, signature: "s" }]) {
    const r = await s.gate.decide(body, { transport: "t" });
    assert.equal(r.ok, false, JSON.stringify(body));
  }
});

test("decide: ticket type and supervisorId are validated; plugin accepts only tool type", async () => {
  const s = await setup();
  const sup = "39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f";
  for (const [over, reason] of [
    [{ type: undefined }, "type_invalid"],
    [{ type: "wardenclaw.ticket.v1" }, "type_invalid"],
    [{ type: "wardenclaw.hw.v1" }, "type_invalid"],
    [{ type: "wardenclaw.ticket.tool.v1", supervisorId: sup }, "supervisor_id_invalid"],
    [{ type: "wardenclaw.ticket.exec.v1" }, "supervisor_id_invalid"],
    [{ type: "wardenclaw.ticket.exec.v1", supervisorId: "SUP" }, "supervisor_id_invalid"],
    // valid exec-ticket signature over a plugin tool entry: wrong domain
    [{ type: "wardenclaw.ticket.exec.v1", supervisorId: sup }, "ticket_type_mismatch"],
  ]) {
    const r = await s.gate.decide(await s.dev.signDecision(s.payload(over)), { transport: "t" });
    assert.equal(r.reason, reason, JSON.stringify(over));
  }
  assert.equal(s.gate.store.get(s.rec.id).status, "pending");
  // tampering with type after signing is not possible
  const body = await s.dev.signDecision(s.payload());
  body.payload.type = "wardenclaw.ticket.exec.v1";
  body.payload.supervisorId = sup;
  assert.equal((await s.gate.decide(body, { transport: "t" })).reason, "ticket_type_mismatch");
  assert.equal((await s.gate.decide(await s.dev.signDecision(s.payload()), { transport: "t" })).ok, true);
});

test("decide (ws): connection deviceId must match deviceId in the signature", async () => {
  const s = await setup();
  const r = await s.gate.decide(await s.dev.signDecision(s.payload()), { transport: "ws", authenticatedDeviceId: s.other.deviceId });
  assert.equal(r.reason, "device_mismatch");
});

test("verifyRequest: signed GET is accepted once", async () => {
  const s = await setup();
  const h = await s.dev.signedHeaders("pending", s.now());
  const req = { action: "pending", deviceId: h["x-wardenclaw-device"], ts: h["x-wardenclaw-ts"], nonce: h["x-wardenclaw-nonce"], signature: h["x-wardenclaw-signature"] };
  assert.equal((await s.gate.verifyRequest(req)).ok, true);
  assert.equal((await s.gate.verifyRequest(req)).reason, "nonce_reused");
  assert.equal((await s.gate.verifyRequest({ ...req, action: "status", nonce: randomUUID() })).reason, "bad_signature");
});
