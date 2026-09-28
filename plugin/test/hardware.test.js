// SPDX-License-Identifier: Apache-2.0
// Second factor (YubiKey): risk in the signing string and end-to-end hw forwarding to wardend.
// hw is only active with HARDWARE_KEY (src/features.js), disabled in the first release: such tests are skipped.
// Fixture hw_vectors.json: Go ground truth, single instance in protocol/vectors/ at repo root.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { randomUUID } from "node:crypto";
import * as ed from "@noble/ed25519";
import { decisionSigningString, TICKET_EXEC } from "../src/canonical.js";

const SUP = "39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f";
import { verifyEd25519, bufferToB64url } from "../src/crypto.js";
import { parseDecisionBody } from "../src/verify.js";
import { HARDWARE_KEY } from "../src/features.js";
import { WardendRelay } from "../src/relay.js";
import { makeDevice, makeGate, tmpDir } from "./helpers.js";

const hv = JSON.parse(fs.readFileSync(new URL("../../protocol/vectors/hw_vectors.json", import.meta.url), "utf8"));

test("hw_vectors: signing string with and without risk matches Go, Go signature verifies", async () => {
  assert.ok(hv.cases.length >= 2);
  for (const c of hv.cases) {
    const p = { ...c.payload, ts: Number(c.payload.ts) };
    assert.equal(decisionSigningString({ deviceId: c.deviceId, ...p }), c.signingString, c.name);
    const pub = bufferToB64url(await ed.getPublicKeyAsync(Buffer.from(c.seed, "hex")));
    assert.ok(verifyEd25519(c.signingString, c.signature, pub), c.name);
    const parsed = parseDecisionBody({ deviceId: c.deviceId, payload: p, signature: c.signature });
    assert.equal(parsed.ok, true, c.name);
    assert.equal(decisionSigningString({ deviceId: c.deviceId, ...parsed.value.payload }), c.signingString, `${c.name}: after parsing`);
  }
});

const HW = { credentialId: "E4cRA0BaXWcvxV28onR6iy", clientDataJSON: "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0", authenticatorData: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ", signature: "MEUCIQD-sig_x" };

test("parseDecisionBody: risk and hw are validated by form", { skip: !HARDWARE_KEY && "second factor is disabled (src/features.js)" }, () => {
  const base = { deviceId: "a".repeat(64), signature: "s", payload: { type: TICKET_EXEC, supervisorId: SUP, id: "wd-1", digest: "b".repeat(64), decision: "allow", ts: 1, nonce: "12345678" } };
  assert.equal(parseDecisionBody({ ...base, payload: { ...base.payload, risk: 0 } }).ok, true);
  const withHw = parseDecisionBody({ ...base, payload: { ...base.payload, risk: 100 }, hw: HW });
  assert.equal(withHw.ok, true);
  assert.deepEqual(withHw.value.hw, HW);
  for (const risk of [101, -1, 5.5, "90", null]) assert.equal(parseDecisionBody({ ...base, payload: { ...base.payload, risk } }).reason, "risk_invalid", String(risk));
  for (const hw of [null, "x", [], { ...HW, signature: "" }, { ...HW, signature: 5 }, { credentialId: "a" }, { ...HW, clientDataJSON: "{bad json}" }]) {
    assert.equal(parseDecisionBody({ ...base, hw }).reason, "hw_invalid", JSON.stringify(hw));
  }
  // extra hw fields are not forwarded
  assert.deepEqual(Object.keys(parseDecisionBody({ ...base, hw: { ...HW, extra: "x" } }).value.hw).sort(), Object.keys(HW).sort());
});

function fakeWardend(sockPath, state) {
  const server = net.createServer((c) => {
    let buf = "";
    c.setEncoding("utf8");
    c.on("data", (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const req = JSON.parse(buf.slice(0, i));
        buf = buf.slice(i + 1);
        let result;
        if (req.method === "pending") result = { ok: true, seq: 1, pending: state.pending, supervisorId: SUP, host: "h", mode: "ticket" };
        else if (req.method === "decide") {
          state.decided.push(req.params);
          result = req.params.hw ? { ok: true, id: req.params.payload.id, decision: "allow" } : { ok: false, reason: "hardware_required", hardwareRule: "hw-rm", id: req.params.payload.id };
        } else if (req.method === "status") result = { ok: true, mode: "ticket", protocol: 1 };
        c.write(JSON.stringify({ jsonrpc: "2.0", id: req.id, result }) + "\n");
      }
    });
  });
  return new Promise((r) => server.listen(sockPath, () => r(server)));
}

test("relay: hw and risk are forwarded to wardend byte-for-byte, wardend rejection (hardware_required) reaches the app", { skip: !HARDWARE_KEY && "second factor is disabled (src/features.js)" }, async () => {
  const dir = tmpDir();
  const sock = path.join(dir, "w.sock");
  const digest = "c".repeat(64);
  const item = { id: `wd-${digest.slice(0, 32)}`, kind: "exec", digest, envelope: { v: 1, type: "exec", argv: ["rm", "x"] }, meta: { class: "root", hardware: { required: true, rule: "hw-rm", credentials: [] } }, createdAt: Date.now(), expiresAt: Date.now() + 60000 };
  const state = { pending: [item], decided: [] };
  const srv = await fakeWardend(sock, state);
  after(() => srv.close());
  const dev = await makeDevice();
  const g = makeGate({ devices: [dev] });
  g.clock.t = Date.now();
  g.gate.relay = new WardendRelay({ socketPath: sock, logger: g.logger, onChange: () => g.gate.store.touch() });
  await g.gate.relay.refresh();
  const rec = g.gate.pendingSnapshot().pending.find((p) => p.id === item.id);
  assert.deepEqual(rec.meta.hardware, item.meta.hardware, "meta.hardware reaches the app");

  // without hw: plugin pre-verification passes (signature is valid), wardend rejects -- reason is returned
  const noHw = await dev.signDecision({ type: TICKET_EXEC, supervisorId: SUP, id: item.id, digest, decision: "allow", ts: g.now(), nonce: randomUUID(), risk: 90 });
  const r1 = await g.gate.decide(noHw, { transport: "http" });
  assert.equal(r1.ok, false);
  assert.equal(r1.reason, "hardware_required");
  assert.equal(r1.hardwareRule, "hw-rm");

  // with hw: body reaches wardend in full (risk, hw), plugin journal records hw
  const body = { ...(await dev.signDecision({ type: TICKET_EXEC, supervisorId: SUP, id: item.id, digest, decision: "allow", ts: g.now(), nonce: randomUUID(), risk: 90 })), hw: HW };
  const r2 = await g.gate.decide(JSON.parse(JSON.stringify(body)), { transport: "http" });
  assert.equal(r2.ok, true, JSON.stringify(r2));
  assert.deepEqual(state.decided.at(-1), body);
  const j = g.journal.entries.filter((e) => e.kind === "relay_decision").at(-1);
  assert.deepEqual(j.data?.hw ?? j.hw, HW);

  // tampering with risk breaks the device signature at pre-verification -- does not reach wardend
  const n = state.decided.length;
  const tampered = { ...(await dev.signDecision({ type: TICKET_EXEC, supervisorId: SUP, id: item.id, digest, decision: "allow", ts: g.now(), nonce: randomUUID(), risk: 90 })), hw: HW };
  tampered.payload.risk = 10;
  const r3 = await g.gate.decide(tampered, { transport: "http" });
  assert.equal(r3.reason, "bad_signature");
  assert.equal(state.decided.length, n);

  // malformed hw -- form rejection, does not reach wardend
  const r4 = await g.gate.decide({ ...body, hw: { credentialId: "x" } }, { transport: "http" });
  assert.equal(r4.reason, "hw_invalid");
  assert.equal(state.decided.length, n);
});

test("without second factor (HARDWARE_KEY false) decision with hw is rejected, without hw is parsed", { skip: HARDWARE_KEY && "second factor is enabled" }, () => {
  const base = { deviceId: "a".repeat(64), signature: "s", payload: { type: TICKET_EXEC, supervisorId: SUP, id: "wd-1", digest: "b".repeat(64), decision: "allow", ts: 1, nonce: "12345678", risk: 90 } };
  assert.equal(parseDecisionBody(base).ok, true);
  for (const hw of [HW, null, { credentialId: "x" }]) assert.equal(parseDecisionBody({ ...base, hw }).reason, "hw_not_in_release", JSON.stringify(hw));
});
