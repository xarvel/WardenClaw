// SPDX-License-Identifier: Apache-2.0
// Plugin shutdown (gate.close, PendingStore.close: gateway_stop, including reload): waiting
// enforce calls immediately receive block "plugin stopped" instead of hanging until TTL; a decision
// arriving after shutdown does not allow anything (architecture report plugin 2, 28.09).
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { makeDevice, makeGate, tmpDir } from "./helpers.js";
import { createBeforeToolCallHandler } from "../src/hook.js";
import { PendingStore } from "../src/store.js";

const ev = (over = {}) => ({ toolName: "exec", params: { command: "ls -la" }, runId: "r", toolCallId: randomUUID(), ...over });
const ctx = (over = {}) => ({ agentId: "main", sessionKey: "agent:main:main", ...over });

/** Promise or timeout rejection (test TTL 60 s: response must arrive immediately). */
function within(p, ms = 1000) {
  let t;
  return Promise.race([p, new Promise((_, rej) => (t = setTimeout(() => rej(new Error(`no response within ${ms} ms`)), ms)))]).finally(() => clearTimeout(t));
}

test("enforce: close wakes waiting calls, block \"plugin stopped\" immediately, not on TTL", async () => {
  const dev = await makeDevice();
  const g = makeGate({ devices: [dev], config: { mode: "enforce", ttlMs: 60_000 } });
  const handler = createBeforeToolCallHandler({ gate: g.gate, config: g.config, logger: g.logger });
  const p1 = handler(ev(), ctx());
  const p2 = handler(ev({ params: { command: "rm -rf build" } }), ctx());
  const [rec1, rec2] = g.gate.store.listPending();
  g.gate.close();
  for (const r of await within(Promise.all([p1, p2]))) {
    assert.equal(r.block, true);
    assert.match(r.blockReason, /^wardenclaw-gate: plugin stopped/);
  }
  assert.equal(g.gate.store.get(rec1.id).status, "stopped");
  assert.equal(g.gate.store.get(rec2.id).status, "stopped");
  assert.equal(g.gate.store.listPending().length, 0);
  assert.equal(g.gate.counters.stopped, 2);
  assert.equal(g.gate.counters.expired, 0);
  assert.deepEqual(
    g.journal.entries.filter((e) => e.kind === "stopped").map((e) => e.data.id).sort(),
    [rec1.id, rec2.id].sort(),
  );
  assert.ok(g.logger.lines.some((l) => /^warn .*shutdown: 2 pending call\(s\) rejected/.test(l)));
  assert.ok(g.logger.lines.some((l) => /BLOCK exec .*plugin stopped/.test(l)));
});

test("enforce: Allow after shutdown is late and does not allow anything", async () => {
  const dev = await makeDevice();
  const g = makeGate({ devices: [dev], config: { mode: "enforce", ttlMs: 60_000 } });
  const handler = createBeforeToolCallHandler({ gate: g.gate, config: g.config, logger: g.logger });
  const p = handler(ev(), ctx());
  const rec = g.gate.store.listPending()[0];
  g.gate.close();
  const r = await within(p);
  assert.equal(r.block, true);
  const d = await g.gate.decide(await dev.signDecision({ id: rec.id, digest: rec.digest, decision: "allow", ts: g.now(), nonce: randomUUID() }), { transport: "test" });
  assert.equal(d.ok, true);
  assert.equal(d.late, true);
  assert.equal(d.status, "stopped");
  assert.equal(g.gate.store.get(rec.id).status, "stopped");
  assert.equal(g.gate.counters.allowed, 0);
});

test("enforce: Allow before shutdown passes, close does not affect it", async () => {
  const dev = await makeDevice();
  const g = makeGate({ devices: [dev], config: { mode: "enforce", ttlMs: 60_000 } });
  const handler = createBeforeToolCallHandler({ gate: g.gate, config: g.config, logger: g.logger });
  const p = handler(ev(), ctx());
  const rec = g.gate.store.listPending()[0];
  await g.gate.decide(await dev.signDecision({ id: rec.id, digest: rec.digest, decision: "allow", ts: g.now(), nonce: randomUUID() }), { transport: "test" });
  g.gate.close();
  assert.deepEqual(await within(p), {});
  assert.equal(g.gate.store.get(rec.id).status, "allowed");
  assert.equal(g.gate.counters.stopped, 0);
  assert.ok(!g.logger.lines.some((l) => /shutdown:/.test(l)));
});

test("enforce: call arriving in an already-stopped gate is blocked immediately", async () => {
  const dev = await makeDevice();
  const g = makeGate({ devices: [dev], config: { mode: "enforce", ttlMs: 60_000 } });
  const handler = createBeforeToolCallHandler({ gate: g.gate, config: g.config, logger: g.logger });
  g.gate.close();
  const r = await within(handler(ev(), ctx()));
  assert.equal(r.block, true);
  assert.match(r.blockReason, /plugin stopped/);
  assert.equal(g.gate.store.listAll()[0].status, "stopped");
  g.gate.close(); // repeated close is a no-op
  assert.equal(g.gate.counters.stopped, 1);
});

test("observe: close marks entries stopped, no waiters, no warning", async () => {
  const dev = await makeDevice();
  const g = makeGate({ devices: [dev], config: { mode: "observe", ttlMs: 60_000 } });
  const handler = createBeforeToolCallHandler({ gate: g.gate, config: g.config, logger: g.logger });
  assert.equal(await handler(ev(), ctx()), undefined);
  g.gate.close();
  assert.equal(g.gate.store.listAll()[0].status, "stopped");
  assert.equal(g.gate.store.listPending().length, 0);
  assert.ok(!g.logger.lines.some((l) => /shutdown:/.test(l)));
});

test("PendingStore.close: long-poll wakes, decision wait resolves with stopped, snapshot is no longer written", async () => {
  const dir = tmpDir();
  const store = new PendingStore({ dir });
  const rec = store.create({ digest: "d", toolName: "exec", paramsPreview: "ls", source: "test", mode: "enforce" }, 60_000);
  const waiting = store.waitDecision(rec.id, { timeoutMs: 60_000 });
  const poll = store.waitChange(store.seq, 60_000);
  assert.equal(store.close(), 1);
  assert.equal(await within(poll), true);
  const r = await within(waiting);
  assert.equal(r.outcome, "stopped");
  assert.equal(r.record?.status, "stopped");
  // after close the snapshot is not written (otherwise the old instance would overwrite the new pending.json)
  const file = path.join(dir, "pending.json");
  fs.rmSync(file, { force: true });
  store.decide(rec.id, "allow", "dev");
  await new Promise((res) => setTimeout(res, 300));
  assert.equal(fs.existsSync(file), false);
  assert.equal(store.get(rec.id).status, "stopped");
  assert.equal(store.close(), 0);
});
