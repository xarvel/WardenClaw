// SPDX-License-Identifier: Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { makeDevice, makeGate } from "./helpers.js";
import { createBeforeToolCallHandler } from "../src/hook.js";
import { toolMatches, DEFAULT_TOOLS, resolveConfig } from "../src/config.js";

const ev = (over = {}) => ({ toolName: "exec", params: { command: "ls -la" }, runId: "r", toolCallId: randomUUID(), ...over });
const ctx = (over = {}) => ({ agentId: "main", sessionKey: "agent:main:main", ...over });

test("config: defaults and normalisation", () => {
  const c = resolveConfig({});
  assert.equal(c.mode, "observe");
  assert.equal(c.ttlMs, 120000);
  assert.equal(c.tsWindowMs, 60000);
  assert.deepEqual(c.tools, DEFAULT_TOOLS);
  assert.deepEqual(c.exemptAgents, []);
  assert.equal(c.requireDeviceToken, true);
  const e = resolveConfig({ mode: "enforce", tools: ["exec"], ttlMs: 5000, exemptAgents: ["cron-x"], trustedDeviceIds: ["a"], devices: [{ deviceId: "a", publicKey: "k" }] });
  assert.equal(e.mode, "enforce");
  assert.deepEqual(e.tools, ["exec"]);
  assert.equal(e.ttlMs, 5000);
  assert.deepEqual(e.devices, [{ deviceId: "a", publicKey: "k" }]);
});

test("toolMatches: by name (case-insensitive) and by toolKind", () => {
  assert.equal(toolMatches({ toolName: "exec" }, DEFAULT_TOOLS), true);
  assert.equal(toolMatches({ toolName: "Bash" }, DEFAULT_TOOLS), true);
  assert.equal(toolMatches({ toolName: "bash" }, DEFAULT_TOOLS), true);
  assert.equal(toolMatches({ toolName: "read" }, DEFAULT_TOOLS), false);
  assert.equal(toolMatches({ toolName: "exec", toolKind: "code_mode_exec" }, ["code_mode_exec"]), true);
  assert.equal(toolMatches({ toolName: "web_fetch" }, ["exec"]), false);
});

test("observe: hook creates pending, logs, and returns undefined immediately", async () => {
  const dev = await makeDevice();
  const g = makeGate({ devices: [dev], config: { mode: "observe" } });
  const handler = createBeforeToolCallHandler({ gate: g.gate, config: g.config, logger: g.logger });
  const t0 = Date.now();
  const r = await handler(ev(), ctx());
  assert.equal(r, undefined);
  assert.ok(Date.now() - t0 < 200);
  const pending = g.gate.store.listPending();
  assert.equal(pending.length, 1);
  assert.equal(pending[0].toolName, "exec");
  assert.equal(pending[0].command, "ls -la");
  assert.ok(g.logger.lines.some((l) => /saw tool=exec/.test(l)));
  assert.ok(g.logger.lines.some((l) => /observe: exec/.test(l)));
  assert.equal(g.gate.counters.observed, 1);
});

test("observe: non-executing tool is logged but no pending is created", async () => {
  const dev = await makeDevice();
  const g = makeGate({ devices: [dev] });
  const handler = createBeforeToolCallHandler({ gate: g.gate, config: g.config, logger: g.logger });
  assert.equal(await handler(ev({ toolName: "read", params: { path: "/etc/hosts" } }), ctx()), undefined);
  assert.equal(g.gate.store.listPending().length, 0);
  assert.ok(g.logger.lines.some((l) => /saw tool=read .* gated=false/.test(l)));
  assert.equal(g.gate.status().seenTools[0].toolName, "read");
});

test("enforce: allow by signature -> {}", async () => {
  const dev = await makeDevice();
  const g = makeGate({ devices: [dev], config: { mode: "enforce", ttlMs: 5000 } });
  const handler = createBeforeToolCallHandler({ gate: g.gate, config: g.config, logger: g.logger });
  const p = handler(ev(), ctx());
  const rec = g.gate.store.listPending()[0];
  const r = await g.gate.decide(await dev.signDecision({ id: rec.id, digest: rec.digest, decision: "allow", ts: g.now(), nonce: randomUUID() }), { transport: "test" });
  assert.equal(r.ok, true);
  assert.deepEqual(await p, {});
});

test("enforce: deny by signature -> block", async () => {
  const dev = await makeDevice();
  const g = makeGate({ devices: [dev], config: { mode: "enforce", ttlMs: 5000 } });
  const handler = createBeforeToolCallHandler({ gate: g.gate, config: g.config, logger: g.logger });
  const p = handler(ev(), ctx());
  const rec = g.gate.store.listPending()[0];
  await g.gate.decide(await dev.signDecision({ id: rec.id, digest: rec.digest, decision: "deny", ts: g.now(), nonce: randomUUID() }), { transport: "test" });
  const r = await p;
  assert.equal(r.block, true);
  assert.match(r.blockReason, /denied by device/);
});

test("enforce: timeout without signature -> block (fail-closed)", async () => {
  const dev = await makeDevice();
  const g = makeGate({ devices: [dev], config: { mode: "enforce", ttlMs: 1000 } });
  const handler = createBeforeToolCallHandler({ gate: g.gate, config: g.config, logger: g.logger });
  const r = await handler(ev(), ctx());
  assert.equal(r.block, true);
  assert.match(r.blockReason, /no signed decision/);
  assert.equal(g.gate.store.listAll()[0].status, "expired");
});

test("enforce: abortSignal cancels the wait -> block", async () => {
  const dev = await makeDevice();
  const g = makeGate({ devices: [dev], config: { mode: "enforce", ttlMs: 10000 } });
  const handler = createBeforeToolCallHandler({ gate: g.gate, config: g.config, logger: g.logger });
  const ac = new AbortController();
  const p = handler(ev(), ctx({ abortSignal: ac.signal }));
  setTimeout(() => ac.abort(), 50);
  const r = await p;
  assert.equal(r.block, true);
  assert.match(r.blockReason, /call aborted/);
});

test("enforce: untrusted signature does not release the call; trusted one does", async () => {
  const dev = await makeDevice();
  const stranger = await makeDevice();
  const g = makeGate({ devices: [dev], config: { mode: "enforce", ttlMs: 5000 } });
  const handler = createBeforeToolCallHandler({ gate: g.gate, config: g.config, logger: g.logger });
  const p = handler(ev(), ctx());
  const rec = g.gate.store.listPending()[0];
  const bad = await g.gate.decide(await stranger.signDecision({ id: rec.id, digest: rec.digest, decision: "allow", ts: g.now(), nonce: randomUUID() }), { transport: "test" });
  assert.equal(bad.ok, false);
  assert.equal(g.gate.store.get(rec.id).status, "pending");
  await g.gate.decide(await dev.signDecision({ id: rec.id, digest: rec.digest, decision: "allow", ts: g.now(), nonce: randomUUID() }), { transport: "test" });
  assert.deepEqual(await p, {});
});

test("exemptAgents: agent in the list is skipped without pending", async () => {
  const dev = await makeDevice();
  const g = makeGate({ devices: [dev], config: { mode: "enforce", exemptAgents: ["cron-agent"] } });
  const handler = createBeforeToolCallHandler({ gate: g.gate, config: g.config, logger: g.logger });
  assert.equal(await handler(ev(), ctx({ agentId: "cron-agent" })), undefined);
  assert.equal(g.gate.store.listAll().length, 0);
});

test("observe: late decision for an already-observed entry is recorded as late", async () => {
  const dev = await makeDevice();
  const g = makeGate({ devices: [dev], config: { mode: "observe", ttlMs: 60000 } });
  const handler = createBeforeToolCallHandler({ gate: g.gate, config: g.config, logger: g.logger });
  await handler(ev(), ctx());
  const rec = g.gate.store.listPending()[0];
  const r = await g.gate.decide(await dev.signDecision({ id: rec.id, digest: rec.digest, decision: "allow", ts: g.now(), nonce: randomUUID() }), { transport: "test" });
  assert.equal(r.ok, true);
  assert.equal(r.late, false); // entry is still pending (in observe it waits for a signature until TTL)
  assert.equal(g.gate.store.get(rec.id).status, "allowed");
  // after TTL -- expired; a second decision is late
  g.clock.t += 61000;
  const rec2 = g.gate.createPending({ toolName: "exec", params: { command: "id" }, source: "test" });
  g.clock.t += 61000;
  g.gate.store.expireStale();
  const r2 = await g.gate.decide(await dev.signDecision({ id: rec2.id, digest: rec2.digest, decision: "deny", ts: g.now(), nonce: randomUUID() }), { transport: "test" });
  assert.equal(r2.ok, true);
  assert.equal(r2.late, true);
  assert.equal(g.gate.store.get(rec2.id).status, "expired");
});
