// SPDX-License-Identifier: Apache-2.0
// HTTP routes on a real node:http server via a fake api.registerHttpRoute.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { randomUUID } from "node:crypto";
import { makeDevice, makeGate } from "./helpers.js";
import { createHttpHandlers } from "../src/http.js";
import { createBeforeToolCallHandler } from "../src/hook.js";

async function serve(handlers) {
  const routes = { "/wardenclaw/pending": handlers.pending, "/wardenclaw/status": handlers.status, "/wardenclaw/decide": handlers.decide, "/wardenclaw/request": handlers.request };
  const server = http.createServer(async (req, res) => {
    const p = new URL(req.url, "http://x").pathname;
    const h = routes[p];
    if (!h) {
      res.statusCode = 404;
      return res.end();
    }
    await h(req, res);
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { server, base };
}

async function boot(config = {}) {
  const dev = await makeDevice();
  const stranger = await makeDevice();
  const g = makeGate({ devices: [dev], config: { requestToken: "req-secret", ...config } });
  // gate now = fixed clock; for HTTP tests we sync to real time
  g.clock.t = Date.now();
  const { server, base } = await serve(createHttpHandlers({ gate: g.gate, config: g.config, logger: g.logger }));
  after(() => server.close());
  return { dev, stranger, ...g, server, base };
}

test("GET /wardenclaw/pending: no signature -> 401, with signature and token -> 200, long-poll wakes on new entry", async () => {
  const s = await boot();
  const r0 = await fetch(`${s.base}/wardenclaw/pending`);
  assert.equal(r0.status, 401);
  assert.equal((await r0.json()).reason, "device_id_invalid");

  const r1 = await fetch(`${s.base}/wardenclaw/pending?wait=0`, { headers: await s.dev.signedHeaders("pending") });
  assert.equal(r1.status, 200);
  const j1 = await r1.json();
  assert.equal(j1.mode, "observe");
  assert.deepEqual(j1.pending, []);

  // long-poll: request hangs until the hook creates an entry
  const t0 = Date.now();
  const p = fetch(`${s.base}/wardenclaw/pending?since=${j1.seq}&wait=5000`, { headers: await s.dev.signedHeaders("pending") });
  setTimeout(() => s.gate.createPending({ toolName: "exec", params: { command: "uname -a" }, agentId: "main", source: "test" }), 150);
  const j2 = await (await p).json();
  assert.ok(Date.now() - t0 < 3000, "long-poll must wake before timeout");
  assert.equal(j2.pending.length, 1);
  assert.equal(j2.pending[0].command, "uname -a");
  assert.match(j2.pending[0].digest, /^[0-9a-f]{64}$/);
});

test("GET /wardenclaw/pending: no Bearer or wrong token -> 401; signature replay -> 401 nonce_reused", async () => {
  const s = await boot();
  const noTok = await s.dev.signedHeaders("pending");
  delete noTok.authorization;
  assert.equal((await (await fetch(`${s.base}/wardenclaw/pending?wait=0`, { headers: noTok })).json()).reason, "device_token_missing");
  const h = await s.dev.signedHeaders("pending");
  assert.equal((await (await fetch(`${s.base}/wardenclaw/pending?wait=0`, { headers: { ...h, authorization: "Bearer nope" } })).json()).reason, "device_token_mismatch");
  // signature was valid -> nonce claimed; replaying the same headers even with correct token is rejected
  assert.equal((await (await fetch(`${s.base}/wardenclaw/pending?wait=0`, { headers: h })).json()).reason, "nonce_reused");
  // foreign device
  assert.equal((await (await fetch(`${s.base}/wardenclaw/pending?wait=0`, { headers: await s.stranger.signedHeaders("pending") })).json()).reason, "untrusted_device");
});

test("POST /wardenclaw/decide: full enforce cycle via HTTP", async () => {
  const s = await boot({ mode: "enforce", ttlMs: 5000 });
  const hook = createBeforeToolCallHandler({ gate: s.gate, config: s.config, logger: s.logger });
  const hookP = hook({ toolName: "Bash", params: { command: "echo hi" }, toolCallId: "c1" }, { agentId: "main", sessionKey: "k" });
  const list = await (await fetch(`${s.base}/wardenclaw/pending?wait=0`, { headers: await s.dev.signedHeaders("pending") })).json();
  assert.equal(list.pending.length, 1);
  const rec = list.pending[0];
  const body = await s.dev.signDecision({ id: rec.id, digest: rec.digest, decision: "allow", ts: Date.now(), nonce: randomUUID() });

  const noAuth = await fetch(`${s.base}/wardenclaw/decide`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  assert.equal(noAuth.status, 401);

  const ok = await fetch(`${s.base}/wardenclaw/decide`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${s.dev.token}` }, body: JSON.stringify(body) });
  assert.equal(ok.status, 200);
  const jr = await ok.json();
  assert.equal(jr.ok, true);
  assert.equal(jr.status, "allowed");
  assert.deepEqual(await hookP, {});

  // replaying the same decision -> 403 nonce_reused
  const replay = await fetch(`${s.base}/wardenclaw/decide`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${s.dev.token}` }, body: JSON.stringify(body) });
  assert.equal(replay.status, 403);
  assert.equal((await replay.json()).reason, "nonce_reused");

  // status
  const st = await (await fetch(`${s.base}/wardenclaw/status`, { headers: await s.dev.signedHeaders("status") })).json();
  assert.equal(st.counters.allowed, 1);
  assert.equal(st.seenTools[0].toolName, "Bash");
});

test("POST /wardenclaw/request: external caller (PreToolUse) in observe and enforce", async () => {
  const s = await boot({ mode: "observe" });
  const bad = await fetch(`${s.base}/wardenclaw/request`, { method: "POST", headers: { authorization: "Bearer wrong" }, body: "{}" });
  assert.equal(bad.status, 401);
  const r = await fetch(`${s.base}/wardenclaw/request`, {
    method: "POST",
    headers: { authorization: "Bearer req-secret", "content-type": "application/json" },
    body: JSON.stringify({ toolName: "Bash", params: { command: "ls" }, sessionKey: "claude:abc", source: "claude-code" }),
  });
  const j = await r.json();
  assert.equal(j.decision, "observe");
  assert.equal(s.gate.store.listPending()[0].source, "claude-code");

  const e = await boot({ mode: "enforce", ttlMs: 800 });
  const r2 = await fetch(`${e.base}/wardenclaw/request`, {
    method: "POST",
    headers: { authorization: "Bearer req-secret", "content-type": "application/json" },
    body: JSON.stringify({ toolName: "Bash", params: { command: "ls" } }),
  });
  const j2 = await r2.json();
  assert.equal(j2.decision, "deny");
  assert.equal(j2.outcome, "timeout");
});

test("requireDeviceToken=false: signature alone is sufficient", async () => {
  const s = await boot({ requireDeviceToken: false });
  const h = await s.dev.signedHeaders("pending");
  delete h.authorization;
  assert.equal((await fetch(`${s.base}/wardenclaw/pending?wait=0`, { headers: h })).status, 200);
});
