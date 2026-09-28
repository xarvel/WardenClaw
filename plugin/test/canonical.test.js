// SPDX-License-Identifier: Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalJson, sha256Hex, toolCallDigest, decisionSigningString } from "../src/canonical.js";

test("canonicalJson: keys are sorted, undefined is dropped, arrays preserve order", () => {
  const s = canonicalJson({ b: 1, a: { z: [3, 1, { y: undefined, x: null }], k: "ы" }, u: undefined });
  assert.equal(s, '{"a":{"k":"ы","z":[3,1,{"x":null}]},"b":1}');
});

test("canonicalJson: primitives and unicode same as JSON.stringify", () => {
  assert.equal(canonicalJson("a\"b\n"), JSON.stringify("a\"b\n"));
  assert.equal(canonicalJson(1.5), "1.5");
  assert.equal(canonicalJson(true), "true");
  assert.equal(canonicalJson(null), "null");
  assert.equal(canonicalJson(undefined), "null");
});

test("toolCallDigest: deterministic, depends on each field, params key order does not matter", () => {
  const base = { toolName: "exec", params: { command: "ls -la", cwd: "/tmp" }, agentId: "main", sessionKey: "agent:main:x", runId: "r1", toolCallId: "c1" };
  const d1 = toolCallDigest(base);
  assert.match(d1, /^[0-9a-f]{64}$/);
  assert.equal(toolCallDigest({ ...base, params: { cwd: "/tmp", command: "ls -la" } }), d1);
  assert.notEqual(toolCallDigest({ ...base, params: { command: "ls -la /", cwd: "/tmp" } }), d1);
  assert.notEqual(toolCallDigest({ ...base, toolName: "Bash" }), d1);
  assert.notEqual(toolCallDigest({ ...base, sessionKey: "other" }), d1);
  assert.notEqual(toolCallDigest({ ...base, toolCallId: "c2" }), d1);
  // Known value: pins the format (when the format changes, do it deliberately and in sync with the app).
  const expected = sha256Hex('{"agentId":"main","params":{"command":"ls -la","cwd":"/tmp"},"runId":"r1","sessionKey":"agent:main:x","toolCallId":"c1","toolName":"exec"}');
  assert.equal(d1, expected);
});

test("toolCallDigest: missing fields are not included in JSON", () => {
  const d = toolCallDigest({ toolName: "exec", params: {} });
  assert.equal(d, sha256Hex('{"params":{},"toolName":"exec"}'));
});

test("decisionSigningString: fixed set and order of fields, ticket type inside", () => {
  const s = decisionSigningString({ type: "wardenclaw.ticket.tool.v1", deviceId: "d", id: "i", digest: "h", decision: "allow", ts: 5, nonce: "n" });
  assert.equal(s, '{"decision":"allow","deviceId":"d","digest":"h","id":"i","nonce":"n","ts":5,"type":"wardenclaw.ticket.tool.v1"}');
  const e = decisionSigningString({ type: "wardenclaw.ticket.exec.v1", supervisorId: "s", deviceId: "d", id: "i", digest: "h", decision: "allow", ts: 5, nonce: "n" });
  assert.equal(e, '{"decision":"allow","deviceId":"d","digest":"h","id":"i","nonce":"n","supervisorId":"s","ts":5,"type":"wardenclaw.ticket.exec.v1"}');
});
