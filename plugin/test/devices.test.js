// SPDX-License-Identifier: Apache-2.0
// Device directory from the gateway DB: temporary sqlite with the same schema as device_pairing_paired.
import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { SqliteDeviceDirectory, CompositeDeviceDirectory, StaticDeviceDirectory, gatewaySqlitePath } from "../src/devices.js";
import { deviceIdOfPublicKey, publicKeyMatchesDeviceId } from "../src/crypto.js";
import { verifyDecision, NonceCache } from "../src/verify.js";
import { makeDevice, tmpDir } from "./helpers.js";

function gatewayDb(rows) {
  const file = path.join(tmpDir(), "openclaw.sqlite");
  const db = new DatabaseSync(file);
  db.exec(`CREATE TABLE device_pairing_paired (
    device_id TEXT NOT NULL PRIMARY KEY, public_key TEXT NOT NULL, display_name TEXT, operator_label TEXT, platform TEXT,
    device_family TEXT, client_id TEXT, client_mode TEXT, browser_origin TEXT, role TEXT, roles_json TEXT, scopes_json TEXT,
    approved_scopes_json TEXT, remote_ip TEXT, tokens_json TEXT, approved_via TEXT, node_surface_json TEXT, pending_node_surface_json TEXT,
    created_at_ms INTEGER NOT NULL, approved_at_ms INTEGER NOT NULL, last_seen_at_ms INTEGER, last_seen_reason TEXT) STRICT`);
  const ins = db.prepare("INSERT INTO device_pairing_paired (device_id, public_key, display_name, tokens_json, created_at_ms, approved_at_ms) VALUES (?,?,?,?,?,?)");
  for (const r of rows) ins.run(r.deviceId, r.publicKey, r.displayName ?? null, JSON.stringify(r.tokens ?? {}), 1, 1);
  db.close();
  return file;
}

test("SqliteDeviceDirectory: reads public_key and tokens from device_pairing_paired", async () => {
  const dev = await makeDevice();
  const file = gatewayDb([{ deviceId: dev.deviceId, publicKey: dev.publicKey, displayName: "wardenclaw-app", tokens: { operator: { token: "T1", role: "operator" }, node: { token: "T2" } } }]);
  const d = new SqliteDeviceDirectory(file, { cacheMs: 10 });
  const r = await d.getDevice(dev.deviceId);
  assert.equal(r.publicKey, dev.publicKey);
  assert.equal(r.keyMismatch, undefined);
  assert.equal(r.displayName, "wardenclaw-app");
  assert.deepEqual(r.tokens.sort(), ["T1", "T2"]);
  assert.equal(await d.getDevice("b".repeat(64)), null);
  assert.equal(await new SqliteDeviceDirectory(path.join(path.dirname(file), "nope.sqlite")).getDevice("x"), null);

  // Composite: config overrides the key, tokens come from the DB
  const c = new CompositeDeviceDirectory([new StaticDeviceDirectory([{ deviceId: dev.deviceId, publicKey: dev.publicKey }]), d]);
  const m = await c.getDevice(dev.deviceId);
  assert.equal(m.publicKey, dev.publicKey);
  assert.equal(m.source, "config");
  assert.deepEqual(m.tokens.sort(), ["T1", "T2"]);
  assert.equal(gatewaySqlitePath("/x"), "/x/state/openclaw.sqlite");
});

test("deviceIdOfPublicKey: sha256(raw 32 bytes) hex, same as in pairing", async () => {
  const dev = await makeDevice();
  assert.equal(deviceIdOfPublicKey(dev.publicKey), dev.deviceId);
  assert.equal(deviceIdOfPublicKey(`${dev.publicKey}=`), dev.deviceId);
  assert.equal(deviceIdOfPublicKey("PUBKEY"), null);
  assert.equal(deviceIdOfPublicKey(""), null);
  assert.equal(deviceIdOfPublicKey(undefined), null);
  assert.ok(publicKeyMatchesDeviceId(dev.publicKey, dev.deviceId.toUpperCase()));
  assert.ok(!publicKeyMatchesDeviceId(dev.publicKey, "a".repeat(64)));
});

// Regression for crypto review 2026-09-28 finding 2 (PoC TestReviewGatewayDBKeySubstitution): agent
// overwrote the trusted phone public_key in openclaw.sqlite with its own key and self-signed a decision.
test("gateway DB key substitution: foreign key for this deviceId is not returned and decision is rejected", async () => {
  const phone = await makeDevice();
  const agent = await makeDevice();
  const file = gatewayDb([{ deviceId: phone.deviceId, publicKey: agent.publicKey, tokens: { operator: { token: "T3" } } }]);
  const sqlite = new SqliteDeviceDirectory(file, { cacheMs: 10 });
  const r = await sqlite.getDevice(phone.deviceId);
  assert.equal(r.publicKey, "", "foreign key is not returned");
  assert.equal(r.keyMismatch, true);
  assert.deepEqual(r.tokens, ["T3"]);

  const now = 1_800_000_000_000;
  const digest = "d".repeat(64);
  const body = await agent.signDecision({ id: "c0ffee00-0000-4000-8000-000000000001", digest, decision: "allow", ts: now, nonce: randomUUID() });
  body.deviceId = phone.deviceId; // on behalf of the phone
  const ctx = (directory) => ({ now, trustedDeviceIds: [phone.deviceId], tsWindowMs: 60_000, directory, nonces: new NonceCache({ windowMs: 60_000, now: () => now }), getPending: () => ({ digest }) });
  const v1 = await verifyDecision(body, ctx(new CompositeDeviceDirectory([new StaticDeviceDirectory([]), sqlite])));
  assert.deepEqual([v1.ok, v1.reason], [false, "pubkey_id_mismatch"]);
  // a directory that would return the key as-is (old behaviour) is still rejected in verify
  const raw = { getDevice: async () => ({ deviceId: phone.deviceId, publicKey: agent.publicKey, tokens: [], source: "stub" }) };
  const v2 = await verifyDecision(body, ctx(raw));
  assert.deepEqual([v2.ok, v2.reason], [false, "pubkey_id_mismatch"]);
  // with the phone key pinned in config, DB substitution has no effect: agent decision -> bad_signature
  const pinned = new CompositeDeviceDirectory([new StaticDeviceDirectory([{ deviceId: phone.deviceId, publicKey: phone.publicKey }]), sqlite]);
  const v3 = await verifyDecision(body, ctx(pinned));
  assert.deepEqual([v3.ok, v3.reason], [false, "bad_signature"]);
  const own = await phone.signDecision({ id: "c0ffee00-0000-4000-8000-000000000001", digest, decision: "allow", ts: now, nonce: randomUUID() });
  const v4 = await verifyDecision(own, ctx(pinned));
  assert.equal(v4.ok, true);
});

test("StaticDeviceDirectory: config entry with a key not belonging to this deviceId is not used", async () => {
  const phone = await makeDevice();
  const other = await makeDevice();
  const s = new StaticDeviceDirectory([
    { deviceId: phone.deviceId, publicKey: other.publicKey },
    { deviceId: other.deviceId, publicKey: other.publicKey },
  ]);
  assert.deepEqual(s.rejected, [phone.deviceId]);
  assert.equal(await s.getDevice(phone.deviceId), null);
  assert.equal((await s.getDevice(other.deviceId)).publicKey, other.publicKey);
});
