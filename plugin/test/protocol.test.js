// SPDX-License-Identifier: Apache-2.0
// Protocol version (protocol/README.md, "Protocol version"): constants, server response check,
// the protocol field in GET /wardenclaw/status and WS wardenclaw.status.
import { test } from "node:test";
import assert from "node:assert/strict";
import { makeDevice, makeGate, tmpDir } from "./helpers.js";
import { PROTOCOL, checkServerProtocol } from "../src/protocol.js";
import plugin from "../index.js";

test("protocol version: the first release speaks protocol 1", () => {
  assert.equal(PROTOCOL, 1);
});

test("checkServerProtocol: server too old, client too old, same version", () => {
  const cases = [
    [{ protocol: 1 }, null],
    [{ ok: true }, "server_too_old"],
    [undefined, "server_too_old"],
    [{ protocol: 0 }, "server_too_old"],
    [{ protocol: "1" }, "server_too_old"],
    [{ protocol: 1.5 }, "server_too_old"],
    [{ protocol: 2 }, "client_too_old"],
  ];
  for (const [r, want] of cases) assert.equal(checkServerProtocol(r).mismatch, want, JSON.stringify(r));
  assert.deepEqual(checkServerProtocol({ protocol: 2 }), { protocol: 2, mismatch: "client_too_old" });
});

test("plugin status: protocol in gate.status and WS wardenclaw.status", async () => {
  const g = makeGate({ devices: [] });
  const st = g.gate.status();
  assert.equal(st.protocol, PROTOCOL);
  assert.equal(st.minClient, undefined);

  const dev = await makeDevice();
  const dir = tmpDir();
  const methods = {};
  const api = {
    pluginConfig: { mode: "observe", relay: false, stateDir: dir, trustedDeviceIds: [dev.deviceId] },
    runtime: { state: { resolveStateDir: () => dir } },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
    registerHttpRoute() {},
    registerGatewayMethod: (name, fn) => (methods[name] = fn),
    on() {},
  };
  plugin.register(api);
  let got;
  await methods["wardenclaw.status"]({ client: { connect: { device: { id: dev.deviceId } } }, respond: (ok, payload, err) => (got = { ok, payload, err }) });
  assert.equal(got.ok, true);
  assert.equal(got.payload.protocol, PROTOCOL);
});
