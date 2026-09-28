// SPDX-License-Identifier: GPL-3.0-or-later
// End-to-end test of the app client (real src/core/wardendClient.ts) against a real wardend:
// pairing via a link from `wardend pair start`, `wardend pair approve`, a root card via long-poll,
// signed ticket -> exec runs. Expo modules are replaced with node stubs.
//
//   WARDEND_BIN=/path/to/wardend node scripts/e2e-wardend.mjs
// wardend installs a seccomp filter: when running under another wardend, use:
//   systemd-run --user --wait --pipe -p WorkingDirectory=$PWD -E WARDEND_BIN=... $(which node) scripts/e2e-wardend.mjs
import { execFileSync, spawn } from "node:child_process";
import { createRequire } from "node:module";
import Module from "node:module";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const bin = process.env.WARDEND_BIN;
if (!bin) throw new Error("WARDEND_BIN not set");
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const out = path.join(root, ".test-build-e2e");
fs.rmSync(out, { recursive: true, force: true });
execFileSync(
  path.join(root, "node_modules/.bin/tsc"),
  ["--ignoreConfig", "--outDir", out, "--module", "commonjs", "--moduleResolution", "node10", "--target", "es2020", "--strict", "--skipLibCheck", "--esModuleInterop", "--ignoreDeprecations", "6.0", "src/core/wardendClient.ts"],
  { cwd: root, stdio: "inherit" },
);
// Expo stubs
const secure = new Map();
const stubs = {
  "expo-crypto": { randomUUID: () => crypto.randomUUID(), getRandomBytes: (n) => new Uint8Array(crypto.randomBytes(n)) },
  "expo-secure-store": { getItemAsync: async (k) => secure.get(k) ?? null, setItemAsync: async (k, v) => void secure.set(k, v), deleteItemAsync: async (k) => void secure.delete(k) },
};
const origLoad = Module._load;
Module._load = function (req, parent, isMain) {
  if (stubs[req]) return stubs[req];
  return origLoad.call(this, req, parent, isMain);
};
const require = createRequire(path.join(out, "x.js"));
const { loadOrCreateIdentity } = require(path.join(out, "identity.js"));
const { WardendClient } = require(path.join(out, "wardendClient.js"));
const { parsePairLink, supervisorIdFromKey, wardendItemToPending } = require(path.join(out, "wardendProto.js"));
const { checkExecPending } = require(path.join(out, "execEnvelope.js"));

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "wd-e2e-"));
const sock = path.join(dir, "wardend.sock");
const wd = spawn(bin, ["run", "--state-dir", dir, "--mode", "ticket", "--ttl", "30s", "--http-listen", "127.0.0.1:0", "--quiet", "--", "sh", "-c", "sleep 2; bash -c 'echo root-ran'"], { stdio: ["ignore", "pipe", "inherit"] });
let output = "";
wd.stdout.on("data", (d) => (output += d));
const exited = new Promise((r) => wd.on("exit", r));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const cli = (...a) => execFileSync(bin, [...a, "--socket", sock], { encoding: "utf8" });
const step = (s) => console.log(`• ${s}`);

try {
  for (let i = 0; i < 50 && !fs.existsSync(sock); i++) await sleep(100);
  const addr = JSON.parse(cli("status")).http.addr;
  const started = cli("pair", "start", "--url", `http://${addr}`, "--qr", "none", "--no-wait");
  const linkText = /wardenclaw:\/\/pair\?\S+/.exec(started)[0];
  step(`pair start → ${linkText.slice(0, 60)}…`);
  const link = parsePairLink(linkText);
  const identity = await loadOrCreateIdentity();
  const client = new WardendClient({ baseUrl: link.url, pinnedKey: link.key, identity });
  const sup = supervisorIdFromKey(link.key);
  const ping = await client.ping();
  if (ping.supervisorId !== sup) throw new Error("ping: supervisorId does not match");
  step("ping: response is signed with the key from the QR code");
  // client with a foreign pinned key must reject the response
  const evil = new WardendClient({ baseUrl: link.url, pinnedKey: Buffer.alloc(32, 7).toString("base64url"), identity });
  await evil.ping().then(() => { throw new Error("foreign key was accepted"); }, (e) => { if (e.reason !== "unsigned_response") throw e; });
  step("wrong key: response rejected (unsigned_response)");
  const pr = await client.pair(link.code, sup, "e2e phone");
  if (pr.status !== "pending") throw new Error(`pair: ${JSON.stringify(pr)}`);
  step(`pair -> ${pr.id} pending, fingerprint ${pr.fingerprint}`);
  const listed = cli("pair", "list");
  if (!listed.includes(pr.fingerprint)) throw new Error("pair list: fingerprint missing");
  if ((await client.pairStatus(pr.id)).status !== "pending") throw new Error("pair status is not pending");
  cli("pair", "approve", pr.id);
  if ((await client.pairStatus(pr.id)).status !== "approved") throw new Error("pair status is not approved");
  step("pair approve -> approved");
  let since = 0;
  let decided = 0;
  let done = false;
  exited.then(() => (done = true));
  for (let i = 0; i < 20 && !done; i++) {
    const res = await client.pending(since, 1000).catch((e) => (done ? { seq: since, pending: [] } : Promise.reject(e)));
    since = res.seq;
    for (const it of res.pending) {
      const rec = wardendItemToPending(it);
      const chk = checkExecPending(rec, sup);
      if (!chk.ok) throw new Error(`envelope: ${chk.reason}`);
      const { response } = await client.decide(rec, "allow");
      if (!response.ok) throw new Error(`decide: ${JSON.stringify(response)}`);
      step(`decide allow ${rec.id.slice(0, 12)} (${chk.envelope.argv.join(" ").slice(0, 40)})`);
      decided++;
    }
  }
  if (decided < 2) throw new Error(`signed ${decided} cards, expected 2 (sleep and bash)`);
  const code = await Promise.race([exited, sleep(10000).then(() => "timeout")]);
  if (code !== 0 || !output.includes("root-ran")) throw new Error(`wardend: code=${code} out=${output}`);
  const cfg = JSON.parse(fs.readFileSync(path.join(dir, "config.json"), "utf8"));
  if (cfg.trusted_devices?.[0]?.id !== identity.deviceId) throw new Error("trusted_devices not written");
  step("exec completed, device in trusted_devices");
  console.log("E2E OK");
} finally {
  wd.kill("SIGTERM");
  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(out, { recursive: true, force: true });
}
