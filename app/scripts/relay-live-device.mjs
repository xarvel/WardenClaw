// SPDX-License-Identifier: GPL-3.0-or-later
// A device for the cross-language check of the relay transport: the app's own session
// (src/core/relaySession.ts) in node, with node's WebSocket, against a real relay and a real
// supervisor. Started by daemon/relaynode_test.go (TestRelayLiveNodeDevice) with a pair link:
//
//   node scripts/relay-live-device.mjs 'wardenclaw://pair?v=1&…'
//
// Fresh keys; pairs with the code of the link, waits for approval, allows the first card and
// denies the second, exits 0 after both are closed. Not part of the app bundle.
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const out = path.join(root, ".test-build-e2e/relay-live");
execFileSync(
  path.join(root, "node_modules/.bin/tsc"),
  ["--ignoreConfig", "--rootDir", path.join(root, "src"), "--outDir", out, "--module", "commonjs", "--moduleResolution", "node10", "--target", "es2020", "--strict", "--skipLibCheck", "--esModuleInterop", "--ignoreDeprecations", "6.0", "--types", "node", "src/core/relaySession.ts"],
  { cwd: root, stdio: "inherit" },
);
const require = createRequire(path.join(out, "core/x.js"));
const proto = require(path.join(out, "core/relayProto.js"));
const { RelaySession } = require(path.join(out, "core/relaySession.js"));
const { decisionSigningString, TICKET_EXEC } = require(path.join(out, "core/canonical.js"));
const { b64url, bytesToHex, utf8Encode } = require(path.join(out, "core/bytes.js"));
const ed = require("@noble/ed25519");

const say = (...a) => console.log("node device:", ...a);
const link = proto.parsePairLink(process.argv[2] ?? "");
const seed = new Uint8Array(crypto.randomBytes(32));
const pub = ed.getPublicKey(seed);
const deviceId = crypto.createHash("sha256").update(pub).digest("hex");
const sign = (s) => b64url.encode(ed.sign(utf8Encode(s), seed));
say(`id ${deviceId.slice(0, 8)}, supervisor ${link.supervisorId.slice(0, 8)}, relay ${link.relay}`);

const finish = (code, why) => {
  say(why);
  session.stop();
  process.exit(code);
};
setTimeout(() => finish(1, "FAIL: timeout"), 150_000);

let cards = 0;
let closed = 0;
let approved;
const whenApproved = new Promise((r) => (approved = r));
const session = new RelaySession({
  link: { relay: link.relay, supervisorId: link.supervisorId, key: link.key, enc: link.enc },
  device: { deviceId, publicKey: b64url.encode(pub), sign, encPrivate: new Uint8Array(crypto.randomBytes(32)) },
  version: "0.0.0-live",
  seq: 0,
  trusted: false,
  socket: (url) => new WebSocket(url),
  random: (n) => new Uint8Array(crypto.randomBytes(n)),
  hooks: {
    onState: (s, d) => say(`state ${s}${d ? ` (${d})` : ""}`),
    onRefused: (reason, id) => say(`REFUSED ${reason} ${id ?? ""}`),
    onPairStatus: (st) => {
      say(`pair.status ${st.status}${st.reason ? ` ${st.reason}` : ""} fingerprint ${st.fingerprint}`);
      if (st.status === "approved") approved();
      if (st.status === "rejected" || st.status === "refused") finish(1, "FAIL: pairing");
    },
    onStatus: (st) => say(`status: supervisor ${String(st.supervisorId).slice(0, 8)}, pending ${st.pending.length}`),
    onCard: (c) => {
      const decision = cards++ === 0 ? "allow" : "deny";
      say(`card ${c.id} (supervisor signature verified), sending ${decision}`);
      const payload = { type: TICKET_EXEC, supervisorId: link.supervisorId, id: c.id, digest: c.digest, decision, ts: Date.now(), nonce: crypto.randomUUID() };
      session
        .sendTicket({ deviceId, payload, signature: sign(decisionSigningString({ ...payload, deviceId })) })
        .then((r) => say(`ticket.result ${JSON.stringify(r)}`))
        .catch((e) => finish(1, `FAIL: ticket: ${e.message}`));
    },
    onCardDone: (d) => {
      say(`card.done ${d.id} ${d.outcome}`);
      if (++closed === 2) setTimeout(() => finish(0, "OK: two cards decided over the relay"), 500);
    },
  },
});

session.start();
while (session.state !== "ready") await new Promise((r) => setTimeout(r, 50));
const first = await session.pair(link.code, "node device");
say(`pair request answered: ${first.status}`);
await whenApproved;
say(`trusted, last seq ${session.lastSeq}`);
