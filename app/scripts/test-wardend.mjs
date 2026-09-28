// SPDX-License-Identifier: GPL-3.0-or-later
// Tests of the link to wardend (src/core/wardendSession.ts) as the controller drives it: the
// platform (keys, storage, the app state, the card list) is a plain object here, the relay is the
// in-memory one of test-relay.mjs, and a small supervisor answers the frames wardend would answer.
// Loaded by test-core.mjs after it compiled src/core into .test-build/.
import { createRequire } from "node:module";
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { FakeRelay, card, fakeKv, ticket, until } from "./test-relay.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const out = path.join(root, ".test-build");
const require = createRequire(path.join(out, "core/x.js"));
const ws = require(path.join(out, "core/wardendSession.js"));
const state = require(path.join(out, "core/relayState.js"));
const i18n = require(path.join(out, "core/i18n/index.js"));
const { fingerprint } = require(path.join(out, "core/relayProto.js"));
const { b64url, hexToBytes, utf8Encode } = require(path.join(out, "core/bytes.js"));
const ed = require("@noble/ed25519");
const rv = JSON.parse(fs.readFileSync(path.join(root, "../protocol/vectors/relay_vectors.json"), "utf8"));

const UNPAIRED = { status: "unpaired", relay: null, host: null, supervisorId: null, pairId: null, mode: null, policyMode: null, lastError: null, lastReason: null, lastOkAt: null, signed: 0 };
const STATE_KEY = `wc.relay.state.v1.${rv.supervisor.id}`;

/** What controller.ts gives the session, with everything it was told kept for the assertions. */
function bind(relay, o = {}) {
  const app = { wardend: { ...UNPAIRED }, serverHw: undefined, cards: [], removed: 0, notes: [], logs: [], owner: [], seen: [], link: o.link ?? null, kv: o.kv ?? fakeKv() };
  ws.bindWardendSession({
    device: () => ({ deviceId: rv.device.id, publicKey: rv.device.key, sign: (s) => b64url.encode(ed.sign(utf8Encode(s), hexToBytes(rv.device.seed))) }),
    identityError: () => null,
    encPrivate: async () => hexToBytes(rv.device.encPrivate),
    requireOwner: async (prompt) => {
      app.owner.push(prompt);
      if (o.ownerRefuses) throw new Error("not confirmed");
    },
    socket: relay.factory,
    random: (n) => new Uint8Array(crypto.randomBytes(n)),
    version: "1.0.0",
    saveLink: async (rec) => void (app.link = rec),
    clearLink: async () => void (app.link = null),
    loadRelayState: (sid) => state.loadRelayState(app.kv, sid),
    relayStateWriter: (sid, initial, onError) => new state.RelayStateWriter(app.kv, sid, initial, onError),
    state: () => app.wardend,
    setState: (patch, serverHw) => {
      app.wardend = { ...app.wardend, ...patch };
      if (serverHw !== undefined) app.serverHw = serverHw;
      app.seen.push(`${app.wardend.status}:${app.wardend.lastReason ?? ""}`);
    },
    note: (kind, body, by) => app.notes.push({ kind, by, ...body }),
    log: (line) => app.logs.push(line),
    removeCards: () => {
      app.cards = [];
      app.removed++;
    },
    syncCards: (pending) => void (app.cards = pending.map((p) => p.id)),
    timing: { readyMs: 300, relay: { backoffMinMs: 1, backoffMaxMs: 4, replyMs: 300, retryMs: 1, rateEveryMs: 1, rateRetryMs: 1 } },
  });
  if (o.link) ws.adoptWardendLink(o.link);
  return app;
}

/** Nothing of a finished test keeps running. */
function unbind() {
  ws.setPushTokenSource(null);
  bind(new FakeRelay());
}

/** wardend's side of the channel: answers pairing, status requests (trusted devices only) and tickets while it is online. */
function supervisor(relay, o = {}) {
  const sup = { online: true, trusted: o.trusted ?? false, cards: [], next: 0, pairAnswer: { status: "pending" } };
  const timer = setInterval(() => {
    while (sup.online && sup.next < relay.got.length) {
      const e = relay.got[sup.next++];
      if (e.type === "pair") relay.push("pair.status", { re: (sup.re = e.id), id: "pr-1", fingerprint: rv.pair.fingerprint, supervisorId: rv.supervisor.id, host: "agent-host", expiresAt: Date.now() + 60_000, ...sup.pairAnswer });
      else if (e.kind === "status.req" && sup.trusted) relay.push("status", { ok: true, protocol: 1, supervisorId: rv.supervisor.id, host: "agent-host", mode: "ticket", policyMode: "root", pending: sup.cards });
      else if (e.kind === "ticket") {
        const tk = relay.open(e);
        sup.cards = sup.cards.filter((c) => c.id !== tk.payload.id);
        relay.push("ticket.result", { ok: true, id: tk.payload.id, decision: tk.payload.decision });
        relay.push("card.done", { id: tk.payload.id, outcome: tk.payload.decision === "allow" ? "approved" : "denied" });
      }
    }
  }, 2);
  sup.stop = () => clearInterval(timer);
  sup.card = (c) => {
    sup.cards.push(c);
    relay.push("card", c);
    return c;
  };
  sup.approve = () => {
    sup.trusted = true;
    relay.push("pair.status", { re: sup.re, id: "pr-1", status: "approved", fingerprint: rv.pair.fingerprint, supervisorId: rv.supervisor.id, host: "agent-host" });
  };
  return sup;
}

const PAIRED = { relay: rv.link.relay, key: rv.supervisor.key, enc: rv.supervisor.enc, supervisorId: rv.supervisor.id, host: "agent-host", pairId: null, pairFrame: null, paired: true, pairedAt: "2026-10-01T00:00:00.000Z" };

test("wardend link: pair from the QR, approval, card, allow, done; deny; push token; forget server", async () => {
  const relay = new FakeRelay();
  const app = bind(relay);
  const sup = supervisor(relay);
  try {
    await ws.pairWithWardend(rv.link.text, " Test phone ");
    assert.deepEqual(app.owner, ["owner.pair"]);
    assert.equal(relay.sockets[0].url, `${rv.link.relay}/${rv.supervisor.id}`);
    assert.equal(relay.open(relay.got[0]).payload.name, "Test phone");
    assert.equal(app.wardend.status, "awaiting-approval");
    assert.equal(app.wardend.pairId, "pr-1");
    assert.equal(app.wardend.relay, rv.link.relay);
    assert.deepEqual({ ...app.link, pairId: null }, { ...PAIRED, pairFrame: relay.got[0].id, paired: false, pairedAt: null });
    assert.equal(app.notes[0].kind, "pairing");
    assert.ok(app.notes[0].summary.includes(rv.pair.fingerprint), "the journal names the fingerprint to compare");
    assert.equal(fingerprint(rv.device.id), rv.pair.fingerprint);
    assert.deepEqual(ws.activeWardendLink(), app.link);

    sup.reFirst = sup.re;
    sup.approve();
    await until("connected", () => app.wardend.status === "connected");
    assert.equal(app.link.paired, true);
    assert.equal(app.link.pairFrame, null);
    assert.equal(app.wardend.pairId, null);
    assert.equal(app.wardend.mode, "ticket");
    assert.equal(app.wardend.policyMode, "root");
    assert.equal(app.wardend.host, "agent-host");
    assert.ok(app.serverHw, "the status feeds the hardware rules");
    assert.equal(app.notes[1].kind, "connect");

    const c1 = sup.card(card("wd-" + "1".repeat(32)));
    await until("card in the feed", () => app.cards.includes(c1.id));
    const r1 = await ws.sendWardendTicket(ticket(c1, "allow"));
    assert.deepEqual(r1, { ok: true, id: c1.id, decision: "allow" });
    await until("card.done closes it", () => app.cards.length === 0);

    const c2 = sup.card(card("wd-" + "2".repeat(32)));
    await until("second card", () => app.cards.includes(c2.id));
    assert.deepEqual(await ws.sendWardendTicket(ticket(c2, "deny")), { ok: true, id: c2.id, decision: "deny" });
    await until("denied card closed", () => app.cards.length === 0);
    assert.equal(relay.open(relay.got.filter((e) => e.kind === "ticket")[1]).payload.decision, "deny");

    // the push token goes to the relay, not to wardend
    assert.deepEqual(await ws.wardendPushRegister({ platform: "apns", token: "ab".repeat(32), environment: "production", topic: "com.wardenclaw.app" }), { supervisorId: rv.supervisor.id, configured: true });
    assert.deepEqual(relay.push_[0], { type: "push.register", platform: "apns", token: "ab".repeat(32), environment: "production", topic: "com.wardenclaw.app" });
    assert.deepEqual(await ws.wardendPushRegister({ platform: "fcm", token: "t", environment: "production", topic: "x" }), { supervisorId: rv.supervisor.id, configured: false }, "a relay without credentials says so");

    // seq and the handled ids are stored, and stay when the server is forgotten
    await until("state stored", () => app.kv.m.has(STATE_KEY));
    ws.setPushTokenSource(async () => ({ platform: "apns", token: "ab".repeat(32) }));
    sup.card(card("wd-" + "3".repeat(32)));
    await until("third card", () => app.cards.length === 1);
    await ws.forgetWardend();
    assert.deepEqual(app.owner, ["owner.pair", "owner.forget"]);
    assert.deepEqual(relay.push_.at(-1), { type: "push.unregister", platform: "apns", token: "ab".repeat(32) });
    assert.equal(app.link, null);
    assert.equal(ws.activeWardendLink(), null);
    const kept = JSON.parse(app.kv.m.get(STATE_KEY));
    assert.ok(kept.seq >= 1 && kept.seen.length >= 1, "the resume state of the forgotten server stays");
    assert.deepEqual(app.cards, []);
    assert.deepEqual({ ...app.wardend, signed: 0 }, UNPAIRED);
    assert.equal(app.serverHw, null);
    assert.equal(app.notes.at(-1).by, "me");
    await until("connection closed", () => !relay.live());
    await assert.rejects(ws.sendWardendTicket(ticket(c1, "allow")), new RegExp(i18n.t("err.noWardend")));

    // paired again with the same server: the session resumes where it stopped, the old frames do not come again
    const resumes = relay.resumes.length;
    await ws.pairWithWardend(rv.link.text, "Test phone");
    assert.equal(relay.resumes[resumes], kept.seq);
    assert.deepEqual(app.cards, [], "the card of the forgotten pairing is not shown again");
    assert.notEqual(app.link.pairFrame, sup.reFirst);
  } finally {
    sup.stop();
    unbind();
  }
});

test("wardend link: reconnect resyncs the cards from the status; a relay without wardend is not 'no network'; a revoked phone", async () => {
  const relay = new FakeRelay();
  relay.peerOnline = true;
  const app = bind(relay, { link: PAIRED });
  const sup = supervisor(relay, { trusted: true });
  try {
    assert.equal(ws.wardendStateFromLink(PAIRED).status, "connecting", "paired and not heard yet");
    const a = card("wd-" + "a".repeat(32));
    sup.cards.push(a);
    ws.startWardend();
    await until("connected", () => app.wardend.status === "connected");
    assert.deepEqual(app.cards, [a.id], "the status after the connect brings the pending cards");

    // the connection drops; meanwhile one card is decided elsewhere and another appears
    const b = card("wd-" + "b".repeat(32));
    sup.cards = [b];
    app.seen.length = 0;
    relay.cut();
    await until("unavailable", () => app.seen.includes("unavailable:relay_unreachable"));
    await until("resynced", () => app.wardend.status === "connected" && app.cards.length === 1 && app.cards[0] === b.id);
    assert.equal(app.wardend.lastError, null);
    assert.ok(relay.resumes.length >= 2, "the session resumed from its seq");

    // wardend goes away, the relay stays and says so
    sup.online = false;
    relay.setPeer(false);
    await until("server offline", () => app.wardend.lastReason === "supervisor_offline");
    assert.equal(app.wardend.status, "unavailable");
    assert.equal(app.wardend.lastError, i18n.t("err.supervisorOffline"));
    assert.ok(relay.live(), "the relay connection is alive");
    assert.deepEqual(app.cards, [b.id], "its cards stay in the feed");
    await assert.rejects(ws.sendWardendTicket(ticket(b, "allow")), new RegExp(i18n.t("err.supervisorOffline").slice(0, 20)), "a ticket nobody answers is not an applied decision");
    // a card that waited in the relay's queue does not say that wardend is back
    const late = card("wd-" + "c".repeat(32));
    relay.push("card", late);
    await until("queued card shown", () => app.cards.includes(late.id));
    assert.equal(app.wardend.lastReason, "supervisor_offline");
    sup.next = relay.got.length; // what was sent meanwhile expired with the wait
    sup.online = true;
    app.seen.length = 0;
    relay.setPeer(true);
    await until("back", () => app.wardend.status === "connected");
    assert.equal(app.seen[0], "connecting:", "back on the relay, not heard yet");
    assert.equal(app.wardend.lastReason, null);
    assert.deepEqual(app.cards, [b.id], "its status is the truth about the cards");

    // wardend pair revoke: the relay stops forwarding for this device
    relay.refuseNext = "not_trusted";
    relay.refuseTimes = 1000;
    await ws.refreshServerStatus();
    assert.equal(app.wardend.lastReason, "untrusted_device");
    assert.equal(app.wardend.status, "unavailable");
  } finally {
    sup.stop();
    unbind();
  }
});

test("wardend link: a relaunch while waiting for approval; rejected and refused requests; no owner, no connection", async () => {
  // approved while the app was closed and the pair.status is gone from the queue: the status of a trusted device says it
  let relay = new FakeRelay();
  let app = bind(relay, { link: { ...PAIRED, paired: false, pairedAt: null, pairId: "pr-1", pairFrame: "ab".repeat(16) } });
  let sup = supervisor(relay, { trusted: true });
  try {
    ws.startWardend();
    await until("paired after the relaunch", () => app.wardend.status === "connected");
    assert.equal(app.link.paired, true);
  } finally {
    sup.stop();
    unbind();
  }

  relay = new FakeRelay();
  app = bind(relay);
  sup = supervisor(relay);
  try {
    await ws.pairWithWardend(rv.link.text, "p");
    // the rejection of an earlier request changes nothing
    const old = relay.push("pair.status", { re: "0".repeat(32), id: "pr-0", status: "rejected", supervisorId: rv.supervisor.id });
    await until("old answer acked", () => relay.acks.includes(old.id));
    assert.equal(app.wardend.status, "awaiting-approval");
    relay.push("pair.status", { re: sup.re, id: "pr-1", status: "rejected", supervisorId: rv.supervisor.id });
    await until("rejected", () => app.wardend.status === "rejected");
    assert.equal(app.wardend.lastError, i18n.t("err.pairRejected"));
    assert.equal(app.link, null);
    await until("closed", () => !relay.live());

    sup.pairAnswer = { status: "refused", reason: "bad_code" };
    await assert.rejects(ws.pairWithWardend(rv.link.text, "p"), (e) => e.message === i18n.t("wdr.bad_code"));
    assert.equal(app.wardend.status, "unpaired");
    assert.equal(app.wardend.lastError, i18n.t("wdr.bad_code"));
    assert.equal(app.link, null);

    await assert.rejects(ws.pairWithWardend("wardenclaw://pair?v=1&url=https%3A%2F%2Fpi&key=x&code=K7Q4M2XD", "p"), (e) => e.message === i18n.t("link.noAddress"), "a link without a relay is not a pair link");
  } finally {
    sup.stop();
    unbind();
  }

  // a relay that never says whether wardend is connected, and a wardend that does not answer: "connecting", not a guess
  relay = new FakeRelay();
  app = bind(relay, { link: PAIRED });
  try {
    ws.startWardend();
    await until("status asked", () => relay.got.some((e) => e.kind === "status.req"));
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(app.wardend.status, "connecting");
    assert.equal(app.wardend.lastReason, null);
  } finally {
    unbind();
  }

  relay = new FakeRelay();
  app = bind(relay, { ownerRefuses: true });
  try {
    await assert.rejects(ws.pairWithWardend(rv.link.text, "p"), /not confirmed/);
    assert.equal(relay.sockets.length, 0, "nothing is sent before the owner confirms");
    assert.equal(app.wardend.status, "unpaired");
  } finally {
    unbind();
  }

  // no relay: pairing says so and leaves nothing behind
  const dead = { factory: () => ({ send() {}, close() {}, onopen: null, onmessage: null, onclose: null, onerror: null }) };
  app = bind(dead);
  try {
    await assert.rejects(ws.pairWithWardend(rv.link.text, "p"), (e) => e.message === i18n.t("err.relayUnreachable"));
    assert.equal(app.wardend.status, "unpaired");
    assert.equal(app.link, null);
  } finally {
    unbind();
  }
});
