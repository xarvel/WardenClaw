// SPDX-License-Identifier: Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { JOURNAL_SIG_DOMAIN, Journal, verifyJournalFile } from "../src/journal.js";
import { signWithJwk, verifyEd25519 } from "../src/crypto.js";
import { tmpDir } from "./helpers.js";

test("journal: hash chain and signatures are verified; key survives restart", () => {
  const dir = tmpDir();
  const j = new Journal(dir);
  j.append("start", { mode: "observe" });
  j.append("pending", { id: "a", digest: "b" });
  const pub = j.publicKey;
  const j2 = new Journal(dir); // "restart": continues the chain with the same key
  assert.equal(j2.publicKey, pub);
  assert.equal(j2.seq, 2);
  j2.append("decision", { id: "a", decision: "allow" });
  const v = verifyJournalFile(j.file, pub);
  assert.deepEqual(v, { ok: true, entries: 3 });
  assert.equal(fs.statSync(j.keyFile).mode & 0o777, 0o600);
});

test("journal: entry tampering detected (hash), hash tampering detected (sig), deletion detected (prevHash)", () => {
  const dir = tmpDir();
  const j = new Journal(dir);
  j.append("a", { x: 1 });
  j.append("b", { x: 2 });
  j.append("c", { x: 3 });
  const lines = fs.readFileSync(j.file, "utf8").split("\n").filter(Boolean);
  const write = (arr) => fs.writeFileSync(j.file, arr.join("\n") + "\n");

  const tampered = JSON.parse(lines[1]);
  tampered.data.x = 99;
  write([lines[0], JSON.stringify(tampered), lines[2]]);
  assert.equal(verifyJournalFile(j.file, j.publicKey).error, "hash_mismatch");

  const rehashed = JSON.parse(lines[1]);
  rehashed.hash = "f".repeat(64);
  write([lines[0], JSON.stringify(rehashed), lines[2]]);
  assert.equal(verifyJournalFile(j.file, j.publicKey).error, "hash_mismatch");

  write([lines[0], lines[2]]);
  const v = verifyJournalFile(j.file, j.publicKey);
  assert.equal(v.ok, false);
  assert.ok(["seq_gap", "prev_hash_mismatch"].includes(v.error));

  // Wrong public key -> bad_signature on the first entry
  write(lines);
  const other = new Journal(tmpDir());
  assert.equal(verifyJournalFile(j.file, other.publicKey).error, "bad_signature");
  assert.equal(verifyJournalFile(path.join(dir, "missing.jsonl"), j.publicKey).ok, true);
});

test("journal: entry signature covers domain wardenclaw.journal.v1 + hash; bare hash signature is rejected (crypto review, finding 8)", () => {
  const dir = tmpDir();
  const j = new Journal(dir);
  const e = j.append("start", { mode: "observe" });
  assert.equal(JOURNAL_SIG_DOMAIN, "wardenclaw.journal.v1\n");
  assert.equal(verifyEd25519(JOURNAL_SIG_DOMAIN + e.hash, e.sig, j.publicKey), true);
  assert.equal(verifyEd25519(e.hash, e.sig, j.publicKey), false);
  // an entry signed with the same key in the old format (without domain) is rejected
  const raw = fs.readFileSync(j.file, "utf8").replace(e.sig, signWithJwk(j.key.privateJwk, e.hash));
  fs.writeFileSync(j.file, raw);
  assert.equal(verifyJournalFile(j.file, j.publicKey).error, "bad_signature");
});
