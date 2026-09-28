// SPDX-License-Identifier: Apache-2.0
// Append-only plugin journal: JSONL, hash chain, each entry signed with the plugin key.
// hash = sha256(prevHash + canonicalJson({seq, ts, kind, data, prevHash}))
// sig  = Ed25519(journalKey, "wardenclaw.journal.v1\n" + hash) base64url -- same format as the
// wardend journal (signature domain, crypto review, finding 8)
import fs from "node:fs";
import path from "node:path";
import { canonicalJson, sha256Hex } from "./canonical.js";
import { generateJournalKey, signWithJwk, verifyEd25519 } from "./crypto.js";

/** Prefix of the entry signing string: signs JOURNAL_SIG_DOMAIN + hash, not the bare hash. */
export const JOURNAL_SIG_DOMAIN = "wardenclaw.journal.v1\n";

export const GENESIS = "0".repeat(64);

export class Journal {
  /**
   * @param {string} dir plugin state directory
   */
  constructor(dir) {
    this.dir = dir;
    this.file = path.join(dir, "journal.jsonl");
    this.keyFile = path.join(dir, "journal-key.json");
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.key = this.#loadOrCreateKey();
    const tail = readTail(this.file);
    this.lastHash = tail?.hash ?? GENESIS;
    this.seq = tail?.seq ?? 0;
  }

  get publicKey() {
    return this.key.publicKey;
  }

  #loadOrCreateKey() {
    try {
      const parsed = JSON.parse(fs.readFileSync(this.keyFile, "utf8"));
      if (parsed?.publicKey && parsed?.privateJwk) return parsed;
    } catch {}
    const key = generateJournalKey();
    fs.writeFileSync(this.keyFile, JSON.stringify(key), { mode: 0o600 });
    return key;
  }

  /**
   * @param {string} kind
   * @param {unknown} data
   */
  append(kind, data) {
    const seq = this.seq + 1;
    const prevHash = this.lastHash;
    const body = { seq, ts: Date.now(), kind, data, prevHash };
    const hash = sha256Hex(prevHash + canonicalJson(body));
    const sig = signWithJwk(this.key.privateJwk, JOURNAL_SIG_DOMAIN + hash);
    const entry = { ...body, hash, sig };
    fs.appendFileSync(this.file, JSON.stringify(entry) + "\n", { mode: 0o600 });
    this.lastHash = hash;
    this.seq = seq;
    return entry;
  }
}

/** @param {string} file */
function readTail(file) {
  let raw;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch {
    return null;
  }
  const lines = raw.split("\n").filter(Boolean);
  if (!lines.length) return null;
  try {
    return JSON.parse(lines[lines.length - 1]);
  } catch {
    return null;
  }
}

/**
 * Verify the journal: hash chain and signatures. Returns {ok, entries, error?, badSeq?}.
 * @param {string} file
 * @param {string} [publicKey] base64url; if not provided, signatures are not checked
 */
export function verifyJournalFile(file, publicKey) {
  const raw = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
  const lines = raw.split("\n").filter(Boolean);
  let prev = GENESIS;
  let expectedSeq = 1;
  // entries counts the verified prefix: everything before the bad entry
  const fail = (error, badSeq) => ({ ok: false, entries: expectedSeq - 1, error, badSeq });
  for (const line of lines) {
    let e;
    try {
      e = JSON.parse(line);
    } catch {
      return fail("invalid_json", expectedSeq);
    }
    const { hash, sig, ...body } = e;
    if (body.seq !== expectedSeq) return fail("seq_gap", body.seq);
    if (body.prevHash !== prev) return fail("prev_hash_mismatch", body.seq);
    if (sha256Hex(prev + canonicalJson(body)) !== hash) return fail("hash_mismatch", body.seq);
    if (publicKey && !verifyEd25519(JOURNAL_SIG_DOMAIN + hash, sig, publicKey)) return fail("bad_signature", body.seq);
    prev = hash;
    expectedSeq += 1;
  }
  return { ok: true, entries: expectedSeq - 1 };
}
