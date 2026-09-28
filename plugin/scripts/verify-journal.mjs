#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Verify the plugin journal as a third party: node scripts/verify-journal.mjs [state-dir]
// Default: ~/.openclaw/wardenclaw-gate. The public key is read from journal-key.json
// (or pass --pubkey <base64url> to verify a journal copy without the key file).
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { verifyJournalFile } from "../src/journal.js";

const args = process.argv.slice(2);
const pubIdx = args.indexOf("--pubkey");
const pubkeyArg = pubIdx >= 0 ? args[pubIdx + 1] : null;
const dir = args.find((a, i) => !a.startsWith("--") && (pubIdx < 0 || i !== pubIdx + 1)) ?? path.join(os.homedir(), ".openclaw", "wardenclaw-gate");
const file = dir.endsWith(".jsonl") ? dir : path.join(dir, "journal.jsonl");
let pubkey = pubkeyArg;
if (!pubkey) {
  try {
    pubkey = JSON.parse(fs.readFileSync(path.join(path.dirname(file), "journal-key.json"), "utf8")).publicKey;
  } catch {}
}
const r = verifyJournalFile(file, pubkey ?? undefined);
console.log(JSON.stringify({ file, signaturesChecked: !!pubkey, ...r }, null, 2));
process.exit(r.ok ? 0 : 1);
