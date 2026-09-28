// SPDX-License-Identifier: Apache-2.0
// Cross-implementation canonical JSON fixtures: single source of truth in protocol/vectors/ at repo root.
// The same vectors are checked by the wardend Go encoder and the app canonical.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { canonicalJson, decisionSigningString, sha256Hex } from "../src/canonical.js";

const vf = JSON.parse(fs.readFileSync(new URL("../../protocol/vectors/canonical_vectors.json", import.meta.url), "utf8"));

test("canonical_vectors: byte-for-byte match with wardend (Go) and the app (TS)", () => {
  assert.ok(vf.cases.length > 0);
  for (const c of vf.cases) {
    const s = canonicalJson(c.value);
    assert.equal(s, c.canonical, c.name);
    assert.equal(sha256Hex(s), c.sha256, c.name);
  }
});

test("canonical_vectors: ticket signing string (exec and tool) matches the fixture", () => {
  const cs = vf.cases.filter((c) => c.name.startsWith("decision-signing-string"));
  assert.equal(cs.length, 2);
  for (const c of cs) assert.equal(decisionSigningString(c.value), c.canonical, c.name);
});
