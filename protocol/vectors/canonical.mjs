// SPDX-License-Identifier: Apache-2.0
// Reference implementation of canonical JSON and the digest (protocol/README.md, section 2).
// The format is FIXED and matches app/src/core/canonical.ts and daemon/envelope/canonical.go:
// object keys are sorted, undefined is dropped, arrays preserve order, numbers and strings as
// JSON.stringify. gen_vectors.mjs builds canonical_vectors.json from it.
import { createHash } from "node:crypto";

/**
 * @param {unknown} v
 * @returns {string}
 */
export function canonicalJson(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const obj = /** @type {Record<string, unknown>} */ (v);
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

/** @param {string} s */
export function sha256Hex(s) {
  return createHash("sha256").update(s, "utf8").digest("hex");
}
