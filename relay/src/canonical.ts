// SPDX-License-Identifier: AGPL-3.0-or-later
// Canonical JSON, byte-for-byte the plugin's canonical.js and the app's canonical.ts
// (protocol/README.md section 2): keys sorted as Array.prototype.sort (UTF-16 code units),
// undefined members dropped, JSON.stringify for scalars, no whitespace.

export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const obj = v as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}
