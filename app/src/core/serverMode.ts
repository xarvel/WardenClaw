// SPDX-License-Identifier: GPL-3.0-or-later
// What a paired wardend is doing, from its status. wardend has no modes of its own: every launch
// outside an approved tree waits for a signed ticket from the phone (the modes are the app's,
// autosign.ts). The status may still name the rule set, policyMode (tripwire or root), which the
// Connect tab shows next to the status.

const POLICIES = ["tripwire", "root"] as const;

function oneOf<T extends string>(v: unknown, allowed: readonly T[]): T | null {
  return typeof v === "string" && (allowed as readonly string[]).includes(v) ? (v as T) : null;
}

/** Fields present on a status body. A missing field is omitted so a caller can keep the last value. */
export function applyServerRun(status: unknown): { policyMode?: string | null } {
  if (!status || typeof status !== "object") return {};
  const s = status as Record<string, unknown>;
  const out: { policyMode?: string | null } = {};
  if ("policyMode" in s) out.policyMode = oneOf(s.policyMode, POLICIES);
  return out;
}

/** Why a paired wardend is not taking decisions. "offline": the relay answers and wardend is not connected to it; "down" is the only one that is "no network". */
export type LinkFault = "revoked" | "protocol" | "offline" | "down";

export function linkFault(status: string, reason: string | null | undefined): LinkFault | null {
  if (status !== "unavailable") return null;
  switch (reason) {
    case "untrusted_device":
      return "revoked";
    case "supervisor_offline":
      return "offline";
    case "protocol_mismatch":
      return "protocol";
    default:
      return "down";
  }
}

/**
 * Whether Allow and Deny can reach the place that will apply them.
 * A mock card never leaves the phone. Any other card needs wardend.
 */
export function decisionPathOpen(mock: boolean, wardendUp: boolean): boolean {
  return mock || wardendUp;
}
