// SPDX-License-Identifier: GPL-3.0-or-later
// What wardend is actually doing, from its status (mode + policyMode).
// The feed and the persistent notification use this so "connected" is not read as "protected".

export type RunCopy = "observe" | "denylist" | "tripwire" | "root" | "ticket";

const MODES = ["observe", "deny-list", "ticket"] as const;
const POLICIES = ["tripwire", "root"] as const;

function oneOf<T extends string>(v: unknown, allowed: readonly T[]): T | null {
  return typeof v === "string" && (allowed as readonly string[]).includes(v) ? (v as T) : null;
}

/** Fields present on a status body. A missing field is omitted so a caller can keep the last value. */
export function applyServerRun(status: unknown): { mode?: string | null; policyMode?: string | null } {
  if (!status || typeof status !== "object") return {};
  const s = status as Record<string, unknown>;
  const out: { mode?: string | null; policyMode?: string | null } = {};
  if ("mode" in s) out.mode = oneOf(s.mode, MODES);
  if ("policyMode" in s) out.policyMode = oneOf(s.policyMode, POLICIES);
  return out;
}

/**
 * Which sentence to show once the phone is connected.
 * observe and deny-list do not ask; ticket asks, and tripwire only about risky commands.
 * null: the server has not named a mode yet, so the UI must not claim that cards will appear.
 */
export function runCopy(mode: string | null | undefined, policy: string | null | undefined): RunCopy | null {
  if (mode === "observe") return "observe";
  if (mode === "deny-list") return "denylist";
  if (mode !== "ticket") return null;
  if (policy === "tripwire") return "tripwire";
  if (policy === "root") return "root";
  return "ticket";
}

/** observe and deny-list are not a gate that asks. Ticket modes are. */
export function runAsks(copy: RunCopy | null): boolean {
  return copy === "tripwire" || copy === "root" || copy === "ticket";
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
 * A mock card never leaves the phone. A wardend card needs wardend; anything else needs the gateway.
 */
export function decisionPathOpen(via: "wardend" | "openclaw" | undefined, mock: boolean, wardendUp: boolean, gatewayUp: boolean): boolean {
  if (mock) return true;
  if (via === "wardend") return wardendUp;
  return gatewayUp;
}
