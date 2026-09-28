// SPDX-License-Identifier: Apache-2.0
// Plugin config normalisation (api.pluginConfig).
import path from "node:path";
import os from "node:os";

export const DEFAULT_TOOLS = [
  // OpenClaw-owned
  "exec",
  "process",
  "write",
  "edit",
  "apply_patch",
  "code_mode_exec",
  // Native claude-cli / Claude Code names (in case the host does not map them to OpenClaw equivalents)
  "Bash",
  "Write",
  "Edit",
  "MultiEdit",
  "NotebookEdit",
];

/** Defaults of the time settings; the boolean settings default to true unless set to false. */
export const DEFAULTS = {
  ttlMs: 120_000,
  tsWindowMs: 60_000,
};

/** @typedef {ReturnType<typeof resolveConfig>} GateConfig */

/**
 * @param {Record<string, unknown> | undefined} raw
 * @param {{ gatewayStateDir?: string }} [env]
 */
export function resolveConfig(raw, env = {}) {
  const r = raw && typeof raw === "object" ? raw : {};
  const mode = r.mode === "enforce" ? "enforce" : "observe";
  const tools = stringList(r.tools);
  const devices = Array.isArray(r.devices)
    ? r.devices
        .filter((d) => d && typeof d === "object" && typeof d.deviceId === "string" && typeof d.publicKey === "string")
        .map((d) => ({ deviceId: d.deviceId.trim(), publicKey: d.publicKey.trim() }))
    : [];
  const baseState = env.gatewayStateDir ?? path.join(os.homedir(), ".openclaw");
  const stateDir = trimmedString(r.stateDir);
  const wardendSocket = trimmedString(r.wardendSocket);
  return {
    mode,
    trustedDeviceIds: stringList(r.trustedDeviceIds),
    tools: tools.length ? tools : DEFAULT_TOOLS,
    toolsIsDefault: tools.length === 0,
    // bounds are the same as in the openclaw.plugin.json schema
    ttlMs: clampInt(r.ttlMs, DEFAULTS.ttlMs, 1000, 3_600_000),
    tsWindowMs: clampInt(r.tsWindowMs, DEFAULTS.tsWindowMs, 1000, 600_000),
    exemptAgents: stringList(r.exemptAgents),
    requireDeviceToken: r.requireDeviceToken !== false,
    requestToken: trimmedString(r.requestToken),
    devices,
    stateDir: stateDir ? expandHome(stateDir) : path.join(baseState, "wardenclaw-gate"),
    logAllTools: r.logAllTools !== false,
    // relay to wardend (seccomp execve gate): if the socket exists, wardend exec entries go
    // through the plugin routes; signature is verified by wardend, optionally also by the plugin.
    relay: r.relay !== false,
    wardendSocket: wardendSocket ? expandHome(wardendSocket) : path.join(os.homedir(), ".wardend", "wardend.sock"),
    relayPreverify: r.relayPreverify !== false,
  };
}

/** Non-empty trimmed strings of an array; anything else yields an empty list. */
function stringList(v) {
  return Array.isArray(v) ? v.filter((x) => typeof x === "string" && x.trim()).map((x) => x.trim()) : [];
}

/** Trimmed string, or null for an empty or non-string value. */
function trimmedString(v) {
  return typeof v === "string" && v.trim() ? v.trim() : null;
}

/** Finite number rounded and clamped to [min, max]; anything else yields the fallback. */
function clampInt(v, fallback, min, max) {
  return typeof v === "number" && Number.isFinite(v) ? Math.min(max, Math.max(min, Math.round(v))) : fallback;
}

/** @param {string} p */
function expandHome(p) {
  return p.replace(/^~(?=$|\/)/, os.homedir());
}

/**
 * Whether the call should pass through the gate: by toolName (exact or case-insensitive) or by toolKind.
 * @param {{toolName: string, toolKind?: string}} ev
 * @param {string[]} tools
 */
export function toolMatches(ev, tools) {
  const name = ev.toolName ?? "";
  const lower = name.toLowerCase();
  for (const t of tools) {
    if (t === name || t.toLowerCase() === lower) return true;
    if (ev.toolKind && t === ev.toolKind) return true;
  }
  return false;
}
