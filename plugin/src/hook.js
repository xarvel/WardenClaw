// SPDX-License-Identifier: Apache-2.0
// before_tool_call handler. Extracted separately to allow testing without the gateway.
import { toolMatches } from "./config.js";

/**
 * @param {{ gate: import("./gate.js").Gate, config: import("./config.js").GateConfig, logger: { info(m: string): void, warn(m: string): void } }} deps
 */
export function createBeforeToolCallHandler({ gate, config, logger }) {
  /**
   * @param {{ toolName: string, params: Record<string, unknown>, toolKind?: string, toolInputKind?: string, runId?: string, toolCallId?: string }} event
   * @param {{ agentId?: string, sessionKey?: string, sessionId?: string, runId?: string, toolCallId?: string, toolKind?: string, toolInputKind?: string, abortSignal?: AbortSignal, requester?: Record<string, unknown> }} ctx
   * @returns {Promise<undefined | { block: true, blockReason: string } | {}>}
   */
  return async function beforeToolCall(event, ctx) {
    const toolName = event.toolName ?? ctx.toolName ?? "?";
    const toolKind = event.toolKind ?? ctx.toolKind;
    const toolInputKind = event.toolInputKind ?? ctx.toolInputKind;
    const agentId = ctx.agentId;
    const sessionKey = ctx.sessionKey;
    const runId = event.runId ?? ctx.runId;
    const toolCallId = event.toolCallId ?? ctx.toolCallId;
    gate.recordSeen(toolName, toolKind, { agentId });
    const matched = toolMatches({ toolName, toolKind }, config.tools);
    if (config.logAllTools || matched) {
      logger.info(`[wardenclaw-gate] saw tool=${toolName}${toolKind ? ` kind=${toolKind}` : ""}${toolInputKind ? ` input=${toolInputKind}` : ""} agent=${agentId ?? "?"} session=${sessionKey ?? "?"} run=${runId ?? "?"} call=${toolCallId ?? "?"} requester=${ctx.requester?.channel ?? "-"} gated=${matched}`);
    }
    if (!matched) return undefined;
    if (agentId && config.exemptAgents.includes(agentId)) {
      logger.info(`[wardenclaw-gate] agent ${agentId} is in exemptAgents: skipping ${toolName}`);
      return undefined;
    }
    let rec;
    try {
      rec = gate.createPending({ toolName, params: event.params ?? {}, toolKind, toolInputKind, agentId, sessionKey, runId, toolCallId, source: "before_tool_call" });
    } catch (e) {
      logger.warn(`[wardenclaw-gate] failed to create pending for ${toolName}: ${String(e?.message ?? e)}`);
      if (config.mode === "enforce") return { block: true, blockReason: "wardenclaw-gate: internal gate error (fail-closed)" };
      return undefined;
    }
    if (config.mode === "observe") {
      gate.counters.observed += 1;
      logger.info(`[wardenclaw-gate] observe: ${toolName} ${rec.id.slice(0, 8)} digest=${rec.digest.slice(0, 12)} -- not blocking`);
      return undefined;
    }
    logger.info(`[wardenclaw-gate] enforce: waiting for signature for ${toolName} ${rec.id.slice(0, 8)} (up to ${Math.round(config.ttlMs / 1000)} s)`);
    let result;
    try {
      result = await gate.waitDecision(rec.id, { signal: ctx.abortSignal });
    } catch (e) {
      logger.warn(`[wardenclaw-gate] error waiting for decision ${rec.id.slice(0, 8)}: ${String(e?.message ?? e)}`);
      return { block: true, blockReason: "wardenclaw-gate: error waiting for decision (fail-closed)" };
    }
    if (result.allow) {
      logger.info(`[wardenclaw-gate] ALLOW ${toolName} ${rec.id.slice(0, 8)} by device ${result.record?.deviceId?.slice(0, 12) ?? "?"}`);
      return {};
    }
    logger.warn(`[wardenclaw-gate] BLOCK ${toolName} ${rec.id.slice(0, 8)}: ${result.reason}`);
    return { block: true, blockReason: `wardenclaw-gate: ${result.reason}` };
  };
}
