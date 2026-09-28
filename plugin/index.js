// SPDX-License-Identifier: Apache-2.0
// wardenclaw-gate: cryptographic execution gate for OpenClaw (stage A: observe).
// Plugin entry point. Everything that can be tested without the gateway lives in src/.
import path from "node:path";
import os from "node:os";
import { resolveConfig } from "./src/config.js";
import { Gate } from "./src/gate.js";
import { Journal } from "./src/journal.js";
import { CompositeDeviceDirectory, SqliteDeviceDirectory, StaticDeviceDirectory, gatewaySqlitePath } from "./src/devices.js";
import { createBeforeToolCallHandler } from "./src/hook.js";
import { LONG_POLL_MAX_MS, createHttpHandlers } from "./src/http.js";
import { WardendRelay } from "./src/relay.js";

// definePluginEntry from the SDK is a thin wrapper; if the openclaw/plugin-sdk alias is not
// available (local load via plugins.load.paths), we export an equivalent object directly.
let define = (entry) => entry;
try {
  const m = await import("openclaw/plugin-sdk/plugin-entry");
  if (typeof m?.definePluginEntry === "function") define = m.definePluginEntry;
} catch {
  // SDK alias unavailable -- proceed without it
}

export default define({
  id: "wardenclaw-gate",
  name: "WardenClaw Gate",
  description: "Cryptographic execution gate: every executing tool call requires a WardenClaw device signature",
  register(api) {
    const logger = api.logger ?? console;
    const gatewayStateDir = resolveGatewayStateDir(api);
    const config = resolveConfig(api.pluginConfig, { gatewayStateDir });
    const journal = new Journal(config.stateDir);
    const directory = new CompositeDeviceDirectory([new StaticDeviceDirectory(config.devices), new SqliteDeviceDirectory(gatewaySqlitePath(gatewayStateDir))]);
    // relay to wardend: store is created by Gate, so we wire onChange afterwards
    let gateRef = null;
    const relay = config.relay ? new WardendRelay({ socketPath: config.wardendSocket, logger, onChange: () => gateRef?.store.touch() }) : null;
    const gate = new Gate({ config, directory, journal, logger, relay });
    gateRef = gate;
    relay?.start();
    journal.append("start", { mode: config.mode, tools: config.tools, trustedDeviceIds: config.trustedDeviceIds, ttlMs: config.ttlMs, exemptAgents: config.exemptAgents, pid: process.pid });
    logger.info(`[wardenclaw-gate] start: mode=${config.mode} tools=[${config.tools.join(",")}]${config.toolsIsDefault ? " (default)" : ""} trusted=[${config.trustedDeviceIds.map((d) => d.slice(0, 12)).join(",")}] ttl=${config.ttlMs}ms state=${config.stateDir} journalKey=${journal.publicKey}`);
    if (config.mode === "enforce" && !config.trustedDeviceIds.length) logger.warn("[wardenclaw-gate] enforce with no trustedDeviceIds: ALL executing calls will be blocked on timeout");

    // Hook on all tools without a matcher: in observe mode we need to see which toolName/toolKind
    // actually arrive (main unknown: native Bash/Write/Edit from claude-cli). Filter by config.tools
    // is inside the handler. timeoutMs is required: runner default for before_tool_call is 15 s,
    // after which the host blocks the call.
    api.on("before_tool_call", createBeforeToolCallHandler({ gate, config, logger }), { priority: 100, timeoutMs: config.ttlMs + 5000 });

    const http = createHttpHandlers({ gate, config, logger });
    api.registerHttpRoute({ path: "/wardenclaw/pending", auth: "plugin", match: "exact", handler: http.pending });
    api.registerHttpRoute({ path: "/wardenclaw/status", auth: "plugin", match: "exact", handler: http.status });
    api.registerHttpRoute({ path: "/wardenclaw/decide", auth: "plugin", match: "exact", handler: http.decide });
    api.registerHttpRoute({ path: "/wardenclaw/request", auth: "plugin", match: "exact", handler: http.request });

    // Same operations via WebSocket gateway methods: socket is already authenticated with a device
    // token; deviceId is taken from the verified connect.device and matched against the signature.
    if (typeof api.registerGatewayMethod === "function") {
      const connDevice = (client) => {
        const id = client?.connect?.device?.id;
        return typeof id === "string" ? id.trim() : undefined;
      };
      const isTrusted = (deviceId) => Boolean(deviceId) && config.trustedDeviceIds.includes(deviceId);
      const forbidden = (respond, message) => respond(false, undefined, { code: "FORBIDDEN", message });
      api.registerGatewayMethod(
        "wardenclaw.pending",
        async ({ params, respond, client }) => {
          if (!isTrusted(connDevice(client))) return forbidden(respond, "untrusted device");
          const since = typeof params?.since === "number" ? params.since : 0;
          const wait = Math.min(LONG_POLL_MAX_MS, typeof params?.wait === "number" ? params.wait : 0);
          if (wait > 0) await gate.store.waitChange(since, wait);
          respond(true, { ...gate.pendingSnapshot(), now: gate.now() });
        },
        { scope: "operator.approvals" },
      );
      api.registerGatewayMethod(
        "wardenclaw.decide",
        async ({ params, respond, client }) => {
          const deviceId = connDevice(client);
          if (!deviceId) return forbidden(respond, "device identity required");
          const result = await gate.decide(params, { transport: "ws", authenticatedDeviceId: deviceId });
          // a refusal carries the full result (reason, stage) next to the error
          respond(result.ok, result, result.ok ? undefined : { code: "FORBIDDEN", message: result.reason });
        },
        { scope: "operator.approvals" },
      );
      api.registerGatewayMethod(
        "wardenclaw.status",
        async ({ respond, client }) => {
          if (!isTrusted(connDevice(client))) return forbidden(respond, "untrusted device");
          respond(true, { ...gate.status(), now: gate.now() });
        },
        { scope: "operator.read" },
      );
    }

    api.on?.("gateway_stop", () => {
      journal.append("stop", { counters: gate.counters });
      gate.close();
    });
  },
});

/** Gateway state directory from the runtime; older runtimes lack the resolver, so fall back to the env or the default. */
function resolveGatewayStateDir(api) {
  try {
    const dir = api?.runtime?.state?.resolveStateDir?.(process.env);
    if (typeof dir === "string" && dir) return dir;
  } catch {
    // resolver failed: same fallback as a runtime without it
  }
  return process.env.OPENCLAW_STATE_DIR || path.join(os.homedir(), ".openclaw");
}
