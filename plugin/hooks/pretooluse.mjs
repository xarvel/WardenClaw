#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Claude Code PreToolUse hook: fallback path if the gateway before_tool_call hook does NOT see
// native Bash/Write/Edit from claude-cli. Works independently of OpenClaw: reads the call JSON
// from stdin, POSTs to /wardenclaw/request, and in gate enforce mode blocks the call without a
// signed allow.
//
// NOT added to ~/.claude/settings.json by default (the user enables it manually). Setup example
// in README.
//
// Environment variables:
//   WARDENCLAW_GATE_URL    gateway base URL, default http://127.0.0.1:18789
//   WARDENCLAW_GATE_TOKEN  requestToken from plugin config (or file in WARDENCLAW_GATE_TOKEN_FILE)
//   WARDENCLAW_GATE_TOOLS  comma-separated, default Bash,Write,Edit,MultiEdit,NotebookEdit
//   WARDENCLAW_GATE_FAIL   "open" | "closed" (default closed: gate unavailable = deny)
//   WARDENCLAW_GATE_TIMEOUT_MS  how long to wait for a response (default 130000 = TTL 120 s + buffer)
//
// Claude Code contract: stdin {session_id, cwd, hook_event_name:"PreToolUse", tool_name, tool_input, tool_use_id};
// stdout JSON {hookSpecificOutput:{hookEventName:"PreToolUse", permissionDecision:"allow"|"deny", permissionDecisionReason}};
// exit 2 + stderr also blocks the call.
import fs from "node:fs";

const base = (process.env.WARDENCLAW_GATE_URL || "http://127.0.0.1:18789").replace(/\/+$/, "");
const tools = (process.env.WARDENCLAW_GATE_TOOLS || "Bash,Write,Edit,MultiEdit,NotebookEdit").split(",").map((s) => s.trim()).filter(Boolean);
const failOpen = process.env.WARDENCLAW_GATE_FAIL === "open";
const timeoutMs = Number(process.env.WARDENCLAW_GATE_TIMEOUT_MS) || 130_000;

function readToken() {
  if (process.env.WARDENCLAW_GATE_TOKEN) return process.env.WARDENCLAW_GATE_TOKEN.trim();
  if (process.env.WARDENCLAW_GATE_TOKEN_FILE) return fs.readFileSync(process.env.WARDENCLAW_GATE_TOKEN_FILE, "utf8").trim();
  return "";
}

/** Prints the decision for Claude Code and exits. */
function emitDecision(decision, reason) {
  process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: decision, permissionDecisionReason: reason } }) + "\n");
  process.exit(0);
}

/** The gate cannot answer: deny, or step aside when WARDENCLAW_GATE_FAIL=open. */
function fail(reason) {
  if (failOpen) {
    process.stderr.write(`wardenclaw-gate: ${reason} (fail-open)\n`);
    process.exit(0);
  }
  emitDecision("deny", `wardenclaw-gate: ${reason} (fail-closed)`);
}

const raw = fs.readFileSync(0, "utf8");
let input;
try {
  input = JSON.parse(raw || "{}");
} catch {
  fail("invalid JSON on stdin");
}
const toolName = String(input.tool_name ?? "");
if (!tools.includes(toolName)) process.exit(0); // not our tool: Claude Code continues normally

const body = {
  toolName,
  params: input.tool_input ?? {},
  agentId: process.env.OPENCLAW_AGENT_ID || undefined,
  sessionKey: input.session_id ? `claude-code:${input.session_id}` : undefined,
  toolCallId: input.tool_use_id || undefined,
  source: "claude-code-pretooluse",
};

const ac = new AbortController();
const timer = setTimeout(() => ac.abort(), timeoutMs);
try {
  const res = await fetch(`${base}/wardenclaw/request`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${readToken()}` },
    body: JSON.stringify(body),
    signal: ac.signal,
  });
  clearTimeout(timer);
  const reply = await res.json().catch(() => ({}));
  if (!res.ok || !reply.ok) fail(`gate responded ${res.status} ${reply.reason ?? ""}`.trim());
  if (reply.decision === "allow") emitDecision("allow", `wardenclaw-gate: signed (${reply.id?.slice(0, 8)})`);
  if (reply.decision === "observe" || reply.decision === "exempt") process.exit(0); // observe: do not interfere, Claude Code decides
  emitDecision("deny", `wardenclaw-gate: ${reply.reason ?? reply.outcome ?? "no signature"}`);
} catch (e) {
  clearTimeout(timer);
  fail(`gate unavailable: ${String(e?.message ?? e)}`);
}
