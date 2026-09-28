// SPDX-License-Identifier: GPL-3.0-or-later
// Normalizes cards into the app model: wardend exec records (gate, the main path) and, in the
// OpenClaw adapter, gateway approval cards (exec / plugin) and wardenclaw-gate plugin records (gate).
import type { GatePending, ToolCall } from "./gate";
import { utf8Encode } from "./bytes";
import { canonicalJson, TICKET_EXEC, TICKET_TOOL, toolCallDigest, type TicketScope } from "./canonical";
import { checkExecPending, ENV_VALUE_MAX, ENV_NAME_MAX, unknownEnvelopeVersion, type ExecEnvVar, type ExecLink } from "./execEnvelope";
import { commandView, envView, headlineText, sanitizeText, textView, type CommandView, type EnvView } from "./display";
import { parseHardwareMeta, type HardwareMeta } from "./hardware";
import { t, type MsgKey } from "./i18n";

export type ApprovalKind = "exec" | "plugin" | "gate";

/** Where the record being signed came from: directly from wardend or via the OpenClaw adapter (gateway plugin). */
export type GateVia = "wardend" | "openclaw";

export type Card = {
  id: string;
  kind: ApprovalKind;
  /** Only for kind === "gate": the frozen call digest and the plugin mode. */
  gate?: { digest: string; mode: "observe" | "enforce"; source: string; toolKind: string | null; exec?: ExecCardInfo; tool?: ToolCardInfo; via: GateVia };
  summary: string; // one line in plain language
  command?: string;
  cwd?: string | null;
  host?: string | null;
  toolName?: string | null;
  pluginId?: string | null;
  title?: string | null;
  description?: string | null;
  args?: string | null;
  agentId: string | null;
  sessionKey: string | null;
  createdAtMs: number;
  expiresAtMs: number | null;
  raw: unknown;
  /** Command display (protocol/DISPLAY.md): parts, rules, flags. Absent for tool calls without a command. */
  view?: CommandView | null;
  /** Test card of the bench build (wardenclaw://bench?mockcard|mockui): "Test" badge, the decision
   *  goes nowhere, the text is not sent to the remote judge. Cards from the server never have it. */
  mock?: true;
};

/** Tool call (gateway plugin): whether the phone recomputed the digest itself. digestOk=false: deny only. */
export type ToolCardInfo = { digestOk: boolean; problem: string | null };

/** wardend exec record (execve at the OS level): what we show and whether it can be signed. */
export type ExecCardInfo = {
  digestOk: boolean;
  problem: string | null;
  argv: string[];
  cwd: string;
  exe: string;
  uid: number;
  gid: number;
  chain: ExecLink[];
  host: string;
  supervisorId: string;
  /** Envelope env (signed) and its display (DISPLAY.md, section 7a): variables that change program behavior.
   *  Always present on wardend records (normalizeExecPending); absent only on bench mock cards. */
  env?: ExecEnvVar[];
  envView?: EnvView;
  // The rest is meta: not in the digest (on the adapter path the gateway sets it). Display only, and
  // only toward caution: meta cannot lower the requirements, wardend checks the YubiKey itself.
  cls: string | null; // root | delegating
  /** wardend meta.hardware: whether a YubiKey is needed (required / risk threshold) and which key. */
  hardware: HardwareMeta | null;
  rule: string | null;
  delegating: string | null; // explanation if the exec moves execution out of supervision
  insideRoot: number | null; // pid of the approved root (escalation inside the tree)
  judgeMeta: string | null; // meta.judge / meta.opinion: a third-party opinion from the transport, not the owner's assessment
  /** meta.category and meta.detail: why the server asks (tripwire rule category). The server's assessment, not signed. */
  category: string | null;
  detail: string | null;
  /** meta.provenance (self-built category): origin of the program file, as reported by the server. */
  provenance: Provenance | null;
};

/**
 * Origin of the program file (wardend `provenance.go`). The server computes it only for files the
 * agent owns or can modify, that is, not from system packages. interp, head and libs are taken from
 * the file itself: the agent wrote them, they are data, not explanations.
 */
export type Provenance = {
  kind: "elf-dynamic" | "elf-static" | "script" | "other";
  sha256: string | null;
  interp: string | null; // interpreter from the shebang (kind=script)
  head: string | null; // beginning of the script text, up to 512 bytes
  libs: string[]; // ELF: NEEDED libraries
  net: boolean; // ELF: the imports include network functions
};

const PROV_KINDS: readonly Provenance["kind"][] = ["elf-dynamic", "elf-static", "script", "other"];

/** meta.provenance → Provenance; not an object → null, anything extra or invalid is dropped. */
export function parseProvenance(v: unknown): Provenance | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const r = v as Rec;
  const sha = asStr(r.sha256)?.toLowerCase() ?? null;
  const text = (x: unknown, n: number) => {
    const s = asStr(x);
    return s ? s.slice(0, n) : null;
  };
  return {
    kind: PROV_KINDS.includes(r.kind as Provenance["kind"]) ? (r.kind as Provenance["kind"]) : "other",
    sha256: sha && /^[0-9a-f]{64}$/.test(sha) ? sha : null,
    interp: text(r.interp, 200),
    head: text(r.head, 2048),
    libs: Array.isArray(r.libs) ? r.libs.filter((x): x is string => typeof x === "string" && x.length > 0).slice(0, 32).map((x) => x.slice(0, 120)) : [],
    net: r.net === true,
  };
}

/** Tripwire category codes (wardend `policy/tripwire.go`, `supervisor.go`) → human-readable name (ux-ia-flows 4.3). */
const CATEGORY_KEYS: Record<string, MsgKey> = {
  delegate: "cat.delegate",
  container: "cat.container",
  remote: "cat.remote",
  privilege: "cat.privilege",
  "net-write": "cat.netWrite",
  "pkg-run": "cat.pkgRun",
  publish: "cat.publish",
  destructive: "cat.destructive",
  "protected-write": "cat.protectedWrite",
  "outside-work": "cat.outsideWork",
  "secret-read": "cat.secretRead",
  "agent-config": "cat.agentConfig",
  guard: "cat.guard",
  device: "cat.device",
  cloud: "cat.cloud",
  "self-built": "cat.selfBuilt",
  "mount-ns": "cat.mountNs",
  "loader-env": "cat.loaderEnv",
};

/** One-phrase category explanation, where the name alone does not explain why it is dangerous. */
const CATEGORY_HINTS: Record<string, MsgKey> = {
  "self-built": "cat.selfBuilt.hint",
  "mount-ns": "cat.mountNs.hint",
  "loader-env": "cat.loaderEnv.hint",
};

export function categoryLabel(code: string): string {
  const k = CATEGORY_KEYS[code];
  return k ? t(k) : t("cat.other", { code });
}

export function categoryHint(code: string | null): string | null {
  const k = code ? CATEGORY_HINTS[code] : undefined;
  return k ? t(k) : null;
}

/** "Why it asks": the category in words and the server detail ("Deletes or rewrites · git reset"). */
export function whyAsks(exec: ExecCardInfo | null | undefined): string | null {
  if (!exec?.category) return null;
  const label = categoryLabel(exec.category);
  return exec.detail ? `${label} · ${exec.detail}` : label;
}

/** Provenance facts as lines for the card: file type, libraries, network, hash prefix. The script beginning is shown separately. */
export function provenanceFacts(p: Provenance | null | undefined): string[] {
  if (!p) return [];
  const out: string[] = [];
  if (p.kind === "elf-dynamic") {
    const libs = p.libs.map((l) => sanitizeText(l));
    const shown = libs.slice(0, 4).join(", ") + (libs.length > 4 ? ` +${libs.length - 4}` : "");
    out.push(libs.length ? t("prov.elfDynamic", { libs: shown }) : t("prov.elfDynamicNoLibs"));
    if (p.net) out.push(t("prov.net"));
  } else if (p.kind === "elf-static") out.push(t("prov.elfStatic"));
  else if (p.kind === "script") out.push(p.interp ? t("prov.script", { interp: sanitizeText(p.interp) }) : t("prov.scriptNoInterp"));
  else out.push(t("prov.other"));
  if (p.sha256) out.push(`sha256 ${p.sha256.slice(0, 16)}…`);
  return out;
}

const AGENT_NAMES = new Set(["claude", "codex", "gemini", "opencode", "openclaw", "aider", "goose", "cursor-agent"]);

/** Which agent is asking: the gateway agentId, the claude-cli wrapper or a known name in the process chain. */
export function agentOf(card: Card): string | null {
  if (card.agentId) return sanitizeText(card.agentId);
  if (card.view?.form === "wrapper") return "claude";
  for (const l of card.gate?.exec?.chain ?? []) {
    const base = l.exe.split("/").pop() ?? "";
    if (AGENT_NAMES.has(base)) return base;
  }
  return null;
}

type Rec = Record<string, unknown>;
const asRec = (v: unknown): Rec => (v && typeof v === "object" ? (v as Rec) : {});
const asStr = (v: unknown): string | null => (typeof v === "string" ? v : null);
const asNum = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

export function clip(s: unknown, n: number): string {
  const t = typeof s === "string" ? s : JSON.stringify(s) ?? "";
  return t.length > n ? `${t.slice(0, n)}…(+${t.length - n})` : t;
}

export function normalizeApproval(item: unknown, kindHint?: ApprovalKind): Card | null {
  const it = asRec(item);
  const id = asStr(it.id);
  if (!id) return null;
  const req = asRec(it.request);
  const pres = asRec(it.presentation);
  const kind: ApprovalKind =
    (asStr(it.approvalKind) as ApprovalKind | null) ??
    (asStr(it.kind) as ApprovalKind | null) ??
    kindHint ??
    (req.command || req.commandArgv || req.systemRunPlan ? "exec" : "plugin");
  const plan = asRec(req.systemRunPlan);
  const createdAtMs = asNum(it.createdAtMs) ?? asNum(it.createdAt) ?? Date.now();
  const expiresAtMs = asNum(it.expiresAtMs) ?? asNum(it.expiresAt) ?? (asNum(req.timeoutMs) ? createdAtMs + (asNum(req.timeoutMs) as number) : null);

  if (kind === "exec") {
    const argv = Array.isArray(req.commandArgv) ? (req.commandArgv as unknown[]).join(" ") : "";
    const command = asStr(plan.commandText) ?? asStr(req.command) ?? argv ?? asStr(pres.commandText) ?? "";
    const cwd = asStr(plan.cwd) ?? asStr(req.cwd) ?? null;
    const host = asStr(req.host) ?? asStr(pres.host) ?? null;
    const view = textView(command);
    return {
      id,
      kind,
      summary: `${clip(headlineText(view), 300)}${cwd ? `  ·  ${t("feed.inCwd", { cwd: sanitizeText(cwd) })}` : ""}`,
      view,
      command,
      cwd,
      host,
      agentId: asStr(plan.agentId) ?? asStr(req.agentId) ?? asStr(pres.agentId) ?? null,
      sessionKey: asStr(plan.sessionKey) ?? asStr(req.sessionKey) ?? asStr(it.sessionKey) ?? null,
      createdAtMs,
      expiresAtMs,
      raw: item,
    };
  }
  const toolName = asStr(req.toolName) ?? asStr(pres.toolName) ?? null;
  const pluginId = asStr(req.pluginId) ?? asStr(pres.pluginId) ?? null;
  const title = asStr(req.title) ?? asStr(pres.title) ?? null;
  const description = asStr(req.description) ?? asStr(pres.description) ?? null;
  const detail = asStr(req.detail) ?? asStr(pres.detail) ?? null;
  const rest: Rec = { ...req };
  for (const k of ["title", "description", "detail", "pluginId", "toolName", "severity", "agentId", "sessionKey", "id", "timeoutMs", "twoPhase"]) delete rest[k];
  const args = Object.keys(rest).length ? clip(rest, 2000) : null;
  const what = toolName || pluginId || title || t("card.tool");
  const brief = description || detail || args || "";
  return {
    id,
    kind,
    summary: sanitizeText(`${what}${brief ? `: ${clip(brief, 200)}` : ""}`),
    toolName,
    pluginId,
    title,
    description: description ?? detail,
    args,
    agentId: asStr(req.agentId) ?? asStr(pres.agentId) ?? null,
    sessionKey: asStr(req.sessionKey) ?? asStr(it.sessionKey) ?? null,
    createdAtMs,
    expiresAtMs,
    raw: item,
  };
}

/**
 * Pending record → card. Source: wardend directly (exec records "wd-…") or the wardenclaw-gate
 * plugin via the gateway (its own uuid records and relays of the same "wd-…" records).
 * supervisorId is the supervisor pinned via QR (for via "wardend"): we do not sign an envelope from
 * another supervisor.
 */
/** A record this app version cannot show (an envelope of an unknown version). It cannot be allowed. */
export type UnshownRecord = { id: string; via: GateVia; v: string; expiresAtMs: number | null };

/**
 * Split pending records: an exec record with an envelope of an unknown version (v is not 1) does not
 * become a card, this version cannot understand its content. It goes to unshown: the feed says how
 * many such requests there are and that the app needs an update. No buttons: the phone cannot
 * recompute the digest of such an envelope, so there is nothing to sign, and the request expires on
 * the server (fail-closed).
 */
export function splitUnshown(pending: GatePending[], via: GateVia): { shown: GatePending[]; unshown: UnshownRecord[] } {
  const shown: GatePending[] = [];
  const unshown: UnshownRecord[] = [];
  for (const p of pending) {
    const v = p.kind === "exec" ? unknownEnvelopeVersion(p) : null;
    if (v === null) shown.push(p);
    else unshown.push({ id: p.id, via, v, expiresAtMs: p.expiresAt || null });
  }
  return { shown, unshown };
}

export function normalizeGatePending(p: GatePending, via: GateVia = "openclaw", supervisorId?: string | null): Card {
  if (p.kind === "exec") return normalizeExecPending(p, via, supervisorId);
  // tool call: show what the phone recomputed itself; without a recomputation, as sent, but deny only
  const chk = checkToolPending(p);
  const shown = chk.ok ? chk : { command: p.command, filePath: p.filePath, paramsPreview: p.paramsPreview, agentId: p.agentId, sessionKey: p.sessionKey };
  const isExec = !!shown.command;
  const view = shown.command ? textView(shown.command) : null;
  const what = view ? headlineText(view) : sanitizeText(shown.filePath ? `${p.toolName} ${shown.filePath}` : `${p.toolName}: ${clip(shown.paramsPreview, 200)}`);
  const tool: ToolCardInfo = { digestOk: chk.ok, problem: chk.ok ? null : chk.reason };
  return {
    id: p.id,
    kind: "gate",
    gate: { digest: p.digest, mode: p.mode, source: p.source, toolKind: p.toolKind, tool, via },
    view,
    summary: clip(what, 300),
    command: isExec ? shown.command ?? undefined : undefined,
    cwd: null,
    host: null,
    toolName: p.toolName,
    pluginId: "wardenclaw-gate",
    title: p.toolName,
    description: chk.ok ? (isExec ? null : shown.paramsPreview) : t("feed.toolUnverified", { problem: chk.reason }),
    args: isExec ? null : clip(shown.paramsPreview, 2000),
    agentId: shown.agentId,
    sessionKey: shown.sessionKey,
    createdAtMs: p.createdAt,
    expiresAtMs: p.expiresAt,
    raw: p,
  };
}

/** Tool call preview in the phone journal: this many characters, then "…(+N)". */
export const JOURNAL_PREVIEW_MAX = 500;

/** Size of the call params in UTF-8 bytes, as the plugin measures it (CLIENT_CALL_MAX_BYTES); null if not JSON. */
export function callParamsBytes(call: unknown): number | null {
  try {
    const s = JSON.stringify((call as { params?: unknown } | null)?.params);
    return typeof s === "string" ? utf8Encode(s).length : null;
  } catch {
    return null;
  }
}

/**
 * Card raw for the "requested" entry in the phone journal (privacy H-6). The journal is append-only
 * and never cleaned, so the plugin tool call (call) is not written there: params may contain the
 * content of files being written, up to 512 KiB. Instead, callOmitted: the params size in bytes and
 * whether the digest recomputed by the phone matched; the plugin's paramsPreview, command and filePath
 * are cut to JOURNAL_PREVIEW_MAX (the plugin does not cut command at all). The record digest stays:
 * it locates the call in the plugin journal on the gateway. wardend exec records (signed envelope)
 * and gateway cards are written as is.
 */
export function journalRaw(card: Card): unknown {
  const raw = card.raw;
  if (card.kind !== "gate" || card.gate?.exec || !raw || typeof raw !== "object" || Array.isArray(raw)) return raw;
  const { call, ...rest } = raw as Rec;
  const out: Rec = { ...rest };
  for (const k of ["paramsPreview", "command", "filePath"]) if (typeof out[k] === "string") out[k] = clip(out[k], JOURNAL_PREVIEW_MAX);
  if (call !== undefined) out.callOmitted = { paramsBytes: callParamsBytes(call), digestOk: card.gate?.tool?.digestOk === true };
  return out;
}

export type ToolCheck =
  | { ok: true; command: string | null; filePath: string | null; paramsPreview: string; agentId: string | null; sessionKey: string | null }
  | { ok: false; reason: string };

/**
 * Plugin record of a tool call: allow can be signed only if the phone itself recomputed
 * toolCallDigest from call and it matched the record digest.
 * id "wd-…" means a wardend exec record: such a record is not allowed disguised as a tool (the
 * ticket signing string is the same).
 */
export function checkToolPending(p: GatePending): ToolCheck {
  if (typeof p.id !== "string" || p.id.startsWith("wd-")) return { ok: false, reason: t("err.toolWdId") };
  const call = p.call as ToolCall | undefined;
  if (!call || typeof call !== "object" || !call.params || typeof call.params !== "object" || Array.isArray(call.params)) return { ok: false, reason: t("err.toolNoCall") };
  if (call.toolName !== p.toolName) return { ok: false, reason: t("err.toolDigest") };
  let digest = "";
  try {
    digest = toolCallDigest(call);
  } catch {
    digest = "";
  }
  if (!digest || digest !== p.digest) return { ok: false, reason: t("err.toolDigest") };
  const sv = (v: unknown) => (typeof v === "string" ? v : null);
  return { ok: true, ...summarizeToolParams(call.params as Rec), agentId: sv(call.agentId), sessionKey: sv(call.sessionKey) };
}

/** What to show from params (like the plugin's summarizeParams, but from the recomputed call). */
function summarizeToolParams(params: Rec): { command: string | null; filePath: string | null; paramsPreview: string } {
  const sv = (v: unknown) => (typeof v === "string" ? v : undefined);
  const command = sv(params.command) ?? (Array.isArray(params.commandArgv) ? (params.commandArgv as unknown[]).map(String).join(" ") : undefined) ?? sv(params.cmd);
  const filePath = sv(params.file_path) ?? sv(params.path) ?? sv(params.filePath) ?? sv(params.notebook_path);
  const content = typeof params.content === "string" ? ` (${t("feed.toolContentLen", { n: params.content.length })})` : "";
  const preview = command ?? (filePath ? `${filePath}${content}` : canonicalJson(params));
  return { command: command ?? null, filePath: filePath ?? null, paramsPreview: clip(preview, 4000) };
}

/** Why allow cannot be signed for a gate card (null: it can): the exec envelope or the tool call was not recomputed by the phone. */
export function gateAllowRefusal(card: Card): string | null {
  const g = card.gate;
  if (!g) return t("err.notGateCard");
  if (g.exec) return g.exec.digestOk ? null : g.exec.problem ?? t("err.envelopeBad");
  if (g.tool?.digestOk) return null;
  return g.tool?.problem ?? t("err.toolUnverified");
}

/**
 * Why the autopilot (the app judge) does not allow the card on its own, null if it can: the signed
 * env loads foreign code into the program (LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH with a non-empty
 * value, DISPLAY.md 7a). Only a human allows that. The signed envelope decides, not the server meta
 * (the loader-env category only explains).
 */
export function autopilotAllowRefusal(card: Card): string | null {
  const loader = card.gate?.exec?.envView?.loader ?? [];
  return loader.length ? t("envVars.autopilotNo", { names: loader.join(", ") }) : null;
}

/** env of an unparsed envelope: show what was sent (only a deny can be signed anyway). */
function rawEnvVars(v: unknown): ExecEnvVar[] {
  if (!Array.isArray(v)) return [];
  const out: ExecEnvVar[] = [];
  for (const x of v.slice(0, 512)) {
    const e = asRec(x);
    const name = asStr(e.name);
    const value = asStr(e.value);
    if (name === null || value === null) continue;
    const cps = Array.from(value);
    const cut = (asNum(e.cut) ?? 0) + Math.max(0, cps.length - ENV_VALUE_MAX);
    out.push(cut > 0 ? { name: Array.from(name).slice(0, ENV_NAME_MAX).join(""), value: cps.slice(0, ENV_VALUE_MAX).join(""), cut } : { name: Array.from(name).slice(0, ENV_NAME_MAX).join(""), value });
  }
  return out;
}

/**
 * Ticket type for a gate card: a wardend exec record is signed with an exec ticket for its supervisor
 * (supervisorId from the envelope, covered by the recomputed digest), everything else with a tool
 * ticket for the plugin.
 */
export function gateTicketScope(card: Card): TicketScope {
  const exec = card.gate?.exec;
  return exec ? { type: TICKET_EXEC, supervisorId: exec.supervisorId } : { type: TICKET_TOOL };
}

/** wardend exec record → card. The envelope is checked right here: digestOk=false → cannot be signed. */
function normalizeExecPending(p: GatePending, via: GateVia, supervisorId?: string | null): Card {
  const chk = checkExecPending(p, via === "wardend" ? supervisorId : null);
  const meta = asRec(p.meta);
  const env = chk.ok ? chk.envelope : null;
  const rawEnv = asRec(p.envelope);
  const argv = env?.argv ?? (Array.isArray(rawEnv.argv) ? (rawEnv.argv as unknown[]).map(String) : []);
  const rawChain = Array.isArray(rawEnv.ppidChain) ? (rawEnv.ppidChain as unknown[]).map((l) => asRec(l)).map((l) => ({ pid: asNum(l.pid) ?? 0, exe: asStr(l.exe) ?? "" })) : [];
  const chain = env?.ppidChain ?? rawChain;
  const vars = env?.env ?? rawEnvVars(rawEnv.env);
  // envelope failed the check: show what was sent, but only a deny can be signed
  const view = commandView({ argv, exe: env?.exe ?? asStr(rawEnv.exe) ?? "", cwd: env?.cwd ?? asStr(rawEnv.cwd) ?? "", chain: chain.map((l) => l.exe) });
  const command = view.command;
  const judge = meta.judge ?? meta.opinion;
  const exec: ExecCardInfo = {
    digestOk: chk.ok,
    problem: chk.ok ? null : chk.reason,
    argv,
    cwd: env?.cwd ?? asStr(rawEnv.cwd) ?? "",
    exe: env?.exe ?? asStr(rawEnv.exe) ?? "",
    uid: env?.uid ?? -1,
    gid: env?.gid ?? -1,
    chain,
    host: env?.requester.host ?? "",
    // envelope not parsed: for a deny to a direct wardend, use the pinned supervisorId
    supervisorId: env?.requester.supervisorId ?? (via === "wardend" ? supervisorId ?? "" : ""),
    env: vars,
    envView: envView(vars),
    cls: asStr(meta.class),
    hardware: parseHardwareMeta(meta),
    rule: asStr(meta.rule),
    delegating: asStr(meta.delegating) ?? (meta.delegating === true ? t("common.yes") : null),
    insideRoot: asNum(meta.insideRoot),
    judgeMeta: judge !== undefined && judge !== null ? clip(JSON.stringify(judge), 400) : null,
    category: categoryCode(meta.category),
    detail: asStr(meta.detail) ? clip(sanitizeText(asStr(meta.detail) as string), 120) : null,
    provenance: parseProvenance(meta.provenance),
  };
  return {
    id: p.id,
    kind: "gate",
    gate: { digest: p.digest, mode: "enforce", source: "wardend", toolKind: "exec", exec, via },
    view,
    summary: clip(`${headlineText(view)}${exec.cwd ? `  ·  ${t("feed.inCwd", { cwd: sanitizeText(exec.cwd) })}` : ""}`, 300),
    command,
    cwd: exec.cwd,
    host: exec.host,
    toolName: "wardend.exec",
    pluginId: "wardend",
    title: exec.exe,
    description: null,
    args: argv.length > 1 ? clip(JSON.stringify(argv), 2000) : null,
    agentId: null,
    sessionKey: null,
    createdAtMs: p.createdAt,
    expiresAtMs: p.expiresAt,
    raw: p,
  };
}

/** Category code: a short identifier of lowercase letters, digits and hyphens, otherwise null. */
function categoryCode(v: unknown): string | null {
  const s = asStr(v);
  return s && /^[a-z0-9][a-z0-9-]{0,39}$/.test(s) ? s : null;
}

export function extractList(res: unknown): unknown[] {
  if (Array.isArray(res)) return res;
  const r = asRec(res);
  for (const k of ["approvals", "items", "pending", "requests", "list"]) if (Array.isArray(r[k])) return r[k] as unknown[];
  return [];
}
