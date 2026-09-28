// SPDX-License-Identifier: GPL-3.0-or-later
// Normalizes wardend exec records into the app's card model.
import type { GatePending } from "./gate";
import { TICKET_EXEC, type TicketScope } from "./canonical";
import { checkExecPending, ENV_VALUE_MAX, ENV_NAME_MAX, isRootExec, unknownEnvelopeVersion, type ExecEnvVar, type ExecLink } from "./execEnvelope";
import { commandView, envView, headlineText, sanitizeText, type CommandView, type EnvView } from "./display";
import { parseHardwareMeta, type HardwareMeta } from "./hardware";
import { t, type MsgKey } from "./i18n";

/** "gate": a wardend exec record, signed with a ticket. "exec": a command as text without a record (judge bench cases). */
export type ApprovalKind = "exec" | "gate";

export type Card = {
  id: string;
  kind: ApprovalKind;
  /** Only for kind === "gate": the record digest (what the ticket signs) and the checked envelope. */
  gate?: { digest: string; source: string; toolKind: string | null; exec?: ExecCardInfo };
  summary: string; // one line in plain language
  command?: string;
  cwd?: string | null;
  host?: string | null;
  toolName?: string | null;
  title?: string | null;
  description?: string | null;
  args?: string | null;
  agentId: string | null;
  sessionKey: string | null;
  createdAtMs: number;
  expiresAtMs: number | null;
  raw: unknown;
  /** Command display (protocol/DISPLAY.md): parts, rules, flags. */
  view?: CommandView | null;
  /** Test card of the bench build (wardenclaw://bench?mockcard|mockui): "Test" badge, the decision
   *  goes nowhere, the text is not sent to the remote judge. Cards from the server never have it. */
  mock?: true;
};

/** wardend exec record (execve at the OS level): what we show and whether it can be signed. */
export type ExecCardInfo = {
  digestOk: boolean;
  problem: string | null;
  argv: string[];
  cwd: string;
  exe: string;
  uid: number;
  gid: number;
  /**
   * Signed envelope type "rootexec": wardend runs the program as its own user (uid/gid above, root
   * in the hardened install), outside the gate. Always dangerous, never for the autopilot.
   */
  rootExec: boolean;
  chain: ExecLink[];
  host: string;
  supervisorId: string;
  /** Envelope env (signed) and its display (DISPLAY.md, section 7a): variables that change program behavior.
   *  Always present on wardend records (normalizeExecPending); absent only on bench mock cards. */
  env?: ExecEnvVar[];
  envView?: EnvView;
  // The rest is meta: not in the digest. Display only, and
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

/** Which agent is asking: the card agentId, the claude-cli wrapper or a known name in the process chain. */
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

/** A record this app version cannot show (an envelope of an unknown version). It cannot be allowed. */
export type UnshownRecord = { id: string; v: string; expiresAtMs: number | null };

/**
 * Split pending records: an exec record with an envelope of an unknown version (v is not 1) does not
 * become a card, this version cannot understand its content. It goes to unshown: the feed says how
 * many such requests there are and that the app needs an update. No buttons: the phone cannot
 * recompute the digest of such an envelope, so there is nothing to sign, and the request expires on
 * the server (fail-closed).
 */
export function splitUnshown(pending: GatePending[]): { shown: GatePending[]; unshown: UnshownRecord[] } {
  const shown: GatePending[] = [];
  const unshown: UnshownRecord[] = [];
  for (const p of pending) {
    const v = unknownEnvelopeVersion(p);
    if (v === null) shown.push(p);
    else unshown.push({ id: p.id, v, expiresAtMs: p.expiresAt || null });
  }
  return { shown, unshown };
}

/**
 * Why the autopilot (the app judge) does not allow the card on its own, null if it can: the signed
 * env loads foreign code into the program (LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH with a non-empty
 * value, DISPLAY.md 7a). Only a human allows that. The signed envelope decides, not the server meta
 * (the loader-env category only explains).
 */
export function autopilotAllowRefusal(card: Card): string | null {
  const exec = card.gate?.exec;
  // a rootexec card (signed type): only a human hands out root
  if (exec?.rootExec) return t("rootExec.autopilotNo");
  const loader = exec?.envView?.loader ?? [];
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

/** Why allow cannot be signed for a card (null: it can): the phone did not recompute the exec envelope. */
export function gateAllowRefusal(card: Card): string | null {
  const exec = card.gate?.exec;
  if (!exec) return t("err.notGateCard");
  return exec.digestOk ? null : exec.problem ?? t("err.envelopeBad");
}

/** Ticket for a card: an exec ticket for its supervisor (supervisorId from the envelope, covered by the recomputed digest). */
export function gateTicketScope(card: Card): TicketScope {
  return { type: TICKET_EXEC, supervisorId: card.gate?.exec?.supervisorId ?? "" };
}

/**
 * wardend exec record → card. The envelope is checked right here: digestOk=false → cannot be signed.
 * supervisorId is the supervisor pinned via QR: we do not sign an envelope from another supervisor.
 */
export function normalizeGatePending(p: GatePending, supervisorId?: string | null): Card {
  const chk = checkExecPending(p, supervisorId);
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
    // from the parsed (signed) envelope; an unparsed one shows the raw type only toward caution
    rootExec: env ? isRootExec(env) : rawEnv.type === "rootexec",
    chain,
    host: env?.requester.host ?? "",
    // envelope not parsed: for a deny, use the pinned supervisorId
    supervisorId: env?.requester.supervisorId ?? supervisorId ?? "",
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
    gate: { digest: p.digest, source: "wardend", toolKind: "exec", exec },
    view,
    summary: clip(`${headlineText(view)}${exec.cwd ? `  ·  ${t("feed.inCwd", { cwd: sanitizeText(exec.cwd) })}` : ""}`, 300),
    command,
    cwd: exec.cwd,
    host: exec.host,
    toolName: "wardend.exec",
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
