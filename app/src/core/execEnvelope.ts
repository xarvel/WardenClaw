// SPDX-License-Identifier: GPL-3.0-or-later
// Exec envelope v1 of the wardend supervisor (seccomp gate for execve on the host). The app receives
// it in a pending record of type "exec" (via the wardenclaw-gate plugin relay) and BEFORE signing
// recomputes digest = sha256(canonicalJson(envelope)) itself: the digest is signed, not what the
// transport showed. The format is pinned by cross-fixtures (protocol/vectors at the monorepo root).
import { canonicalJson, sha256Hex } from "./canonical";
import { commandView, type EnvVar } from "./display";
import { t } from "./i18n";

export type ExecLink = { pid: number; exe: string };
export type ExecEnvVar = EnvVar;

/**
 * "exec": an execve the seccomp gate holds; the program runs as the caller (uid/gid of the
 * envelope are the caller's). "rootexec" (protocol 2, README 3a): a `wardend rootexec` request from
 * under the gate; wardend itself runs the program as its own user, uid/gid are the ids of THAT
 * launch (0 in the hardened install), exe is the file wardend pinned. Same 14 fields, same digest.
 */
export type ExecEnvelopeType = "exec" | "rootexec";

export type ExecEnvelope = {
  v: 1;
  type: ExecEnvelopeType;
  argv: string[];
  cwd: string;
  exe: string; // realpath of what will be executed
  uid: number;
  gid: number;
  ppidChain: ExecLink[]; // [0] is the calling process itself, then its parents
  /** Variables that change program behavior (chosen by wardend), in envp order, duplicates kept. */
  env: ExecEnvVar[];
  envHash: string;
  requester: { host: string; supervisorId: string };
  pidfdCookie: string;
  ts: number;
  nonce: string;
};

const KEYS = ["argv", "cwd", "env", "envHash", "exe", "gid", "nonce", "pidfdCookie", "ppidChain", "requester", "ts", "type", "uid", "v"];

/** An env variable value is at most this many code points: wardend cuts off the rest (the count is in cut). */
export const ENV_VALUE_MAX = 1024;
/** Maximum code points for an env variable name (wardend uses the same limit). */
export const ENV_NAME_MAX = 256;

/** The digest is computed over the whole envelope as is (all 14 fields, env too): sha256(canonicalJson). */
export function execEnvelopeDigest(env: ExecEnvelope | Record<string, unknown>): string {
  return sha256Hex(canonicalJson(env));
}

const isStr = (x: unknown): x is string => typeof x === "string";
const isInt = (x: unknown): x is number => typeof x === "number" && Number.isSafeInteger(x);

/** env entry: exactly {name,value} or {name,value,cut}; name non-empty without "=", cut an integer > 0, value ≤ 1024 code points. */
function isEnvVar(x: unknown): x is ExecEnvVar {
  if (!x || typeof x !== "object" || Array.isArray(x)) return false;
  const o = x as Record<string, unknown>;
  const k = Object.keys(o).sort();
  const plain = k.length === 2 && k[0] === "name" && k[1] === "value";
  const cut = k.length === 3 && k[0] === "cut" && k[1] === "name" && k[2] === "value";
  if (!plain && !cut) return false;
  if (!isStr(o.name) || !isStr(o.value) || o.name === "" || o.name.includes("=")) return false;
  if (cut && !(isInt(o.cut) && o.cut > 0)) return false;
  // UTF-16 length is never less than the code point count: only long values need counting
  return o.value.length <= ENV_VALUE_MAX || Array.from(o.value).length <= ENV_VALUE_MAX;
}

/** Envelope version this app cannot show (the v field is present and not 1), as a string; otherwise null. */
export function unknownEnvelopeVersion(rec: { envelope?: unknown }): string | null {
  const e = rec.envelope;
  if (!e || typeof e !== "object" || Array.isArray(e) || !("v" in e)) return null;
  const v = (e as Record<string, unknown>).v;
  return v === 1 ? null : String(typeof v === "string" ? v : JSON.stringify(v)).slice(0, 16);
}

/** Strict shape check of the envelope from a pending record; null: do not accept (extra fields, not v1, etc.). */
export function execEnvelopeFromPending(rec: { envelope?: unknown }): ExecEnvelope | null {
  const e = rec.envelope;
  if (!e || typeof e !== "object" || Array.isArray(e)) return null;
  const o = e as Record<string, unknown>;
  const keys = Object.keys(o).sort();
  if (keys.length !== KEYS.length || keys.some((k, i) => k !== KEYS[i])) return null;
  if (o.v !== 1 || (o.type !== "exec" && o.type !== "rootexec")) return null;
  if (!Array.isArray(o.argv) || !o.argv.every(isStr)) return null;
  if (!Array.isArray(o.env) || !o.env.every(isEnvVar)) return null;
  if (!isStr(o.cwd) || !isStr(o.exe) || !isStr(o.envHash) || !isStr(o.pidfdCookie) || !isStr(o.nonce)) return null;
  if (!isInt(o.uid) || !isInt(o.gid) || !isInt(o.ts)) return null;
  if (!Array.isArray(o.ppidChain)) return null;
  for (const l of o.ppidChain) {
    if (!l || typeof l !== "object") return null;
    const lo = l as Record<string, unknown>;
    if (Object.keys(lo).length !== 2 || !isInt(lo.pid) || !isStr(lo.exe)) return null;
  }
  const r = o.requester as Record<string, unknown> | null;
  if (!r || typeof r !== "object" || Object.keys(r).length !== 2 || !isStr(r.host) || !isStr(r.supervisorId)) return null;
  return o as unknown as ExecEnvelope;
}

/** A rootexec envelope: the program runs as wardend's user (root), not as the agent. Signed, part of the digest. */
export function isRootExec(env: Pick<ExecEnvelope, "type"> | null | undefined): boolean {
  return env?.type === "rootexec";
}

/**
 * One-line command for the card (protocol/DISPLAY.md): the inner command of the claude-cli wrapper
 * only on an exact template match, otherwise the `sh -c` script or argv in shell quoting.
 */
export function execDisplayCommand(env: Pick<ExecEnvelope, "argv"> & Partial<ExecEnvelope>): string {
  return commandView({ argv: env.argv, exe: env.exe, cwd: env.cwd, chain: env.ppidChain?.map((l) => l.exe) }).command;
}

export type ExecCheck = { ok: true; envelope: ExecEnvelope } | { ok: false; reason: string };

/**
 * wardend exec record: strictly parse the envelope and recompute the digest OURSELVES. Signing is
 * allowed only if it matches the record digest: otherwise the transport (plugin/tunnel) showed one
 * thing and is asking to sign another.
 */
export function checkExecPending(p: { id: string; digest: string; envelope?: unknown }, expectedSupervisorId?: string | null): ExecCheck {
  const env = execEnvelopeFromPending(p);
  const v = env ? null : unknownEnvelopeVersion(p);
  if (!env) return { ok: false, reason: v !== null ? t("env.unknownVersion", { v }) : t("env.notV1") };
  // direct connection: the envelope must come from the supervisor whose key is pinned via QR
  if (expectedSupervisorId && env.requester.supervisorId !== expectedSupervisorId) return { ok: false, reason: t("env.otherSupervisor") };
  const d = execEnvelopeDigest(env);
  if (d !== p.digest) return { ok: false, reason: t("env.digestMismatch", { record: p.digest.slice(0, 12), computed: d.slice(0, 12) }) };
  if (!p.id.startsWith("wd-") || p.id !== `wd-${d.slice(0, 32)}`) return { ok: false, reason: t("env.idMismatch") };
  return { ok: true, envelope: env };
}

