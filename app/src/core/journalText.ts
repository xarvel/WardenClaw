// SPDX-License-Identifier: GPL-3.0-or-later
// Text of journal entries. An entry stores the string key and the parameters (the msg field in
// payload), and the text is built at display time in the current language: after a language change
// old entries read in the new language, and codes like deny and blocklist show as words. The summary
// column stays the text as of the time of writing: search runs over it, and it is also what old
// entries without msg (upgrade path: entries written before this format was added)
// and entries with a corrupted msg show.
// The module is pure (no RN): it is compiled by the tests.
import { callParamsBytes } from "./approvals";
import { MsgKey, MsgParams, isMsgKey, t, tOr } from "./i18n";

export type JournalMsg = { key: string; params: MsgParams };

/** Rating sources that have no risk (manual mode, model not configured or did not respond, no time left for an answer). */
export const UNRATED_SOURCES = ["manual", "no-model", "model-error", "no-time"];

// Code parameters that are translated at display time. Other parameters are substituted as is.
const DERIVE: Record<string, (p: MsgParams) => { key: MsgKey; params: MsgParams }> = {
  "j.verdict": (p) => {
    const reason = String(p.reason ?? "").trim();
    const source = String(p.source ?? "");
    // without a model or on its error, the risk number is a placeholder, not a rating
    const rated = typeof p.risk === "number" && !UNRATED_SOURCES.includes(source);
    return {
      key: reason ? "j.verdict" : "j.verdictNoReason",
      params: { summary: String(p.summary ?? ""), proposal: proposalText(String(p.decision ?? "")), risk: rated ? t("journal.risk", { risk: p.risk }) : t("journal.unrated"), source: sourceText(source), reason },
    };
  },
};

/** The judge's proposal in words (in a rating entry, decision is a proposal, not the outcome). */
export function proposalText(decision: string): string {
  if (decision === "allow" || decision === "allow-once") return t("journal.dec.proposeAllow");
  if (decision === "deny") return t("journal.dec.proposeDeny");
  if (decision === "ask") return t("journal.dec.proposeAsk");
  return decision;
}

/** Rating source in words: blocklist rule, model, "no model configured". */
export function sourceText(source: string): string {
  const key = { blocklist: "src.blocklist", injection: "src.injection", model: "src.model", "model-error": "src.modelError", "no-model": "src.noModel", "no-time": "src.noTime", manual: "feed.chip.why.manual" }[source];
  return key ? tOr(key, source) : source;
}

/** Why there is no rating, in words (for "Not rated (…)"). */
export function unratedWhy(source: string): string {
  const key = { manual: "feed.chip.why.manual", "no-model": "feed.chip.why.noModel", "model-error": "feed.chip.why.modelError", "no-time": "feed.chip.why.noTime" }[source];
  return key ? tOr(key, source) : sourceText(source);
}

function cleanParams(v: unknown): MsgParams | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const out: MsgParams = {};
  for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
    if (!/^\w{1,32}$/.test(k)) continue;
    if (typeof x === "string") out[k] = x.slice(0, 2000);
    else if (typeof x === "number" && Number.isFinite(x)) out[k] = x;
  }
  return out;
}

/** msg from the entry payload: only a journal key (j.*) present in the dictionary, and simple parameters. */
export function entryMsg(payload: string | null | undefined): JournalMsg | null {
  if (!payload) return null;
  let obj: unknown;
  try {
    obj = JSON.parse(payload);
  } catch {
    return null;
  }
  const m = (obj as { msg?: unknown } | null)?.msg as { key?: unknown; params?: unknown } | undefined;
  if (!m || typeof m !== "object" || typeof m.key !== "string") return null;
  if (!m.key.startsWith("j.") || !isMsgKey(m.key)) return null;
  const params = m.params === undefined ? {} : cleanParams(m.params);
  if (!params) return null;
  return { key: m.key, params };
}

/** Journal message text in the current language. */
export function renderMsg(m: JournalMsg): string {
  const d = DERIVE[m.key];
  if (d) {
    const r = d(m.params);
    return t(r.key, r.params);
  }
  return t(m.key as MsgKey, m.params);
}

/** Entry text for display: from msg if it is present and intact, otherwise the stored summary. */
export function entryText(e: { summary: string; payload: string | null }): string {
  const m = entryMsg(e.payload);
  return m ? renderMsg(m) : e.summary;
}

/**
 * Entry payload for the journal screen: indented JSON. Old "requested" entries (written before the
 * current payload format was introduced) carry
 * the whole plugin tool call (raw.call, params can hold file contents up to 512 KiB): the screen
 * does not render it, but shows it as new entries do: callOmitted with the params size in bytes
 * (approvals.ts, journalRaw). The entry itself in the database does not change: the hash chain
 * rests on it. Not JSON: as is.
 */
export function payloadView(payload: string): string {
  let obj: unknown;
  try {
    obj = JSON.parse(payload);
  } catch {
    return payload;
  }
  const raw = obj && typeof obj === "object" && !Array.isArray(obj) ? (obj as { raw?: unknown }).raw : undefined;
  if (raw && typeof raw === "object" && !Array.isArray(raw) && "call" in raw) {
    const { call, ...rest } = raw as Record<string, unknown>;
    obj = { ...(obj as Record<string, unknown>), raw: { ...rest, callOmitted: { paramsBytes: callParamsBytes(call) } } };
  }
  return JSON.stringify(obj, null, 1) ?? payload;
}

/**
 * The summary and payload fields of a new entry: key and parameters in payload.msg (next to the
 * other entry data), summary holds the text in the current language for search and for old app
 * versions.
 */
export function journalMsg(key: MsgKey, params: MsgParams = {}, extra: Record<string, unknown> | null = null): { summary: string; payload: string } {
  const msg: JournalMsg = { key, params };
  return { summary: renderMsg(msg), payload: JSON.stringify({ ...(extra ?? {}), msg }) };
}
