// SPDX-License-Identifier: GPL-3.0-or-later
// Experimental: on-device judge. Pure functions without RN (tested in scripts/test-core.mjs).
// Short output: the first request returns only decision and risk; the explanation is a separate
// request made when the human expands the card. The system prompt and the start of the user message
// are shared by both requests, so the second request takes the card from the llama.cpp prefix cache.
import type { Card } from "../core/approvals";
import { buildUserPrompt, judgeRules } from "../core/decide";
import type { Lang } from "../core/i18n";

export type Decision3 = "allow" | "ask" | "deny";

export const SHORT_SCHEMA = {
  type: "object",
  properties: {
    decision: { type: "string", enum: ["allow", "deny", "ask"] },
    risk: { type: "integer", minimum: 0, maximum: 100 },
  },
  required: ["decision", "risk"],
  additionalProperties: false,
};

export const EXPLAIN_SCHEMA = {
  type: "object",
  properties: {
    reason: { type: "string" },
    explanation: { type: "string" },
    goal_fit: { type: "string" },
  },
  required: ["reason", "explanation", "goal_fit"],
  additionalProperties: false,
};

/** Enough for {"decision":"allow","risk":100} with room to spare; the grammar keeps it from drifting into text. */
export const SHORT_N_PREDICT = 32;
export const EXPLAIN_N_PREDICT = 320;

export function localSystemPrompt(): string {
  return `${judgeRules()}

Reply with EXACTLY one JSON object in the format given at the end of the user message, and no text around it.`;
}

/** The card without the "Return only JSON." tail: the shared prefix of the verdict and the explanation. */
export function cardBody(card: Card): string {
  return buildUserPrompt(card).replace(/\n*Return only JSON\.\s*$/, "").trimEnd();
}

export function verdictUserPrompt(card: Card): string {
  return `${cardBody(card)}

Return only JSON: {"decision":"allow"|"deny"|"ask","risk":<integer 0-100>}`;
}

// Language of the explanation strings, by UI language (a new UI language adds its name here)
const LANGUAGE_NAMES: Record<Lang, string> = { en: "English" };

export function explainUserPrompt(card: Card, decision: Decision3, risk: number, lang: Lang): string {
  const language = LANGUAGE_NAMES[lang] ?? "English";
  return `${cardBody(card)}

Your verdict for this action was "${decision}" with risk ${risk}. Explain it. Write every string value in ${language}, briefly (reason one sentence, explanation up to 3 sentences, goal_fit up to 2).
Return only JSON: {"reason":"one sentence","explanation":"what exactly the command does, part by part","goal_fit":"whether it matches the agent's stated goal; if no goal is stated, say so"}`;
}

function firstJsonObject(text: string): Record<string, unknown> | null {
  const s = text.indexOf("{");
  const e = text.lastIndexOf("}");
  if (s < 0 || e <= s) return null;
  try {
    const o = JSON.parse(text.slice(s, e + 1));
    return o && typeof o === "object" ? (o as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Parsing of the short reply. llama.rn sometimes returns text with a chat template prefix, so we look for {…}. */
export function parseShort(text: string): { decision: Decision3; risk: number } | null {
  const o = firstJsonObject(text);
  if (!o) return null;
  const d = o.decision;
  if (d !== "allow" && d !== "ask" && d !== "deny") return null;
  const r = typeof o.risk === "number" && Number.isFinite(o.risk) ? Math.max(0, Math.min(100, Math.round(o.risk))) : null;
  if (r === null) return null;
  return { decision: d, risk: r };
}

export type Explanation = { reason: string; explanation: string; goalFit: string };

export function parseExplain(text: string): Explanation | null {
  const o = firstJsonObject(text);
  if (!o) return null;
  const s = (v: unknown) => (typeof v === "string" ? v.trim() : "");
  const e = { reason: s(o.reason), explanation: s(o.explanation), goalFit: s(o.goal_fit) };
  return e.reason || e.explanation ? e : null;
}

/** Kev-multi: 5 "yes/no" questions. Risk = the highest "yes" probability, flags = questions with p ≥ 0.5. */
export const KEV_FLAG_KEYS = ["secrets", "exfil", "obfuscated", "destructive", "persistence"] as const;
export function kevOpinion(pYes: number[], decision: Decision3): { decision: Decision3; risk: number; flags: string[] } {
  const risk = pYes.length ? Math.round(Math.max(...pYes) * 100) : 0;
  const flags = KEV_FLAG_KEYS.filter((_, i) => (pYes[i] ?? 0) >= 0.5);
  return { decision, risk, flags: [...flags] };
}
