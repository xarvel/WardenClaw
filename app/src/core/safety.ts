// SPDX-License-Identifier: GPL-3.0-or-later
// Whether a card is dangerous and why, in human words (protocol/DISPLAY.md, section 8).
// What makes it dangerous: blocklist and injection rules, sanitizer flags (invisible, bidi,
// homoglyphs), a delegating launch and an environment with a loader or flags (section 7a), all
// from the signed envelope. meta from the transport can only add caution (the server says
// "delegating"), but never removes it.
import { categoryLabel, type Card } from "./approvals";
import { ruleMsgKey, type Verdict } from "./decide";
import type { EnvEntry, EnvView, MixedWord } from "./display";
import { MsgKey, t } from "./i18n";

/** At most this many words with mixed alphabets in the reasons; the rest as a number. */
const MIXED_WORDS_SHOWN = 3;
/** A long word in a reason: a window around the first foreign letter. */
const WORD_MAX = 40;

function clipWord(word: string, firstOdd: number): string {
  const a = Array.from(word);
  if (a.length <= WORD_MAX) return word;
  const from = Math.max(0, Math.min(firstOdd - 15, a.length - WORD_MAX));
  const to = Math.min(a.length, from + WORD_MAX);
  return `${from > 0 ? "…" : ""}${a.slice(from, to).join("")}${to < a.length ? "…" : ""}`;
}

/**
 * "In the word 'Sоns' a Cyrillic 'о' among Latin letters": where exactly a letter was swapped
 * (protocol/DISPLAY.md, sections 3 and 7: the card's MixedWord). Identical letters of a word are
 * named once.
 */
export function mixedReasons(words: MixedWord[]): string[] {
  const out = words.slice(0, MIXED_WORDS_SHOWN).map((w) => {
    const seen = new Set<string>();
    const letters: string[] = [];
    for (const o of w.odd) {
      if (seen.has(o.char)) continue;
      seen.add(o.char);
      letters.push(t("mixed.letter", { script: t(`script.adj.${o.script}` as MsgKey), char: o.char }));
    }
    return t("flag.mixedWord", { word: clipWord(w.word, w.odd[0]?.at ?? 0), letters: letters.join(", "), among: t(`script.among.${w.among}` as MsgKey) });
  });
  if (words.length > MIXED_WORDS_SHOWN) out.push(t("mixed.more", { n: words.length - MIXED_WORDS_SHOWN }));
  return out;
}

/** A list of names in a reason: without repeats, no longer than NAMES_MAX code points. */
const NAMES_MAX = 120;
function nameList(names: string[]): string {
  const a = Array.from([...new Set(names)].join(", "));
  return a.length > NAMES_MAX ? `${a.slice(0, NAMES_MAX).join("")}…` : a.join("");
}

/**
 * Reasons from the exec environment (DISPLAY.md, section 7a): the loader loads foreign code,
 * invisible or control characters in entries, truncated values, repeated names. The names have
 * already been through the sanitizer.
 */
export function envReasons(ev: EnvView): string[] {
  const out: string[] = [];
  const names = (pred: (e: EnvEntry) => boolean) => nameList(ev.entries.filter(pred).map((e) => e.name));
  if (ev.loader.length) out.push(t("envVars.dangerLoader", { names: nameList(ev.loader) }));
  const text = names((e) => e.flags.some((f) => f === "control" || f === "bidi" || f === "invisible"));
  if (text) out.push(t("envVars.dangerText", { names: text }));
  const cut = names((e) => e.cut > 0);
  if (cut) out.push(t("envVars.dangerCut", { names: cut }));
  const dup = names((e) => e.flags.includes("duplicate"));
  if (dup) out.push(t("envVars.dangerDup", { names: dup }));
  return out;
}

const DG_KEYS: Record<string, MsgKey> = {
  "session-detach": "dg.sessionDetach",
  "service-managers": "dg.serviceManagers",
  containers: "dg.containers",
  multiplexers: "dg.multiplexers",
  schedulers: "dg.schedulers",
  "privilege-and-ns": "dg.privilegeAndNs",
  remote: "dg.remote",
};

export type Safety = {
  dangerous: boolean;
  /** Reasons in order: rules, flags, environment, delegation. */
  reasons: string[];
  /** Root of a process tree: the approval extends to everything it launches (any exec card). */
  root: boolean;
};

export function cardSafety(card: Card, verdict: Verdict | "pending" | null | undefined): Safety {
  const view = card.view ?? null;
  const exec = card.gate?.exec ?? null;
  const reasons: string[] = [];
  const rules = new Set<string>([...(view?.danger ?? []), ...(verdict && verdict !== "pending" ? verdict.rules ?? [] : [])]);
  for (const id of rules) reasons.push(t(ruleMsgKey(id)));
  for (const f of view?.flags ?? []) {
    // mixed alphabets: which word and which letter, not just "in one word"
    if (f === "mixedScript" && view?.mixed?.length) reasons.push(...mixedReasons(view.mixed));
    else reasons.push(t(`flag.${f}` as MsgKey));
  }
  // environment from the signed envelope: a card with envView.dangerous is dangerous, as with
  // commandView.dangerous
  if (exec?.envView?.dangerous) reasons.push(...envReasons(exec.envView));
  // self-built and mount-ns: the server does not know what is actually launched (the file name
  // proves nothing). They have meta.delegating too, but this is not a delegating launch: it has its
  // own reason.
  const origin = exec?.category === "self-built" || exec?.category === "mount-ns" ? exec.category : null;
  if (view?.delegating) reasons.push(t("feed.dangerDelegating", { what: DG_KEYS[view.delegating] ? t(DG_KEYS[view.delegating]) : view.delegating }));
  else if (exec && !origin && (exec.cls === "delegating" || exec.delegating)) reasons.push(t("feed.dangerDelegatingMeta"));
  if (origin) {
    const label = categoryLabel(origin);
    reasons.push(t("feed.dangerCategory", { what: label.charAt(0).toLowerCase() + label.slice(1) }));
  }
  if (exec && !exec.digestOk) reasons.push(t("feed.dangerEnvelope"));
  const tool = card.gate?.tool ?? null;
  if (tool && !tool.digestOk) reasons.push(t("feed.dangerToolUnverified", { problem: tool.problem ?? t("err.toolUnverified") }));
  return { dangerous: reasons.length > 0, reasons, root: card.kind === "exec" || !!exec };
}

export type BiometricMode = "risky" | "all";

/** Whether biometrics or device passcode is needed before signing allow: dangerous and roots always, the rest per setting. */
export function needsOwnerCheck(s: Safety, mode: BiometricMode): boolean {
  return s.dangerous || s.root || mode === "all";
}

// ---------------------------------------------------------------------------
// Owner confirmation (biometric.ts): what to do at each phone protection level
// ---------------------------------------------------------------------------

/** How the phone can confirm the owner: strong biometrics, device passcode, nothing, module not responding. */
export type OwnerAuthLevel = "biometric" | "passcode" | "none" | "unavailable";

/**
 * prompt: ask for biometrics or the passcode; allow: nothing to confirm with (no screen lock, the
 * settings warn about it); refuse: the biometrics module does not respond, and the action strictly
 * requires confirmation (root, dangerous card, weakening of protection). In a debug build (dev)
 * without the module we let it through, so that Expo Go works.
 */
export function ownerGate(level: OwnerAuthLevel, failClosed: boolean, dev: boolean): "prompt" | "allow" | "refuse" {
  if (level === "biometric" || level === "passcode") return "prompt";
  if (level === "none") return "allow";
  return failClosed && !dev ? "refuse" : "allow";
}

// ---------------------------------------------------------------------------
// What weakens protection: such settings changes require owner confirmation (controller.ts)
// ---------------------------------------------------------------------------

/** Autopilot threshold is higher: more gets allowed automatically. */
export function thresholdWeakens(prev: number, next: number): boolean {
  return next > prev;
}

/** "Every approval" → "Dangerous and roots": some signatures will go without biometrics. */
export function biometricModeWeakens(prev: BiometricMode, next: BiometricMode): boolean {
  return prev === "all" && next === "risky";
}

const normUrl = (u: string) => u.trim().replace(/\/+$/, "").toLowerCase();

/** A different judge address or model: the autopilot trusted the previous one, so it turns off. */
export function judgeChanged(prev: { url: string; model: string }, next: { url: string; model: string }): boolean {
  return normUrl(prev.url) !== normUrl(next.url) || prev.model.trim() !== next.model.trim();
}

/** Host name of an address as typed in settings: without scheme, credentials, port and path, in lower case; null when there is none. */
export function urlHost(u: string): string | null {
  const m = /^\s*(?:[a-z][a-z0-9+.-]*:\/\/)?(?:[^/?#@\s]*@)?(\[[^\]]+\]|[^/?#:\s]+)/i.exec(u);
  return m ? m[1].toLowerCase() : null;
}

/**
 * The judge address points at the agent's host (a paired wardend server, the OpenClaw gateway): a
 * judge there sits inside the loop it is meant to check. Returns that host, or null. A warning
 * only: the owner may still save the address.
 */
export function judgeOnAgentHost(judgeUrl: string, agentUrls: (string | null | undefined)[]): string | null {
  const j = urlHost(judgeUrl);
  if (!j) return null;
  for (const u of agentUrls) {
    const h = u ? urlHost(u) : null;
    if (h && h === j) return h;
  }
  return null;
}

/** Paths of the "no trash-put here" rule from the setting text: comma or newline separated. */
export function parsePathList(text: string): string[] {
  const out: string[] = [];
  for (const raw of text.split(/[,\n]/)) {
    const p = raw.trim();
    if (p && !out.includes(p)) out.push(p);
  }
  return out;
}

/** At least one path is gone from the rule: trash-put on it no longer goes to the human. */
export function pathListWeakens(prev: string[], next: string[]): boolean {
  const keep = new Set(next.map((p) => p.toLowerCase()));
  return prev.some((p) => !keep.has(p.toLowerCase()));
}
