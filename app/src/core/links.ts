// SPDX-License-Identifier: GPL-3.0-or-later
// wardenclaw:// links the app understands. Any app on the phone, or a web page on click, can open
// the scheme, so a link does nothing by itself: a card is only shown, a pairing link only fills in
// the field (connecting takes a tap and the owner's confirmation), a judge link only fills in the
// URL, model and, when it carries one, API key fields on "Mode" (saving takes Save and the owner's
// confirmation; the key reaches SecureStore by that path alone). wardenclaw://bench (benchmark and
// mock cards) is understood only by the bench build.
// A judge link with key=… is a secret, like a pairing link: it is never logged or quoted in an error.
// Pure module (no RN): the tests compile it.

import { errMsg } from "./errMsg";
import { t } from "./i18n";
import { parsePairLink, parseQuery } from "./relayProto";
import { urlHost } from "./safety";

export type LinkRoute =
  | { kind: "card"; id: string }
  | { kind: "feed" }
  | { kind: "pair"; link: string }
  | { kind: "bench"; url: string }
  | { kind: "judge"; url: string; model: string; key?: string } // fields to fill in on "Mode", nothing saved; key is a secret
  | { kind: "judge-invalid"; error: string }; // a judge link the app refused: "Mode" shows why

/** What a judge link leaves for the "Mode" tab: the values for the form, or the reason it was refused. */
export type JudgeLinkRoute = Extract<LinkRoute, { kind: "judge" | "judge-invalid" }>;

/** key is present only when the link carried one (the form's key field is left alone otherwise). */
export type JudgeLink = { url: string; model: string; key?: string };

export const JUDGE_LINK_MAX_URL = 512;
export const JUDGE_LINK_MAX_MODEL = 128;
export const JUDGE_LINK_MAX_KEY = 512;

const JUDGE_LINK_PARAMS = new Set(["url", "model", "key"]);

/** localhost, 127.0.0.0/8 and ::1: the only hosts a judge link may name over plain http. */
export function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  return h === "localhost" || h === "::1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}

/**
 * Parse wardenclaw://judge?url=<encoded>&model=<encoded>[&key=<encoded>]: the OpenAI-compatible
 * base URL (…/v1), the model name and, optionally, the API key for the judge settings form.
 * Throws a readable error. url and model are required; key is optional (the maintainer's decision
 * of 2026-10-15: a link may carry the token of the owner's own endpoint, so that one QR configures
 * the judge end to end), and any other parameter (apiKey, token, timeout, …) refuses the whole
 * link. The key is percent-decoded and trimmed, 1..512 characters, no whitespace or control
 * characters inside; it is a secret, so no error here ever quotes it, and the caller must not log
 * the link. The URL is https://, or http:// on loopback only (the app would not reach a cleartext
 * host anyway, and a link should not teach the owner to use one).
 */
export function parseJudgeLink(input: string): JudgeLink {
  const m = /^wardenclaw:\/\/judge\/?(?:\?(.*))?$/i.exec(input.trim());
  if (!m) throw new Error(t("link.notJudge"));
  let q: Record<string, string>;
  try {
    q = parseQuery(m[1] ?? "");
  } catch {
    throw new Error(t("link.corrupt"));
  }
  const extra = Object.keys(q).filter((k) => !JUDGE_LINK_PARAMS.has(k));
  if (extra.length) throw new Error(t("link.judge.extraParam", { name: extra[0].slice(0, 32) }));
  const url = (q.url ?? "").trim();
  const model = (q.model ?? "").trim();
  if (!url) throw new Error(t("link.judge.noUrl"));
  if (!model) throw new Error(t("link.judge.noModel"));
  if (url.length > JUDGE_LINK_MAX_URL || model.length > JUDGE_LINK_MAX_MODEL) throw new Error(t("link.judge.tooLong"));
  if (/[\u0000-\u001f\u007f-\u009f\s]/.test(url) || /[\u0000-\u001f\u007f-\u009f]/.test(model)) throw new Error(t("link.judge.badChars"));
  const scheme = /^(https?):\/\/[^/?#\s]+/i.exec(url);
  const host = scheme ? urlHost(url) : null;
  if (!scheme || !host) throw new Error(t("link.judge.needHttps"));
  if (scheme[1].toLowerCase() === "http" && !isLoopbackHost(host)) throw new Error(t("link.judge.needHttps"));
  if (!("key" in q)) return { url, model };
  // The key: present means the owner meant to pass one, so an empty value is a mistake, not "no key".
  // Messages about it name the field only, never the value.
  const key = q.key.trim();
  if (!key) throw new Error(t("link.judge.emptyKey"));
  if (key.length > JUDGE_LINK_MAX_KEY) throw new Error(t("link.judge.keyTooLong"));
  if (/[\u0000-\u001f\u007f-\u009f\s]/.test(key)) throw new Error(t("link.judge.keyBadChars"));
  return { url, model, key };
}

/** wardenclaw://feed?card=<id> from a notification → card id (otherwise null). */
export function cardIdFromUrl(url: string | null | undefined): string | null {
  if (!url) return null;
  const m = /^wardenclaw:\/\/feed\?(?:.*&)?card=([^&#]+)/i.exec(url);
  if (!m) return null;
  try {
    return decodeURIComponent(m[1]);
  } catch {
    return null;
  }
}

/**
 * Where a link leads: feed?card= (card), feed (the feed with the "Missed" summary), pair (the field
 * on the "Connect" tab), judge (the URL, model and optional API key fields on the "Mode" tab, in
 * every build; a refused judge link routes to judge-invalid so that "Mode" can say why), bench (only if
 * bench=true). Anything else, including bench in a release, null.
 */
export function routeLink(url: string | null | undefined, opts: { bench: boolean }): LinkRoute | null {
  if (!url) return null;
  const u = url.trim();
  if (/^wardenclaw:\/\/bench\b/i.test(u)) return opts.bench ? { kind: "bench", url: u } : null;
  if (/^wardenclaw:\/\/pair\b/i.test(u)) return { kind: "pair", link: u };
  if (/^wardenclaw:\/\/judge\b/i.test(u)) {
    try {
      return { kind: "judge", ...parseJudgeLink(u) };
    } catch (e) {
      return { kind: "judge-invalid", error: errMsg(e) };
    }
  }
  const id = cardIdFromUrl(u);
  if (id) return { kind: "card", id };
  if (/^wardenclaw:\/\/feed\b/i.test(u)) return { kind: "feed" };
  return null;
}

/** What to do with a pair link that came from outside, given the current server binding. */
export type PairLinkPlan =
  | { kind: "fill" } // no server: the link goes into the field, connecting via the button
  | { kind: "same"; host: string } // link to the already connected server: nothing to do
  | { kind: "replace"; host: string; current: string } // another server: forget the current one first
  | { kind: "invalid"; error: string };

/**
 * Parsing a pair link while a server is already connected (or awaiting approval). Previously such a
 * link went into a field that the connected view does not have, and silently vanished. Connecting
 * is still only on a tap and with the owner's confirmation: the plan says what to show but does
 * nothing.
 */
export function planPairLink(linkText: string, current: { status: string; host: string | null; supervisorId: string | null }): PairLinkPlan {
  const bound = current.status !== "unpaired" && current.status !== "rejected" && !!current.supervisorId;
  let l: ReturnType<typeof parsePairLink>;
  try {
    l = parsePairLink(linkText);
  } catch (e) {
    return bound ? { kind: "invalid", error: errMsg(e) } : { kind: "fill" };
  }
  if (!bound) return { kind: "fill" };
  const host = l.host || l.supervisorId.slice(0, 12);
  if (l.supervisorId === current.supervisorId) return { kind: "same", host: current.host || host };
  return { kind: "replace", host, current: current.host || (current.supervisorId ?? "").slice(0, 12) };
}
