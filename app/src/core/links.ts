// SPDX-License-Identifier: GPL-3.0-or-later
// wardenclaw:// links the app understands. Any app on the phone, or a web page on click, can open
// the scheme, so a link does nothing by itself: a card is only shown, a pairing link only fills in
// the field (connecting takes a tap and the owner's confirmation). wardenclaw://bench (benchmark
// and mock cards) is understood only by the bench build.
// Pure module (no RN): the tests compile it.

import { errMsg } from "./errMsg";
import { parsePairLink } from "./relayProto";

export type LinkRoute = { kind: "card"; id: string } | { kind: "feed" } | { kind: "pair"; link: string } | { kind: "bench"; url: string };

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
 * on the "Connect" tab), bench (only if bench=true). Anything else, including bench in a release,
 * null.
 */
export function routeLink(url: string | null | undefined, opts: { bench: boolean }): LinkRoute | null {
  if (!url) return null;
  const u = url.trim();
  if (/^wardenclaw:\/\/bench\b/i.test(u)) return opts.bench ? { kind: "bench", url: u } : null;
  if (/^wardenclaw:\/\/pair\b/i.test(u)) return { kind: "pair", link: u };
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
