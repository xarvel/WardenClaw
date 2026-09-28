// SPDX-License-Identifier: GPL-3.0-or-later
// "Missed": requests that expired without a decision (the server denied them itself, the agent got
// a denial). The block in the feed stays until the human hides it, and survives a process restart
// (AsyncStorage): the service and the UI live in one JS context, but Android may kill the process.
// Background notifications look here to tell an expired request ("Expired, denied") from a
// decided one.
import AsyncStorage from "@react-native-async-storage/async-storage";
import type { Card } from "./approvals";
import { getState, setState } from "./store";

export type MissedItem = { id: string; summary: string; host: string | null; createdAt: number; expiredAt: number };

const K_MISSED = "wc.missed.v1";
const MAX_MISSED = 20;

/** Card host: from the signed wardend envelope, otherwise from the gateway card. */
export function cardHost(card: Card): string | null {
  return card.gate?.exec?.host || card.host || null;
}

export async function loadMissed(): Promise<MissedItem[]> {
  try {
    const raw = await AsyncStorage.getItem(K_MISSED);
    const list = raw ? (JSON.parse(raw) as MissedItem[]) : [];
    return Array.isArray(list) ? list.filter((m) => m && typeof m.id === "string").slice(0, MAX_MISSED) : [];
  } catch {
    return [];
  }
}

function persist(list: MissedItem[]) {
  (list.length ? AsyncStorage.setItem(K_MISSED, JSON.stringify(list)) : AsyncStorage.removeItem(K_MISSED)).catch(() => {});
}

/** The request expired without a decision. Call before removeCard: the background uses this list to switch the notification to "Expired". */
export function noteMissed(card: Card, at = Date.now()) {
  const s = getState();
  if (s.missed.some((m) => m.id === card.id)) return;
  const item: MissedItem = { id: card.id, summary: card.summary, host: cardHost(card) ?? s.wardend.host, createdAt: card.createdAtMs, expiredAt: card.expiresAtMs && card.expiresAtMs < at ? card.expiresAtMs : at };
  const list = [item, ...s.missed].slice(0, MAX_MISSED);
  setState({ missed: list });
  persist(list);
}

/** "Hide" in the "Missed" block. */
export function dismissMissed() {
  setState({ missed: [] });
  persist([]);
}
