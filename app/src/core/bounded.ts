// SPDX-License-Identifier: GPL-3.0-or-later
// Capped memory of resolved cards: entries live for minutes, while the app
// process (Android background service) lives for weeks. Pure module (no RN): the tests compile it.

/** How many recent ids to remember: resolved ones (seenResolved) and our own decisions (myDecisions). */
export const RESOLVED_MEMORY = 2000;

/** Remove the oldest entries (Set and Map insertion order) while there are more than max. */
export function trimOldest(m: Set<string> | Map<string, unknown>, max = RESOLVED_MEMORY): void {
  const extra = m.size - max;
  if (extra <= 0) return;
  let i = 0;
  for (const k of m.keys()) {
    if (i++ >= extra) break;
    m.delete(k);
  }
}

/** Mark an id in the set as the most recent (end of the order) and trim to the cap. */
export function addRecent(s: Set<string>, id: string, max = RESOLVED_MEMORY): void {
  s.delete(id);
  s.add(id);
  trimOldest(s, max);
}
