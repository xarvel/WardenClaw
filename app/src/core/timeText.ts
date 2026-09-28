// SPDX-License-Identifier: GPL-3.0-or-later
// Clock text shared by the screens and the service notification. Pure module (no RN).

/** HH:MM for a timestamp in milliseconds, local time. */
export function formatHhmm(ms: number): string {
  const d = new Date(ms);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}
