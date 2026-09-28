// SPDX-License-Identifier: GPL-3.0-or-later
// One way to turn a caught value into a sentence. Errors, strings and anything else.

/** Readable message from a caught value. */
export function errMsg(e: unknown): string {
  return String((e as Error)?.message ?? e);
}
