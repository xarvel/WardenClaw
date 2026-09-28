// SPDX-License-Identifier: GPL-3.0-or-later
// Timings of the feed animation and the hold-to-allow gesture.
export const HOLD_MS = 1500;
export const GUARD_MS = 700;
export const LEAVE_MS = 260;
/** Expiry bar turns red when less than this many ms remain. */
export const TTL_URGENT_MS = 20_000;
/** Snackbar auto-dismiss delay in ms. */
export const SNACK_DURATION_MS = 4_000;
/** Debounce gap between dialog opens triggered by a single touch. */
export const DIALOG_DEBOUNCE_MS = 1_000;
/** Max ms between pressOut and press that still counts as a touch (not a TalkBack click). */
export const TOUCH_PRESS_GAP_MS = 300;
/** Extra buffer after LEAVE_MS for the merge re-run, ensuring the animation fully completes. */
export const LEAVE_MERGE_BUFFER_MS = 80;
/** Grace period after LEAVE_MS before a departing card is removed from the list. */
export const LEAVE_GRACE_MS = 60;
