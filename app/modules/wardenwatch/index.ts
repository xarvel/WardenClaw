// SPDX-License-Identifier: GPL-3.0-or-later
// Background watch: JS wrapper of modules/wardenwatch. The headless task name matches
// WatchService.TASK_KEY; the task itself is registered by src/core/background.ts.
import Native from "./src/WardenWatchModule";

export type { WatchTexts, WatchRequest, WatchUpdate } from "./src/WardenWatchModule";
export const WATCH_TASK = "WardenWatch";
export const watch = Native;
export const watchAvailable = () => Native !== null;
