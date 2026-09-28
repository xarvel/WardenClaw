// SPDX-License-Identifier: GPL-3.0-or-later
// "Judge benchmark" spike: JS wrapper for modules/benchprobe.
import Native from "./src/BenchProbeModule";

export type { ProbeSnapshot } from "./src/BenchProbeModule";
export const probe = Native;
