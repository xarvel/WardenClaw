// SPDX-License-Identifier: GPL-3.0-or-later
// Entry point to the bench build code: judge benchmark, mock cards (wardenclaw://bench?…), screen
// protection switch. Loaded only by a lazy require in App.tsx and ModeScreen.tsx under the condition
//   process.env.EXPO_PUBLIC_WARDENCLAW_BENCH === "1"   (bench profile in eas.json)
// In other builds babel-preset-expo inlines the variable's value, Metro folds the condition to false
// before collecting dependencies, and this module, together with runner, the benchmark screen and
// fixtures, does not get into the bundle (check: the preview bundle has no WARDEN_BENCH string).
export { default as BenchModal } from "../ui/screens/BenchScreen";
export { handleBenchUrl } from "./runner";
export { BenchSection, initBenchScreen } from "./BenchSection";
