// SPDX-License-Identifier: GPL-3.0-or-later
// Entry point to the on-phone judge (Experimental) for the rest of the app. Loaded only via
//   process.env.EXPO_PUBLIC_WARDENCLAW_FEATURE_PHONE_JUDGE === "1" ? require("…/localjudge/entry") : null
// Without the build flag (production, preview) Metro bundles neither src/localjudge nor the model
// engines (src/bench/engines: llama.rn, onnxruntime-react-native, @huggingface/tokenizers).
// The feature's screens (src/ui/Experimental.tsx, src/ui/LocalOpinion.tsx) are loaded the same way.
export { getLJ, loadLocalJudgeSettings } from "./state";
export { noteHumanDecision, refreshLocalModels, setFeedFocused, setVisibleCards } from "./runtime";
