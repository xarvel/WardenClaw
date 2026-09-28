// SPDX-License-Identifier: GPL-3.0-or-later
// Experimental: on-device judge. State (a small store on useSyncExternalStore) and settings.
import { useSyncExternalStore } from "react";
import AsyncStorage from "@react-native-async-storage/async-storage";
import type { Decision3, Explanation } from "./prompts";

export type ExpModelId = "qwen4" | "kevm";
export type LocalJudgeMode = "qwen4" | "kevm" | "both";

/** Benchmark catalog entries kept after the spike (docs/judge-bench-spike.md, stages 7-8). */
export const EXP_MODELS: Record<ExpModelId, { benchId: string; title: string }> = {
  qwen4: { benchId: "qwen3-4b-2507-q4_0-short", title: "Qwen3-4B" },
  kevm: { benchId: "kev-0.6b-q4-multi", title: "Kev-multi" },
};

export const modelsForMode = (m: LocalJudgeMode): ExpModelId[] => (m === "both" ? ["kevm", "qwen4"] : [m]);

export type Opinion = {
  model: ExpModelId;
  decision: Decision3;
  risk: number;
  ms: number; // verdict time (excluding model load)
  loadMs: number | null; // load time, if the model was loaded for this card
  flags?: string[]; // Kev-multi: questions with p(yes) ≥ 0.5
  at: number;
};

export type CardOpinions = {
  kevm?: Opinion | "pending" | { error: string };
  qwen4?: Opinion | "pending" | { error: string };
  explain?: (Explanation & { ms: number }) | "pending" | { error: string };
};

export type ModelFileState = "missing" | "downloading" | "verifying" | "ready" | "unverified" | "corrupt" | "error";
export type ModelStatus = { state: ModelFileState; received: number; total: number; error?: string };

export type LocalJudgeState = {
  enabled: boolean;
  mode: LocalJudgeMode;
  loaded: boolean; // settings have been read
  models: Record<ExpModelId, ModelStatus>;
  opinions: Record<string, CardOpinions>;
  inMemory: ExpModelId[]; // which models are currently loaded
  busy: string | null; // "qwen4 · <card>", for debugging
};

let state: LocalJudgeState = {
  enabled: false,
  mode: "qwen4",
  loaded: false,
  models: { qwen4: { state: "missing", received: 0, total: 0 }, kevm: { state: "missing", received: 0, total: 0 } },
  opinions: {},
  inMemory: [],
  busy: null,
};
const subs = new Set<() => void>();
export const getLJ = () => state;
export function setLJ(patch: Partial<LocalJudgeState> | ((s: LocalJudgeState) => Partial<LocalJudgeState>)) {
  state = { ...state, ...(typeof patch === "function" ? patch(state) : patch) };
  for (const s of subs) s();
}
export function subscribeLJ(fn: () => void) {
  subs.add(fn);
  return () => {
    subs.delete(fn);
  };
}
export function useLJ<T>(sel: (s: LocalJudgeState) => T): T {
  return useSyncExternalStore(subscribeLJ, () => sel(state), () => sel(state));
}
export function setOpinion(cardId: string, patch: Partial<CardOpinions>) {
  setLJ((s) => ({ opinions: { ...s.opinions, [cardId]: { ...s.opinions[cardId], ...patch } } }));
}

const K_SETTINGS = "wc.exp.localJudge.v1";

export async function loadLocalJudgeSettings() {
  try {
    const raw = await AsyncStorage.getItem(K_SETTINGS);
    const v = raw ? (JSON.parse(raw) as { enabled?: unknown; mode?: unknown }) : {};
    const mode: LocalJudgeMode = v.mode === "kevm" || v.mode === "both" ? v.mode : "qwen4";
    setLJ({ enabled: v.enabled === true, mode, loaded: true });
  } catch {
    setLJ({ loaded: true });
  }
}

export async function saveLocalJudgeSettings(patch: { enabled?: boolean; mode?: LocalJudgeMode }) {
  setLJ(patch);
  await AsyncStorage.setItem(K_SETTINGS, JSON.stringify({ enabled: state.enabled, mode: state.mode }));
}
