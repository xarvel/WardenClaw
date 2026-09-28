// SPDX-License-Identifier: GPL-3.0-or-later
// Experimental: on-device judge, strictly an adviser. Computes the on-phone model's opinion for cards
// visible on the "Feed" screen and shows it in a separate badge. Never approves, never denies
// and never signs anything: the decision and the signature belong to the human only. Nothing goes
// to the server; the opinion and the human's decision are written to the local journal
// for later comparison.
//
// Runs when: enabled in Experimental, feed focused, app on screen (AppState active),
// card in the visible area of the list. Never runs in the background (wardenwatch service, headless).
// Card left the visible area / user left the feed → the current generation is aborted.
// Models are unloaded after idle time and immediately when the app goes to the background.
import { errMsg } from "../core/errMsg";
import { AppState } from "react-native";
import type { Card } from "../core/approvals";
import { getLang } from "../core/i18n";
import { appendEntry } from "../core/journal";
import { getState, pushLog } from "../core/store";
import { catalogModel } from "../bench/catalog";
import { Engine, loadEngine } from "../bench/engines";
import { kevOpinion } from "./prompts";
import { checkModel } from "./files";
import { CardOpinions, EXP_MODELS, ExpModelId, getLJ, modelsForMode, Opinion, setLJ, setOpinion } from "./state";

export const IDLE_UNLOAD_MS = 60_000;
// Keep the production adviser CPU-only until an iPhone benchmark validates Metal.
const ENGINE_OPTS = { threads: 4, grammar: true, nPredict: 32, nCtx: 2048, gpuLayers: 0 };

let visible: string[] = []; // ids of cards in the visible area of the feed, in order
let feedFocused = false;
let appActive = AppState.currentState === "active";
const wantExplain = new Set<string>();

const engines: Partial<Record<ExpModelId, Engine>> = {};
let running = false;
let current: { cardId: string; model: ExpModelId; what: "verdict" | "explain"; cancelled: boolean } | null = null;
let idleTimer: ReturnType<typeof setTimeout> | null = null;

AppState.addEventListener("change", (st) => {
  appActive = st === "active";
  if (!appActive) {
    cancelCurrent("app left foreground");
    void unloadAll("background");
  } else pump();
});

const canRun = () => getLJ().enabled && feedFocused && appActive && AppState.currentState === "active";

/** The feed reports which cards are currently visible. */
export function setVisibleCards(ids: string[]) {
  visible = ids;
  const live = new Set(getState().cards.map((c) => c.id));
  const ops = getLJ().opinions;
  if (Object.keys(ops).some((id) => !live.has(id))) setLJ({ opinions: Object.fromEntries(Object.entries(ops).filter(([id]) => live.has(id))) });
  if (current && !visible.includes(current.cardId)) cancelCurrent("card left screen");
  pump();
}

export function setFeedFocused(on: boolean) {
  feedFocused = on;
  if (!on) cancelCurrent("left feed");
  pump();
}

/** Card expanded: an explanation is needed (Qwen3-4B only, as a separate request). */
export function requestExplanation(cardId: string, on: boolean) {
  if (on) wantExplain.add(cardId);
  else {
    wantExplain.delete(cardId);
    if (current?.cardId === cardId && current.what === "explain") cancelCurrent("card collapsed");
    const ex = getLJ().opinions[cardId]?.explain;
    if (ex === "pending") setOpinion(cardId, { explain: undefined });
  }
  pump();
}

function cancelCurrent(why: string) {
  if (!current || current.cancelled) return;
  current.cancelled = true;
  const eng = engines[current.model];
  pushLog(`local judge: cancel ${current.model} ${current.what} ${current.cardId.slice(0, 8)} (${why})`);
  // llama.rn stopCompletion may return a non-promise: .catch on undefined crashed the app (build #5)
  if (eng?.stop) Promise.resolve().then(() => eng.stop!()).catch(() => {});
}

function isOpinion(v: CardOpinions[ExpModelId]): v is Opinion {
  return !!v && v !== "pending" && !("error" in v);
}

type Job = { card: Card; model: ExpModelId; what: "verdict" | "explain" };

function nextJob(): Job | null {
  const s = getLJ();
  const cards = getState().cards;
  const models = modelsForMode(s.mode);
  const ready = (m: ExpModelId) => s.models[m].state === "ready";
  // "both": the fast Kev-multi over all visible cards first, then Qwen3-4B
  for (const m of models) {
    if (!ready(m)) continue;
    for (const id of visible) {
      const card = cards.find((c) => c.id === id);
      if (card && (s.opinions[id] ?? {})[m] === undefined) return { card, model: m, what: "verdict" };
    }
  }
  // explanations: after the verdicts of all visible cards
  for (const id of visible) {
    if (!wantExplain.has(id) || !models.includes("qwen4") || !ready("qwen4")) continue;
    const card = cards.find((c) => c.id === id);
    const op = s.opinions[id] ?? {};
    if (card && isOpinion(op.qwen4) && op.explain === undefined) return { card, model: "qwen4", what: "explain" };
  }
  return null;
}

async function ensureEngine(m: ExpModelId): Promise<{ engine: Engine; loadMs: number | null }> {
  const have = engines[m];
  if (have) return { engine: have, loadMs: null };
  const t0 = Date.now();
  const engine = await loadEngine(catalogModel(EXP_MODELS[m].benchId), ENGINE_OPTS);
  engines[m] = engine;
  setLJ((s) => ({ inMemory: [...new Set([...s.inMemory, m])] }));
  pushLog(`local judge: ${m} loaded in ${Date.now() - t0} ms`);
  return { engine, loadMs: Date.now() - t0 };
}

export async function unloadAll(why: string) {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = null;
  if (running) return; // unload once the current job finishes (pump sets the timer again)
  for (const m of Object.keys(engines) as ExpModelId[]) {
    const e = engines[m];
    delete engines[m];
    await Promise.resolve()
      .then(() => e?.release())
      .catch(() => {});
    pushLog(`local judge: ${m} unloaded (${why})`);
  }
  setLJ({ inMemory: [] });
}

function scheduleIdleUnload() {
  if (idleTimer) clearTimeout(idleTimer);
  if (!Object.keys(engines).length) return;
  idleTimer = setTimeout(() => void unloadAll("idle"), IDLE_UNLOAD_MS);
}

function journalOpinion(card: Card, op: Opinion) {
  appendEntry({
    ts: Date.now(),
    kind: "local_opinion",
    approval_id: card.id,
    approval_kind: card.kind,
    summary: `${EXP_MODELS[op.model].title}: ${op.decision} · risk ${op.risk} · ${(op.ms / 1000).toFixed(1)} s`,
    decided_by: null,
    decision: op.decision,
    latency_ms: op.ms,
    payload: JSON.stringify({ experimental: true, model: EXP_MODELS[op.model].benchId, opinion: op }),
  });
}

/** Human decision on a card: log the local model's opinion (if any) next to it for later comparison. */
export function noteHumanDecision(card: Card, decision: string, applied: boolean) {
  const op = getLJ().opinions[card.id];
  if (!op) return;
  cancelCurrentFor(card.id);
  const ops = (["kevm", "qwen4"] as ExpModelId[]).map((m) => op[m]).filter(isOpinion);
  if (!ops.length) return;
  const human = decision === "allow-once" ? "allow" : decision;
  appendEntry({
    ts: Date.now(),
    kind: "local_opinion",
    approval_id: card.id,
    approval_kind: card.kind,
    summary: `${ops.map((o) => `${EXP_MODELS[o.model].title}: ${o.decision}`).join(", ")} · human: ${human}${applied ? "" : " (not applied)"}`,
    decided_by: null,
    decision: human,
    latency_ms: null,
    payload: JSON.stringify({ experimental: true, human, applied, opinions: ops, agree: ops.map((o) => ({ model: o.model, same: o.decision === human })) }),
  });
}

function cancelCurrentFor(cardId: string) {
  if (current?.cardId === cardId) cancelCurrent("card resolved");
}

async function runJob(job: Job) {
  const { card, model, what } = job;
  const cur = { cardId: card.id, model, what, cancelled: false };
  current = cur;
  setLJ({ busy: `${model} · ${what} · ${card.id.slice(0, 8)}` });
  if (what === "verdict") setOpinion(card.id, { [model]: "pending" });
  else setOpinion(card.id, { explain: "pending" });
  try {
    const { engine, loadMs } = await ensureEngine(model);
    if (cur.cancelled) throw new Error("cancelled");
    if (what === "verdict") {
      const t0 = Date.now();
      const out = await engine.judge(card);
      const ms = Date.now() - t0;
      if (cur.cancelled) throw new Error("cancelled");
      if (!out.decision) throw new Error(out.error ?? "unparsed answer");
      const op: Opinion =
        model === "kevm"
          ? { model, ...kevOpinion(out.probs ?? [], out.decision), ms, loadMs, at: Date.now() }
          : { model, decision: out.decision, risk: out.risk ?? 50, ms, loadMs, at: Date.now() };
      setOpinion(card.id, { [model]: op });
      journalOpinion(card, op);
    } else {
      const op = getLJ().opinions[card.id]?.qwen4;
      if (!isOpinion(op) || !engine.explain) throw new Error("no verdict");
      const r = await engine.explain(card, op.decision, op.risk, getLang());
      if (cur.cancelled) throw new Error("cancelled");
      setOpinion(card.id, { explain: r.explanation ? { ...r.explanation, ms: r.ms } : { error: "unparsed answer" } });
    }
  } catch (e) {
    const msg = errMsg(e);
    if (cur.cancelled || msg === "cancelled") {
      // recompute when the card comes back on screen
      if (what === "verdict") setOpinion(card.id, { [model]: undefined });
      else setOpinion(card.id, { explain: undefined });
    } else {
      pushLog(`local judge: ${model} ${what} failed: ${msg}`);
      if (what === "verdict") setOpinion(card.id, { [model]: { error: msg.slice(0, 200) } });
      else setOpinion(card.id, { explain: { error: msg.slice(0, 200) } });
    }
  } finally {
    current = null;
    setLJ({ busy: null });
  }
}

/** Main loop: one job at a time, without blocking the UI (all native calls are async). */
export function pump() {
  if (running) return;
  if (!canRun()) {
    if (!appActive) void unloadAll("background");
    else scheduleIdleUnload();
    return;
  }
  const job = nextJob();
  if (!job) {
    scheduleIdleUnload();
    return;
  }
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = null;
  running = true;
  runJob(job).finally(() => {
    running = false;
    setTimeout(pump, 0);
  });
}

/** Experimental turned off or mode changed: abort, unload, forget unfinished work. */
export async function resetLocalJudge() {
  cancelCurrent("settings changed");
  wantExplain.clear();
  setLJ((s) => {
    const opinions: typeof s.opinions = {};
    for (const [id, op] of Object.entries(s.opinions)) {
      const clean: CardOpinions = {};
      for (const k of ["kevm", "qwen4", "explain"] as const) {
        const v = op[k];
        if (v && v !== "pending") (clean as Record<string, unknown>)[k] = v;
      }
      opinions[id] = clean;
    }
    return { opinions };
  });
  await unloadAll("settings changed");
  pump();
}

/** On opening the feed/settings: check the weights (no download). */
export async function refreshLocalModels() {
  for (const m of ["qwen4", "kevm"] as ExpModelId[]) await checkModel(m).catch(() => {});
  pump();
}
