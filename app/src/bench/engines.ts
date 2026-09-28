// SPDX-License-Identifier: GPL-3.0-or-later
// "Judge benchmark" spike: runtimes. llama.rn (GGUF, JSON via a grammar from a JSON schema,
// prompt prefix cache) and onnxruntime-react-native (Kev / Laya, one pass without generation).
// Native packages load lazily: if a module failed to build, only its engine fails, not the app.
import * as FS from "expo-file-system/legacy";
import type { Card } from "../core/approvals";
import { buildUserPrompt, extractJson, systemPrompt } from "../core/decide";
import type { Lang } from "../core/i18n";
import { EXPLAIN_N_PREDICT, EXPLAIN_SCHEMA, Explanation, SHORT_N_PREDICT, SHORT_SCHEMA, explainUserPrompt, localSystemPrompt, parseExplain, parseShort, verdictUserPrompt } from "../localjudge/prompts";
import type { BenchModel } from "./catalog";
import { argmaxDecision, buildKevMultiSequence, buildKevSequence, kevMultiDecision, buildLayaSequence, Decision3, KEV_DELIMS, layaTemperature, LayaConfig, LayaIds, softmax, VERDICT_KEYS } from "./typed";

export const MODELS_DIR = `${FS.documentDirectory}models/`;
export const modelDir = (m: BenchModel) => `${MODELS_DIR}${m.dirId ?? m.id}/`;
const plainPath = (uri: string) => uri.replace(/^file:\/\//, "");

export type EngineOptions = { threads: number; grammar: boolean; nPredict: number; nCtx: number; gpuLayers: number };

export type JudgeOutput = {
  decision: Decision3 | null; // null = answer not parsed
  jsonValid: boolean | null; // null for typed models (no JSON is generated)
  risk?: number | null;
  probs?: number[]; // allow/ask/deny for Kev/Laya
  promptTokens?: number;
  cachedTokens?: number;
  promptTps?: number;
  genTokens?: number;
  genTps?: number;
  promptMs?: number;
  genMs?: number;
  inputTokens?: number;
  raw?: string;
  error?: string;
};

export interface Engine {
  info: Record<string, unknown>;
  judge(card: Card): Promise<JudgeOutput>;
  release(): Promise<void>;
  /** Abort the current generation (llama.rn stopCompletion); ORT runs one pass, nothing to abort. */
  stop?(): Promise<void>;
  /** Short mode: explanation as a separate request (the card comes from the prefix cache). */
  explain?(card: Card, decision: Decision3, risk: number, lang: Lang): Promise<{ explanation: Explanation | null; ms: number; genTokens?: number; raw?: string }>;
}

// ---------------------------------------------------------------------------
// llama.rn
// ---------------------------------------------------------------------------
const VERDICT_SCHEMA = {
  type: "object",
  properties: {
    decision: { type: "string", enum: ["allow", "deny", "ask"] },
    risk: { type: "integer", minimum: 0, maximum: 100 },
    explanation: { type: "string" },
    goal_fit: { type: "string" },
    reason: { type: "string" },
  },
  required: ["decision", "risk", "explanation", "goal_fit", "reason"],
  additionalProperties: false,
};

function parseVerdict(text: string): { decision: Decision3 | null; valid: boolean; risk: number | null } {
  // "Valid JSON" = strict JSON.parse of the whole trimmed answer + decision from the set + numeric risk.
  let valid = false;
  let obj: Record<string, unknown> | null = null;
  try {
    obj = JSON.parse(text.trim()) as Record<string, unknown>;
    valid = !!obj && typeof obj === "object" && ["allow", "ask", "deny"].includes(String(obj.decision)) && typeof obj.risk === "number";
  } catch {
    try {
      obj = extractJson(text); // as in production: extract the outer {...}
    } catch {
      obj = null;
    }
  }
  const d = obj?.decision;
  const decision = d === "allow" || d === "ask" || d === "deny" ? d : null;
  const risk = typeof obj?.risk === "number" ? (obj.risk as number) : null;
  return { decision, valid, risk };
}

async function loadLlama(m: BenchModel, o: EngineOptions): Promise<Engine> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { initLlama } = require("llama.rn") as typeof import("llama.rn");
  const ctx = await initLlama({
    model: `${modelDir(m)}${m.main}`,
    n_ctx: o.nCtx,
    n_batch: 512,
    n_threads: o.threads,
    use_mlock: true,
    use_mmap: true,
    n_gpu_layers: o.gpuLayers,
  });
  const short = !!m.short;
  const sys = short ? localSystemPrompt() : systemPrompt();
  const schema = short ? SHORT_SCHEMA : VERDICT_SCHEMA;
  return {
    info: { gpu: (ctx as unknown as { gpu?: boolean }).gpu ?? null, reasonNoGPU: (ctx as unknown as { reasonNoGPU?: string }).reasonNoGPU ?? null, model: (ctx as unknown as { model?: { desc?: string; size?: number; nParams?: number } }).model ?? null },
    async judge(card) {
      const res = await ctx.completion({
        messages: [
          { role: "system", content: sys },
          { role: "user", content: short ? verdictUserPrompt(card) : buildUserPrompt(card) },
        ],
        temperature: 0,
        n_predict: short ? SHORT_N_PREDICT : o.nPredict,
        enable_thinking: false,
        ...(o.grammar || short ? { response_format: { type: "json_schema", json_schema: { strict: true, schema } } } : {}),
      } as Parameters<typeof ctx.completion>[0]);
      const text = String(res.content || res.text || "");
      const sv = short ? parseShort(text) : null;
      const v = short ? { decision: sv?.decision ?? null, valid: !!sv, risk: sv?.risk ?? null } : parseVerdict(text);
      const tm = res.timings;
      return {
        decision: v.decision,
        jsonValid: v.valid,
        risk: v.risk,
        promptTokens: tm?.prompt_n,
        cachedTokens: tm?.cache_n,
        promptTps: tm?.prompt_per_second,
        promptMs: tm?.prompt_ms,
        genTokens: tm?.predicted_n,
        genTps: tm?.predicted_per_second,
        genMs: tm?.predicted_ms,
        raw: text.length > 600 ? `${text.slice(0, 600)}…` : text,
      };
    },
    async explain(card, decision, risk, lang) {
      const t0 = Date.now();
      const res = await ctx.completion({
        messages: [
          { role: "system", content: sys },
          { role: "user", content: explainUserPrompt(card, decision, risk, lang) },
        ],
        temperature: 0,
        n_predict: EXPLAIN_N_PREDICT,
        enable_thinking: false,
        response_format: { type: "json_schema", json_schema: { strict: true, schema: EXPLAIN_SCHEMA } },
      } as Parameters<typeof ctx.completion>[0]);
      const text = String(res.content || res.text || "");
      return { explanation: parseExplain(text), ms: Date.now() - t0, genTokens: res.timings?.predicted_n, raw: text.slice(0, 600) };
    },
    stop: async () => {
      await ctx.stopCompletion();
    },
    release: () => ctx.release(),
  };
}

// ---------------------------------------------------------------------------
// ONNX Runtime: Kev / Laya
// ---------------------------------------------------------------------------
type OrtModule = typeof import("onnxruntime-react-native");
type TokenizerT = { encode(text: string, o?: { add_special_tokens?: boolean }): { ids: number[] }; token_to_id(t: string): number | undefined };

async function readJson<T>(uri: string): Promise<T> {
  return JSON.parse(await FS.readAsStringAsync(uri)) as T;
}

async function loadTokenizer(dir: string): Promise<TokenizerT> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { Tokenizer } = require("@huggingface/tokenizers") as { Tokenizer: new (json: unknown, cfg: unknown) => TokenizerT };
  return new Tokenizer(await readJson(`${dir}tokenizer.json`), await readJson(`${dir}tokenizer_config.json`));
}

function typedState(card: Card): string {
  // The same card the LLM judge sees, without the JSON instruction.
  return buildUserPrompt(card).replace(/\n*Return only JSON\.\s*$/, "").trim();
}

async function loadKev(m: BenchModel, o: EngineOptions, multi = false): Promise<Engine> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const ort = require("onnxruntime-react-native") as OrtModule;
  const dir = modelDir(m);
  const tok = await loadTokenizer(dir);
  const enc = (t: string) => Array.from(tok.encode(t, { add_special_tokens: false }).ids, Number);
  const [STATE, Q, OPT, END, DECIDE] = KEV_DELIMS.map((d) => {
    const ids = enc(d);
    if (ids.length !== 1) throw new Error(`kev delimiter ${d} → ${ids.length} tokens`);
    return ids[0];
  });
  const session = await ort.InferenceSession.create(plainPath(`${dir}${m.main}`), {
    executionProviders: ["cpu"],
    graphOptimizationLevel: "all",
    intraOpNumThreads: o.threads,
  } as never);
  return {
    info: { inputs: session.inputNames, outputs: session.outputNames },
    async judge(card) {
      const delim = { STATE, Q, OPT, END, DECIDE };
      const seq = multi ? buildKevMultiSequence(enc, delim, typedState(card)) : null;
      const single = multi ? null : buildKevSequence(enc, delim, typedState(card));
      const tokens = seq ? seq.tokens : single!.tokens;
      const n = tokens.length;
      const out = await session.run({
        input_ids: new ort.Tensor("int64", BigInt64Array.from(tokens, (x) => BigInt(x)), [1, n]),
        attention_mask: new ort.Tensor("int64", new BigInt64Array(n).fill(BigInt(1)), [1, n]),
      });
      const logits = out[session.outputNames.includes("logits") ? "logits" : session.outputNames[0]].data as Float32Array;
      if (seq) {
        const pYes = seq.groups.map((e) => softmax(e.map((i) => Number(logits[i])))[1]);
        return { decision: kevMultiDecision(pYes), jsonValid: null, probs: pYes.map((x) => Math.round(x * 1e4) / 1e4), inputTokens: n };
      }
      const p = softmax(single!.ends.map((i) => Number(logits[i])));
      return { decision: argmaxDecision(p), jsonValid: null, probs: p.map((x) => Math.round(x * 1e4) / 1e4), inputTokens: n };
    },
    release: () => session.release(),
  };
}

async function loadLaya(m: BenchModel, o: EngineOptions): Promise<Engine> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const ort = require("onnxruntime-react-native") as OrtModule;
  const dir = modelDir(m);
  const cfg = await readJson<LayaConfig>(`${dir}laya_config.json`);
  const tok = await loadTokenizer(dir);
  const id = (t: string) => {
    const v = tok.token_to_id(t);
    if (v === undefined) throw new Error(`special token ${t} missing`);
    return v;
  };
  const ids: LayaIds = { cls: id("[CLS]"), sep: id("[SEP]"), mask: id("[MASK]"), pad: id("[PAD]"), maskTok: "[MASK]" };
  const enc = (t: string) => Array.from(tok.encode(t, { add_special_tokens: false }).ids, Number);
  const session = await ort.InferenceSession.create(plainPath(`${dir}${m.main}`), {
    executionProviders: ["cpu"],
    graphOptimizationLevel: "all",
    intraOpNumThreads: o.threads,
  } as never);
  const temp = layaTemperature(cfg);
  return {
    info: { inputs: session.inputNames, outputs: session.outputNames, temp },
    async judge(card) {
      const { ids: seq, markers } = buildLayaSequence(enc, ids, typedState(card), cfg);
      if (markers.length !== VERDICT_KEYS.length) throw new Error(`options do not fit: ${markers.length}`);
      const L = seq.length;
      const K = markers.length;
      const out = await session.run({
        input_ids: new ort.Tensor("int64", BigInt64Array.from(seq, (x) => BigInt(x)), [1, L]),
        attention_mask: new ort.Tensor("int64", new BigInt64Array(L).fill(BigInt(1)), [1, L]),
        marker_pos: new ort.Tensor("int64", BigInt64Array.from(markers, (x) => BigInt(x)), [1, K]),
        marker_mask: new ort.Tensor("bool", new Uint8Array(K).fill(1), [1, K]),
        qtype: new ort.Tensor("int64", BigInt64Array.from([BigInt(0)]), [1]),
      });
      const logits = out.logits.data as Float32Array;
      const p = softmax(Array.from(logits.subarray(0, K), (v) => v / temp));
      return { decision: argmaxDecision(p), jsonValid: null, probs: p.map((x) => Math.round(x * 1e4) / 1e4), inputTokens: L };
    },
    release: () => session.release(),
  };
}

export async function loadEngine(m: BenchModel, o: EngineOptions): Promise<Engine> {
  if (m.engine === "llama") return loadLlama(m, o);
  if (m.engine === "kev-onnx") return loadKev(m, o);
  if (m.engine === "kev-multi-onnx") return loadKev(m, o, true);
  return loadLaya(m, o);
}
