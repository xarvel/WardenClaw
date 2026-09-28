// SPDX-License-Identifier: GPL-3.0-or-later
// "Judge benchmark" spike: candidates. Weights are downloaded from HuggingFace on a button tap into
// documentDirectory/models/<id>/, nothing is packed into the APK. Nothing here is selected by default
// for the app's judge.

export type EngineKind = "llama" | "kev-onnx" | "kev-multi-onnx" | "laya-onnx";

export type ModelFile = { name: string; url: string; size: number; sha256?: string };

export type BenchModel = {
  id: string;
  title: string;
  engine: EngineKind;
  license: string;
  files: ModelFile[];
  /** Main file (GGUF or .onnx); the other files sit next to it. */
  main: string;
  /** Weights directory shared with another entry (prompt variants of one model). */
  dirId?: string;
  /** Dropped after the spike (stage 7): in the benchmark list only behind a developer flag. */
  retired?: boolean;
  /** llama: short output (decision + risk), explanation as a separate request (stage 8). */
  short?: boolean;
};

const HF = "https://huggingface.co";
const f = (repo: string, name: string, size: number, saveAs?: string, sha256?: string): ModelFile => ({ name: saveAs ?? name, url: `${HF}/${repo}/resolve/main/${name}`, size, ...(sha256 ? { sha256 } : {}) });

export const CATALOG: BenchModel[] = [
  {
    id: "qwen3-1.7b-q4_0",
    title: "Qwen3-1.7B Q4_0",
    engine: "llama",
    license: "Apache-2.0",
    files: [f("unsloth/Qwen3-1.7B-GGUF", "Qwen3-1.7B-Q4_0.gguf", 1056782912)],
    main: "Qwen3-1.7B-Q4_0.gguf",
    retired: true,
  },
  {
    id: "qwen3-1.7b-q4_k_m",
    title: "Qwen3-1.7B Q4_K_M",
    engine: "llama",
    license: "Apache-2.0",
    files: [f("unsloth/Qwen3-1.7B-GGUF", "Qwen3-1.7B-Q4_K_M.gguf", 1107409472)],
    main: "Qwen3-1.7B-Q4_K_M.gguf",
    retired: true,
  },
  {
    id: "qwen3-4b-2507-q4_0",
    title: "Qwen3-4B-Instruct-2507 Q4_0",
    engine: "llama",
    license: "Apache-2.0",
    files: [f("unsloth/Qwen3-4B-Instruct-2507-GGUF", "Qwen3-4B-Instruct-2507-Q4_0.gguf", 2375773280, undefined, "e0ba675d86ab277c61701c6793659b2ae801d95e3be791464c321e6fbf613be2")],
    main: "Qwen3-4B-Instruct-2507-Q4_0.gguf",
  },
  {
    id: "qwen3-4b-2507-q4_0-short",
    title: "Qwen3-4B-Instruct-2507 Q4_0, short output (decision + risk)",
    engine: "llama",
    license: "Apache-2.0",
    files: [],
    main: "Qwen3-4B-Instruct-2507-Q4_0.gguf",
    dirId: "qwen3-4b-2507-q4_0",
    short: true,
  },
  {
    id: "qwen3-4b-2507-q4_k_m",
    title: "Qwen3-4B-Instruct-2507 Q4_K_M",
    engine: "llama",
    license: "Apache-2.0",
    files: [f("unsloth/Qwen3-4B-Instruct-2507-GGUF", "Qwen3-4B-Instruct-2507-Q4_K_M.gguf", 2497281120)],
    main: "Qwen3-4B-Instruct-2507-Q4_K_M.gguf",
    retired: true,
  },
  {
    id: "qwen2.5-1.5b-q4_0",
    title: "Qwen2.5-1.5B-Instruct Q4_0 (baseline 26.09)",
    engine: "llama",
    license: "Apache-2.0",
    files: [f("Qwen/Qwen2.5-1.5B-Instruct-GGUF", "qwen2.5-1.5b-instruct-q4_0.gguf", 1066227232)],
    main: "qwen2.5-1.5b-instruct-q4_0.gguf",
    retired: true,
  },
  {
    id: "kev-0.6b-q4-onnx",
    title: "Kev-0.6B q4 (ONNX, typed)",
    engine: "kev-onnx",
    license: "Apache-2.0",
    files: [
      f("onnx-community/kev-0.6b-ONNX", "onnx/model_q4.onnx", 1245327, "model_q4.onnx", "db4657bb2f14f073cb4d289260dfc50af31adc1260a04cb2fe17c4f03da0881a"),
      f("onnx-community/kev-0.6b-ONNX", "onnx/model_q4.onnx_data", 374822912, "model_q4.onnx_data", "20668ed757f5de294c254cab111910fbc37fb11addca8189e3f58b3c695f90f1"),
      f("onnx-community/kev-0.6b-ONNX", "tokenizer.json", 7031645, undefined, "c0382117ea329cdf097041132f6d735924b697924d6f6fc3945713e96ce87539"),
      f("onnx-community/kev-0.6b-ONNX", "tokenizer_config.json", 9678, undefined, "3c04ed3ca964ea2f6b2b5faf0dc4d31aec1cb1e8b4bcf63f402d295046b422b5"),
    ],
    main: "model_q4.onnx",
    retired: true, // single choice; weights shared with kev-multi
  },
  {
    id: "kev-0.6b-q4-multi",
    title: "Kev-0.6B q4, 5 noul questions (ONNX, typed)",
    engine: "kev-multi-onnx",
    license: "Apache-2.0",
    files: [],
    main: "model_q4.onnx",
    dirId: "kev-0.6b-q4-onnx",
  },
  {
    id: "laya-onnx-fp32",
    title: "Laya 421M fp32 (ONNX, typed)",
    engine: "laya-onnx",
    license: "Apache-2.0",
    files: [
      f("receptron/laya-onnx", "laya.onnx", 3807291),
      f("receptron/laya-onnx", "laya.onnx.data", 1685258240),
      f("receptron/laya-onnx", "laya_config.json", 369),
      f("receptron/laya-onnx", "tokenizer/tokenizer.json", 3583228, "tokenizer.json"),
      f("receptron/laya-onnx", "tokenizer/tokenizer_config.json", 308, "tokenizer_config.json"),
    ],
    main: "laya.onnx",
    retired: true,
  },
];

/** The entry that holds the files (prompt variants point to it via dirId). */
export const filesOf = (m: BenchModel): ModelFile[] => (m.dirId ? CATALOG.find((x) => x.id === m.dirId) ?? m : m).files;
export const modelSize = (m: BenchModel): number => filesOf(m).reduce((s, x) => s + x.size, 0);
export const catalogModel = (id: string): BenchModel => {
  const m = CATALOG.find((x) => x.id === id);
  if (!m) throw new Error(`unknown model ${id}`);
  return m;
};
