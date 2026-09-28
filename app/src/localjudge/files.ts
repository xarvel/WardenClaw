// SPDX-License-Identifier: GPL-3.0-or-later
// Experimental: local judge weights. Same documentDirectory/models/<id>/ directory as the benchmark,
// so weights already downloaded during the spike are picked up without downloading again. Each file
// is checked against the sha256 from the catalog (natively, modules/benchprobe); the result is cached
// by size and mtime.
import { errMsg } from "../core/errMsg";
import * as FS from "expo-file-system/legacy";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { probe } from "../../modules/benchprobe";
import { catalogModel, filesOf, modelSize, type ModelFile } from "../bench/catalog";
import { modelDir } from "../bench/engines";
import { EXP_MODELS, ExpModelId, getLJ, ModelStatus, setLJ } from "./state";

const K_VERIFIED = "wc.exp.verified.v1";
/** Free space margin on top of the model size. */
export const SPACE_MARGIN = 300 * 1024 * 1024;

type VerifiedCache = Record<string, { size: number; mtime: number; sha256: string }>;
async function loadCache(): Promise<VerifiedCache> {
  try {
    return JSON.parse((await AsyncStorage.getItem(K_VERIFIED)) ?? "{}") as VerifiedCache;
  } catch {
    return {};
  }
}
async function saveCache(c: VerifiedCache) {
  await AsyncStorage.setItem(K_VERIFIED, JSON.stringify(c));
}

const benchModel = (id: ExpModelId) => catalogModel(EXP_MODELS[id].benchId);
export const expModelSize = (id: ExpModelId) => modelSize(benchModel(id));
export const expModelDir = (id: ExpModelId) => modelDir(benchModel(id));

function setStatus(id: ExpModelId, st: Partial<ModelStatus>) {
  setLJ((s) => ({ models: { ...s.models, [id]: { ...s.models[id], total: expModelSize(id), ...st } } }));
}

type FileInfo = { exists: boolean; size: number; mtime: number };
async function info(uri: string): Promise<FileInfo> {
  const i = (await FS.getInfoAsync(uri)) as { exists: boolean; size?: number; modificationTime?: number };
  return { exists: i.exists, size: i.size ?? 0, mtime: i.modificationTime ?? 0 };
}

export const nativeHashAvailable = () => typeof probe?.sha256File === "function";

async function hashFile(uri: string): Promise<string> {
  if (!probe?.sha256File) throw new Error("sha256 not available in this build");
  return probe.sha256File(uri.replace(/^file:\/\//, ""));
}

/** true = the file is present and its sha256 matches (from the cache or recomputed). */
async function verifyFile(uri: string, f: ModelFile, cache: VerifiedCache, rehash: boolean): Promise<"ok" | "missing" | "size" | "sha" | "unverified"> {
  const i = await info(uri);
  if (!i.exists) return "missing";
  if (i.size !== f.size) return "size";
  if (!f.sha256) return "ok";
  const c = cache[uri];
  if (!rehash && c && c.size === i.size && c.mtime === i.mtime && c.sha256 === f.sha256) return "ok";
  if (!nativeHashAvailable()) return "unverified";
  const sha = await hashFile(uri);
  if (sha !== f.sha256) {
    delete cache[uri];
    return "sha";
  }
  cache[uri] = { size: i.size, mtime: i.mtime, sha256: sha };
  return "ok";
}

/** Check the weights on disk: size and sha256. Downloads nothing. */
export async function checkModel(id: ExpModelId, rehash = false): Promise<ModelStatus> {
  const cur = getLJ().models[id].state;
  if (cur === "downloading" || cur === "verifying") return getLJ().models[id];
  const dir = expModelDir(id);
  const files = filesOf(benchModel(id));
  const cache = await loadCache();
  let present = 0;
  let anyMissing = false;
  for (const f of files) {
    const i = await info(`${dir}${f.name}`);
    if (i.exists && i.size === f.size) present += f.size;
    else anyMissing = true;
  }
  if (anyMissing) {
    setStatus(id, { state: "missing", received: present, error: undefined });
    return getLJ().models[id];
  }
  setStatus(id, { state: "verifying", received: present, error: undefined });
  let result: ModelStatus["state"] = "ready";
  for (const f of files) {
    const r = await verifyFile(`${dir}${f.name}`, f, cache, rehash);
    if (r === "sha" || r === "size") {
      result = "corrupt";
      break;
    }
    if (r === "unverified") result = "unverified";
  }
  await saveCache(cache);
  setStatus(id, { state: result, received: present });
  return getLJ().models[id];
}

export async function freeBytes(): Promise<number> {
  return FS.getFreeDiskStorageAsync();
}

let active: { id: ExpModelId; dr: FS.DownloadResumable } | null = null;

/** Download missing files: free space check first, sha256 after each file. */
export async function downloadModel(id: ExpModelId): Promise<void> {
  if (active) throw new Error("another download is running");
  const dir = expModelDir(id);
  const files = filesOf(benchModel(id));
  await FS.makeDirectoryAsync(dir, { intermediates: true }).catch(() => {});
  let have = 0;
  for (const f of files) {
    const i = await info(`${dir}${f.name}`);
    if (i.exists && i.size === f.size) have += f.size;
  }
  const need = expModelSize(id) - have;
  const free = await freeBytes();
  if (need + SPACE_MARGIN > free) {
    const msg = `not enough space: need ${Math.ceil((need + SPACE_MARGIN) / 1e6)} MB, free ${Math.floor(free / 1e6)} MB`;
    setStatus(id, { state: "error", error: msg });
    throw new Error(msg);
  }
  const cache = await loadCache();
  let base = 0;
  try {
    for (const f of files) {
      const dest = `${dir}${f.name}`;
      const i = await info(dest);
      if (i.exists && i.size === f.size) {
        base += f.size;
        continue;
      }
      if (i.exists) await FS.deleteAsync(dest, { idempotent: true });
      setStatus(id, { state: "downloading", received: base, error: undefined });
      let last = 0;
      const dr = FS.createDownloadResumable(f.url, dest, {}, (p) => {
        const now = Date.now();
        if (now - last > 400) {
          last = now;
          setStatus(id, { state: "downloading", received: base + p.totalBytesWritten });
        }
      });
      active = { id, dr };
      const res = await dr.downloadAsync();
      active = null;
      if (!res) throw new Error("cancelled");
      if (res.status >= 400) throw new Error(`HTTP ${res.status} for ${f.name}`);
      setStatus(id, { state: "verifying", received: base + f.size });
      const v = await verifyFile(dest, f, cache, true);
      if (v === "size" || v === "sha" || v === "missing") {
        await FS.deleteAsync(dest, { idempotent: true });
        throw new Error(`${f.name}: ${v === "sha" ? "sha256 mismatch" : "size mismatch"}, file removed`);
      }
      base += f.size;
    }
    await saveCache(cache);
    await checkModel(id);
  } catch (e) {
    active = null;
    await saveCache(cache).catch(() => {});
    const msg = errMsg(e);
    if (msg === "cancelled" || /cancel/i.test(msg)) setStatus(id, { state: "missing", received: base, error: undefined });
    else setStatus(id, { state: "error", received: base, error: msg });
    throw e;
  }
}

export async function cancelDownload() {
  const a = active;
  active = null;
  if (a) await a.dr.cancelAsync().catch(() => {});
}

export async function deleteModelFiles(id: ExpModelId) {
  await FS.deleteAsync(expModelDir(id), { idempotent: true });
  const cache = await loadCache();
  for (const k of Object.keys(cache)) if (k.startsWith(expModelDir(id))) delete cache[k];
  await saveCache(cache);
  setStatus(id, { state: "missing", received: 0, error: undefined });
}
