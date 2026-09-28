// SPDX-License-Identifier: Apache-2.0
// Device directory: sources for public keys and device tokens.
// 1) Static list from plugin config (devices: [{deviceId, publicKey}]);
// 2) Gateway storage: table device_pairing_paired in <stateDir>/state/openclaw.sqlite
//    (read-only; in 2026.9.x the ~/.openclaw/devices/*.json directory is no longer used).
// Calling api.runtime.gateway.request("device.pair.list") from third-party plugins is rejected
// ("Calls from arbitrary external plugins are rejected"), so we read the DB directly.
// A key is only used if deviceId = sha256(key), as in pairing: the gateway DB may write an
// agent uid, and a foreign key under a trusted id would sign decisions on behalf of the phone.
// Such a key is not returned (publicKey "", keyMismatch), and verify.js rejects it again ("pubkey_id_mismatch").
import path from "node:path";
import fs from "node:fs";
import { publicKeyMatchesDeviceId } from "./crypto.js";

/** How long a gateway DB lookup (including a miss) is reused: pairing changes show up within this time. */
const DEVICE_CACHE_MS = 30_000;

/**
 * @typedef {{ deviceId: string, publicKey: string, tokens: string[], displayName?: string | null, source: string, keyMismatch?: boolean }} DeviceRecord
 */

export class StaticDeviceDirectory {
  /** @param {{deviceId: string, publicKey: string}[]} devices */
  constructor(devices) {
    /** config entries whose key does not belong to this deviceId: not used */
    this.rejected = devices.filter((d) => !publicKeyMatchesDeviceId(d.publicKey, d.deviceId)).map((d) => d.deviceId);
    this.map = new Map(devices.filter((d) => publicKeyMatchesDeviceId(d.publicKey, d.deviceId)).map((d) => [d.deviceId, d]));
  }
  /** @returns {Promise<DeviceRecord | null>} */
  async getDevice(deviceId) {
    const d = this.map.get(deviceId);
    return d ? { deviceId: d.deviceId, publicKey: d.publicKey, tokens: [], displayName: null, source: "config" } : null;
  }
}

export class SqliteDeviceDirectory {
  /**
   * @param {string} dbPath path to openclaw.sqlite
   * @param {{ cacheMs?: number }} [opts]
   */
  constructor(dbPath, opts = {}) {
    this.dbPath = dbPath;
    this.cacheMs = opts.cacheMs ?? DEVICE_CACHE_MS;
    /** @type {Map<string, {at: number, rec: DeviceRecord | null}>} */
    this.cache = new Map();
  }

  /** @returns {Promise<DeviceRecord | null>} */
  async getDevice(deviceId) {
    const c = this.cache.get(deviceId);
    if (c && Date.now() - c.at < this.cacheMs) return c.rec;
    const rec = await this.#query(deviceId);
    this.cache.set(deviceId, { at: Date.now(), rec });
    return rec;
  }

  async #query(deviceId) {
    if (!fs.existsSync(this.dbPath)) return null;
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(this.dbPath, { readOnly: true });
    try {
      const row = db
        .prepare("SELECT device_id, public_key, display_name, tokens_json FROM device_pairing_paired WHERE device_id = ?")
        .get(deviceId);
      if (!row) return null;
      const keyOk = publicKeyMatchesDeviceId(String(row.public_key), deviceId);
      return {
        deviceId: String(row.device_id),
        publicKey: keyOk ? String(row.public_key) : "",
        tokens: parseTokens(row.tokens_json),
        displayName: row.display_name == null ? null : String(row.display_name),
        source: "gateway-sqlite",
        ...(keyOk ? {} : { keyMismatch: true }),
      };
    } finally {
      db.close();
    }
  }
}

/**
 * Device tokens from the tokens_json column: an object of {token, ...} entries. A malformed
 * value yields no tokens (the device token check then fails), not an error.
 * @param {unknown} tokensJson
 * @returns {string[]}
 */
function parseTokens(tokensJson) {
  const tokens = [];
  try {
    const entries = JSON.parse(String(tokensJson ?? "{}"));
    for (const v of Object.values(entries ?? {})) {
      if (v && typeof v === "object" && typeof v.token === "string") tokens.push(v.token);
    }
  } catch {
    // malformed JSON: no tokens
  }
  return tokens;
}

/** First tries the static list, then the gateway DB (for tokens and keys not in config). */
export class CompositeDeviceDirectory {
  /** @param {{getDevice(id: string): Promise<DeviceRecord | null>}[]} dirs */
  constructor(dirs) {
    this.dirs = dirs;
  }
  async getDevice(deviceId) {
    /** @type {DeviceRecord | null} */
    let merged = null;
    for (const d of this.dirs) {
      const r = await d.getDevice(deviceId).catch(() => null);
      if (!r) continue;
      if (!merged) merged = { ...r };
      else merged.tokens = [...merged.tokens, ...r.tokens.filter((t) => !merged.tokens.includes(t))];
    }
    return merged;
  }
}

/** @param {string} gatewayStateDir */
export function gatewaySqlitePath(gatewayStateDir) {
  return path.join(gatewayStateDir, "state", "openclaw.sqlite");
}
