// SPDX-License-Identifier: Apache-2.0
// Shared test helpers: device keys via @noble/ed25519 (same as the app), fakes.
import * as ed from "@noble/ed25519";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { bufferToB64url } from "../src/crypto.js";
import { decisionSigningString, requestSigningString, TICKET_TOOL } from "../src/canonical.js";
import { resolveConfig } from "../src/config.js";
import { Gate } from "../src/gate.js";
import { Journal } from "../src/journal.js";
import { StaticDeviceDirectory } from "../src/devices.js";

/** Device: @noble key, deviceId = sha256(pub) hex, publicKey base64url (same as identity.ts). */
export async function makeDevice() {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  const deviceId = createHash("sha256").update(pub).digest("hex");
  const publicKey = bufferToB64url(pub);
  const token = `tok_${randomUUID()}`;
  return {
    deviceId,
    publicKey,
    token,
    priv,
    async sign(message) {
      return bufferToB64url(await ed.signAsync(new TextEncoder().encode(message), priv));
    },
    /** Decision; without type defaults to plugin tool call ticket (TICKET_TOOL), same as the app tool card. */
    async signDecision(payload) {
      const p = { type: TICKET_TOOL, ...payload };
      return { deviceId, payload: p, signature: await this.sign(decisionSigningString({ deviceId, ...p })) };
    },
    async signedHeaders(action, now = Date.now()) {
      const ts = now;
      const nonce = randomUUID();
      return {
        "x-wardenclaw-device": deviceId,
        "x-wardenclaw-ts": String(ts),
        "x-wardenclaw-nonce": nonce,
        "x-wardenclaw-signature": await this.sign(requestSigningString({ action, deviceId, ts, nonce })),
        authorization: `Bearer ${token}`,
      };
    },
  };
}

export function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "wcgate-"));
}

export function fakeLogger() {
  const lines = [];
  const push = (lvl) => (m) => lines.push(`${lvl} ${m}`);
  return { lines, info: push("info"), warn: push("warn"), error: push("error"), debug: push("debug") };
}

export class MemoryJournal {
  constructor() {
    this.entries = [];
    this.publicKey = "mem";
  }
  append(kind, data) {
    const e = { seq: this.entries.length + 1, kind, data };
    this.entries.push(e);
    return e;
  }
}

/** Directory with tokens (for Bearer verification). */
export function directoryFor(devices) {
  const base = new StaticDeviceDirectory(devices.map((d) => ({ deviceId: d.deviceId, publicKey: d.publicKey })));
  return {
    async getDevice(id) {
      const r = await base.getDevice(id);
      if (!r) return null;
      const d = devices.find((x) => x.deviceId === id);
      return { ...r, tokens: d?.token ? [d.token] : [] };
    },
  };
}

/**
 * Build a Gate from fakes. now is a controllable clock.
 * @param {{ devices: Awaited<ReturnType<typeof makeDevice>>[], config?: Record<string, unknown>, realJournal?: boolean }} opts
 */
export function makeGate(opts) {
  const clock = { t: 1_800_000_000_000 };
  const now = () => clock.t;
  const dir = tmpDir();
  const config = resolveConfig({ trustedDeviceIds: opts.devices.map((d) => d.deviceId), stateDir: dir, ...(opts.config ?? {}) });
  const logger = fakeLogger();
  const journal = opts.realJournal ? new Journal(dir) : new MemoryJournal();
  const gate = new Gate({ config, directory: directoryFor(opts.devices), journal, logger, now });
  return { gate, config, logger, journal, clock, now, dir };
}
