// SPDX-License-Identifier: AGPL-3.0-or-later
// Test parties with real Ed25519 keys and a small socket wrapper around the relay's frames.

import { SELF } from "cloudflare:test";
import { expect } from "vitest";
import * as ed from "@noble/ed25519";
import { canonicalJson } from "../src/canonical";
import { b64urlEncode, randomHex, sha256Hex } from "../src/crypto";
import { HELLO_TYPE } from "../src/frames";

const te = new TextEncoder();

export interface Party {
  priv: Uint8Array;
  pub: string; // b64url
  enc: string; // b64url, any 32 bytes for the relay's purposes
  id: string;
}

export async function party(): Promise<Party> {
  const priv = ed.utils.randomSecretKey();
  const pubRaw = await ed.getPublicKeyAsync(priv);
  const enc = new Uint8Array(32);
  crypto.getRandomValues(enc);
  return { priv, pub: b64urlEncode(pubRaw), enc: b64urlEncode(enc), id: await sha256Hex(pubRaw) };
}

export async function sign(p: Party, msg: string): Promise<string> {
  return b64urlEncode(await ed.signAsync(te.encode(msg), p.priv));
}

export class Sock {
  private queue: Record<string, unknown>[] = [];
  private waiters: ((f: Record<string, unknown>) => void)[] = [];
  closed: { code: number; reason: string } | null = null;
  /** the `online` of every `peer` frame, in order */
  peers: boolean[] = [];
  constructor(readonly ws: WebSocket) {
    ws.accept();
    ws.addEventListener("message", (ev) => {
      const f = JSON.parse(String(ev.data)) as Record<string, unknown>;
      // presence comes whenever the supervisor connects or leaves: kept apart from the frames a test steps through
      if (f.type === "peer") {
        this.peers.push(f.online as boolean);
        return;
      }
      const w = this.waiters.shift();
      if (w) w(f);
      else this.queue.push(f);
    });
    ws.addEventListener("close", (ev) => {
      this.closed = { code: ev.code, reason: ev.reason };
    });
  }
  send(f: unknown) {
    this.ws.send(JSON.stringify(f));
  }
  next(timeoutMs = 2000): Promise<Record<string, unknown>> {
    const q = this.queue.shift();
    if (q) return Promise.resolve(q);
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("no frame within timeout")), timeoutMs);
      this.waiters.push((f) => {
        clearTimeout(t);
        resolve(f);
      });
    });
  }
  async expectNone(ms = 300): Promise<void> {
    await new Promise((r) => setTimeout(r, ms));
    expect(this.queue).toEqual([]);
  }
}

export async function connect(sid: string): Promise<Sock> {
  const res = await SELF.fetch(`https://relay/v1/ws/${sid}`, { headers: { Upgrade: "websocket" } });
  expect(res.status).toBe(101);
  return new Sock(res.webSocket as WebSocket);
}

/** Connects and authenticates; returns the socket after `welcome`. */
export async function login(sid: string, p: Party, role: "supervisor" | "device"): Promise<Sock> {
  const s = await connect(sid);
  const ch = await s.next();
  expect(ch.type).toBe("challenge");
  const hello = { role, key: p.pub, enc: p.enc, ts: Date.now(), nonce: ch.nonce as string, client: { name: "test", version: "0", protocol: 1 } };
  const sig = await sign(p, canonicalJson({ type: HELLO_TYPE, ...hello }));
  s.send({ type: "hello", ...hello, sig });
  const w = await s.next();
  expect(w.type, JSON.stringify(w)).toBe("welcome");
  expect(w.id).toBe(p.id);
  return s;
}

export function msg(to: string, kind: string, body = "cipher", extra: Record<string, unknown> = {}) {
  return { type: "msg", id: randomHex(16), to, ts: Date.now(), exp: Date.now() + 60_000, body, kind, ...extra };
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Replaces the global fetch; calls to `origin` are recorded and answered with `status`, the rest pass through. */
export function stubFetch(origin: string, status = 200, body = "") {
  const calls: { url: string; headers: Record<string, string>; body: string }[] = [];
  const real = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (!url.startsWith(origin)) return real(input, init);
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((v, k) => (headers[k] = v));
    calls.push({ url, headers, body: String(init?.body) });
    return new Response(body, { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return { calls, restore: () => (globalThis.fetch = real) };
}
