// SPDX-License-Identifier: GPL-3.0-or-later
// Client of the wardend HTTP endpoint (own transport, without the OpenClaw gateway).
//   GET  /v1/ping?nonce          check that the server at the address answers with the key from the QR
//                                (and the protocol version)
//   POST /v1/pair                pairing request (one-time code, signature of the new key)
//   GET  /v1/pair/status?id      wait for `wardend pair approve` on the server
//   GET  /v1/pending?since&wait  long-poll ≤ 25 s
//   GET  /v1/status              protocol and minClient are checked on every connection (protocolVersion.ts)
//   POST /v1/decide              ticket (signDecision, same as for the plugin)
//   POST /v1/push/register       iPhone APNs token (the signature covers the body), /v1/push/unregister
// Every response must be signed with the key from the QR and bound to the request: action, deviceId,
// nonce, for decide the ticket's id and digest; ping by its own type (checkResponse). Otherwise the
// response is dropped: a tunnel or someone in the middle can neither slip in a card, nor pose as the
// server, nor pass off a response to another request (for example, ping) as a response to decide. A
// signed rejection before the request signature is checked is a WardendHttpError with unbound: the
// reason is visible, but it does not count as a response to our request.
import { randomUUID } from "expo-crypto";
import { DeviceIdentity, publicKeyB64Url, signPayload } from "./identity";
import { GateDecision, TICKET_EXEC } from "./canonical";
import { DecisionTarget, GateDecideResponse, SignedDecision, signDecision, signDecisionWithHardware } from "./gate";
import { HardwareSigner } from "./hardware";
import { assertServerProtocol } from "./protocolVersion";
import { ResponseExpectation, checkResponse, decideResponseMatches, pairSigningString, supervisorIdFromKey, wardendRequestSigningString } from "./wardendProto";

export type WardendItem = Record<string, unknown> & { id: string; digest: string };
export type WardendPendingResponse = { ok: true; seq: number; mode: string; supervisorId: string; host: string; pending: WardendItem[]; now: number };
export type WardendPairResponse = { ok: true; id: string; status: "pending" | "approved" | "rejected"; fingerprint: string; supervisorId: string; host: string; expiresAt: number };
export type WardendPairStatus = { ok: true; id: string; status: "pending" | "approved" | "rejected" | "revoked" | "unknown"; fingerprint: string; host: string };
export type WardendPushBody = { deviceId: string; platform: "apns"; token?: string; topic?: string; environment?: "sandbox" | "production" };

export class WardendHttpError extends Error {
  constructor(
    public status: number,
    public reason: string,
    /** Rejection before the request signature is checked: signed by the server, but not bound to this request. */
    public unbound = false,
  ) {
    super(`wardend: ${status} ${reason}`);
  }
}

export type WardendClientOptions = { baseUrl: string; pinnedKey: string; identity: DeviceIdentity };

export class WardendClient {
  constructor(private readonly opts: WardendClientOptions) {}

  get baseUrl() {
    return this.opts.baseUrl;
  }

  private signedHeaders(action: string, nonce: string): Record<string, string> {
    const { identity } = this.opts;
    const ts = Date.now();
    return {
      "x-wardenclaw-device": identity.deviceId,
      "x-wardenclaw-ts": String(ts),
      "x-wardenclaw-nonce": nonce,
      "x-wardenclaw-signature": signPayload(identity, wardendRequestSigningString({ supervisorId: supervisorIdFromKey(this.opts.pinnedKey), action, deviceId: identity.deviceId, ts, nonce })),
    };
  }

  /** Headers of a request with a JSON body: signature over {type, supervisorId, action, body, deviceId, ts, nonce}. */
  private signedBodyHeaders(action: string, nonce: string, body: Record<string, unknown>): Record<string, string> {
    const { identity } = this.opts;
    const ts = Date.now();
    return {
      "content-type": "application/json",
      "x-wardenclaw-device": identity.deviceId,
      "x-wardenclaw-ts": String(ts),
      "x-wardenclaw-nonce": nonce,
      "x-wardenclaw-signature": signPayload(identity, wardendRequestSigningString({ supervisorId: supervisorIdFromKey(this.opts.pinnedKey), action, deviceId: identity.deviceId, ts, nonce, body })),
    };
  }

  private expect(action: string, nonce: string): ResponseExpectation {
    return { ctx: { action, deviceId: this.opts.identity.deviceId, nonce } };
  }

  /** Request with a response signature check. ok:false in the body → WardendHttpError (except decide); rejection before authentication → always WardendHttpError with unbound. */
  private async call<T>(path: string, want: ResponseExpectation, init: RequestInit & { timeoutMs?: number; allowNotOk?: boolean }, signal?: AbortSignal): Promise<T> {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), init.timeoutMs ?? 15000);
    const onOuter = () => ac.abort();
    signal?.addEventListener("abort", onOuter, { once: true });
    try {
      const res = await fetch(`${this.opts.baseUrl}${path}`, { ...init, signal: ac.signal });
      const text = await res.text();
      const check = checkResponse(this.opts.pinnedKey, want, res.status, text, res.headers.get("x-wardend-signature"));
      if (check === "invalid") throw new WardendHttpError(res.status, "unsigned_response");
      let body: unknown = null;
      try {
        body = JSON.parse(text);
      } catch {}
      const rec = (body ?? {}) as { ok?: boolean; reason?: string };
      if (check === "unbound") throw new WardendHttpError(res.status, typeof rec.reason === "string" ? rec.reason : `HTTP ${res.status}`, true);
      if (!init.allowNotOk && (!res.ok || rec.ok === false)) throw new WardendHttpError(res.status, rec.reason ?? `HTTP ${res.status}`);
      return body as T;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onOuter);
    }
  }

  /** The server at the QR address answers with the QR key and speaks a protocol version we understand (otherwise ProtocolMismatchError). */
  async ping(): Promise<{ supervisorId: string; protocol?: number; minClient?: number }> {
    const nonce = randomUUID();
    const r = await this.call<{ supervisorId: string; protocol?: number; minClient?: number }>(`/v1/ping?nonce=${encodeURIComponent(nonce)}`, { ping: true, nonce }, { method: "GET" });
    assertServerProtocol(r, "wardend");
    return r;
  }

  pair(code: string, supervisorId: string, name: string): Promise<WardendPairResponse> {
    const { identity } = this.opts;
    const payload = { code, deviceId: identity.deviceId, pubkey: publicKeyB64Url(identity), name, supervisorId, ts: Date.now(), nonce: randomUUID() };
    const signature = signPayload(identity, pairSigningString(payload));
    return this.call("/v1/pair", { ctx: { action: "pair", deviceId: identity.deviceId, nonce: payload.nonce } }, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...payload, signature }) });
  }

  pairStatus(id: string, signal?: AbortSignal): Promise<WardendPairStatus> {
    const nonce = randomUUID();
    return this.call(`/v1/pair/status?id=${encodeURIComponent(id)}`, this.expect("pair.status", nonce), { method: "GET", headers: this.signedHeaders("pair.status", nonce) }, signal);
  }

  pending(since: number, waitMs = 25000, signal?: AbortSignal): Promise<WardendPendingResponse> {
    const nonce = randomUUID();
    return this.call(`/v1/pending?since=${since}&wait=${waitMs}`, this.expect("pending", nonce), { method: "GET", headers: this.signedHeaders("pending", nonce), timeoutMs: waitMs + 10000 }, signal);
  }

  /** Server status; checks the protocol version right here (ProtocolMismatchError), the controller calls it on every connection. */
  async status(signal?: AbortSignal): Promise<Record<string, unknown>> {
    const nonce = randomUUID();
    const st = await this.call<Record<string, unknown>>("/v1/status", this.expect("status", nonce), { method: "GET", headers: this.signedHeaders("status", nonce) }, signal);
    assertServerProtocol(st, "wardend");
    return st;
  }

  /** This phone's APNs token: wardend sends a push to it when a card appears. */
  pushRegister(token: string, topic: string, environment: "sandbox" | "production"): Promise<{ ok: true }> {
    const nonce = randomUUID();
    const body: WardendPushBody = { deviceId: this.opts.identity.deviceId, platform: "apns", token, topic, environment };
    return this.call("/v1/push/register", this.expect("push.register", nonce), { method: "POST", headers: this.signedBodyHeaders("push.register", nonce, body), body: JSON.stringify(body) });
  }

  /** Remove the token (or all of the device's tokens if token is not set). */
  pushUnregister(token?: string): Promise<{ ok: true; removed: number }> {
    const nonce = randomUUID();
    const body: WardendPushBody = { deviceId: this.opts.identity.deviceId, platform: "apns", ...(token ? { token } : {}) };
    return this.call("/v1/push/unregister", this.expect("push.unregister", nonce), { method: "POST", headers: this.signedBodyHeaders("push.unregister", nonce, body), body: JSON.stringify(body) });
  }

  /**
   * Sign and send a ticket (exec type only: wardend does not accept any other). The wardend response
   * {ok, reason?, hardwareRule?} is returned as is only if it is signed as the response to this ticket (id and
   * digest in the signature, id and decision in the body). Otherwise throws WardendHttpError: a response to
   * another request, an unsigned one or a rejection before the ticket signature is checked is not a server
   * decision, the card stays.
   */
  async decide(pending: DecisionTarget, decision: GateDecision, opts: { risk?: number; hardware?: HardwareSigner } = {}): Promise<{ signed: SignedDecision; response: GateDecideResponse }> {
    if (pending.ticket.type !== TICKET_EXEC) throw new Error("wardend: only exec tickets");
    const signed = opts.hardware
      ? await signDecisionWithHardware(this.opts.identity, pending, decision, opts.hardware, opts.risk)
      : signDecision(this.opts.identity, pending, decision, Date.now(), opts.risk);
    const p = signed.payload;
    const want: ResponseExpectation = { ctx: { action: "decide", deviceId: this.opts.identity.deviceId, nonce: p.nonce, id: p.id, digest: p.digest } };
    let response = await this.call<GateDecideResponse>("/v1/decide", want, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(signed), allowNotOk: true });
    if (!decideResponseMatches(response, p)) throw new WardendHttpError(200, "response_mismatch");
    if (response.ok && !response.status) response = { ...response, status: "ok" };
    return { signed, response };
  }
}
