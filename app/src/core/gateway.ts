// SPDX-License-Identifier: GPL-3.0-or-later
// Thin client for the OpenClaw gateway protocol (protocol 4) for React Native.
// Flow: WS open → event connect.challenge {nonce, ts} → req "connect" (auth + device signature v3)
// → res hello-ok {auth:{role,scopes,deviceToken?}} → events {type:"event"} and responses {type:"res"}.
import { errMsg } from "./errMsg";
import { randomUUID } from "expo-crypto";
import { Platform } from "react-native";
import { DeviceIdentity, publicKeyB64Url, signPayload } from "./identity";
import { t } from "./i18n";

export const PROTOCOL_VERSION = 4;
export const ROLE = "operator";
export const SCOPES = ["operator.read", "operator.approvals"];
export const CLIENT_DISPLAY_NAME = "wardenclaw-app";
export const CLIENT_VERSION = "0.1.0";

export type GatewayAuth = { bootstrapToken: string } | { deviceToken: string };

export type GatewayError = {
  code?: string;
  message?: string;
  details?: Record<string, unknown>;
};

export class GatewayRequestError extends Error {
  code?: string;
  details?: Record<string, unknown>;
  constructor(err: GatewayError) {
    super(err.message ?? err.code ?? "gateway error");
    this.code = err.code;
    this.details = err.details;
  }
  get detailCode(): string | undefined {
    const c = this.details?.code;
    return typeof c === "string" ? c : undefined;
  }
}

export type HelloOk = {
  protocol?: number;
  server?: { version?: string };
  auth?: { role?: string; scopes?: string[]; deviceToken?: string };
};

export type GatewayEvent = { type: "event"; event: string; payload?: unknown; seq?: number };

type Pending = { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> };

export type GatewayHandlers = {
  onHello: (hello: HelloOk) => void;
  onEvent: (evt: GatewayEvent) => void;
  onConnectError: (err: GatewayRequestError | Error) => void;
  onClose: (code: number, reason: string, wasConnected: boolean) => void;
  onLog?: (line: string) => void;
};

export type GatewayOptions = {
  url: string;
  identity: DeviceIdentity;
  auth: GatewayAuth;
  handlers: GatewayHandlers;
  handshakeTimeoutMs?: number;
  keepaliveMs?: number;
};

function b64urlNormalize(s: string) {
  return s.trim().replace(/[A-Z]/g, (c) => c.toLowerCase());
}

/** One connection. Reconnecting is decided by the layer above (controller). */
export class GatewayConnection {
  private ws: WebSocket | null = null;
  private pending = new Map<string, Pending>();
  private seq = 0;
  private connectSent = false;
  private helloReceived = false;
  private closed = false;
  private handshakeTimer: ReturnType<typeof setTimeout> | null = null;
  private keepaliveTimer: ReturnType<typeof setInterval> | null = null;

  constructor(private readonly opts: GatewayOptions) {}

  get connected() {
    return this.helloReceived && !this.closed;
  }

  start() {
    const { url, handlers } = this.opts;
    handlers.onLog?.(`ws → ${url}`);
    let ws: WebSocket;
    try {
      ws = new WebSocket(url);
    } catch (e) {
      handlers.onConnectError(e instanceof Error ? e : new Error(String(e)));
      return;
    }
    this.ws = ws;
    ws.onopen = () => {
      handlers.onLog?.("ws open, waiting for connect.challenge");
      this.handshakeTimer = setTimeout(() => {
        if (!this.connectSent) {
          handlers.onConnectError(new Error(t("gw.noChallenge")));
          this.close(1008, "challenge timeout");
        }
      }, this.opts.handshakeTimeoutMs ?? 10000);
    };
    ws.onmessage = (ev) => this.handleMessage(String(ev.data));
    ws.onerror = (ev: unknown) => {
      const msg = (ev as { message?: string })?.message ?? t("gw.wsError");
      handlers.onLog?.(`ws error: ${msg}`);
      if (!this.helloReceived) handlers.onConnectError(new Error(msg));
    };
    ws.onclose = (ev) => {
      const wasConnected = this.helloReceived;
      this.closed = true;
      if (this.handshakeTimer) clearTimeout(this.handshakeTimer);
      if (this.keepaliveTimer) clearInterval(this.keepaliveTimer);
      this.keepaliveTimer = null;
      const err = new Error(t("gw.closed", { code: ev.code }));
      for (const [, p] of this.pending) {
        clearTimeout(p.timer);
        p.reject(err);
      }
      this.pending.clear();
      handlers.onClose(ev.code, ev.reason ?? "", wasConnected);
    };
  }

  /** Keepalive: a light request every 20 s; silence = dead socket (Cloudflare/okhttp may drop it without close). */
  private startKeepalive() {
    if (this.keepaliveTimer) clearInterval(this.keepaliveTimer);
    this.keepaliveTimer = setInterval(() => {
      if (this.closed) return;
      this.request("health", {}, 10000).catch((e) => {
        if (this.closed) return;
        this.opts.handlers.onLog?.(`keepalive failed: ${errMsg(e)}`);
        this.close(4001, "keepalive failed");
        // okhttp may not deliver onclose for an already dead socket: force it.
        this.forceClosed(4001, "keepalive failed");
      });
    }, this.opts.keepaliveMs ?? 20000);
  }

  private forceClosed(code: number, reason: string) {
    const ws = this.ws;
    if (!ws) return;
    const handler = ws.onclose as ((ev: { code: number; reason: string }) => void) | null;
    ws.onclose = null;
    handler?.({ code, reason });
  }

  close(code = 1000, reason = "client close") {
    if (this.closed) return;
    this.closed = true;
    if (this.keepaliveTimer) clearInterval(this.keepaliveTimer);
    this.keepaliveTimer = null;
    try {
      this.ws?.close(code, reason);
    } catch {}
  }

  request<T = unknown>(method: string, params: unknown = {}, timeoutMs = 15000): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const ws = this.ws;
      if (!ws || this.closed || ws.readyState !== 1) {
        reject(new Error(t("gw.notConnected")));
        return;
      }
      const id = `${++this.seq}:${randomUUID()}`;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(t("gw.timeout", { method, ms: timeoutMs })));
      }, timeoutMs);
      this.pending.set(id, { resolve: (v) => resolve(v as T), reject, timer });
      try {
        ws.send(JSON.stringify({ type: "req", id, method, params }));
      } catch (e) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(e instanceof Error ? e : new Error(String(e)));
      }
    });
  }

  private handleMessage(raw: string) {
    let frame: Record<string, unknown>;
    try {
      frame = JSON.parse(raw);
    } catch {
      return;
    }
    if (frame.type === "event" && typeof frame.event === "string") {
      if (frame.event !== "tick") this.opts.handlers.onLog?.(`← event ${frame.event}${typeof frame.seq === "number" ? ` #${frame.seq}` : ""}`);
      if (frame.event === "connect.challenge") {
        this.sendConnect(frame.payload as { nonce?: string; ts?: number } | undefined);
        return;
      }
      this.opts.handlers.onEvent(frame as GatewayEvent);
      return;
    }
    if (frame.type === "res" && typeof frame.id === "string") {
      const p = this.pending.get(frame.id);
      if (!p) return;
      this.pending.delete(frame.id);
      clearTimeout(p.timer);
      if (frame.ok === true) p.resolve(frame.payload);
      else p.reject(new GatewayRequestError((frame.error as GatewayError) ?? { message: t("gw.error") }));
    }
  }

  private sendConnect(challenge?: { nonce?: string; ts?: number }) {
    if (this.connectSent) return;
    this.connectSent = true;
    if (this.handshakeTimer) clearTimeout(this.handshakeTimer);
    const { identity, auth, handlers } = this.opts;
    const nonce = typeof challenge?.nonce === "string" ? challenge.nonce.trim() : "";
    const signedAtMs = typeof challenge?.ts === "number" ? challenge.ts : Date.now();
    const token = "bootstrapToken" in auth ? auth.bootstrapToken : auth.deviceToken;
    const platform = Platform.OS; // "android" | "ios"
    const payload = [
      "v3",
      identity.deviceId,
      "cli",
      "cli",
      ROLE,
      SCOPES.join(","),
      String(signedAtMs),
      token,
      nonce,
      b64urlNormalize(platform),
      "",
    ].join("|");
    const params = {
      minProtocol: PROTOCOL_VERSION,
      maxProtocol: PROTOCOL_VERSION,
      client: {
        id: "cli", // client.id on the wire is a closed gateway enum
        displayName: CLIENT_DISPLAY_NAME,
        version: CLIENT_VERSION,
        platform,
        mode: "cli",
        instanceId: `${CLIENT_DISPLAY_NAME}@${identity.deviceId.slice(0, 8)}`,
      },
      caps: ["approvals", "exec-approvals", "plugin-approvals"],
      auth: "bootstrapToken" in auth ? { bootstrapToken: auth.bootstrapToken } : { deviceToken: auth.deviceToken },
      role: ROLE,
      scopes: SCOPES,
      device: {
        id: identity.deviceId,
        publicKey: publicKeyB64Url(identity),
        signature: signPayload(identity, payload),
        signedAt: signedAtMs,
        nonce,
      },
    };
    handlers.onLog?.(`connect (${"bootstrapToken" in auth ? "setup-code" : "device-token"})`);
    this.request<HelloOk>("connect", params, 20000)
      .then((hello) => {
        this.helloReceived = true;
        this.startKeepalive();
        handlers.onHello(hello);
      })
      .catch((e) => {
        handlers.onConnectError(e instanceof Error ? e : new Error(String(e)));
        this.close(1008, "connect failed");
      });
  }
}

export function pairingDetails(err: unknown): { requestId?: string; reason?: string; hint?: string } | null {
  if (!(err instanceof GatewayRequestError)) return null;
  if (err.detailCode !== "PAIRING_REQUIRED") return null;
  const d = err.details ?? {};
  return {
    requestId: typeof d.requestId === "string" ? d.requestId : undefined,
    reason: typeof d.reason === "string" ? d.reason : undefined,
    hint: typeof d.remediationHint === "string" ? d.remediationHint : undefined,
  };
}

export const TERMINAL_AUTH_CODES = new Set([
  "AUTH_DEVICE_TOKEN_MISMATCH",
  "AUTH_TOKEN_MISSING",
  "AUTH_TOKEN_MISMATCH",
  "AUTH_BOOTSTRAP_TOKEN_INVALID",
  "AUTH_BOOTSTRAP_TOKEN_EXPIRED",
]);
