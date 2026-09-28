// SPDX-License-Identifier: GPL-3.0-or-later
// WardenClaw protocol version (envelope, signing strings, wardend and plugin APIs; one numbering
// for everything). wardend in ping and status, and the wardenclaw-gate plugin in status, return
// protocol (what the server speaks) and minClient (the oldest client it still understands). A
// mismatch is a separate clear error, "update the server" or "update the app", not bad_signature.
// Pure module (no RN).
import { t } from "./i18n";

/** Protocol version this app speaks. Bumped on any incompatible change. */
export const PROTOCOL = 1;
/** Oldest server (wardend, plugin) the app still works with. */
export const MIN_SERVER_PROTOCOL = 1;

export type ProtocolComponent = "wardend" | "plugin";
export type ProtocolCheck = { ok: true } | { ok: false; code: "server_old" | "client_old"; protocol: number | null; minClient: number | null };

const int = (x: unknown): number | null => (typeof x === "number" && Number.isSafeInteger(x) ? x : null);

/** ping or status response: no protocol field or it is below MIN_SERVER_PROTOCOL means the server is older; PROTOCOL < minClient means the app is older. */
export function checkServerProtocol(body: unknown): ProtocolCheck {
  const b = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
  const protocol = int(b.protocol);
  const minClient = int(b.minClient);
  if (protocol === null || protocol < MIN_SERVER_PROTOCOL) return { ok: false, code: "server_old", protocol, minClient };
  if (minClient !== null && PROTOCOL < minClient) return { ok: false, code: "client_old", protocol, minClient };
  return { ok: true };
}

const RAW = /^protocol_mismatch: (server_old|client_old) (wardend|plugin)\b/;

/**
 * Protocol version mismatch. message is the raw text for "Details" (codes and numbers), and
 * explainProtocolError puts it into words: this way the error goes through lastError and alerts,
 * like connection errors.
 */
export class ProtocolMismatchError extends Error {
  constructor(
    public code: "server_old" | "client_old",
    public component: ProtocolComponent,
    public protocol: number | null,
    public minClient: number | null,
  ) {
    super(`protocol_mismatch: ${code} ${component} (server protocol ${protocol ?? "none"}, minClient ${minClient ?? "none"}; app protocol ${PROTOCOL}, oldest server ${MIN_SERVER_PROTOCOL})`);
  }
}

/** Throw ProtocolMismatchError if the server and the app will not understand each other. */
export function assertServerProtocol(body: unknown, component: ProtocolComponent): void {
  const c = checkServerProtocol(body);
  if (!c.ok) throw new ProtocolMismatchError(c.code, component, c.protocol, c.minClient);
}

/** Raw ProtocolMismatchError text in words (what to update); detail is the raw text. Any other error: null. */
export function explainProtocolError(raw: string | null | undefined): { text: string; detail: string } | null {
  const m = raw ? RAW.exec(raw.trim()) : null;
  if (!m) return null;
  const text = m[1] === "client_old" ? t("proto.clientOld") : m[2] === "plugin" ? t("proto.pluginOld") : t("proto.serverOld");
  return { text, detail: (raw as string).trim().slice(0, 600) };
}
