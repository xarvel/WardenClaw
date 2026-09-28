// SPDX-License-Identifier: GPL-3.0-or-later
// Connection errors in words. fetch on Android (expo/fetch, okhttp) and iOS (NSURLSession) returns
// raw text like "fetch failed: java.net.ConnectException: Failed to connect to /127.0.0.1:19887":
// a human needs "no connection to the server, the address is such and such, what to check", and
// the raw text stays behind an expander for debugging. Pure module (no RN): the tests compile it.
import { t } from "./i18n";
import { explainProtocolError } from "./protocolVersion";

const NETWORK_ERROR =
  /Network request failed|Failed to fetch|fetch failed|ConnectException|Failed to connect|ECONNREFUSED|ECONNRESET|ETIMEDOUT|ENOTFOUND|EHOSTUNREACH|ENETUNREACH|UnknownHostException|Unable to resolve host|SocketTimeoutException|SocketException|NoRouteToHostException|timed out|timeout|Could not connect to the server|Internet connection appears to be offline|NSURLErrorDomain|network connection was lost|\babort/i;

/** Whether the message looks like a lost connection (rather than a server refusal with a reason). */
export function isNetworkError(msg: string | null | undefined): boolean {
  return !!msg && NETWORK_ERROR.test(msg);
}

function hostOf(url: string): string {
  const m = /^[a-z]+:\/\/(\[[^\]]+\]|[^/:?#\s]+)(?::(\d+))?/i.exec(url.trim());
  if (!m) return url.trim();
  return m[2] ? `${m[1]}:${m[2]}` : m[1];
}

function isLoopback(url: string): boolean {
  const h = hostOf(url).replace(/:\d+$/, "").replace(/^\[|\]$/g, "").toLowerCase();
  return h === "localhost" || h === "::1" || h.startsWith("127.");
}

/**
 * Connection error with the server at url, in words: what happened and what to check; detail is
 * the raw text for the "Details" expander. Not a connection error (server refusal, invalid link):
 * null, such text is already human-readable and is shown as is.
 */
export function explainNetError(raw: string | null | undefined, url: string | null | undefined): { text: string; detail: string } | null {
  if (!raw || !isNetworkError(raw)) return null;
  const addr = url ? hostOf(url) : "";
  const parts = [addr ? t("net.noConnectionTo", { addr }) : t("net.noConnection")];
  parts.push(url && isLoopback(url) ? t("net.checkLoopback") : t("net.check"));
  return { text: parts.join(" "), detail: raw.trim().slice(0, 600) };
}

/** Connection error or protocol version mismatch in words, raw text in detail; anything else: null (the text is already human-readable). */
export function explainError(raw: string | null | undefined, url: string | null | undefined): { text: string; detail: string } | null {
  return explainProtocolError(raw) ?? explainNetError(raw, url);
}
