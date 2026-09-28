// SPDX-License-Identifier: Apache-2.0
// WardenClaw protocol version (protocol/README.md, "Protocol version"): single numbering for the
// envelope, signing strings, wardend and plugin API. Bumped on any change that breaks an existing
// client or server; adding a new optional field to a response does not bump it.

/** protocol version spoken by the plugin: its API for the app and relay to wardend */
export const PROTOCOL = 1;
/** lowest app (client) protocol version the plugin still accepts */
export const MIN_CLIENT = 1;
/** oldest wardend protocol the relay supports */
export const MIN_SERVER_PROTOCOL = 1;

/**
 * Checks the ping or status response of a server: no protocol field or protocol <
 * MIN_SERVER_PROTOCOL means server is older than client; PROTOCOL < minClient means client is
 * older than server.
 * @param {any} r server response
 * @returns {{ protocol: number | null, minClient: number | null, mismatch: null | "server_too_old" | "client_too_old" }}
 */
export function checkServerProtocol(r) {
  const int = (v) => (Number.isSafeInteger(v) ? v : null);
  const protocol = int(r?.protocol);
  const minClient = int(r?.minClient);
  let mismatch = null;
  if (protocol === null || protocol < MIN_SERVER_PROTOCOL) mismatch = "server_too_old";
  else if (minClient !== null && PROTOCOL < minClient) mismatch = "client_too_old";
  return { protocol, minClient, mismatch };
}
