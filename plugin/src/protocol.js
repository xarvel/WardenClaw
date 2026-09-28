// SPDX-License-Identifier: Apache-2.0
// WardenClaw protocol version (protocol/README.md, "Protocol version"): single numbering for the
// envelope, signing strings, wardend and plugin API. Bumped on any change that breaks an existing
// client or server; adding a new optional field to a response does not bump it.

/** protocol version spoken by the plugin: its API for the app and its relay to wardend */
export const PROTOCOL = 1;

/**
 * Checks the status response of a server: the protocol field must be the number the plugin
 * speaks. No field or a lower number means the server is older than the client; a higher number
 * means the client is older than the server.
 * @param {any} r server response
 * @returns {{ protocol: number | null, mismatch: null | "server_too_old" | "client_too_old" }}
 */
export function checkServerProtocol(r) {
  const protocol = Number.isSafeInteger(r?.protocol) ? r.protocol : null;
  let mismatch = null;
  if (protocol === null || protocol < PROTOCOL) mismatch = "server_too_old";
  else if (protocol > PROTOCOL) mismatch = "client_too_old";
  return { protocol, mismatch };
}
