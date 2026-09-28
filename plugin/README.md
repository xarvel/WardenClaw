# wardenclaw-gate

*Take back control.* In `enforce` mode an OpenClaw tool call does not run without the phone's signature.

> **Optional adapter.** Since v0.3 WardenClaw does not depend on OpenClaw: the `wardend` supervisor
> pairs with the phone itself (`wardend pair start`, QR in the terminal) and serves the app itself
> over HTTP with signed responses (`../daemon/README.md`, section 4; `../daemon/deploy/CLOUDFLARE.md`).
> This plugin is only needed if you want to sign **OpenClaw's own tool calls** (the
> `before_tool_call` hook) or carry wardend cards through the gateway tunnel. In the app it is turned on
> with the switch "Connect → Adapters → OpenClaw (gateway)" (off by default). If the phone
> is paired with wardend directly, the app does not take exec records of the same supervisor from the plugin (relay),
> so that one exec does not make two cards.

An OpenClaw plugin: a cryptographic execution gate. Every executing tool call (exec / Bash / Write / Edit / apply_patch / code_mode_exec, the list is configurable) gets a canonical digest and a `pending` record; the WardenClaw app signs the decision with the paired device's Ed25519 key; the plugin verifies the signature and in `enforce` mode physically does not release the call without a valid `allow` (fail-closed). Stage A: `observe` mode: the hook only records what it sees and accepts signatures, blocking nothing.

Design: this README; the envelope and signature protocol: `../daemon/README.md`.

## Layout

```
openclaw.plugin.json   manifest + JSON schema of the config (mode, trustedDeviceIds, tools, ttlMs, exemptAgents, ...)
package.json           type=module, openclaw.extensions: ["./index.js"], devDependency @noble/ed25519 (tests only)
index.js               register(api): before_tool_call hook, HTTP routes, gateway WS methods, journal
src/canonical.js       canonicalJson, sha256Hex, toolCallDigest, decisionSigningString, requestSigningString  (format = app/src/core/canonical.ts)
src/crypto.js          Ed25519 via node:crypto (key base64url raw 32 bytes, as in device.pair.list), timing-safe secret comparison
src/config.js          config normalization, DEFAULT_TOOLS, toolMatches
src/store.js           PendingStore: pending records in memory + pending.json snapshot, waiting for a decision, long-poll waiters, TTL
src/verify.js          verifyDecision / verifySignedRequest / NonceCache (order: device → time window → signature → nonce → pending/digest)
src/devices.js         device directory: static (config) + read-only reads of device_pairing_paired from ~/.openclaw/state/openclaw.sqlite
src/journal.js         append-only JSONL: hash chain + signature with the plugin key (journal-key.json, 0600), verifyJournalFile
src/gate.js            core: createPending / waitDecision / decide / status / stats of seen tools
src/hook.js            before_tool_call handler (observe: returns at once; enforce: waits for allow up to the TTL, otherwise block)
src/relay.js           relay to wardend (seccomp execve gate): long-poll on its unix socket, "wd-…" exec records into pending, decide → wardend
src/http.js            GET /wardenclaw/pending (long-poll ≤25 s), GET /wardenclaw/status, POST /wardenclaw/decide, POST /wardenclaw/request
hooks/pretooluse.mjs   fallback: Claude Code PreToolUse hook (NOT set in settings.json)
scripts/verify-journal.mjs  journal verification by a third party
test/                  node:test (41 tests; + relay with a fake wardend and e2e with the real ../daemon/wardend, canonical JSON cross fixtures): canonicalization/digest, signatures (@noble/ed25519 ↔ node:crypto), time window, nonce, enforce/observe/abort/stop, journal, HTTP, sqlite directory
```

Plugin state (by default `~/.openclaw/wardenclaw-gate/`): `journal.jsonl`, `journal-key.json`, `pending.json`.

`pending.json` is only a snapshot for diagnostics: the plugin does not read it on start or reload, pending records are not restored from it, and `params` (the full call) are not written to it; they exist only in memory. A call waiting in `enforce` gets a block `wardenclaw-gate: plugin stopped (reload or gateway shutdown)…` at once on a plugin reload or gateway stop, as soon as the gateway stops the old instance (`gateway_stop`), instead of hanging until the TTL: the new instance has no record of it, and an Allow from the phone would no longer reach it (the plugin rejects such a decision or logs it as late). So change `mode` and the rest of the config (hybrid reload recreates the plugin instance) when no calls are in flight.

## Protocol

**Call digest**: `sha256(canonicalJson({toolName, params, agentId, sessionKey, runId, toolCallId}))`, undefined fields are left out. Params are frozen at hook time.

**Decision** (`POST /wardenclaw/decide` or the WS method `wardenclaw.decide`):

```json
{ "deviceId": "<hex64>", "payload": { "type": "wardenclaw.ticket.tool.v1", "id": "<pending id>", "digest": "<hex64>", "decision": "allow|deny", "ts": 1790000000000, "nonce": "<uuid>" }, "signature": "<base64url Ed25519>" }
```

The signed string is `canonicalJson({type, deviceId, id, digest, decision, ts, nonce[, supervisorId][, risk]})`. The ticket type is under the signature (`protocol/README.md`, §4): for its own records the plugin accepts only `wardenclaw.ticket.tool.v1` (without `supervisorId`), for wardend exec records (`wd-…`) only `wardenclaw.ticket.exec.v1` with that wardend's `supervisorId`, and it forwards such a ticket as is; anything else is refused with `ticket_type_mismatch` (shape: `type_invalid`, `supervisor_id_invalid`). Optional second-factor fields (format: `protocol/HARDWARE.md`): `payload.risk` (integer 0..100, the app judge's rating; if present, it is part of the signing string) and `hw` (a YubiKey FIDO2 assertion `{credentialId, clientDataJSON, authenticatorData, signature}`, base64url). The plugin checks only the shape of `hw` and **passes it through** to wardend for `wd-…` exec records (relay); wardend checks the key, challenge and signCount. For the plugin's own records `hw` is currently neither required nor checked. In the first release `hw` support is off via the constant `HARDWARE_KEY = false` in `src/features.js`: the plugin rejects a decision with an `hw` field with reason `hw_not_in_release` instead of silently letting it through; what is said above about `hw` holds with `HARDWARE_KEY = true` (that is how the feature comes back, see `daemon/docs/hwkey.md`). Checks: `deviceId ∈ trustedDeviceIds`; the public key from the paired-device store (or `devices` in the config); `|now − ts| ≤ tsWindowMs` (60 s); the signature; the nonce is unique (taken only after a valid signature); `id` is known and `digest` matches the frozen record. Response: `{ok:true, id, decision, late, status}` or `{ok:false, reason}` (403/401).

**HTTP authentication** (routes with `auth: "plugin"`; the app does not and must not have the gateway's shared token):
- GET `pending`/`status`: headers `X-Wardenclaw-Device`, `X-Wardenclaw-Ts`, `X-Wardenclaw-Nonce`, `X-Wardenclaw-Signature` (signature over `canonicalJson({action, deviceId, ts, nonce})`, without `type` and `supervisorId`: it is not the wardend request string, and a signature for one does not work for the other; comparison in `protocol/README.md`, section 5, vector `pluginRequest` in `protocol/vectors/transport_vectors.json`, test `test/request-vector.test.js`).
- All app routes also require `Authorization: Bearer <device-token>`: the same token the device sends in `connect.auth.deviceToken`; it is checked against `tokens_json` of the paired device (`requireDeviceToken: true` by default).
- `POST /wardenclaw/request` (external requester, the PreToolUse hook): `Authorization: Bearer <requestToken>` from the config; without `requestToken` the route is closed (403).

**Protocol version** (`protocol/README.md`, section 10; constants in `src/protocol.js`): the response of `GET /wardenclaw/status` and WS `wardenclaw.status` carries `protocol` (the version the plugin speaks, currently 1) and `minClient` (the oldest client it still supports, currently 1). The app compares them with its own constants and on a mismatch says what to update.

**WS methods** (over a socket already authenticated with the device token): `wardenclaw.pending {since, wait}`, `wardenclaw.decide <body as above>`, `wardenclaw.status`; deviceId is taken from `client.connect.device.id` and must match the signature. Scope `operator.approvals` (status: `operator.read`).

**Hook**: registered without a `matcher` (observe has to see every toolName/toolKind), `priority: 100`, `timeoutMs: ttlMs + 5000`; otherwise the runner's 15 s default would fire before the TTL (and would also block the call: for `before_tool_call` a timeout is fail-closed). In `enforce`: allow → `{}`, deny/timeout/abortSignal/plugin stop/error → `{block:true, blockReason}`.

## Relay to wardend (OS-level execve gate; optional)

If the unix socket of the `wardend` supervisor exists (`wardendSocket`, default `~/.wardend/wardend.sock`, turned off with `relay: false`), the plugin keeps a long-poll to it and **adds wardend exec records to the `/wardenclaw/pending` response** (and WS `wardenclaw.pending`). Their `id` starts with `wd-`, and they have the fields `kind: "exec"`, `envelope` (envelope v1: argv, cwd, exe, uid, gid, ppidChain, env, envHash, requester, pidfdCookie, ts, nonce; the plugin passes it on as is) and `meta` (policy class, rule, "delegating"). The plugin **forwards decisions on `wd-…` in `/wardenclaw/decide` as is** to wardend (`decide` over JSON-RPC) and returns its response with `relayed: true`.

The relay checks the wardend protocol version with the `status` RPC on every connect, once a minute, and before a decision if it has not checked for a while. If wardend has no `protocol`/`minClient` fields, its `protocol` is below 1 or its `minClient` is above 1, the relay **does not forward** decisions on exec records (response `{ok:false, reason:"wardend_protocol_mismatch", relayed:true}`, journal entry `relay_decision` with this response), writes the reason in words to the gateway log (`[wardenclaw-gate] relay: wardend does not report a protocol version… update wardend` or `…update the wardenclaw-gate plugin`) and to the plugin status: `wardend.error = "wardend_protocol_mismatch"`, `wardend.errorText` (the same words), `wardend.protocol` and `wardend.minClient` (what wardend answered). wardend records stay in the feed: the request is visible, it cannot be allowed, and it expires by TTL. Once wardend is updated to a compatible version, forwarding resumes on its own, and the log shows `[wardenclaw-gate] relay: wardend protocol version (…) is compatible again`.

Trust: **wardend verifies the signature** (its `trusted_devices`) and decides the fate of the execve. The plugin is a dumb transport through the existing gateway tunnel; `relayPreverify: true` (default) is an extra early check with the same `verifyDecision` (separate nonce accounting), so that garbage does not reach the supervisor. The app recomputes `digest = sha256(canonicalJson(envelope))` itself and signs with the same key and in the same format as tool records. The plugin forwards a decision on "wd-…" only if it served that record to the client as `kind: "exec"` itself (otherwise `not_served_as_exec`): the ticket signing string is still the same for exec and tool records. Tool records in `/wardenclaw/pending` carry `call` (exactly what the digest covers: `toolName`, `params`, `agentId`, `sessionKey`, `runId`, `toolCallId`; `params` over 512 KiB are not served), the app recomputes the digest and does not allow without a match; `call` is not written to the journal. A device key (config or gateway DB) is accepted only if `sha256(key) = deviceId`, otherwise `pubkey_id_mismatch`. The canonical JSON format is checked against the wardend Go implementation with cross fixtures (`protocol/vectors/canonical_vectors.json`).

## Enabling it locally (a human does this; the config below is just text)

1. Dev dependencies are not needed to run it (only for the tests): `cd wardenclaw-gate && npm test`.
2. The app's key and id: `openclaw devices list` → the `wardenclaw-app` device row; its Device ID (64 hex) is `<APP_DEVICE_ID>` below. The plugin reads the public key itself from `~/.openclaw/state/openclaw.sqlite` (table `device_pairing_paired`); you can also duplicate it in `devices` in the config.
3. Add to `~/.openclaw/openclaw.json` (plugin from a path, without installing it into `~/.openclaw/plugins`):

```json5
{
  plugins: {
    load: { paths: ["/path/to/wardenclaw-gate"] },
    entries: {
      "wardenclaw-gate": {
        enabled: true,
        config: {
          mode: "observe",
          trustedDeviceIds: ["<APP_DEVICE_ID>"],
          ttlMs: 120000,
          exemptAgents: [],
          // requestToken: "<long random secret>"   // only if you need the PreToolUse hook
        }
      }
    }
  }
}
```

Alternative to `load.paths`: `openclaw plugins install --link /path/to/wardenclaw-gate --force && openclaw plugins enable wardenclaw-gate` (see `docs/plugins/hooks.md`, `manage-plugins.md`).

4. Apply: by default hybrid reload picks up the config; after editing the plugin code, `openclaw plugins reload wardenclaw-gate`. Check: `openclaw plugins inspect wardenclaw-gate --runtime --json`, and the gateway log has the line `[wardenclaw-gate] start: mode=observe ...`.
5. Open the WardenClaw app (it is already paired as `wardenclaw-app`): on the "Connect" tab, under "Adapters", the "Plugin" row reads "online · mode observe · signed N". Every executing call shows up in the feed as a `GATE · OBSERVE` card; Allow/Deny send a signed decision, and the plugin's response and the signature are written to the app journal and to `~/.openclaw/wardenclaw-gate/journal.jsonl`.

`before_tool_call` does not require `hooks.allowConversationAccess` (tool-policy.md), so the plugin needs no extra permissions.

## What to watch in stage A (the main unknown: does the hook see claude-cli's native tools)

The gateway log has, for every call: `[wardenclaw-gate] saw tool=<name> kind=<toolKind> agent=… session=… run=… call=… requester=… gated=<true|false>`. According to the docs (`gateway/cli-backends.md`), claude-cli native requests "pass through canonical `before_tool_call` policy before exec policy and approval, with native tool names and file arguments projected into their OpenClaw equivalents", so we expect `exec` for Bash and `write`/`edit` for Write/Edit; `DEFAULT_TOOLS` also has the native names just in case. Summary by name: `GET /wardenclaw/status` → `seenTools` (or WS `wardenclaw.status`).

If claude-cli's Bash/Write/Edit do NOT show up in the log (the hook does not see them), use the fallback below.

## observe → enforce

1. Make sure the app keeps the connection in autopilot/observe mode (Expo Go keeps the socket only in the foreground; 24/7 needs a dev build with a foreground service), otherwise all 28 crons hit the 120 s timeout and get blocked. Or list their agentIds in `exemptAgents` (that is a hole; the maintainer's decision).
2. In the config: `mode: "enforce"`. Hybrid reload picks it up (the plugin instance is recreated with the new config).
3. Optionally `hooks.timeouts.before_tool_call` in the gateway config, if the operator hook limit is below `ttlMs + 5000` (operator timeouts override the plugin's value).
4. Check: a command from chat → a `GATE` card without the "observe" mark → with no tap the call is blocked after 120 s with `wardenclaw-gate: no signed decision within 120 s`; after Allow it runs.

Rollback: `mode: "observe"` or `enabled: false`.

## Revoking a device

The plugin trusts the devices in its own `trustedDeviceIds` (it takes the key from the gateway's paired-device DB or from `devices` in the config). `wardend pair revoke` changes only wardend (its `trusted_devices`) and does not reach here: a phone revoked there, as long as its id is in `trustedDeviceIds`, still sees the plugin's feed (tool records and wardend exec records through the relay) and can allow the plugin's tool calls; wardend rejects its decisions on exec records. Revoke the device in both places:

1. wardend: `wardend pair revoke <id>` (daemon/docs/CLI.md, `wardend pair`).
2. Plugin: delete the id from `plugins.entries["wardenclaw-gate"].config.trustedDeviceIds` in `~/.openclaw/openclaw.json` (and from `devices`, if it is duplicated there) and save the file; hybrid reload recreates the plugin with the new list (pending calls are rejected when that happens, see above about `pending.json`).
3. Check: the line `[wardenclaw-gate] start: … trusted=[…]` in the gateway log (ids by their first 12 characters) no longer has this device.
4. If the phone should not reach the gateway any more: `openclaw devices remove <deviceId>`. Its device token stops opening the gateway, and without a key in `devices` in the config the plugin will not find its public key either.

## Fallback: Claude Code PreToolUse hook

If `before_tool_call` does not see native Bash/Write/Edit, the gate for claude-cli is done on the Claude Code side: the `PreToolUse` hook calls `hooks/pretooluse.mjs`, which sends `POST /wardenclaw/request` and blocks the call without a signed allow (with the plugin in `observe` it only records and does not interfere). It also works for Write/Edit, independently of the OpenClaw bridge.

Setup (NOT applied; a human writes it to `~/.claude/settings.json`). The hook is fail-closed: while the gate does not
answer (plugin not loaded, no `requestToken` in its config, no `request.token` file, wrong
port), Claude Code gets a deny on every Bash, Write and Edit. So first `requestToken` in the
plugin config (`observe` mode) and the `request.token` file, then a manual check:

```bash
echo '{"session_id":"check","tool_name":"Bash","tool_input":{"command":"true"}}' | \
  WARDENCLAW_GATE_URL=http://127.0.0.1:18789 WARDENCLAW_GATE_TOKEN_FILE=$HOME/.openclaw/wardenclaw-gate/request.token \
  node /path/to/wardenclaw-gate/hooks/pretooluse.mjs
```

In observe the hook prints nothing and exits with code 0. A line with `"permissionDecision":"deny"` means
the gate is unavailable and it is too early to install the hook. The block below is added to the existing `hooks` section of the file
and does not replace the whole file; rollback: remove the `PreToolUse` entry.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "WARDENCLAW_GATE_URL=http://127.0.0.1:18789 WARDENCLAW_GATE_TOKEN_FILE=$HOME/.openclaw/wardenclaw-gate/request.token node /path/to/wardenclaw-gate/hooks/pretooluse.mjs",
            "timeout": 140
          }
        ]
      }
    ]
  }
}
```

`request.token` is a file (0600) with the same value as `requestToken` in the plugin config. Put in your own gateway port (`gateway.port`). `WARDENCLAW_GATE_FAIL=open` makes the hook fail-open (not recommended). The script exits with `permissionDecision: deny` when the gate is unavailable.

Limitation: the Claude Code hook sees Claude's `session_id`, not the OpenClaw sessionKey; in the pending record `sessionKey = claude-code:<session_id>`, `source = claude-code-pretooluse`, and `agentId` comes from `OPENCLAW_AGENT_ID` if the gateway passes it into the environment.

## Verifying the journal

```
node scripts/verify-journal.mjs                 # ~/.openclaw/wardenclaw-gate/journal.jsonl + journal-key.json
node scripts/verify-journal.mjs /path/copy.jsonl --pubkey <base64url>
```

Checks the prevHash/hash chain (sha256) and the signature of every record with the plugin key. The journal public key is printed at start (`journalKey=…`) and served in `status.journalPublicKey`.

## What the tests cover

- canonicalization (sorting, undefined, unicode, nesting), digest (determinism, dependence on every field, a pinned reference value), the fixed format of the signing strings;
- a @noble/ed25519 signature (as in the app) is verified by node:crypto with a base64url key; a foreign key, a modified payload, a swapped deviceId are rejected;
- the ±60 s window; the nonce is single-use and taken only after a valid signature; digest/`id` are checked against the frozen record; garbage bodies; WS: the socket's deviceId = the signature's deviceId;
- hook: observe returns `undefined` at once and creates a pending record; a non-executing tool is logged without a pending record; enforce: allow → `{}`, deny → block, timeout → block (fail-closed), abortSignal → block, an untrusted signature does not release; exemptAgents; late decisions;
- HTTP on a real `node:http`: 401 without a signature/token or with a foreign token, nonce replay, long-poll wakes up on a new record, the full enforce cycle through `/decide`, `/request` in observe and enforce (timeout → deny), `requireDeviceToken=false`;
- journal: chain and signatures, detection of tampering/deletion, the key survives a restart, 0600 permissions;
- the sqlite directory on the `device_pairing_paired` schema (key, tokens, composite with the config).

## What can only be checked on a live gateway

1. Loading the plugin from `plugins.load.paths` (Jiti/native import, the `openclaw/plugin-sdk/plugin-entry` alias; there is a fallback to a direct object export).
2. Whether `before_tool_call` sees claude-cli's native Bash/Write/Edit and under which names/`toolKind` (the main unknown; look at `saw tool=` in the log and `status.seenTools`). Whether `runId`/`toolCallId`/`ctx.abortSignal` are filled in for them.
3. Whether `api.on(..., {timeoutMs})` really overrides the 15-second default for `before_tool_call` (and there is no smaller operator `hooks.timeoutMs`).
4. The `auth: "plugin"` HTTP routes are reachable at `https://<your-gateway>/wardenclaw/...` through the Cloudflare tunnel (long-poll 25 s < the 100 s limit) and on the local port.
5. Reading `device_pairing_paired` from the live sqlite (WAL, concurrent gateway writes) in read-only mode without locks; the `wardenclaw-app` device token in `tokens_json` matches what the app sends as Bearer (in the smoke test the key and 1 token were read).
6. `registerGatewayMethod` for a third-party plugin: whether the gateway accepts `wardenclaw.*` methods with scope `operator.approvals` and whether `client.connect.device.id` arrives.
7. Behavior in enforce: a block with `blockReason` reaches the model/chat; the turn does not hang after `block`.
8. PreToolUse hook: the stdin/stdout format of the current Claude Code version and the `OPENCLAW_AGENT_ID` variable in the claude-cli environment.

## License

Copyright (C) 2026 The WardenClaw Authors (see [AUTHORS](../AUTHORS)).

wardenclaw-gate is licensed under the **Apache License 2.0** ([LICENSE](LICENSE), SPDX
`Apache-2.0`), so it can be taken into OpenClaw or any other harness without friction. The
protocol specification and the test vectors the tests read live in [`protocol/`](../protocol/)
at the repository root, also Apache-2.0.

See [NOTICE](NOTICE). "WardenClaw" and the logo are trademarks and are not covered by the
license (Apache-2.0 section 6), see [TRADEMARKS.md](../TRADEMARKS.md).
Contributions: [CONTRIBUTING.md](../CONTRIBUTING.md) (DCO sign-off); vulnerabilities:
[SECURITY.md](../SECURITY.md).
