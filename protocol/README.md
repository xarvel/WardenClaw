# WardenClaw protocol, version 1

This directory is the normative description of the wire formats shared by `wardend`, the
WardenClaw app ([`app/`](../app/)), the OpenClaw plugin ([`plugin/`](../plugin/)) and `wardenctl`: the exec envelope, the signed
decision ticket, the optional hardware second factor, and the signing strings of the wardend
HTTP transport and pairing.

**License.** Everything in this directory, including the test vectors in
[`vectors/`](vectors/), is licensed under the [Apache License 2.0](LICENSE), not under the
licenses of the implementations. You may implement the protocol in any harness, key, watch or
client, open or closed. The Go code in `daemon/envelope/` and `daemon/hwkey/` is the reference
implementation and stays under AGPL-3.0-or-later with the rest of wardend.

Files:

- `README.md`: envelope, canonical JSON, ticket, transport, pairing, es256 devices (Apple Watch),
  push notifications and the protocol version (this file);
- [`HARDWARE.md`](HARDWARE.md): the FIDO2 / YubiKey second factor carried in a ticket;
- [`DISPLAY.md`](DISPLAY.md): how clients show an exec envelope to the human before signing
  (sanitizer, parts of a command, the claude-cli wrapper, blocklist and injection rules);
- test vectors: [`vectors/`](vectors/) (the only copy; the tests of wardend, the app and the
  plugin all read it, see "Test vectors" below).

## 1. Notation

- `sha256(x)` is SHA-256; `hex` is lowercase hex; `b64url` is base64url without padding.
- Signatures are Ed25519 (RFC 8032) over the bytes of the signing string, encoded `b64url`.
  A device may instead hold an `es256` key (ECDSA P-256, see section 7); it signs the same bytes.
  The supervisor key is always Ed25519.
- `deviceId` = `hex(sha256(raw public key))` of a device: the raw 32-byte Ed25519 key, or the
  65-byte SEC1 uncompressed P-256 key of an `es256` device.
  `supervisorId` = `hex(sha256(raw public key))` of the wardend supervisor key.
  Public keys travel as `b64url` of the raw bytes.
- Times (`ts`) are milliseconds since the Unix epoch (JavaScript `Date.now()`).
- `nonce` is a random string chosen by the signer; the envelope uses 16 random bytes in hex.

## 2. Canonical JSON

Every signed or hashed structure is serialized with `canonicalJson`, which is exactly what
this JavaScript produces:

```js
function canonicalJson(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
}
```

(the reference is `plugin/src/canonical.js`; object members whose value is `undefined`
are omitted, `null` is kept).

Implementations in other languages have to reproduce ECMAScript behaviour, not their own JSON
encoder:

- object keys are sorted by UTF-16 code units (as `Array.prototype.sort()`), which differs from
  a byte-wise or code-point sort for characters outside the BMP;
- strings escape only `"`, `\` and control characters below U+0020 (`\b \t \n \f \r`, the rest
  as lowercase `\u00xx`); `<`, `>`, `&`, U+2028, U+2029 and DEL are written as is;
- numbers are formatted as ECMAScript `Number::toString` (`1e+21`, `1e-7`, `0.000001`);
- no whitespace anywhere;
- invalid UTF-8 is an error: an envelope that cannot be encoded is not built, and wardend
  denies the exec (`EPERM`), because the approver could neither display nor recompute it.

## 3. Exec envelope v1

wardend builds one envelope for every "root" exec that needs approval:

```
{v:1, type:"exec", argv, cwd, exe, uid, gid, ppidChain:[{pid, exe}], env, envHash,
 requester:{host, supervisorId}, pidfdCookie, ts, nonce}
```

| field | meaning |
|---|---|
| `v` | `1` |
| `type` | `"exec"` |
| `argv` | argument vector of the new program, array of strings |
| `cwd` | working directory of the calling process |
| `exe` | realpath of the file being executed |
| `uid`, `gid` | effective uid and gid of the caller |
| `ppidChain` | `[0]` is the calling process itself (`pid` = tgid, `exe` = its image before the exec), then its ancestors up to, not including, the supervisor |
| `env` | the variables that change what the program does, shown to the human: `[{name, value}]` or `{name, value, cut}`, see below |
| `envHash` | `hex(sha256(envp))`, the environment sorted and joined with NUL separators |
| `requester.host` | host name, for display only |
| `requester.supervisorId` | see "Notation" |
| `pidfdCookie` | `pidfs:<inode>` of the caller's pidfd (unique within one boot, binds the ticket to one process instance), otherwise `start:<pid>:<starttime>` |
| `ts`, `nonce` | creation time and 16 random bytes in hex |

`env` lists, in the order of `envp`, every entry `NAME=value` whose name selects it (below);
a name that occurs twice is listed twice (the glibc loader takes the last value, `getenv` the
first), entries without `=` are skipped. `value` holds at most 1024 code points (Unicode scalars,
not bytes): a longer value keeps its first 1024, and `cut` is the number of code points removed
(an integer > 0; absent when nothing was removed). An entry that is not valid UTF-8 is an error
as in `argv`: no envelope, the exec is denied. `envHash` still covers the whole environment.

A name is selected when its ASCII upper case

- is one of `BASH_ENV ENV SHELLOPTS BASHOPTS PS4 PROMPT_COMMAND ZDOTDIR SHELL PAGER MANPAGER EDITOR
  VISUAL BROWSER GLIBC_TUNABLES HOSTALIASES LOCALDOMAIN MAKEFILES CC CXX CPP LESSOPEN LESSCLOSE
  RUSTC RUSTC_WRAPPER DOCKER_HOST SSL_CERT_FILE SSL_CERT_DIR`,
- or starts with `LD_ DYLD_ GIT_ BASH_FUNC_ PYTHON PIP_ NODE_ NPM_CONFIG_ YARN_ PERL RUBY BUNDLE_
  GEM_ LUA_ CARGO_ GO CGO_ DOCKER_ KUBE`,
- or ends with `PATH HOME CONFIG RC _OPTIONS _OPTS FLAGS _PROXY ASKPASS _CA_BUNDLE`,

unless it looks like a secret (contains `TOKEN SECRET PASSWORD PASSWD CREDENTIAL PRIVATE_KEY
API_KEY APIKEY ACCESS_KEY COOKIE AUTH_CONFIG` or ends with `_AUTH`): such values do not leave the
host. These are the loader, the start-up files and exported functions of shells, the search paths
and options of interpreters, configuration files and directories (git, kubectl, curl, docker),
programs that tools run by name (pager, editor, askpass, compiler), proxies and trust anchors.
The list is not complete: the rest of the environment is signed only through `envHash`, and the
human does not see it. Only wardend selects; clients show every entry they get (DISPLAY.md,
section 7a).

`digest = hex(sha256(canonicalJson(envelope)))`. The pending record id is `"wd-"` followed by
the first 32 hex characters of the digest.

An approver must recompute the digest from the envelope it shows (a strict parse: exactly the
14 fields above; each `env` entry has exactly `name`, `value` and optionally `cut`, `name` is
non-empty without `=`, `value` has at most 1024 code points, `cut` is an integer > 0) and compare it with the record's `digest` and `id`, and, when it talks to
wardend directly, compare `requester.supervisorId` with the key it pinned at pairing. On any
mismatch it may sign only a `deny`.

## 4. Decision ticket

```json
{"deviceId":"<hex64>","payload":{"type":"wardenclaw.ticket.exec.v1","supervisorId":"<hex64>","id":"wd-…","digest":"<hex64>","decision":"allow|deny","ts":1790000000000,"nonce":"…"},"signature":"<b64url>"}
```

Signing string:

```
canonicalJson({type, deviceId, id, digest, decision, ts, nonce[, supervisorId][, risk]})
```

`payload.type` names what is being decided, and it is signed:

| `type` | decides | `supervisorId` |
|---|---|---|
| `wardenclaw.ticket.exec.v1` | a wardend exec record (`wd-…`), sent to `/v1/decide`, to the socket, or through the gateway plugin's relay | required: the `supervisorId` of the wardend that queued the record, which is `requester.supervisorId` of its envelope |
| `wardenclaw.ticket.tool.v1` | a tool call held by the gateway plugin `wardenclaw-gate` | absent |

A decision signed as one type is not valid as the other, and an exec ticket is valid only for its own
wardend. So a tool card that shows `read README.md` but carries the id and digest of a wardend
record yields a tool ticket, which wardend rejects. wardend accepts only exec tickets with its own
`supervisorId`; the plugin accepts only tool tickets for its own records and passes exec tickets to
wardend unchanged, never anything else. There is no untyped form.

`payload.risk` is optional (integer 0..100, the approver's risk score); when present it is part of
the signing string. An optional `hw` field carries a FIDO2 assertion bound to the ticket, see
[`HARDWARE.md`](HARDWARE.md).

Verification by wardend, in this order:

0. `type` is `wardenclaw.ticket.exec.v1` and `supervisorId` is this wardend's (checked before the
   signature, so a mismatch consumes no nonce);
1. `deviceId` is a trusted device, and its public key is known;
2. `|now - ts|` is within the time window (60 s by default);
3. the signature is valid;
4. the nonce has not been used by this device (it is consumed only after a valid signature);
5. `id` is a known pending record and `digest` matches it;
6. for `allow`, when a hardware rule applies or `hw` is present: the second factor.

The plugin checks its own records the same way, with `type` `wardenclaw.ticket.tool.v1` in step 0.

Rejections use these reasons: `type_invalid` (missing or unknown type), `supervisor_id_invalid` (an
exec ticket without a 64-hex `supervisorId`, or a tool ticket with one), `ticket_type_mismatch`,
`supervisor_mismatch`, `untrusted_device`, `bad_signature`, `digest_mismatch`,
`stale_timestamp`, `nonce_reused`, `unknown_pending`, `already_decided`, `pubkey_conflict`,
`risk_invalid`, and the `hw_*` reasons of [`HARDWARE.md`](HARDWARE.md).

## 5. wardend HTTP transport

Endpoints: `GET /v1/pending?since&wait` (long poll, at most 25 s), `GET /v1/status`,
`POST /v1/decide` (body: a ticket), `POST /v1/pair`, `GET /v1/pair/status?id=…`,
`POST /v1/push/register`, `POST /v1/push/unregister` (section 8), `GET /v1/ping`
(no authentication).

**Requests** other than `decide`, `pair` and `ping` carry the headers `X-Wardenclaw-Device`,
`X-Wardenclaw-Ts`, `X-Wardenclaw-Nonce`, `X-Wardenclaw-Signature`. The signature is made with the
device key over

```
canonicalJson({type:"wardenclaw.req.v1", supervisorId, action, deviceId, ts, nonce})
```

where `action` is `"pending"`, `"status"` or `"pair.status"` and `supervisorId` is the id of the
server's key pinned from the pairing link. The type and `supervisorId` keep a request good for one
wardend only: a request signed for another wardend the device is paired with, or for the gateway
plugin (its own string, below), fails with `bad_signature`. The same time window applies, and a
nonce is single-use per device and action.

**Requests to the gateway plugin.** The OpenClaw plugin `wardenclaw-gate` authenticates
`GET /wardenclaw/pending` and `GET /wardenclaw/status` with the same four headers and the same
device key, but over a shorter string, without a type and without `supervisorId`:

```
canonicalJson({action, deviceId, ts, nonce})
```

where `action` is `"pending"` or `"status"`. By default (`requireDeviceToken`) these routes also
need `Authorization: Bearer <device token>` of the device's gateway pairing (plugin/README.md). The
plugin's WebSocket methods (`wardenclaw.pending`, `wardenclaw.status`) sign nothing: the gateway
socket is already authenticated by the device token. The vector is `pluginRequest` in
`vectors/transport_vectors.json`: the same device, action, `ts` and nonce as the wardend `request`
next to it, a different string and signature.

| | wardend, `GET /v1/…` | gateway plugin, `GET /wardenclaw/…` |
|---|---|---|
| signed string | `{type:"wardenclaw.req.v1", supervisorId, action, deviceId, ts, nonce}` | `{action, deviceId, ts, nonce}` |
| bound to | this wardend (`supervisorId` of the key pinned from the pairing link) | the device and the action only: any plugin that trusts the device accepts it |
| actions | `pending`, `status`, `pair.status`; with `body` in the string: `push.register`, `push.unregister` | `pending`, `status` |
| also required | nothing | the device token of the gateway pairing (`Authorization: Bearer`, unless `requireDeviceToken` is off) |
| trusted devices | `trusted_devices` of wardend (`wardend pair`) | `trustedDeviceIds` of the plugin config |
| window, nonce | `ts_window` (60 s), nonce single-use per device and action | `tsWindowMs` (60 s), nonce single-use per device, shared with the plugin's tickets |

Why a signature for one path is no good on the other: the strings differ in `type` and
`supervisorId`, so a request captured on its way to the plugin fails at wardend with
`bad_signature`, and a wardend request fails at the plugin the same way. The plugin has no key of
its own pinned by the phone, so there is nothing like `supervisorId` to bind its requests to; the
device token and `trustedDeviceIds` limit who is served. The relay path uses no wardend request
string at all: the plugin reads wardend over its unix socket, and only the tickets (section 4) go
from the phone to wardend unchanged. Trust is separate too: `wardend pair revoke` doesn't remove the
device from the plugin's `trustedDeviceIds` (daemon/docs/CLI.md, `wardend pair`). A type for the
plugin's string would be a breaking change and needs a new protocol version (section 10).

Requests **with a JSON body** (`push.register`, `push.unregister`) carry the same four headers, and
the signature also covers the body:

```
canonicalJson({type:"wardenclaw.req.v1", supervisorId, action, body, deviceId, ts, nonce})
```

where `body` is the request body as a JSON object (the server parses the body it received and
canonicalizes it, so the client may serialize it in any key order). `deviceId` inside the body must
equal the `X-Wardenclaw-Device` header.

**Responses** are all signed with the supervisor key, header `X-Wardend-Signature`
(`X-Wardend-Supervisor` carries the `supervisorId`, not trusted). The signed string is bound to the
request, not only to its nonce, and has one of three types:

```
canonicalJson({type:"wardenclaw.resp.v1", action, deviceId, nonce, status, bodySha256[, id, digest]})
canonicalJson({type:"wardenclaw.ping.v1", nonce, status, bodySha256})
canonicalJson({type:"wardenclaw.resp.unauth.v1", action, status, bodySha256})
```

`status` is the HTTP status code and `bodySha256` is `hex(sha256(response body))`.

| Type | When | Bound to |
|---|---|---|
| `wardenclaw.resp.v1` | the request is authenticated: the device signature verified and its nonce was claimed by this very request (for `decide`: the ticket passed the signature and nonce checks, whatever the outcome after that: accepted, `unknown_pending`, `digest_mismatch`, a second-factor reason, `already_decided`; for `pair`: the new key's signature verified) | `action` (`pending`, `status`, `decide`, `pair`, `pair.status`, `push.register`, `push.unregister`), `deviceId` (the header, the ticket's or the pairing body's), the request nonce (`X-Wardenclaw-Nonce`, the ticket's `payload.nonce`, the pairing body's `nonce`), and for `decide` the ticket's `id` and `digest`; the `decide` body also names `id` and, on success, `decision` |
| `wardenclaw.ping.v1` | `GET /v1/ping` (no authentication) | the `?nonce` parameter only |
| `wardenclaw.resp.unauth.v1` | a rejection before the request is authenticated: bad or missing signature, stale `ts`, unknown device, a reused nonce, a malformed or foreign-type ticket, a pairing request rejected before its signature verified, 400/404/405/413 | `action` only, no nonce and no `deviceId`: anyone can get such a response for any request |

A client accepts a response only if it is signed by the key pinned from the pairing link and:
- for `ping`, verifies as `wardenclaw.ping.v1` with its own nonce;
- for any other request, verifies as `wardenclaw.resp.v1` with its own action, deviceId, nonce (and
  for `decide` the ticket id and digest), and for `decide` the body's `id` (and `decision` when
  `ok:true`) equals what it sent;
- a response that verifies only as `wardenclaw.resp.unauth.v1` with its own action and an
  `{ok:false}` body is a rejection that is not bound to the request: the client may show its reason,
  but must not take it as the answer (for `decide` the decision is neither applied nor rejected, the
  card stays).

So a proxy that saw a request nonce can't hand the phone the signed `ping` (or the response to
another request, or a rejection of a junk request with the same nonce) as the answer to `decide`,
`push.register` or anything else.

## 6. Pairing

The pairing link, shown as a QR code:

```
wardenclaw://pair?code=<code>&host=<host>&key=<b64url supervisor public key>&url=<public url>&v=1
```

`code` is a one-time code (8 characters, displayed as `XXXX-XXXX`, compared without dashes and
spaces in upper case), `host` is for display only, `url` is the public address of the wardend
HTTP endpoint.

`POST /v1/pair` body: `{code, deviceId, pubkey, alg?, name, supervisorId, ts, nonce, signature}`,
where `pubkey` is the new device's public key and the signature is made with the new device's key
over

```
canonicalJson({type:"wardenclaw.pair.v1", code, deviceId, pubkey, name, supervisorId, ts, nonce[, alg]})
```

`alg` is `"ed25519"` (the default when absent) or `"es256"`. When the body carries `alg`, it is part
of the signing string; an `es256` device must send it. Without `alg` the string is the v1 one.

`supervisorId` must be the id of the key from the link, so a request cannot be replayed to another
supervisor. The server operator then confirms the device out of band, comparing the fingerprint:
the first 16 hex characters of `deviceId` in groups of four (`0123 4567 89ab cdef`).

## 7. es256 devices (Apple Watch)

A device may hold an ECDSA P-256 key instead of Ed25519. The case in mind is Apple Watch: its
Secure Enclave generates and keeps a P-256 key (CryptoKit `SecureEnclave.P256.Signing`) and has no
Ed25519. The watch is paired as a device of its own, with its own key, and talks to wardend over
HTTPS like the phone.

- **Key.** `pubkey` is the SEC1 uncompressed point `0x04 || X || Y` (65 bytes), `b64url`. The point
  must be on the curve. `deviceId = hex(sha256(these 65 bytes))`.
- **Pairing.** `alg: "es256"` in the body and in the signing string (section 6); the pairing
  request is signed with the new P-256 key. wardend stores `alg` in `trusted_devices`
  (`{"id", "pubkey", "alg": "es256", "name"}`); entries without `alg` are Ed25519.
- **Signatures.** ECDSA with SHA-256 over exactly the same bytes as an Ed25519 device signs: the
  ticket signing string (section 4), the request signing strings (section 5). Encoding: `b64url` of
  either raw `r || s` (64 bytes, each value big-endian, left-padded to 32 bytes) or DER (ASN.1
  `SEQUENCE {INTEGER r, INTEGER s}`, what Secure Enclave returns as `derRepresentation`). Both high
  and low `s` are accepted: Secure Enclave does not normalize `s`, and nothing in the protocol is
  keyed by signature bytes (replays are stopped by the single-use nonce).
- **No algorithm negotiation.** A ticket or request carries no `alg`. wardend verifies with the
  algorithm recorded at pairing, which the device signed. An Ed25519 signature under the id of an
  `es256` device, or a 65-byte key declared as `ed25519`, is rejected (`bad_signature`,
  `pubkey_invalid`). Unknown values of `alg` give `alg_unsupported`.
- **Second factor.** The watch cannot carry a FIDO2 assertion. A card with
  `meta.hardware.required: true` (or a score rule that fires) therefore cannot be approved from the
  watch: an `allow` without `hw` gets `hardware_required`, and an assertion made for another
  device's ticket does not match the challenge, which covers `deviceId`. `deny` never needs the key.
- **Approve only in the app.** wardend accepts any correctly signed ticket and cannot tell where the
  user tapped. Approving from a notification action is a client restriction: the watch app offers
  only "Deny" and "Open" as notification actions (a double-tap gesture on Series 9 and Ultra 2 hits
  the first non-destructive action, so "Allow" must never be one) and approves only inside the app
  after an explicit confirmation. "Deny" from a notification is an ordinary signed `deny` ticket.

## 8. Push notifications (APNs)

Optional. When `apns` is set in wardend's config, a new card triggers an APNs notification to every
push token registered by a trusted device. Without it nothing changes: the app learns about cards by
long poll (and optionally ntfy).

**Register** (`POST /v1/push/register`, signed body, `action: "push.register"`):

```json
{"deviceId": "<hex64>", "platform": "apns", "token": "<APNs device token, lowercase hex>",
 "topic": "<bundle id>", "environment": "sandbox"}
```

`topic` must be one of `apns.topic_ios`, `apns.topic_watch` of the server; `environment` is
`"sandbox"` (development builds) or `"production"` (TestFlight, App Store). A device may have up to 4
tokens; the same token registered again, or by another device, replaces the old entry. Rejections:
`push_not_configured` (409, no `apns` on the server), `platform_unsupported`, `token_invalid`,
`topic_not_allowed`, `environment_invalid`, `device_mismatch`, plus the usual request reasons
(`untrusted_device`, `bad_signature`, `stale_timestamp`, `nonce_reused`).

**Unregister** (`POST /v1/push/unregister`, signed body, `action: "push.unregister"`):
`{"deviceId", "platform"?: "apns", "token"?}`; without `token` all tokens of the device are removed.
Response `{"ok": true, "removed": N}`. Revoking a device on the server removes its tokens too.

**What wardend sends.** HTTP/2 `POST https://api.push.apple.com/3/device/<token>`
(`api.sandbox.push.apple.com` for `sandbox`), token-based auth (JWT ES256 signed with the team's
`.p8` key, `kid` = key id, `iss` = team id, cached 50 minutes), headers
`apns-topic: <topic>`, `apns-push-type: alert`, `apns-priority: 10`,
`apns-expiration: <card expiry, Unix seconds>`, `apns-collapse-id: <card id>`. The payload is
exactly

```json
{"aps":{"alert":{"title":"Approval request","body":"Open to review"},"category":"WARDEN_APPROVAL","sound":"default","interruption-level":"time-sensitive"},"cardId":"wd-…"}
```

It contains no command, host, path or risk: Apple and anyone who sees the notification learn only
that a card exists. The client fetches the card over the signed channel (`/v1/pending`), checks it
as in section 3 and only then shows it. A token that APNs answers with `410 Unregistered` is
deleted. A push token is an address, not a credential: it cannot approve anything.

## 9. Test vectors

| file | covers |
|---|---|
| `vectors/canonical_vectors.json` | canonical JSON: Unicode, control characters, U+2028, UTF-16 key order, numbers, a typed exec envelope and its digest |
| `vectors/hw_vectors.json` | ticket signing strings with `risk`, second-factor challenge and `clientDataJSON` |
| `vectors/transport_vectors.json` | request, pairing and response signing strings, the gateway plugin's request string (`pluginRequest`), the pairing link, the fingerprint |
| `vectors/es256_vectors.json` | an `es256` device: key, `deviceId`, pairing (with `alg`), ticket, request and signed-body (`push.register`) signing strings, signatures raw and DER |
| `vectors/display_vectors.json` | showing a card (DISPLAY.md): sanitizer, homoglyphs, splitting a command, the claude-cli wrapper, rules, delegating launches, full card models including attack cases |

`canonical_vectors.json` is produced by `vectors/gen_vectors.mjs` from the plugin's
JavaScript implementation; `display_vectors.json` by `app/scripts/gen-display-vectors.mjs` from
the app's `display.ts`; the others are produced by the Go reference implementation. The ECDSA
signatures in `es256_vectors.json` use deterministic `k` (RFC 6979) so the file is reproducible;
real devices sign with random `k`, so compare signing strings and verify signatures rather than
comparing signature bytes. The
keys in the vectors are the public RFC 8032 and RFC 6979 test keys or synthetic values. There are no copies:
the Go tests (`daemon/envelope`, `daemon/cmd/wardenctl`), the app (`app/scripts/test-core.mjs`)
and the plugin (`plugin/test/`) read the files in this directory, so every implementation is
checked against the same bytes.

Regenerating (from the repository root):

```sh
node protocol/vectors/gen_vectors.mjs > protocol/vectors/canonical_vectors.json
(cd daemon && go test ./envelope -run 'TestHWVectors|TestTransportVectors|TestES256Vectors' -update-hw -update-transport -update-es256)
```

## 10. Protocol version

The protocol has one version number for everything in this directory: the envelope, the signing
strings, and the APIs of wardend and the gateway plugin. It is an integer; the title of this file
names the current one.

**What the servers send.** wardend sends two integers in `GET /v1/ping`, `GET /v1/status` and the
RPC `status` on its socket; the plugin sends them in `GET /wardenclaw/status` and the WebSocket
method `wardenclaw.status`:

- `protocol`: the version the server speaks;
- `minClient`: the oldest client version the server still supports.

The `"v": 1` in the ping body stays as it is; it is not the protocol version.

**What raises the version.** Any change that breaks an existing client or server: a signing string,
a required field, the envelope format (its `v` rises with it), an API path, or the meaning of a
field. A new optional field in a response does not raise it: clients ignore fields they don't know.
When the version rises, a server that still serves older clients keeps `minClient` at the oldest
version it serves.

**What a client must check.** Every client (the app, `wardenctl`, and the plugin's relay to
wardend) holds two constants, `PROTOCOL` (the version it speaks) and `MIN_SERVER_PROTOCOL` (the
oldest server version it works with), and checks the `ping` or `status` response of the server:

- no `protocol` field, or `protocol < MIN_SERVER_PROTOCOL`: the server is older than the client,
  "update the server";
- `PROTOCOL < minClient`: the client is older than the server, "update the client".

These are their own errors, shown in words, not `type_invalid` or `bad_signature`. While the
versions don't match, the client doesn't sign decisions for that server and the relay doesn't
forward them (it answers `wardend_protocol_mismatch`).

An envelope with a `v` the client doesn't know is not dropped silently: the client says there is a
request it can't show and that it needs an update. Such a request can't be allowed (fail-closed);
it expires on the server like any unanswered request.

| protocol | release | what it is |
|---|---|---|
| 1 | the first public release | everything in this directory: envelope v1, typed tickets with `supervisorId`, the `wardenclaw.req.v1` request string, the three response types, pairing, es256 devices, push. Pre-release builds send no version fields: to a client of protocol 1 they are servers older than the client |

Where the constants live: `daemon/envelope` (`Protocol`, `MinClient`, served by wardend),
`daemon/cmd/wardenctl/client.go`, `plugin/src/protocol.js` (the plugin both serves and, in the relay,
checks wardend) and `app/src/core/protocolVersion.ts`.
