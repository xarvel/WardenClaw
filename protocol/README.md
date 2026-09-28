# WardenClaw protocol, version 1

This directory is the normative description of the wire formats shared by `wardend`, the
WardenClaw app ([`app/`](../app/)), the OpenClaw plugin ([`plugin/`](../plugin/)) and `wardenctl`: the exec envelope, the signed
decision ticket, the optional hardware second factor, and the relay transport: its frames, the
end-to-end encryption of what it carries, pairing and push notifications.

**License.** Everything in this directory, including the test vectors in
[`vectors/`](vectors/), is licensed under the [Apache License 2.0](LICENSE), not under the
licenses of the implementations. You may implement the protocol in any harness, key, watch or
client, open or closed. The Go code in `daemon/envelope/` and `daemon/hwkey/` is the reference
implementation and stays under AGPL-3.0-or-later with the rest of wardend.

Files:

- `README.md`: envelope, canonical JSON, ticket, the relay transport (frames, delivery, payload
  encryption, limits), pairing, es256 devices, push notifications and the protocol version (this
  file);
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

### 3a. The rootexec envelope

A process under the gate may ask wardend to run one command as wardend's own user (root in the
hardened install) through `wardend rootexec` (daemon/docs/rootexec.md). Such a request is an
envelope with the same 14 fields, the same canonical form and the same digest rule, with
`type: "rootexec"` and another meaning of three fields:

| field | in a rootexec envelope |
|---|---|
| `uid`, `gid` | the ids the program WILL run with: wardend's own (`0`, `0` in the hardened install), not the requester's |
| `exe` | realpath of the file wardend opened and pinned for the launch: what runs is that inode, whatever the path holds later |
| `ppidChain` | `[0]` is the requesting process (the `wardend rootexec` client under the gate), then its ancestors up to the supervisor |
| `env` | the environment the program will get (wardend's fixed set, selected as above), `envHash` over all of it |

The strict parse accepts `type` `"exec"` or `"rootexec"` and nothing else. A client that does not
know `"rootexec"` (protocol 1) therefore cannot show or sign such a card, fail-closed, and the
request expires on the server. The `type` is inside the digest: a ticket signed for an exec card
does not fit a rootexec card. The ticket is `wardenclaw.ticket.exec.v1` as for any wardend
record.

A rootexec card is **always dangerous** (DISPLAY.md, section 8), with the reason named first
("runs as root … outside the gate"), and no automatic approver may allow it. `meta` carries
`class: "rootexec"` and a `rootExec` object (`runAsUid`, `runAsUser`, `requesterUid`,
`requesterPid`, `timeoutMs`, `note`), not signed, display only.

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
| `wardenclaw.ticket.exec.v1` | a wardend exec record (`wd-…`), sent as a `ticket` message over the relay (section 11), to wardend's unix socket, or through the gateway plugin | required: the `supervisorId` of the wardend that queued the record, which is `requester.supervisorId` of its envelope |
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

## 5. Relay transport

The relay is the only transport: a phone, or any other approver (`wardenctl`), talks to wardend
through it and nothing else. wardend opens no listening port for approvers; its other interface
is the unix socket on its own machine (daemon/docs/CLI.md).

A transport in which the phone calls the daemon would need a public HTTPS address of the
machine that runs the agent: a tunnel, a hostname, a certificate, and a way to debug three parties
when a request hangs. Nothing about the security model needs that: every card and every ticket is
signed on the ends, so whoever carries the bytes cannot forge a decision.

So the connection goes the other way. The daemon keeps one **outbound** WebSocket to a relay and
so is reachable from anywhere without a public port, a tunnel or NAT games. The phone talks to the
same relay while it is open and is woken by a push notification when it is not. The relay is a
**dumb, untrusted carrier**: it routes frames by identity, queues what could not be delivered yet,
and sends the push. It sees ciphertext.

What the relay can do: delay or drop a message, and know that a supervisor and a device talk and
how often. What it cannot do: read a card, forge a card, forge or replay a ticket, pair a device,
or turn a lost message into an approval. A card that does not reach a phone in time expires on
the daemon and the exec is **denied** (`EPERM`).

### 5.1 Parties and keys

| party | identity key | encryption key | id |
|---|---|---|---|
| supervisor (`wardend`) | Ed25519 (the supervisor key, section 1) | X25519, generated next to it, stored in `state_dir` | `supervisorId` |
| device (app, `wardenctl`) | Ed25519 device key (section 1) | X25519, generated next to it | `deviceId` |
| relay | none. TLS server certificate only | | its URL |

Encryption keys are separate from identity keys: no Ed25519→X25519 conversion, so a device key in
a secure element needs no change. The binding between a
party's identity key and its encryption key is made where the identity key is already trusted:
in the QR for the supervisor, in the signed pairing payload for the device (section 6).

The identity key of a `hello` is Ed25519: an `es256` device (section 7) has no relay connection of
its own in protocol 1.

### 5.2 Frames

A connection carries JSON text frames, one object per WebSocket message, `type` first:

```
{type:"…", …}
```

Numbers are integers, times are `ts` milliseconds as in section 1, binary is `b64url`. A frame
larger than **64 KiB** is refused and the connection closed (code 1009). Unknown `type` is
ignored by the relay and by clients (forward compatibility); unknown members are ignored. An
unknown `kind` of a `msg`: section 5.5.

Two kinds of frames exist: **relay frames**, read by the relay (`challenge`, `hello`, `resume`,
`devices`, `pairing`, `push.register`, `push.unregister`, `ack`, `error`, `ping`, `pong`), and
**envelope frames** (`msg`, `pair`), whose `body` the relay stores and forwards without reading.

### 5.3 Connecting

```
wss://relay.wardenclaw.dev/v1/ws/<supervisorId>
```

One connection serves one channel (section 5.4): the supervisor connects to its own id, a device
opens one connection per supervisor it is paired with.

1. The relay sends `{type:"challenge", nonce, ts}` (`nonce`: 32 random bytes b64url, valid 60 s).
2. The client answers with a signed hello:

```
{type:"hello", role:"supervisor"|"device", key:<b64url Ed25519 pub>, enc:<b64url X25519 pub>,
 ts, nonce:<the challenge nonce>, client:{name, version, protocol}, sig}
```

`sig` = Ed25519 over `canonicalJson({type:"wardenclaw.relay.hello.v1", role, key, enc, ts, nonce,
client})` (section 2). The relay recomputes the id (`hex(sha256(raw key))`), checks the signature,
the nonce (its own, unused, fresh) and `|now - ts| ≤ 120 s`, then replies
`{type:"welcome", id, role, protocol, ts, limits:{frame, queue, ttl}}` or
`{type:"error", code, close:true}` (`role_invalid`, `key_invalid`, `challenge_invalid`,
`stale_timestamp`, `bad_signature`, `protocol_mismatch`: `client.protocol` is not the relay's
`protocol`, `not_this_channel`: a supervisor hello whose key is not the channel's id). A client
that gets a `welcome` with another `protocol` than its own drops the connection.

The connection is now bound to `id` and `role`. Nothing later on it is signed for the relay's
sake: the relay trusts the TLS session it authenticated. Everything that must survive the relay
(cards, tickets, pairing) is signed and encrypted for the other end inside `body`.

A supervisor may hold one connection per `supervisorId`; a second hello for the same id closes the
older one (code 4001 `superseded`). A device may hold several (phone and laptop with the same
key are two connections, both get every message).

After `welcome`, and whenever the supervisor connects or disconnects, the relay tells a device
whether the supervisor is there: `{type:"peer", online:true|false}`. It is a hint for the
screen ("wardend offline"), signed by nobody: nothing is decided on it, and a device that never
gets the frame works the same.

Relay frames that change state are answered with `{type:"ack", what:<type>, …}` (`devices`: also
`count`; `pairing`: also `until`, 0 when closed; `push.register`: also `configured`;
`push.unregister`: also `removed`); envelope
frames with `{type:"ack", id, seq}` (section 5.5; an id the relay already has is acked again with
`duplicate:true`, and `seq:0` if that frame was delivered and deleted). A refused frame gets `{type:"error", code}`; `close:true` in it means the relay
closes the connection right after (code 4002, or 1009 for an oversized frame). The error names the
frame it refuses: `id` for an envelope frame (`msg`, `pair`), `what` (the frame's type) for any
other; a frame that could not be parsed has neither. A client matches the error to the request by
that reference; an error without one goes to the oldest request still waiting for an answer.

**Keepalive.** Either side sends `{type:"ping", ts}`, the other answers `{type:"pong", ts}`. The
exact text `{"type":"ping"}` is answered with `{"type":"pong"}` without waking the channel; it
counts as a sign of life like any other frame. The relay closes a connection silent for 90 s
(code 1001 `idle`); it looks once a minute while a socket is open, so a dead connection is gone
within 150 s. The daemon reconnects with exponential backoff
(1 s … 60 s, jitter) and never stops trying; the app connects when it is in the foreground.

### 5.4 Channels and who may talk to whom

Every supervisor is a **channel** named by its `supervisorId`. A device sends to a channel, a
supervisor sends to a device on its own channel. The relay enforces this:

- After `welcome`, the supervisor sends `{type:"devices", ids:[deviceId…]}`: its trusted devices
  (`trusted_devices` of the config, the same list `wardend status` shows). It re-sends the full
  list whenever it changes (pair approve, revoke). A device that is not on the list gets
  `{type:"error", code:"not_trusted"}` for a `msg` to that channel, and nothing from the channel
  is delivered to it.
- `{type:"pairing", open:true, until:ts}` from the supervisor opens a pairing window: until
  `until` the relay forwards `pair` frames from **any** device to the channel (section 6);
  `{type:"pairing", open:false}` closes it. The relay never opens one on its own.
- A device names the channel in every frame it sends (`to: supervisorId`, the id of the
  connection's URL; anything else is `to_invalid`).

The relay does not know the pairing state beyond these two lists and forgets both when the
supervisor disconnects (the supervisor re-sends them on every hello).

### 5.5 Messages, delivery and acks

```
{type:"msg", id, to, from, seq, ts, exp, body, kind}
```

| member | set by | meaning |
|---|---|---|
| `id` | sender | 16 random bytes hex, unique; the relay and the receiver dedupe by it |
| `to` | sender | `deviceId` (from a supervisor) or `supervisorId` (from a device) |
| `from` | relay | the authenticated id of the sender (a client-supplied `from` is overwritten) |
| `seq` | relay | per (channel, device, direction) counter, 1, 2, 3 … assigned when the relay accepts the frame |
| `ts` | sender | when the sender built it |
| `exp` | sender | after this time the relay drops it undelivered (a card: its `expiresAt`; a ticket: `ts` + 10 min) |
| `body` | sender | the encrypted payload (section 11), b64url |
| `kind` | sender | plaintext hint for the relay and the push: `card`, `card.done`, `ticket`, `ticket.result`, `status`, `status.req`, `pair.status` |

**Acceptance.** The relay stores the frame in the channel's queue for `to`, assigns `seq`, answers
`{type:"ack", id, seq}` to the sender, and forwards the frame to every live connection of `to`.
An `error` instead of `ack` means the frame was not stored: `not_trusted`, `too_large`,
`queue_full` (≥ 200 undelivered frames for that receiver), `expired` (`exp ≤ now`),
`rate_limited`.

**Delivery.** The receiver answers every `msg` it processed with `{type:"ack", id, seq}`; the
relay then deletes it from the queue. Without the ack the frame stays until `exp` and is sent
again on the next `resume`. Receivers therefore dedupe by `id`: a card may arrive twice, the second
copy is ignored; a ticket may arrive twice, wardend already refuses a reused ticket nonce.

A receiver acks what it opened and handled, and also what it opened and definitively refused (a
ticket for an unknown card): another delivery would not change the answer. It does **not** ack a
frame that is not for it, is not from the other end of the channel, is expired or does not open
(`relay_tamper`); the relay drops such a frame at `exp`.

**Unknown kind.** The relay accepts only the kinds of the table. A receiver that gets a `msg` of
a kind it does not know (the other end and the relay are newer than it) treats it like any other
frame up to the box: routing members, sender, `exp`, and the box must open with the AAD of the
frame. Then it acks the frame, delivers nothing and logs it (wardend: `relay_unhandled` in the
journal; the app: its log). The plaintext is not interpreted. So a new kind never sits in the
queue until `exp` for an old client, and never becomes a card or a decision there.

**Resume.** After `welcome`, a client sends `{type:"resume", seq}` (a device: the last `seq` it
acked from this supervisor, 0 for everything) or `{type:"resume", device, seq}` (a supervisor: per
device; without `device`, every device's queue, `seq` ignored). The relay replays every
undelivered, unexpired frame with a higher `seq`, in order, then `{type:"resumed", count}`. A gap
in `seq` on the receiver means frames expired or were dropped; the client asks the other end for
the current state (`status.req` from a device, the supervisor answers with a `status` message that
carries the full pending list, so nothing depends on replay alone).

**Ordering.** Per direction and pair the relay delivers in `seq` order over one connection. Across
reconnects, `resume` restores it. Clients do not rely on order between different pairs.

**Retention.** Undelivered frames live until `exp`, at most 24 h. The relay keeps nothing about a
delivered frame except the `id` for 24 h (dedupe). A channel nobody connects to therefore holds
no frames after a day; what stays are the push tokens (section 8) and the device keys of section 12.

### 5.6 Requests to the gateway plugin

The OpenClaw plugin `wardenclaw-gate` is not on the relay: the app reaches it through the OpenClaw
gateway. It authenticates `GET /wardenclaw/pending` and `GET /wardenclaw/status` with the headers
`X-Wardenclaw-Device`, `X-Wardenclaw-Ts`, `X-Wardenclaw-Nonce`, `X-Wardenclaw-Signature`; the
signature is made with the device key over a string without a type and without `supervisorId`:

```
canonicalJson({action, deviceId, ts, nonce})
```

where `action` is `"pending"` or `"status"`. By default (`requireDeviceToken`) these routes also
need `Authorization: Bearer <device token>` of the device's gateway pairing (plugin/README.md). The
plugin's WebSocket methods (`wardenclaw.pending`, `wardenclaw.status`) sign nothing: the gateway
socket is already authenticated by the device token. The vector is `pluginRequest` in
`vectors/transport_vectors.json`.

The window is `tsWindowMs` (60 s) and a nonce is single-use per device, shared with the plugin's
tickets; the devices served are `trustedDeviceIds` of the plugin config. The plugin has no key of
its own pinned by the phone, so there is nothing like `supervisorId` to bind its requests to; the
device token and `trustedDeviceIds` limit who is served. For wardend's records the plugin reads
wardend over its unix socket, and only the tickets (section 4) go from the phone to wardend
unchanged. Trust is separate too: `wardend pair revoke` doesn't remove the device from the plugin's
`trustedDeviceIds` (daemon/docs/CLI.md, `wardend pair`). A type for the plugin's string would be a
breaking change and needs a new protocol version (section 10).

## 6. Pairing

The pairing link, shown as a QR code by `wardend pair start`:

```
wardenclaw://pair?code=<one-time code>&enc=<b64url X25519>&host=<display name>&key=<b64url Ed25519>
                  &relay=wss://relay.wardenclaw.dev/v1/ws&sid=<supervisorId>&v=1
```

`code` is a one-time code (8 characters, displayed as `XXXX-XXXX`, compared without dashes and
spaces in upper case), `host` is for display only, `relay` is the relay endpoint without the
channel and `sid` the channel. `relay` is a `wss://` address, nothing else: the app refuses a link with any other scheme, with
a query or with credentials in it, and requires `sid` to be the id of `key`. wardend accepts a
`ws://` `relay_url` for a loopback relay (tests, a local proxy), but `pair start` then refuses to
make a link and says why.

`key` and `enc` come from the same QR, which the human scanned from the daemon's own terminal:
that is the binding of the supervisor's two keys. The daemon opens the pairing window on the relay
(`pairing open:true, until: now + pair_code_ttl`) before it prints the QR, so the phone can send at
once.

The phone connects, sends `hello` as a device and then:

```
{type:"pair", id, to:<sid>, ts, exp, body}
```

(a `pair` frame is an envelope frame with `kind:"pair"` set by the relay; the supervisor acks it
like a `msg`)

The supervisor does not know the device's encryption key yet, so for frames of type `pair`
**only** the device's X25519 public key travels in front of the box:

```
body = b64url(devEncPub(32 bytes) || nonce(24) || ciphertext)
```

The box itself is the one of section 11 (same key derivation with `deviceId` = the frame's `from`,
same AAD with `kind:"pair"`). Its plaintext is the pairing payload, which names the device's
encryption key, under the new device's signature:

```
{payload:{code, deviceId, pubkey, enc:<b64url X25519>, name, supervisorId, ts, nonce[, alg]}, signature}
```

`signature` is made with the new device's key over
`canonicalJson({type:"wardenclaw.pair.v1", …payload})`. `alg` is `"ed25519"` (the default when
absent) or `"es256"` (section 7); when the payload carries it, it is part of the signing string.
`supervisorId` must be the id of the key from the link, so a request cannot be replayed to another
supervisor. The key in front of the body is not authenticated by itself: the
supervisor derives the box key from it, opens the body and then **requires** that `payload.enc`
is the same 32 bytes and `payload.deviceId` is the frame's `from`. A mismatch is refused, journaled
as `relay_tamper` and never acked. Then it checks the request
(code, window, key, rate limits), keeps `enc` with the pending request, and answers with a `msg`
of kind `pair.status` to the device, boxed for that key:
`{re, id, status:"pending"|"approved"|"rejected", fingerprint, supervisorId, host, expiresAt}`, or
`{re, status:"refused", reason, fingerprint, supervisorId, host}` when the request was not accepted
(`bad_code`, `pairing_not_active`, …). `re` is the `id` of the `pair` frame the status answers
(32 hex): the supervisor keeps it with the pending request (a retry of the same device replaces
it) and puts it in every `pair.status` about that request. A device ignores a `pair.status`
whose `re` is not the frame of its current request, so a status the relay kept from an earlier
attempt decides nothing. Approval is out of band: the server operator compares the fingerprint (the first 16 hex characters
of `deviceId` in groups of four, `0123 4567 89ab cdef`) and runs `wardend pair approve <id>` on
the unix socket; it records `enc` next to the device's key in `trusted_devices`. After approval
the supervisor re-sends `devices` to the relay and a `pair.status` with `approved`; the device may
send `status.req` from then on. The window on the relay is closed when the last active code is
used or expires.

The relay learns nothing but that a pairing happened: the code, the name and the keys are inside
`body`. The one-time code is what protects pairing; the window on the relay only limits who
may knock.

## 7. es256 devices

A device may hold an ECDSA P-256 key instead of Ed25519. The case in mind is a secure element that
has no Ed25519, such as the Secure Enclave of an Apple Watch (CryptoKit
`SecureEnclave.P256.Signing`). wardend pairs such a device and verifies its tickets. The relay
`hello` (section 5.3) is signed with an Ed25519 key, so an `es256` device has no relay connection of
its own in protocol 1, and no client of this release uses `es256`.

- **Key.** `pubkey` is the SEC1 uncompressed point `0x04 || X || Y` (65 bytes), `b64url`. The point
  must be on the curve. `deviceId = hex(sha256(these 65 bytes))`.
- **Pairing.** `alg: "es256"` in the payload and in the signing string (section 6); the pairing
  request is signed with the new P-256 key. wardend stores `alg` in `trusted_devices`
  (`{"id", "pubkey", "alg": "es256", "name"}`); entries without `alg` are Ed25519.
- **Signatures.** ECDSA with SHA-256 over exactly the same bytes as an Ed25519 device signs: the
  ticket signing string (section 4) and the pairing string (section 6). Encoding: `b64url` of
  either raw `r || s` (64 bytes, each value big-endian, left-padded to 32 bytes) or DER (ASN.1
  `SEQUENCE {INTEGER r, INTEGER s}`, what Secure Enclave returns as `derRepresentation`). Both high
  and low `s` are accepted: Secure Enclave does not normalize `s`, and nothing in the protocol is
  keyed by signature bytes (replays are stopped by the single-use nonce).
- **No algorithm negotiation.** A ticket carries no `alg`. wardend verifies with the
  algorithm recorded at pairing, which the device signed. An Ed25519 signature under the id of an
  `es256` device, or a 65-byte key declared as `ed25519`, is rejected (`bad_signature`,
  `pubkey_invalid`). Unknown values of `alg` give `alg_unsupported`.
- **Second factor.** A watch cannot carry a FIDO2 assertion. A card with
  `meta.hardware.required: true` (or a score rule that fires) therefore cannot be approved from the
  watch: an `allow` without `hw` gets `hardware_required`, and an assertion made for another
  device's ticket does not match the challenge, which covers `deviceId`. `deny` never needs the key.
- **Approve only in the app.** wardend accepts any correctly signed ticket and cannot tell where the
  user tapped. Approving from a notification action is a client restriction: a watch app must offer
  only "Deny" and "Open" as notification actions (a double-tap gesture on Series 9 and Ultra 2 hits
  the first non-destructive action, so "Allow" must never be one) and approve only inside the app
  after an explicit confirmation. "Deny" from a notification is an ordinary signed `deny` ticket.

## 8. Push notifications

The relay sends the push; wardend holds no push token and no push credentials. The APNs and FCM
credentials are the app publisher's and never leave the relay. A device registers over its authenticated connection:

```
{type:"push.register", platform:"apns"|"fcm", token, environment:"sandbox"|"production", topic}
{type:"push.unregister", platform, token}
```

The relay keeps `(deviceId, platform, token)`, at most 8 tokens per device (`too_many_tokens`),
and answers `ack`; `configured` in the ack of `push.register` is false when the relay has no
credentials for that platform (the token is kept, nothing will be pushed). When a `msg` for a device is
accepted and the device has **no live connection**, the relay sends one push per registered token:

- APNs (HTTP/2, token-based auth: a JWT ES256 signed with the publisher's `.p8` key): `{"aps":{"alert":{"title":"Approval
  request","body":"Open to review"},"sound":"default","interruption-level":"time-sensitive",
  "mutable-content":1,"category":"WARDENCLAW_CARD"},"relay":{"sid":…,"id":…,"to":…,"kind":…,
  "exp":…,"body":…}}`.
- FCM (HTTP v1, data message, `priority:"high"`): the members of the `relay` object as the
  message's `data`. FCM data values are strings: `exp` is the decimal string of the number.

The `relay` object carries every routing member the AAD of section 11 covers: `id`, `to`, `kind`,
`exp` as the relay stored them (`exp` after the clamp), and `sid`, which is the frame's `from`
(only a supervisor's frames are pushed). `body` is the frame's `body` when it is at most 3072
characters, else absent. A receiver that holds the box key therefore opens `body` from the
notification alone (`aad = canonicalJson({type:"wardenclaw.relay.aad.v1", id, from: sid, to, kind,
exp})`; `protocol/vectors/relay_vectors.json`, member `push`). A client that shows
the command from the notification checks `supervisorSig` and `exp` like a card from the socket,
and does not ack. When `body` is absent it fetches the frame with
`GET /v1/frames/<supervisorId>/<id>` (section 12).

Only kinds `card` and `card.done` trigger a push. A push is best effort: APNs `Unregistered` or
`BadDeviceToken` deletes the token; a delivery failure is journaled by the relay, not retried,
the frame stays queued for the next connection. A push token is an address, not a credential: it
cannot approve anything.

## 9. Test vectors

| file | covers |
|---|---|
| `vectors/canonical_vectors.json` | canonical JSON: Unicode, control characters, U+2028, UTF-16 key order, numbers, a typed exec envelope and its digest |
| `vectors/hw_vectors.json` | ticket signing strings with `risk`, second-factor challenge and `clientDataJSON` |
| `vectors/transport_vectors.json` | the gateway plugin's request string (`pluginRequest`), the fingerprint |
| `vectors/es256_vectors.json` | an `es256` device: key, `deviceId`, pairing (with `alg`) and ticket signing strings, signatures raw and DER |
| `vectors/relay_vectors.json` | the relay transport: fixed keys, the box key from both ends, a `msg` frame with its aad and nonce, the notification of that frame (`push`), the hello of both roles, a pairing request and its `pair` frame, a card signature, a pairing link |
| `vectors/display_vectors.json` | showing a card (DISPLAY.md): sanitizer, homoglyphs, splitting a command, the claude-cli wrapper, rules, delegating launches, full card models including attack cases |

`canonical_vectors.json` is produced by `vectors/gen_vectors.mjs` from the plugin's
JavaScript implementation; `display_vectors.json` by `app/scripts/gen-display-vectors.mjs` from
the app's `display.ts`; `relay_vectors.json` by `daemon/relayvectors_test.go`, which also reads it
back (`app/scripts/test-relay.mjs` and `relay/test/push.test.ts` reproduce it); the others are
produced by the Go reference implementation. A member of these files that this document does not
name is not part of protocol 1. The ECDSA
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
(cd daemon && go test ./envelope -run 'TestHWVectors|TestES256Vectors' -update-hw -update-es256)
(cd daemon && WARDEN_UPDATE_VECTORS=1 go test -run TestRelayVectors .)
```

## 10. Protocol version

The protocol has one version number for everything in this directory: the envelope, the signing
strings, and the APIs of wardend and the gateway plugin. It is an integer; the title of this file
names the current one.

**What the peers send.** One integer, `protocol`, the version the sender speaks: wardend in the RPC
`status` on its socket and in its relay `hello` (`client.protocol`), the relay in `welcome` and
`GET /v1/ping`, the app in its relay `hello`, the plugin in `GET /wardenclaw/status` and the
WebSocket method `wardenclaw.status`.

**What raises the version.** Any change that breaks an existing client or server: a signing string,
a required field, the envelope format (its `v` rises with it), a frame, an API path, or the meaning
of a field. A new optional field in a response does not raise it: clients ignore fields they don't
know.

**What a peer must check.** Every peer holds one constant, `PROTOCOL`, and compares it with the
number the other side sends. There is no range and no negotiation: another number is refused.

- no `protocol` field, or a lower number: the other side is older, "update the server";
- a higher number: this side is older, "update the client".

These are their own errors, shown in words, not `type_invalid` or `bad_signature`. While the
versions don't match, the client doesn't sign decisions for that server and the plugin doesn't forward
them to wardend (it answers `wardend_protocol_mismatch`). The relay refuses a hello
of another protocol with `protocol_mismatch`; wardend and the app drop a relay whose `welcome`
names another one.

An envelope with a `v` the client doesn't know is not dropped silently: the client says there is a
request it can't show and that it needs an update. Such a request can't be allowed (fail-closed);
it expires on the server like any unanswered request.

| protocol | release | what it is |
|---|---|---|
| 1 | the first public release | everything in this directory: envelope v1 (`exec` and `rootexec`), typed tickets with `supervisorId`, the relay transport with its frames, boxes and signing strings, pairing, push from the relay |

Where the constants live: `daemon/envelope` (`Protocol`), `daemon/cmd/wardenctl/client.go`,
`relay/src/frames.ts`, `plugin/src/protocol.js` (the plugin both serves and, when it forwards to
wardend, checks) and `app/src/core/protocolVersion.ts`.

## 11. Payload encryption and message kinds

Every `msg` and `pair` body is one AEAD box between the two ends (a `pair` body has the device's
encryption key in front of it, section 6):

```
shared = X25519(my enc private, their enc public)
key    = HKDF-SHA256(ikm = shared, salt = sha256(supervisorId || deviceId), info = "wardenclaw.relay.v1")
nonce  = 24 random bytes
body   = b64url(nonce || XChaCha20-Poly1305(key, nonce, plaintext, aad))
aad    = canonicalJson({type:"wardenclaw.relay.aad.v1", id, from, to, kind, exp})
```

`supervisorId || deviceId` is the concatenation of the two hex ids in that fixed order, whoever
sends. `aad` binds the ciphertext to the frame's routing members: a relay that rewrites `to` or
`exp` produces a box that does not open. The relay clamps `exp` to its queue TTL
(`min(exp, now + limits.ttl)`), and `exp` is in the AAD: the **sender must keep `exp` within the
TTL** the relay announced in `welcome` (wardend stays a minute under it), or the frame arrives
with another `exp` and never opens. The plaintext is a JSON object by `kind`:

| kind | direction | plaintext |
|---|---|---|
| `card` | supervisor → device | one pending record (`id, kind, digest, envelope, meta, createdAt, expiresAt`; `envelope` and `digest` as in section 3), plus `supervisorSig`: the supervisor's Ed25519 signature over `canonicalJson({type:"wardenclaw.card.v1", id, digest, createdAt, expiresAt})`, so a card can be shown and journaled with a signature that does not depend on the channel |
| `card.done` | supervisor → device | `{id, outcome}` (`approved`, `denied`, `expired`, `superseded`): the card is closed, the app removes it |
| `ticket` | device → supervisor | the decision ticket of section 4, unchanged (`{deviceId, payload, signature[, hw]}`) |
| `ticket.result` | supervisor → device | `{ok:true, id, decision}` or `{ok:false, reason, id}` (the reasons of section 4); `device_mismatch` when the ticket's `deviceId` is not the frame's `from` |
| `status.req` | device → supervisor | `{}` |
| `status` | supervisor → device | wardend's status object (daemon/docs/CLI.md, `wardend status`; no file paths) with `pending`: the full list (every item as in `card`), plus `pendingCount` and `seq`; when the list would not fit one frame it holds only the cards that do, `pendingTruncated:true` is set (`pendingCount` stays the real number) and the cards left out follow as `card` frames; sent on `status.req` and to every device after each reconnect of the supervisor |
| `pair.status` | supervisor → device | section 6 |

The device key that signs tickets and the supervisor key that signs cards are the identity keys
of section 1. Encryption adds confidentiality against the relay; it replaces no signature.

**Key rotation.** A party that generates a new encryption key pairs again (the QR carries the
supervisor's, the pairing payload the device's). There is no in-band rotation.

## 12. HTTP endpoints of the relay

For a client woken by a notification, which does not keep a socket:

```
GET  /v1/frames/<supervisorId>/<id>   the undelivered frame by id: {ok, frame}
GET  /v1/ping                         {ok, service:"wardenclaw-relay", protocol, now}
```

`GET /v1/frames/…` carries the headers `X-Wardenclaw-Device`, `X-Wardenclaw-Ts`,
`X-Wardenclaw-Nonce` and `X-Wardenclaw-Signature`; the signature is made with the device key over `canonicalJson({type:"wardenclaw.req.v1", supervisorId:"relay",
action:"relay.frame", deviceId, ts, nonce})`, the string `relay` in place of a supervisorId. The
relay knows the device's key from its last hello on that channel, checks the signature, burns the
nonce (`nonce_reused` on a replay) and returns the frame only if `to` is that device (404
otherwise). The frame stays queued until acked over a socket.

## 13. Limits and abuse

The relay has no accounts. Anyone with a key may connect. What keeps it honest:

- a supervisor channel accepts messages only from the devices it listed, or `pair` frames while a
  window is open;
- per connection: 60 frames per minute, burst 20 (a token bucket: 20 frames at once, one more
  every second; every frame counts, acks and pings too). The relay itself does not count
  connections per IP: that limit belongs in front of it (a rate limiting rule of the platform);
- per receiver: 200 queued frames, 24 h;
- a `pairing` window is at most 15 minutes; a channel may hold one open window;
- an `error` frame names the code and the frame; three `rate_limited` in a row close the
  connection (4008), an accepted frame in between starts the count over. A sender paces itself
  below the limit and sends a refused frame again later: wardend and the app keep their requests
  to 15 at once and one more every 1.2 s (acks, pings and the hello are never held back and put
  that budget into debt), and send a frame refused as `rate_limited` again after 3 s, twice at
  most, with the same `id`.

A self-hosted relay is the same program with the operator's own APNs/FCM credentials (or none:
then the app learns about cards only while open). `relay_url` in the daemon config and the `relay`
member of the QR point clients at it; nothing in the protocol names `relay.wardenclaw.dev`.

## 14. Failure modes

| what fails | what the human sees | what the agent gets |
|---|---|---|
| relay down | app: "relay unreachable"; daemon journal: `relay_disconnected` | cards wait on the daemon until `ticket_ttl`, then `EPERM` |
| relay drops a frame | card expires; `card.done expired` never arrives, the app drops it at `expiresAt` | `EPERM` |
| relay replays a frame | ignored by `id`; a replayed ticket is `nonce_reused` | nothing |
| relay rewrites a frame | AEAD fails to open; the receiver logs `relay_tamper` and acks nothing | `EPERM` after TTL |
| push not delivered | card visible when the app is opened, if still within TTL | `EPERM` after TTL if nobody opens it |
| phone offline | as above | as above |

No path leads from a relay failure to an approval. Observe mode (daemon/README.md, `mode`) is unaffected:
nothing waits for the phone there.

## 15. Reference implementation

- `relay/`: Cloudflare Worker (TypeScript). One Durable Object per `supervisorId`
  (`idFromName`), WebSocket Hibernation API for both sides' sockets, DO storage for queues, push
  tokens, seen ids; an alarm every minute while a socket is open (the idle sweep of section 5.3),
  every 10 minutes otherwise, for expiry. APNs via `fetch` with an ES256 JWT (WebCrypto), FCM via
  the HTTP v1 API. Custom domain `relay.wardenclaw.dev`, deployed by the `relay` workflow with
  `wrangler`; secrets `APNS_KEY_P8`, `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_TOPIC`,
  `FCM_SERVICE_ACCOUNT` in the Worker, never in the repository.
- `daemon/relay*.go` and `daemon/relaylink/`: wardend's client (outbound socket, hello, devices,
  resume, ack, box/open with `golang.org/x/crypto`) and the device side that `wardenctl` uses, `relay_url` in the config (default `wss://relay.wardenclaw.dev`; `off` for a
  wardend that no device approves for), `wardend pair start` prints the QR.
- `app/src/core/relaySession.ts` (with `relayBox.ts`, `relayProto.ts`, `relayState.ts`): the
  device's session. X25519 from `@noble/curves`, XChaCha20-Poly1305 from `@noble/ciphers`, HKDF and
  SHA-256 from `@noble/hashes`.
  The device's X25519 key is stored like its identity key; the resume `seq` and the ids of the
  last frames handled are kept per supervisor across launches.
- `vectors/relay_vectors.json`: fixed keys, the box key from both ends, a `msg` frame
  with its aad and nonce, the notification of that frame (`push`), the hello of both roles, a
  pairing request and its `pair` frame, a card signature, a pair link. Generated and read back by
  `daemon/relayvectors_test.go`, reproduced by `app/scripts/test-relay.mjs` and
  `relay/test/push.test.ts`.
