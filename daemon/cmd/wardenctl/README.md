# wardenctl: the WardenClaw approver in the terminal

The terminal counterpart of the WardenClaw phone app: it allows or denies commands that `wardend`
has held in the kernel, from a separate machine, for example your Mac. The protocol is the same as
the app's (`app/src/core/wardendClient.ts`, `wardendProto.ts`): pairing via a
`wardend pair start` link, cards through the relay (end-to-end encrypted), server messages are checked against the
pinned supervisor keys, decisions are signed with an Ed25519 device key, and `require_hardware` rules
need a second YubiKey signature over USB (not in the first release: only the build with `-tags hwkey`,
[docs/hwkey.md](../../docs/hwkey.md)).

The code lives in `daemon/cmd/wardenctl`: it is a separate binary, but in the same module as `wardend`,
so the signature strings, the envelope and the FIDO2 checks are not copied but taken from the
`envelope` and `hwkey` packages. Server and client change in one commit, and the e2e tests build a
real `wardend` from the same tree. The build has no cgo and nothing Linux-specific; targets:
darwin/arm64, darwin/amd64, linux/arm64, linux/amd64.

> Status: prototype (v0.1). Not yet tested with a real YubiKey or in a real macOS Keychain:
> the tests use fake `fido2-*` and `security` (see "Limitations").

## Where to run

**On a separate machine** that the agent does not control, for example your laptop. This is
essential.

wardenctl is the second key held away from the agent. If it runs on the same host and as the same
user as the agent under `wardend`, the agent can:

- read the device key (`~/.config/wardenctl/device.key` is readable by the same user);
- simply run `wardenctl approve <id>` and approve any command for itself.

Then the whole gate is pointless: the agent approves itself.

"Next to the agent" also covers a laptop where other AI agents (Claude Code, Cursor and the like)
run as the same user: wardend does not see them, and the device key is just as readable to them.
That is why on a Mac the key sits in the Keychain with a system prompt on every read, and in the
release `approve` and `watch` sign with the device key only; they allow with a YubiKey touch by
default only in the build with `-tags hwkey` (below). The real boundary is on the server, though:
without a `require_hardware` rule wardend accepts an allow without a YubiKey too, if it was signed
with the device key bypassing wardenctl.

That is why wardenctl checks the environment before every command that needs the key:

| Situation | What wardenctl does |
|---|---|
| the process is under a seccomp filter and wardend is nearby: a wardend ancestor, `~/.wardend` or a `wardend` process of this user | **always refuses** (code 3): this is the agent's tree, there is no way around it |
| not under a filter, but this user has `~/.wardend` or a running `wardend` | refuses (code 3); for demos and tests this can be lifted with `WARDENCTL_ALLOW_SAME_HOST=1`, but then the key is readable by the agent |
| a separate machine (Mac) | works |

```console
$ wardenctl pending            # from the agent's shell on the server
wardenctl: refused: this looks like an agent process under the wardend filter.
  - the process runs under a seccomp filter (Seccomp: 2, filters: 1)
  - wardend is among the parents of this process (pid 1342 /home/me/.local/bin/wardend)
  - this user has a wardend directory /home/me/.wardend
The approver is the second key held away from the agent. Next to the agent (same host, same user) the
agent can read the device key or call wardenctl approve itself and approve any command for itself.
Run wardenctl on a separate machine (for example, the owner's laptop): see README, "Where to run".
Nothing bypasses this from under the wardend filter.
```

The check is heuristic. Another user on the same host passes: their files are not accessible to the
agent if permissions are set correctly. If the agent runs as root, no user on this host is
protected. The wardenctl machine itself must also be out of the agent's reach: do not let the agent
in over SSH and do not mount its `~/.config` for the agent.

## Installing on a Mac

wardenctl holds the key that approves the agent's commands, so its binary must not come from the
agent's machine. Do not build it on the server with wardend and do not copy it from there with `scp`:
there the agent controls the sources, the toolchain and `/tmp`, and checking a hash computed on the
same host proves nothing. Two routes, both entirely on the Mac.

**From a release.** The archive `wardenctl_darwin_arm64.tar.gz` (Intel: `_amd64`) is in every daemon
release next to `checksums.txt`. Releases are not signed: the checksum comes from GitHub over TLS, like
the archive. Each step runs only if the previous one passed:

```bash
U=https://github.com/xarvel/WardenClaw/releases/latest/download
curl --proto '=https' --tlsv1.2 -fsSL --remote-name-all \
    $U/wardenctl_darwin_arm64.tar.gz $U/checksums.txt &&
  grep ' wardenctl_darwin_arm64.tar.gz$' checksums.txt | shasum -a 256 -c &&
  tar -xzf wardenctl_darwin_arm64.tar.gz &&
  mkdir -p ~/bin && install -m 0755 wardenctl_darwin_arm64/wardenctl ~/bin/wardenctl
brew install libfido2   # for a YubiKey, only the -tags hwkey build: fido2-token, fido2-cred, fido2-assert
wardenctl version       # the version of the release
```

`curl` does not set the Gatekeeper quarantine. If the archive was downloaded by a browser, remove
the quarantine (`xattr -d com.apple.quarantine`) only from a file whose checksum above
matched, and never blindly.

**Building on the Mac from a signed tag.** You need the Go version from the `toolchain` line of
`daemon/go.mod`. The tag is verified against `allowed_signers` from the repository root, read before
the checkout:

```bash
git clone https://github.com/xarvel/WardenClaw wardenclaw && cd wardenclaw
git show origin/main:allowed_signers > /tmp/wc-signers
git -c gpg.ssh.allowedSignersFile=/tmp/wc-signers verify-tag daemon/v0.4.0 &&
  git checkout --quiet daemon/v0.4.0 &&
  cd daemon && CGO_ENABLED=0 go build -trimpath -o ~/bin/wardenctl ./cmd/wardenctl
```

The darwin/arm64 binary is ad-hoc signed by the Go linker (`LC_CODE_SIGNATURE` is present); on
Apple Silicon it runs without extra steps. There is no Developer ID signature or notarization yet.

The Mac needs outbound access to the relay from the pairing link (by default
`wss://relay.wardenclaw.dev`), the same one the phone uses. It does not connect to the server directly.

## Pairing

On the server, in your own terminal, not from under the agent:

```console
$ wardend pair start --qr none --no-wait
Scan the QR in the WardenClaw app (Connect tab) or paste the link:
  wardenclaw://pair?code=3M73AW54&enc=Qm9…k2s&host=pi&key=3J0P…Xzc8&relay=wss%3A%2F%2Frelay.wardenclaw.dev%2Fv1%2Fws&sid=b5d6…41c0&v=1
```

On the Mac, put the link in single quotes:

```console
$ wardenctl pair 'wardenclaw://pair?code=3M73AW54&enc=Qm9…k2s&host=pi&key=3J0P…Xzc8&relay=wss%3A%2F%2Frelay.wardenclaw.dev%2Fv1%2Fws&sid=b5d6…41c0&v=1'
Server:      pi (through wss://relay.wardenclaw.dev/v1/ws), supervisor key pinned, fingerprint b5d6 5f91 c874 b635
Device:      "wardenctl@macbook", key: macOS Keychain (service wardenctl)
Request:     p-2gxn89

  This device's fingerprint:  3965 b94b 29d6 8d02

On the server: wardend pair list, compare the fingerprint, then wardend pair approve p-2gxn89
Waiting for approval… (Ctrl-C stops waiting; pairing can be finished with wardenctl status)
```

On the server `wardend pair list` shows the same fingerprint `3965 b94b 29d6 8d02`. Compare it and
run `wardend pair approve p-2gxn89`. wardenctl prints "Approved".

What happens:

1. The link is parsed. The supervisor keys from it are **pinned**: the Ed25519 identity key (`key`;
   `sid` must be its id) and the X25519 encryption key (`enc`). wardenctl connects to the relay
   (`relay`, `wss://` only) as a device on the supervisor's channel. Every message is a box
   (X25519 + XChaCha20-Poly1305) between the device key and the pinned supervisor key, so the relay
   can neither read nor forge it (`protocol/README.md`, sections 5 and 11).
2. A device key is created (Ed25519 for signatures, X25519 for the boxes). On macOS it is stored in the Keychain (via `/usr/bin/security`;
   the seed goes through the stdin of `security -i`, not through argv), on other systems in the file
   `~/.config/wardenctl/device.key` (0600, directory 0700). `--keystore auto|keychain|file` chooses the mode.
   The Keychain item has an empty list of trusted applications (`-T ""`): every read of the key, that
   is every command that talks to the server, shows a system prompt. Answer "Allow", not
   "Always Allow": the latter puts `security` back on the trusted list, and any process of this user
   will again read the key without a prompt. An item created by an earlier version (without the
   prompt) is recreated by wardenctl itself once, on the first command, and it says so.
3. The pairing request goes through the relay: the public key and the device name, together with the
   one-time code from the link.
4. Waiting for the `pair.status` answer until `approved`. The `--no-wait` flag does not wait; then any next
   command, for example `wardenctl status`, completes the pairing.

`--name` sets the device name in `wardend pair list` (default `wardenctl@<hostname>`).

## Commands

| Command | What it does |
|---|---|
| `pair '<link>' [--name n] [--keystore auto\|keychain\|file] [--no-wait] [--timeout 10m]` | pairing, see above |
| `pending` | the queue: id, time left until TTL, a `[DANGEROUS]` mark for a dangerous card, a `[YubiKey]` mark for a card that needs the hardware key, the command (up to 200 characters) |
| `show <id>` | the full card: command, argv element by element, exe, cwd, uid/gid, class and rule, risk, process chain, callerExe, syscall, envHash, pidfd cookie, ts, digest |
| `approve <id> [--no-hw] [--uv] [--device d] [--yes]` | show the card, ask and sign `allow`: in the release with the device key, in the `-tags hwkey` build with a YubiKey touch by default (the root then counts as approved with the key, and its tree passes `require_hardware` rules without escalation). A normal card is allowed by `y`, a dangerous one only by the whole word `allow`, an empty answer cancels. `--no-hw` (only `-tags hwkey`) allows without a YubiKey if wardend does not require it. Without a terminal or with `--yes` there is no prompt, but the id must be at least 12 characters |
| `deny <id>` | sign `deny` (never needs the key) |
| `watch [--no-hw] [--uv] [--device d]` | waits for cards and shows them one at a time, see below; `y` allows with the device key (in the `-tags hwkey` build with a YubiKey touch, `--no-hw` without it) |
| `status` | server, fingerprints, where the key is, YubiKey, connection (latency, clock skew), wardend mode, whether the device is trusted, whether wardend knows your YubiKey (the YubiKey lines only in the `-tags hwkey` build) |
| `hw-register [--device d] [--name n] [--alg auto\|eddsa\|es256] [--uv] [--require-uv]` | bind a YubiKey, see below; only the `-tags hwkey` build, code 2 in the release |
| `hw-check [--device d] [--uv]` | check the bound YubiKey: touch, signature, signCount; only the `-tags hwkey` build, code 2 in the release |
| `forget [--yes]` | delete the server and the device key (Keychain or file). Then on the server `wardend pair revoke <prefix>` |
| `version` | version |

The common flag `--dir` sets the state directory (default `$WARDENCTL_DIR`, otherwise
`$XDG_CONFIG_HOME/wardenctl`, otherwise `~/.config/wardenctl`). One directory serves one server;
a second server needs a separate `--dir`. Flags can also go after the id: `approve wd-1791 --dir ~/.config/wardenctl-b`.
An id can be shortened to a unique prefix of 6+ characters, `wd-` is optional; `approve` without a
prompt (a script, `--yes`) takes only ids of 12+ characters.

Before signing, each card is checked the same way as in the app: the envelope is strictly v1 (exactly 13
fields, types), `requester.supervisorId` equals the pinned one, the digest is **recomputed** from the envelope
and must match the record's digest, the id must equal `wd-<digest[:32]>`. A card that fails the check
is shown as "NOT VERIFIED" and cannot be signed. Control characters from argv and paths
are printed escaped: `\u001b`, bidi characters, a newline as `⏎`.

```console
$ wardenctl pending
pi: mode ticket, cards: 1
  wd-d8a61737e6a71256d9fe0fcc60f0b007  expires in 30s  [YubiKey]
      echo hw-ran

$ wardenctl show 179178ce51
Card wd-179178ce51e2397fd753dab85af4e283
  Signed facts (digest recomputed, matches):
    bash -c script, in parts:
       1. echo root-ran
    argv:     ["bash", "-c", "echo root-ran"]
    exe:      /usr/bin/bash
    cwd:      /home/me/project
    uid/gid:  1000/1000
    host:     pi
    environment (2):
        HOME=/home/me
        PATH=/usr/local/bin:/usr/bin:/bin
    deadline: expires in 30s; no answer means deny
    process chain (caller, then parents):
        45434  /usr/bin/dash
        45398  /usr/bin/node
    envHash:  4a1670ee… (the whole environment; above, only variables that change program behavior)
    process:  pidfs:45435
    ts:       2026-09-27 02:23:28.715
    digest:   179178ce…09667424 (recomputed, matches)
  Allowing covers everything this command starts while it runs.
  Not confirmed (meta from the transport, not part of the digest):
    class:    root
    callerExe: /usr/bin/dash
    syscall:  execve

$ wardenctl approve 179178ce51
Card wd-179178ce51e2397fd753dab85af4e283
  …
Allow wd-179178ce51e2397fd753dab85af4e283? [y/N] y
Touch the YubiKey (/dev/hidraw4)…
Allowed: echo root-ran  (wd-179178ce51e2397fd753dab85af4e283)
```

`approve` first shows the card, like `watch`, and waits for an answer: there is no default answer, a
dangerous card is allowed only by the whole word `allow`. A script is not asked (stdin is not a
terminal or `--yes`), but then the id must be at least 12 characters, so that a short prefix does not
hit another card.

For the claude-cli wrapper (`bash -c "source … && eval '<cmd>'"`) the card shows `<cmd>` under
"Command inside the claude-cli wrapper (full argv below):", as in the app; the full argv is still
visible on a line below.

### watch

```console
$ wardenctl watch
Watching pi (https://wardend.example.com). y: allow, n: deny, d: details, Enter: do nothing. Ctrl-C: quit.
A dangerous card is allowed only by the word allow in full.

Card wd-9c0d8ab11043219647c200dcc05f15d0
  Signed facts (digest recomputed, matches):
    bash -c script, in parts:
       1. echo two
  …
Allow wd-9c0d8ab11043219647c200dcc05f15d0? [y/n/d, Enter: skip] y
Allowed: echo two
```

- `y` (`yes`) allows: in the release with the device key, in the `-tags hwkey` build with a YubiKey
  touch. There watch does not start without a bound YubiKey: either
  `wardenctl hw-register`, or explicitly `watch --no-hw` (then the key is needed only if wardend
  requires it).
- **A dangerous card** (the `!!! DANGEROUS` line: a blocklist or injection rule, invisible characters,
  homoglyphs, a delegating launch) is not allowed by `y`: you have to type the whole word `allow`. This
  is the counterpart of holding the button on the phone and the watch, so that a habitual key does not
  approve something dangerous. `allow` also works for a normal card.
- `n` (`no`) denies.
- `d` (`?`) shows the whole card, like `show`, and asks again.
- **Empty input (Enter) sends nothing.** There is no default answer: the card stays in the
  queue, the phone can decide it, otherwise on TTL the exec gets `EPERM`. Unrecognized input is
  asked again.
- If the card disappears from the queue while you are thinking (another device decided it or the TTL
  ran out), the question is withdrawn: "Card … withdrawn".
- A wardend rejection over the second factor (`hw_*`, `hardware_required`, `stale_timestamp`) keeps the
  card: you can answer `y` again and touch the key again.
- Input is read only at the moment of the question, so nothing intercepts the PIN for `fido2-assert`.
  If stdin is closed, watch from then on only shows cards.
- When the connection drops, watch retries the request every 5 s. If the server stopped trusting the
  device (`untrusted_device`), watch exits.

## YubiKey (second factor over USB)

> Not in the first release: the FIDO code (`fido.go`, the libfido2 utilities) is built only with a tag
> (`go build -tags hwkey`), see [docs/hwkey.md](../../docs/hwkey.md). The release build signs
> `allow` with the device key only (as `--no-hw` did before); `--hw`, `--no-hw`, `--uv`, `--device`,
> `hw-register` and `hw-check` are hidden from help and answer "second factor (FIDO2 hardware keys,
> YubiKey) is not included in this release…" with code 2, and `status` does not show the YubiKey line.

wardenctl calls the libfido2 utilities as external programs (`fido2-token -L`, `fido2-cred -M`,
`fido2-assert -G`), without cgo. The format is the same as the app's over NFC (`protocol/HARDWARE.md` in the monorepo root):

```
challenge      = sha256(canonicalJson({type:"wardenclaw.hw.v1", ticket:"wardenclaw.ticket.exec.v1", deviceId, id, digest, decision, ts, nonce, supervisorId}))
clientDataJSON = {"type":"webauthn.get","challenge":"<base64url>","origin":"wardenclaw:app"}
fido2-assert -G -p [-v]  ← sha256(clientDataJSON), rpId "wardenclaw", credentialId
```

The utilities return authenticatorData as a CBOR byte string, wardenctl unwraps it. wardenctl checks
every assertion itself before sending: the signature with the bound COSE key, rpIdHash, the UP flag.
So "wrong key" shows up immediately, not as a server rejection.

Installing the utilities: macOS: `brew install libfido2`; Debian/Ubuntu: `sudo apt install fido2-tools`
(access to `/dev/hidraw*` is usually granted by the systemd udev rules `60-fido-id.rules` or by the libfido2 package's rules). Without the utilities wardenctl
gives a clear answer:

```
wardenctl: utility fido2-assert (libfido2) not found, cannot sign with a YubiKey over USB without it: install libfido2 (macOS: brew install libfido2; Debian/Ubuntu: sudo apt install fido2-tools; Fedora: sudo dnf install libfido2)
```

**Registration.** After pairing, run `wardenctl hw-register --name "YubiKey 5C"`. The
`fido2-cred` utility creates a credential with rpId `wardenclaw`: EdDSA first, and ES256 if the key
cannot do EdDSA. wardenctl builds a `wchw1:` blob in the app's format, checks it with the same code as
`wardend hw-register`, stores the credentialId and the public key locally and prints the line for the server:

```
On the server run this and restart wardend:

wardend hw-register 'wchw1:eyJjcmVkZW50aWFsSWQiOi…'
```

For keys that return a `fido-u2f` attestation, the variant
`wardend hw-register --cose-key … --credential-id …` is printed. After wardend restarts,
`wardenctl status` shows "the YubiKey bound here is registered: yes".

- `--uv` asks for the key PIN on creation. If the key has a PIN set, `fido2-cred` asks for it itself.
- `--require-uv` adds `--require-uv` to the line for the server: wardend will require the PIN in every
  signature, and wardenctl then always calls `fido2-assert -v`.
- `--device` (or `WARDENCTL_FIDO_DEVICE`) is needed if several FIDO keys are connected. Otherwise
  the only one from `fido2-token -L` is used (`/dev/hidraw4`, on macOS `ioreg://…`).

**Signing.** On a card with `[YubiKey]`, `approve` (or `y` in watch) prints
"Touch the YubiKey (<device>)…", waits up to 2 minutes for a touch and sends the ticket with the `hw` field. wardend checks the
assertion, signCount and rpId (`protocol/HARDWARE.md` in the monorepo root). The key from `meta.hardware.credentials` is only
a hint: the key bound here always signs, and if wardend does not know it, wardenctl says in
advance that `wardend hw-register` needs to be run.

## Protocol version

wardenctl speaks protocol 1 (the constant `clientProtocol` in `client.go`, the contract in
`protocol/README.md`, section 10). wardenctl checks the `protocol` field that wardend
reports; any other number is refused:

- the field is missing or below 1: "wardend does not report a protocol version, but wardenctl
  speaks protocol 1: update wardend";
- the field is above 1: "wardend speaks protocol N, but wardenctl speaks protocol 1: update
  wardenctl".

Both errors exit with code 4; this is not `bad_signature` and not a wardend rejection. A request in an
envelope newer than wardenctl (`v` above 1) does not disappear from `pending`, `show` and `watch`: the
card is shown as "NOT VERIFIED: request from a newer protocol version, update wardenctl (envelope v2,
wardenctl understands v1). Must not be signed.", it cannot be allowed, and it expires on the server by TTL.

## Environment variables

| Variable | Meaning |
|---|---|
| `WARDENCTL_DIR` | state directory (like `--dir`) |
| `WARDENCTL_FIDO_DEVICE` | FIDO device (like `--device`) |
| `WARDENCTL_FIDO2_DIR` | directory with `fido2-*` instead of PATH |
| `WARDENCTL_SECURITY_BIN` | path to `security` (tests substitute a fake one) |
| `WARDENCTL_ALLOW_SAME_HOST=1` | lift the soft "wardend on this machine" refusal (demos/tests; has no effect under a filter) |

Exit codes: 0: success; 1: an error or a wardend rejection; 2: invalid arguments; 3: the "next to the
agent" refusal; 4: the wardenctl and wardend protocol versions are incompatible (see "Protocol version").

## Tests

```bash
cd daemon   # the daemon directory in the monorepo
go test -p 1 ./cmd/wardenctl        # unit tests; inside a wardend tree the e2e tests are skipped
# e2e under a real seccomp: from your own terminal outside wardend, not from an agent session
go test -p 1 -count=1 -v -run E2E ./cmd/wardenctl
```

The e2e tests are run by a human (or CI). Do not wrap them for the agent in `systemd-run --user` and the like:
that is running code outside the gate, and wardend will ask about it with a card carrying that mark.

- **Compatibility with the app** (`proto_test.go`): the fixtures `transport_vectors.json` and
  `hw_vectors.json` from `protocol/vectors/` in the monorepo root (the app's test reads the
  same files). The signed request headers, the pairing body, the link, supervisorId, the
  fingerprint, the response signature check (a foreign nonce, action, device, status, body, key, an
  empty signature; a decide response with a different id or digest; a ping with the ticket nonce
  instead of a decide response is rejected, an unauth rejection is only "not bound"),
  the ticket signature and clientDataJSON are compared byte for byte; the fixture copies in the app
  match the reference.
- **Cards** (`card_test.go`): strict envelope, argv substitution (digest), an extra field, a foreign
  supervisor, an id not derived from the digest, a non-integer uid, the claude-cli wrapper, escaping, id prefixes.
- **YubiKey** (`fido_test.go`): fake `fido2-token/-cred/-assert`, that is the test binary under
  these names with a software authenticator that returns authData in CBOR, like libfido2.
  The blob passes `hwkey.ParseRegistration` (packed x5c EdDSA, packed self ES256 after an EdDSA refusal);
  the assertion passes `hwkey.Store.VerifyAssertion` (the same code as in the supervisor) and does not fit
  another ticket; for `fido-u2f` `--cose-key` is printed; a missing utility gives a clear error; a foreign
  key is caught locally. The Keychain is checked with a fake `security`: write, read,
  delete, the seed never lands in argv. The key file permissions are checked too.
- **Guard** (`guard_test.go`): the rule table, including that the override has no effect under a
  filter.
- **E2E** (`e2e_test.go`, Linux): a real `wardend` is built, `wardend run --mode ticket` is started.
  1. A link with a foreign key is rejected. Pairing goes through `wardend pair start` → `wardenctl pair`
     → comparing the fingerprint with `wardend pair list` → `wardend pair approve`. Then `status`,
     `show`, `approve` (the exec runs), a repeated approve, `deny` (the exec gets `EPERM`, rc 126),
     tickets in the journal, `forget`.
  2. `watch`: Enter (the card expires, rc 126), `d` → `y` (the exec runs), another process decides the
     card (the question is withdrawn), `y` does not allow a dangerous card, and `allow` does.
  3. YubiKey: `hw-register` → a real `wardend hw-register` → a `require_hardware` policy →
     `[YubiKey]` in pending → approve without the utilities (a clear error) → approve with the key → exec,
     `hardware.verified` in the journal.
  4. A wardenctl binary started as a child of `wardend run` refuses with code 3 even with
     `WARDENCTL_ALLOW_SAME_HOST=1`; outside the tree, next to `~/.wardend`, it refuses softly.

## Limitations

- **A real YubiKey and a real Keychain are not tested**: the Pi has neither a key nor macOS. The input
  and output format of `fido2-*` is taken from the libfido2 1.15 man pages and reproduced by the fake
  utilities; the CBOR unwrapping of authData is strict, but with a real key it is the first thing to check
  (`wardenctl hw-register`, then `wardenctl hw-check`). The Keychain item with `-T ""` and its
  recreation are also tested only with the fake `security`: the parsing of `""` in `security -i` is taken
  from Apple's source (`split_line` in `security.c`). On a Mac, first: `wardenctl pair`, then
  `security dump-keychain -a` must show an empty application list for the `wardenctl-device-key` item,
  and `wardenctl status` must trigger a system prompt.
- **No risk assessment.** The CLI has no judge model of its own, so `payload.risk` is not signed, and
  the score-based `require_hardware.min_score` rules do not fire from wardenctl. Static rules
  (class, argv) work. `--hw` attaches the key manually.
- **No notifications**: cards are visible while `watch` is running.
  watch shows cards one at a time, the rest wait in the queue.
- **The time to touch counts against `ts_window`** (60 s by default): the ticket ts is fixed before the touch,
  because it is part of the challenge. Slow PIN entry gives `stale_timestamp`; then just
  retry.
- **The "next to the agent" guard is heuristic** (seccomp, ancestors, `~/.wardend`, `wardend` processes of
  your own uid). It does not help if the agent can reach the wardenctl machine some other way.
- One state directory per server; `forget` does not revoke the device on the server, that is done by
  `wardend pair revoke`.
