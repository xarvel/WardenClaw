# WardenClaw

*Take back control.* Two-factor approval for AI agents.

WardenClaw is an execution gate for AI agents on Linux. A small daemon, **wardend**, runs the agent
harness (OpenClaw, claude-cli or any other) under a seccomp filter and checks every new program it
starts (`execve`) against rules. By default only commands that trip a rule wait for your signature,
such as remote execution, package installs, publishing, reading secrets, destructive commands or
changes to the agent's settings. Everything else runs and is journaled. A command that needs a
signature goes to your phone as an approval card; the **WardenClaw app** shows what exactly will
run, can ask a model you pick for a risk score, and signs the decision with a device key that
never lives on the server. wardend checks the signature against the exact command and only then
lets it through. Every exec and every decision lands in a hash-chained, signed journal.

```
agent harness ──execve──▶ wardend (seccomp + rules) ─┬─ trips a rule ──card──▶ phone app ──signed ticket──▶ wardend ──▶ runs
                                                     └─ everything else ──▶ runs, journaled
```

<!-- Key claims: the same words as site/src/claims.ts; the site build fails when they differ. -->
- The recommended install runs wardend as a root system service and the agent as its own
  unprivileged user, so the model can't turn the guard off. A single-user trial needs no root, but
  there the model could stop wardend.
- wardend reaches the phone app through a relay over one outbound WebSocket, so the server needs no
  public address and no open port. Messages are encrypted end to end: the relay can't read or forge
  them. The OpenClaw plugin is optional: it adds cards for OpenClaw's own tool calls.
- Linux 5.19 or newer with systemd. Approve on Android, iPhone or in a terminal with wardenctl.
- Not closed yet: tripwire knows programs by name and by list (busybox applets, renamed copies and
  readers outside the list run without a card), only `execve` is gated, and the card shows only
  the environment variables of a list (the loader, shells, interpreters, git, proxies): the rest
  of the environment is signed only as a hash, so a variable outside the list can change an
  approved command unseen. Details: [policy modes](site/src/docs/cli.en.md#policy-modes)
  and [why the model can't turn it off](site/src/docs/tamper-resistance.en.md).

## Try it

```sh
wardend wrap -- claude "fix the failing test"
```

One command, no flags: the first run pairs your phone (a QR code, then `Approve this device? [y/N]`), after that the
command runs and every risky exec waits for your decision on the phone. In this mode wardend runs as the same user as the command.
The command cannot get past the exec gate, but it can read wardend's files and edit its config between runs.
The system install below is the one with real separation: wardend as a root service, the agent as its own user.
Getting the binary without root: [try it in 5 minutes](site/src/docs/try.en.md).

## Install

```sh
curl -fsSL https://wardenclaw.dev/install.sh | sudo sh
```

The site serves `install.sh` of the latest release; the archives and checksums come from GitHub
Releases. Releases are not signed: the installer checks the archive against the release's
`checksums.txt`, both fetched from GitHub over TLS, and nothing more. It then sets up the hardened
install (wardend as a root service, the agent as a separate user) in observe mode, and prints the
pairing steps. Read it first, check it by hand, or build from source: see the
[install guide](site/src/docs/install.en.md).

To remove it: `curl -fsSL https://wardenclaw.dev/install.sh | sudo sh -s -- --uninstall` (keeps
the journal and a copy of the config). What stays and why, `--purge`, running the harness again
without wardend and paired devices: the [uninstall guide](site/src/docs/uninstall.en.md).

The site is up at <https://wardenclaw.dev>. It serves `install.sh` only after the first signed
daemon release; until then that URL answers 404 (`daemon/docs/release.md`).

## What's in this repository

| path | what | license |
|---|---|---|
| [`daemon/`](daemon/) | **wardend**, the Go supervisor (seccomp user notification, policy, journal, the relay link to the phone, pairing) and **wardenctl**, a terminal approver for Linux and macOS; `install.sh` and the release scripts | AGPL-3.0-or-later |
| [`app/`](app/) | the **WardenClaw app** (Expo / React Native, Android and iOS): approval cards, signing, risk judge on a model at a URL you set, journal | GPL-3.0-or-later + app store permission |
| [`plugin/`](plugin/) | **wardenclaw-gate**, an optional OpenClaw plugin: gates OpenClaw's own tool calls and relays wardend cards through the gateway | Apache-2.0 |
| [`protocol/`](protocol/) | the **protocol specification** (exec envelope, canonical JSON, decision ticket, transport and pairing) and the **test vectors** every implementation is tested against | Apache-2.0 |
| [`site/`](site/) | the landing page and the **user documentation** (`site/src/docs/`), Astro | code Apache-2.0, docs CC BY 4.0 |

The license map by path is in [LICENSE](LICENSE); the name and the logo are trademarks, see
[TRADEMARKS.md](TRADEMARKS.md).

## Building and testing

Every component builds on its own; there is no root package.

```sh
(cd daemon && go vet ./... && go test -p 1 ./...)        # Go 1.26, Linux >= 5.19 for the tests
(cd app && npm ci && npx tsc --noEmit && npm test)      # Node 24; native builds via EAS
(cd plugin && npm ci && npm test)
(cd site && npm ci && npm run build)
```

The Go module is `github.com/xarvel/WardenClaw/daemon`, so from the first `daemon/v*` tag on
`go install github.com/xarvel/WardenClaw/daemon/cmd/wardenctl@latest` builds the terminal approver.

The protocol vectors in `protocol/vectors/` exist once and are read directly by the daemon, app
and plugin tests. CI (`.github/workflows/`) runs each component only when its paths change,
plus a `protocol` job that regenerates the vectors and checks all three implementations.

Daemon releases are tagged `daemon/vX.Y.Z` ([release process](daemon/docs/release.md)). What
each release brings and what to do when you upgrade: [CHANGELOG.md](CHANGELOG.md).

## Contributing and security

Contributions are welcome under the DCO sign-off, see [CONTRIBUTING.md](CONTRIBUTING.md). Report
vulnerabilities privately, see [SECURITY.md](SECURITY.md). Authors: [AUTHORS](AUTHORS).
