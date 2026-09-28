---
title: wardend CLI reference
description: Install, run and operate wardend, the seccomp exec gate of WardenClaw. Every command, flag, file format and RPC method, verified on a Raspberry Pi 5.
---

# wardend CLI reference

`wardend` starts a process (in production: the OpenClaw gateway) under a seccomp filter and decides the fate of every `execve`/`execveat` in the whole process tree. The kernel stops the call, the supervisor reads argv, cwd, the real binary and the parent chain from the stopped process, and answers `CONTINUE` or an error. Every launch outside an approved subtree waits for an **Ed25519 signature from a WardenClaw device** over a canonical envelope: wardend never decides on its own, a card nobody signs expires into `EPERM`, and there is no local bypass. Children of an approved root pass while its subtree is alive; harness housekeeping is a card of class `service` the app may sign by rule; the risky categories (remote execution, leaving the gate, package installs, publishing, secrets, destructive commands) ride on the card as [risk hints](#policy-modes). Observe (sign everything and watch) or delegate (a judge decides) are modes of the phone app, not of the daemon.

Every command on this page was run on a Raspberry Pi 5 (arm64, Linux 6.18, Go 1.26). Outputs are real, with host names and keys shortened.

> Status: prototype (v0.2). Flags and formats can still change.

## Requirements

- Linux **5.19 or newer** (needs `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`), arm64 or x86_64.
- **The gate itself needs no root**: `no_new_privs` plus a seccomp filter with a notification listener, no cgo, no libseccomp. The recommended [hardened install](../install/) still runs wardend as a root system service, because only a separate user for the harness stops the model from turning wardend off.
- Go 1.26, only to build from source.

## Install

```shell
%INSTALL_CMD%
```

The default is the **hardened install**: wardend as a root system service, the harness under its own user, the release archive checked against its checksums before anything is written, and the phone paired at the end, because until it is nothing the agent launches will run. What the script does step by step, how to check it before piping it into `sudo`, and the flags: [Install wardend](../install/).

<details>
<summary><strong>Build from source</strong></summary>

The commands below are the **single-user** install: fine for a quick try, but a model running as the same user can disable wardend. For real use run the root-side script of the [hardened install](../install/#step-2-run-the-installer) on your build.

```bash
git clone %REPO_URL%
cd wardenclaw/daemon
go build -o wardend .
install -D -m 0755 wardend ~/.local/bin/wardend
mkdir -p ~/.wardend && chmod 700 ~/.wardend
```

</details>

Run the tests (about 10 s; integration tests start real supervised processes, so run them outside any wardend tree):

```bash
go test -p 1 ./...
```

Check the binary:

```console
$ wardend
usage:
  wardend wrap [--policy rules.json] [--ttl 120s] [--state-dir d] [--relay-url wss://…]
               [--qr ansi|utf8|invert|none] [--quiet] -- <cmd...>
                                          try it: gate <cmd...> with the defaults, pair the phone on the first run
  wardend run [--config f] [--state-dir d] [--socket s] [--journal j] [--policy rules.json] [--ttl 120s]
              [--max-pending 64] [--trust <deviceId>[:<pubkey>]]... [--toctou-roots stop|poll|off]
              [--toctou-service off|poll|stop] [--relay-url wss://relay.wardenclaw.dev|off] [--linger 2s]
              [--require-hardened] [--child-user name|uid[:gid]] [--quiet] -- <cmd...>
  wardend config-check [--config f] [--state-dir d] [--policy rules.json] [-- <cmd...>]
  wardend keygen
  wardend approve --key-file <file|-> [--socket s] [--match regex] [--deny] [--count N] [--timeout 30s]
  wardend status [--socket s]
  wardend journal [--socket s] [-n 20]
  wardend verify-journal [--pubkey b64url] <journal.jsonl>
  wardend policy-defaults
```

## External approvers and test automation

`wardenctl` is the supported minimal integration surface for systems that need to inspect and
decide requests without the mobile app. Keep its state and device key on a machine the agent
cannot access.

The four one-shot commands accept a global `--json` flag before or after the command:

```bash
# List pending requests. Only act on entries where verified is true.
wardenctl pending --json

# Inspect one verified request, using a full id or a unique prefix of at least six characters.
wardenctl show wd-3f9a0c --json

# Submit a signed decision with the paired wardenctl device key. From a script, pass the full id.
wardenctl approve wd-3f9a0c1e7b2d4a6f8e0c2b4d6f8a0c2e <!-- feature:hardwareKey -->--no-hw <!-- /feature -->--json
wardenctl deny wd-3f9a0c1e7b2d4a6f8e0c2b4d6f8a0c2e --json
```

`pending` returns `{ok, host, seq, now, pending}`. Every item contains `id`, `digest`,
`createdAt`, `expiresAt`, a display `command`, the original `envelope` and `meta`, plus `verified`.
An item that fails local envelope, supervisor, digest or id verification remains visible with
`verified: false` and `verificationError`, but `approve` and `deny` refuse to sign it. `show`
returns the same item as `card`. A successful decision returns `{ok, id, digest, decision}`<!-- feature:hardwareKey -->, plus
`hardwareRule` when a `require_hardware` rule applied<!-- /feature -->.

The contract deliberately has no embedded policy runner. An external system reads `pending`,
applies its own policy, then invokes `approve` or `deny`. This keeps the signing boundary small and
makes the same path usable in end-to-end tests.

From a script (stdin is not a terminal) or with `--yes`, `approve` shows no card and asks nothing,
so it takes only an id with at least 12 characters after `wd-`: a short prefix in a script can land
on the wrong card. Pass the full `id` from `pending`.<!-- feature:hardwareKey --> An allow is signed with a YubiKey touch by
default, and an unattended system has nobody to touch the key: `--no-hw` signs with the device key
alone. That works only while wardend has no `require_hardware` rule for the command; when one
applies, wardend refuses the decision and the error names the rule.<!-- /feature -->

Exit codes are stable:

| Code | Meaning |
|---|---|
| `0` | The command completed successfully. |
| `1` | Runtime failure, missing/expired request, failed verification, or wardend rejected the decision. |
| `2` | Invalid command line or arguments. |
| `3` | Safety guard refused to run wardenctl inside the agent tree or beside an accessible wardend. |
| `4` | wardend speaks a protocol version this wardenctl doesn't support (`pair`, `status`). |

**Protocol version.** `pair` and `status` compare `protocol` in wardend's status with their own. A wardend without the field or of a lower version gets a message to update wardend, a wardend of a higher version gets a message to update wardenctl, and both exit with code 4. A request whose envelope is newer than wardenctl (`v` above 1) is not dropped: it stays in the list with `verified: false` and a `verificationError` that asks to update wardenctl, and it can't be signed.

Errors are written to stderr. Successful JSON is the only stdout output, so callers can parse it
directly. A minimal shell integration looks like this:

```bash
request_id="$(wardenctl pending --json | jq -r '.pending[] | select(.verified) | .id' | head -n1)"
test -n "$request_id" || exit 0
wardenctl show "$request_id" --json | jq -e '.card.verified == true' >/dev/null
wardenctl approve "$request_id" <!-- feature:hardwareKey -->--no-hw <!-- /feature -->--json
```

Calling `approve` means the external system, not a human, authorized the command. Audit logs retain
the paired device id, so give delegated approvers distinct names and keys.

Flags accept one or two dashes (`-ttl` and `--ttl` are the same). Every command and subcommand of `wardend` and `wardenctl` prints its usage and flags with `--help`, `-h` or `help` (`wardend pair approve --help`, `wardend help run`) to stdout with exit code 0 and does nothing else: no key, no files, no socket or network connection. `wardenctl` answers it before the safety guard, so it works anywhere. A command-line error prints the message and the usage to stderr with exit code 2.

## Commands

### `wardend wrap`

The one-command way in. It runs `<cmd...>` under the gate with defaults and asks your phone before every launch outside an approved subtree. No flags are needed.

```
wardend wrap [flags] -- <cmd...>
```

```console
$ wardend wrap -- claude "fix the failing test"
wardend: no device is paired yet. Pair your phone; claude starts after that.

(the QR code)
Scan the QR in the WardenClaw app (Connect tab) or paste the link:
  wardenclaw://pair?code=B2D6KTKB&enc=rjuB…52c&host=pi&key=nZxU…gXE&relay=wss%3A%2F%2Frelay.wardenclaw.dev%2Fv1%2Fws&sid=831f…a2bb&v=1

Code:       B2D6-KTKB (one-time, until 17:30:57)
Relay:      wss://relay.wardenclaw.dev/v1/ws
Supervisor: pi, key fingerprint 831f 64ae 5ec7 1764

Waiting for the request from the phone (Ctrl+C to stop waiting; then wardend pair list)…

Request p-nyfsqv: "Pixel 9", fingerprint dc06 ce18 88b3 cbec, from relay
Compare the fingerprint with the phone screen.
Approve this device? [y/N] y
Approved: "Pixel 9", fingerprint dc06 ce18 88b3 cbec, deviceId dc06ce18…ca7e3
Written to /home/me/.wardend/config.json (trusted_devices); the supervisor trusts the device right away.

(the command runs and owns the terminal)
wardend: waiting for your decision on the phone: git push origin main
wardend: denied on the phone: git push origin main
wardend: 41 commands seen, 2 asked: 1 allowed, 1 denied, 0 expired. Journal: /home/me/.wardend/journal.jsonl
```

The pairing part is the output of a test run against an in-process relay, with the host and the relay address replaced; the lines after it show the format of the notices and of the summary.

- **Defaults.** The built-in policy, state in `~/.wardend`, the default relay. `~/.wardend/config.json` is read if it exists, and flags override it. Underneath it is `wardend run`: the same supervisor, the same journal, the same cards. Every launch outside an approved subtree is a card on the phone; the app's observe mode signs them all while you watch, delegate lets its judge decide, manual is you.
- **Pairing on the first run.** With no trusted device, wrap prints the QR code and the link of `wardend pair start`, waits for the phone, shows the device's name and key fingerprint and asks `Approve this device? [y/N]`. Only after `y` does the command start. After `n`, no answer, or an expired code, wrap exits with code 1 and the command is never started. The question is asked on the controlling terminal (`/dev/tty`), not on stdin, so the command gets its stdin untouched. Without a terminal (a script, a pipe) wrap does not wait: it exits and says to pair first.
- **While the command runs** it owns the terminal. wardend writes to stderr only what you must see: a card that has waited more than 5 seconds for you, a denial, an expiry.
- **At the exit** a one-line summary goes to stderr (`--quiet` drops it): commands seen, asked, allowed, denied, expired, and the journal path. PATH lookups of a shell and its retries of a denied command are not counted as commands. The exit code is the command's.
- **Fail closed.** If the relay cannot be reached within 10 seconds, wrap says so and exits before starting the command: no card could reach the phone. `--relay-url off` is not a way to get approvals: without a trusted device wrap refuses to start, and with one the decisions can only come over the socket (`wardend approve`). There is no flag that asks nobody: a card nobody signs expires after `--ttl` into `EPERM`.

| Flag | Default | Meaning |
|---|---|---|
| `--policy f` | built-in rules | Rules JSON ([Policy](#policy)). |
| `--ttl d` | `120s` | How long a command waits for the decision. |
| `--state-dir d` | `~/.wardend` | Key, journal, socket, config. |
| `--relay-url u` | `wss://relay.wardenclaw.dev` | The relay the app reaches wardend through. |
| `--qr style` | `ansi` | QR code of the pairing step: `ansi`, `utf8`, `invert`, `none`. |
| `--quiet` | off | No summary at the exit. |

Here wardend runs as the same user as the command. The command cannot get past the exec gate, but it can read wardend's files and edit its config between runs. The system install (`curl -fsSL https://wardenclaw.dev/install.sh | sudo sh`) is the one with real separation: wardend as a root service, the agent as its own user.

### `wardend run`

Starts `<cmd...>` under the supervisor. Everything after `--` is the command. This is what the service runs (the systemd unit of the install) and what [`wardend wrap`](#wardend-wrap) runs underneath: every setting is a flag or a config key, nothing is asked on a terminal, and it starts without a paired device, but then every card waits for a signature nobody can give and expires into `EPERM` (the start prints a warning; pair a phone with `wardend pair start`).

```
wardend run [flags] -- <cmd...>
```

| Flag | Default | Meaning |
|---|---|---|
| `--config f` | `~/.wardend/config.json` if it exists | JSON config (see [Config](#config)). Flags override config values. |
| `--state-dir d` | `~/.wardend` | State directory, created with mode 0700. |
| `--socket s` | `<state-dir>/wardend.sock` | Unix socket for JSON-RPC. |
| `--journal j` | `<state-dir>/journal.jsonl` | Append-only journal. |
| `--policy f` | built-in rules | Policy JSON (see [Policy](#policy)). |
| `--ttl d` | `120s` | How long an exec waits for a ticket before `EPERM`. |
| `--max-pending n` | `64` | Queue limit for execs waiting for a ticket; overflow gets `EAGAIN`. |
| `--trust id[:pubkey]` | none | Trusted device, repeatable. Appended to `trusted_devices` from the config. |
| `--toctou-roots m` | `stop` | Post-exec check for approved roots: `stop`, `poll` or `off`. |
| `--toctou-service m` | `off` | Same for allow-listed service execs. |
| `--relay-url u` | `wss://relay.wardenclaw.dev` | The relay the app reaches wardend through; `off` for none (then only `wardend approve` can sign). |
| `--linger d` | `2s` | After the main child exits, keep serving the rest of the tree this long. |
| `--require-hardened` | off | Refuse to start unless binary, config, key and state directory are root-owned and closed ([hardened install](../install/)). |
| `--child-user u` | none | Run the command as this user (`name` or `uid[:gid]`) after installing the filter; wardend itself stays root. |
| `--quiet` | off | No start and summary lines on stderr. |

The exit code is the child's exit code; death by signal N is `128+N` (SIGTERM gives 143). SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGUSR1 and SIGUSR2 are forwarded to the child.

Without `--quiet`, the start line on stderr is `wardend: pid=… child=… socket=… journal=…` and the summary at the exit is `wardend: execs=… denied=… latency p50=… p95=… max=… exit=…`.

**A card nobody signs.** Without a trusted device every launch waits for the TTL and fails; `deny_always` rules fail at once, without a card:

```console
$ wardend run --ttl 2s --quiet -- sh -c 'dd if=/dev/zero of=/dev/null count=1; echo "dd rc=$?"; ls -d /tmp; echo "ls rc=$?"'
sh: 1: dd: Operation not permitted
dd rc=126
sh: 1: ls: Operation not permitted
ls rc=126
```

(`dd of=/dev/…` is one of the `deny_always` rules; the example writes to `/dev/null`, so it stays harmless even where the rule doesn't apply. `ls` was an ordinary root card: it waited two seconds for a signature that never came, journal reason `ttl expired`.)

**A card signed with a test key.** Every launch outside an approved subtree waits for a signed decision; children of an approved root run at once. In one terminal:

```bash
umask 077
mkdir -p ~/.wardend
wardend keygen > ~/.wardend/demo-device.txt   # test device, outside the command's directory
DEV=$(sed -n 's/^deviceId=//p' ~/.wardend/demo-device.txt)
PUB=$(sed -n 's/^pubkey=//p' ~/.wardend/demo-device.txt)
cd /tmp
wardend run --trust "$DEV:$PUB" --ttl 30s --quiet \
  -- sh -c 'ls -d /etc; ssh -V; echo "ssh rc=$?"'
```

The `sh -c` is the supervised command itself and runs without a card; `ls` is the first launch outside an approved subtree, a root card, and waits in the kernel. In another terminal, outside that command, sign it with the test key:

```console
$ wardend approve --key-file ~/.wardend/demo-device.txt --count 2 --timeout 30s
allow wd-… argv=[ls -d /etc] -> map[decision:allow id:wd-… ok:true]
allow wd-805763d1887fcfb8a26269e7d38f1db9 argv=[ssh -V] -> map[decision:allow id:wd-805763d1887fcfb8a26269e7d38f1db9 ok:true]
```

`ls` prints `/etc`. `ssh` is a delegating spawn (execution leaves the gate), so it is a card of its own even though `ls` was approved: the second line signs it with the risk hint `remote` on the card, and the first terminal prints the OpenSSH version and `ssh rc=0`. Without a ticket within the TTL, or with a signed deny (`--deny`):

```console
/etc
sh: 1: ssh: Operation not permitted
ssh rc=126
```

### `wardend config-check`

Checks the config and the policy the way `wardend run` reads them at start, and starts nothing: no key, no journal, no socket, no state directory. Run it after every edit and before a restart, since a config wardend can't read stops wardend, and the agent with it:

```bash
sudo wardend config-check --config /etc/wardend/config.json && sudo systemctl restart wardend
```

Flags are the path flags of `run`, with the same defaults: `--config` (else `<state-dir>/config.json` if it exists), `--state-dir`, `--policy` (else `policy` from the config, else the built-in rules). A command after `--` is optional and only feeds harness pack detection, as in `run`. It prints every error and warning and exits with 0 if `wardend run` would start with these files, 1 if not (2 for a command-line error). It catches:

- JSON errors in the config or the policy, with line and column (`config /etc/wardend/config.json: line 4, column 3: invalid character '"' after object key:value pair`);
- unknown keys in the config, nested ones too, as an error with a hint (`error: config …: unknown key "ticket_tll" (did you mean "ticket_ttl"?)`): `run` does not start with such a config, so a typo in a key can't silently leave the default. The removed keys `mode` and `policy_mode` are unknown keys too. In a policy file an unknown key is a warning (`unknown key "…" is ignored (did you mean "…"?)`);
- values `run` rejects: `toctou_*`, a `trusted_devices` entry whose key doesn't hash to its id, policy rules that don't compile, the install checks of selfcheck;
- `hardware_keys` (or `require_hardware` in the policy) in a build without the second factor: the error `run` stops with, explained; <!-- feature-item:hardwareKey -->
- no `trusted_devices` (a warning: every card waits for a ticket nobody can sign and is denied after the TTL, until a phone is paired); if `relay_url` is also `off`, the warning says so explicitly: no phone can ever pair without the relay, and the only way to decide is `wardend approve`;
- a config `version` newer than this wardend understands (an error, see [Config](#config)).

The last line before the verdict sums up what `run` would start with, `policy built-in, trusted devices 0` (or the path of your policy file and the number of paired devices); the verdict is `config-check: ok`, or the errors and exit code 1.

### `wardend keygen`

Creates a **test** device key pair: the 32-byte Ed25519 seed (hex), the public key (base64url, raw 32 bytes) and the device id (sha256 of the public key, hex).

```console
$ wardend keygen
seed=22e5e1…6f66
pubkey=fEm6ZDoB…nmr8Y
deviceId=9362e2a4…188d5a
```

In production the phone app holds the key; `keygen` and `approve` exist for demos and tests. The seed is a secret from the process you supervise: that process runs as you and can read any file you can read. Keep the file out of its working directory, do not pass the seed on the command line, and do not leave the test key trusted for a real agent.

### The socket of client commands

`status`, `journal`, `approve` and `pair` talk to the running wardend over its unix socket and find it themselves, the first that applies:

1. `--socket s`, for unusual setups and tests;
2. `$WARDEND_SOCKET`, if set;
3. `~/.wardend/wardend.sock`, if it exists: your own wardend of the single-user install;
4. the system install, if `/etc/wardend/config.json` exists: the socket that config names (`socket`, else `<state_dir>/wardend.sock`), `/var/lib/wardend/wardend.sock` by default;
5. `~/.wardend/wardend.sock`.

The socket of the system install belongs to root, so there the commands run with `sudo`: `sudo wardend status`. Without it the error is the command to retype: `run it with sudo: sudo wardend status`. `hw-register` and `hw-keys` pick their default `--config` the same way: `~/.wardend/config.json` if it exists, else `/etc/wardend/config.json`.

### `wardend approve`

A "device in a terminal": long-polls `pending` on the socket, recomputes each digest from the envelope (like the app does), and signs decisions with a seed.

| Flag | Default | Meaning |
|---|---|---|
| `--key-file path` | required | File from `wardend keygen`, or `-` to read that output from stdin. Must be mode 0600. |
| `--socket s` | see [The socket of client commands](#the-socket-of-client-commands) | Supervisor socket. |
| `--match re` | none | Only sign execs whose argv, joined with spaces, matches this Go regex. |
| `--deny` | off | Sign `deny` instead of `allow`. |
| `--count n` | `1` | How many decisions to send; `0` means no limit until `--timeout`. |
| `--timeout d` | `30s` | How long to wait. |

`--key` is rejected: the seed would show up in the process list. `approve` also refuses to run when this process is already under a seccomp filter, which is what happens inside the command `wardend run` started.

Exit code 1 and `nothing approved` when no decision was sent.

### `wardend status`

Supervisor state over the socket: harness packs, queue, tracker, trusted devices, journal key and metrics.

```console
$ wardend status
{
  "host": "pi",
  "journal": "/home/me/.wardend/journal.jsonl",
  "journalKey": "8bnwSh-K…811T8A",
  "maxPending": 64,
  "metrics": {
    "allowed": 1,
    "byClass": { "supervised_cmd": 1 },
    "decideRejects": 0,
    "denied": 0,
    "execs": 1,
    "latencyUs": { "count": 1, "max": 3233, "p50": 3233, "p95": 3233 },
    "ticketWaitUs": { "count": 0, "max": 0, "p50": 0, "p95": 0 },
    "tickets": { "allowed": 0, "denied": 0, "expired": 0, "queueFull": 0 },
    "toctouKills": 0
  },
  "now": 1790454056134,
  "ok": true,
  "packs": ["claude-cli", "openclaw"],
  "pending": 1,
  "pid": 16346,
  "protocol": 1,
  "startedAt": 1790454055082,
  "supervisorId": "bbcf051f…a15d42",
  "ticketTtlMs": 30000,
  "toctou": { "roots": "stop", "service": "off" },
  "tracker": { "lineage": 0, "roots": 0 },
  "trustedDeviceIds": ["<deviceId>"],
  "warnings": []
}
```

`protocol` is the version of the WardenClaw protocol this wardend speaks; the app and `wardenctl` refuse a wardend that speaks another one. `warnings` is a list of codes, empty when all is well: `no_trusted_devices` means no device is trusted, so every card waits for a ticket nobody can sign and is denied after the TTL (pair a phone: `wardend pair start`; the warning goes away without a restart). `wardend status` prints each warning in words to stderr after the JSON, so stdout stays plain JSON:

```console
wardend: warning: no trusted devices: every card waits for a ticket nobody can sign and is denied after the TTL. Pair a phone: wardend pair start
```

### `wardend journal`

The last N journal records (JSON lines) over the socket; `-n` defaults to 20, and values outside 1 to 1000 fall back to 20.

```console
$ wardend journal -n 1
{"data":{"argv":["sleep","1.5"],"callerExe":"/usr/bin/dash","chain":[…],"class":"root","cwd":"/home/me","decision":"allow","exe":"/usr/bin/sleep","latencyUs":445,"syscall":"execve",…},"hash":"3454679b…","kind":"exec","prevHash":"36557f10…","seq":48,"sig":"feGmW5ib…","ts":1790454062696}
```

### `wardend verify-journal`

Checks the hash chain and the signature of every record. Pass the supervisor's public key (from `status.journalKey` or the `start` record) to check authorship, not only integrity.

```console
$ wardend verify-journal --pubkey 8bnwSh-K…811T8A ~/.wardend/journal.jsonl
{"ok":true,"entries":49,"key":"8bnwSh-K…811T8A"}

$ wardend verify-journal --pubkey 8bnwSh-K…811T8A tampered.jsonl    # one "allow" changed to "deny"
{"ok":false,"entries":1,"error":"hash_mismatch","badSeq":2}

$ wardend verify-journal --pubkey 8bnwSh-K…811T8A cut.jsonl         # one line deleted
{"ok":false,"entries":2,"error":"seq_gap","badSeq":4}
```

Without `--pubkey` it still exits 0 on a valid chain, with a warning that the key came from the journal itself.

### `wardend policy-defaults`

Prints the built-in rules as JSON: the starting point for your own `--policy` file. `--pack claude-cli` or `--pack openclaw` prints a built-in [harness pack](#harness-packs) instead.

```bash
# only if you have no policy file yet: never overwrite the rules you have added
test -e ~/.wardend/policy.json || wardend policy-defaults > ~/.wardend/policy.json
```

### `wardend replay`

Runs the exec records of a journal through this build's classifier, the same code the supervisor uses (harness packs, path zones, risk hints), and prints aggregates only: classes, categories, rules, cards a day and the peaks. Every card is counted as approved, as with the app in observe mode, so children of a root count as inherited the way they would after a signature. Nothing from argv is printed. This is the review of a watching period: what the phone signed, how often, when, and with which hints.

| Flag | Default | Meaning |
|---|---|---|
| `--journal f` | required | Journal to read. It is only read; a copy of a live journal works, a cut last line is skipped. |
| `--config f` | none | Install config: `agent_home`, `work_dirs`, `scratch_dirs`, `packs`, `pack_vars`, `policy`. |
| `--policy f` | config, else built-in | Policy JSON. |
| `--agent-home d` | config, else `$HOME` | `${AGENT_HOME}`. |
| `--packs a,b` | config, else all built-in | Harness packs; `none` for none. |
| `--work-dir d`, `--scratch-dir d` | none | Repeatable; added to the config's lists. |
| `--from t`, `--until t` | whole journal | Unix milliseconds or RFC 3339. |
| `--json` | off | One JSON object instead of text. |
| `--dump f` | none | One line per exec: seq, class, rule and detail. No argv; the file gets mode 0600. |
| `--top n` | `25` | How many rules to list. |

The text report has one line each for the journal path, the time window and the number of records, the policy and packs in use, the classified execs, the classes (`root`, `delegating`, `service`, `inherit`, `refuse`, `deny_always`), the cards with their rate per hour and per day (a window shorter than an hour gets no rates), the peaks in 2, 10 and 60 minutes (2 minutes is the ticket TTL: that many cards pending if nobody answers) and how many came at night, the categories of the risk hints, the refused launches, the top rules behind the cards and the service rules that fired. `--json` gives the same as one object, `--dump` one line per exec without argv.

Read it as: `cards` is how many signatures a day the app gave in observe mode and you would answer by hand; `categories` and `top rules` say why; `service rules` says what the phone signed by rule. A root approved once covers its live subtree, so a long `bash -c` script is one card, not one per command inside it; `ssh`, `docker` or `systemd-run` inside it is a card of its own (delegating); `sudo` is refused without a card.

### `wardend rootexec`

```
wardend rootexec [--socket s] [--cwd d] [--quiet] -- <cmd...>
```

From under the gate: asks wardend to run `<cmd...>` as root after a card on the phone. The agent
has no `sudo` and no `docker` group in the hardened install; this is the one road up, and every
step of it is a card. The command runs with the agent's stdin/stdout/stderr and working
directory, a clean environment, and the file wardend opened and pinned before the card (a swap
of the path after the card changes nothing). Only what the policy's `root_exec` list names may be
asked for (the list starts empty); the gate's own files, privilege and account tools are refused
without a card; only with `"root_exec": {"enabled": true}` in the config
(`install.sh --root-exec`).

Exit code: the command's own; `124` the card expired or the timeout hit; `125` refused before a
card; `126` denied on the phone.

The agent may also just type `sudo` or `docker`: symlinks named `sudo` and `docker` to wardend
sit first on the harness PATH, and `sudo docker restart searxng` or `docker ps` are the same
request with the familiar spelling (no setuid, no sudoers, no docker group; `-i`, `-s`, `-u
<other>`, `-E` are refused with a message). Every request is a card, no exceptions: the built-in
`docker-read` and `systemctl-read` rules name the read-only verbs so the phone may sign them by
rule (`meta.rule`), and a card nobody signs expires into exit 124. There is no mode in which
wardend decides alone.

```console
$ wardend rootexec -- docker restart searxng
wardend rootexec: card wd-02346720465858b52afbe3c90f349c67 is on the phone, waiting for the decision (expires in 2m0s)
wardend rootexec: approved, running (pid 4242)
searxng
```

## Modes

wardend has no mode of its own. Every launch outside an approved subtree is a card the phone signs, and a card nobody signs expires after `ticket_ttl` into `EPERM` (`Operation not permitted`, rc 126, journal reason `ttl expired`): fail-closed, no local bypass. Until a phone is paired nothing the agent launches will run.

**Observe**, **delegate** and deciding by hand are the modes of the phone app, and the daemon asks exactly the same in all three:

| App mode | Who signs |
|---|---|
| observe | the app, every card, automatically; you watch the feed and the journal |
| delegate | the app's on-device judge, by its rules; the rest comes to you |
| manual | you |

<a id="policy-modes"></a>

### Cards, classes and risk hints

One classifier, first match wins (the full table is under [Policy](#policy)):

| Class | What | Decision |
|---|---|---|
| `deny_always` | a rule of the deny list | `EPERM` at once, no card, even inside an approved subtree |
| `service` | harness housekeeping matched by a pack or `service_allow`, only without a risk hint (so `claude mcp add` doesn't pass as `claude`) | a card with `meta.class: "service"` and `meta.rule`; the app signs it by rule. Signed with `inherit: true` it becomes a root, otherwise it passes alone |
| `refuse` | `sudo` and friends under `no_new_privs` | `EPERM` at once, no card |
| `delegating` | execution leaves the gate: `ssh`, `docker`, `systemd-run`, `setsid`, `tmux`… | always a card of its own, never inherited |
| `inherit` | the caller is in the live subtree of an approved root | runs, no card |
| `root` | everything else | a card |

**Risk hints.** The categories below (remote execution, leaving the gate, package installs, publishing, destructive commands, protected paths and secrets, agent settings, adb, cloud CLIs) are hints on the card and in the journal: `category`, `rule` and `detail`. A hint never lets a launch pass and never carries an approval on: a `root` card with the hint `remote` is still a root card, and an approved `scp` doesn't make the next `ssh` free (`ssh` is delegating, a card of its own). What the hints do is tell the phone, its judge in delegate mode and `wardend replay` why a card is risky. Your own hint rules go to `tripwire` in the policy file.

| Category | Fires on | Doesn't fire on |
|---|---|---|
| `delegate` | `systemd-run`; `systemctl` except `status/show/cat/is-*/list-*`; `loginctl` except `list-*/show-*`; `busctl call/set-property`; `dbus-send` except `GetNameOwner/Get*/Introspect`; `tmux`, `screen`, `zellij`; `at`; `crontab` except `-l` | reading state |
| `container` | `docker`/`podman` except `ps/inspect/logs/images/stats/version/info` (and `compose ps/logs/config`); `kubectl` except reads; `flatpak-spawn`, `distrobox`, `toolbox` | |
| `remote` | `ssh`, `scp`, `sftp`, `rsync host:…`, `nc`, `ncat`, `socat`, `telnet` | local `rsync` |
| `privilege` | `nsenter`, `unshare`, `chroot`, `setpriv`, `capsh`, `apt`/`dpkg install`; `sudo` and friends are refused (below) | |
| `net-write` | `curl`/`wget` with a body or a write method to a non-loopback host | GET; writes to 127.0.0.1 |
| `pkg-run` | `npm install/ci/exec`, `npx` with `-y`, `-p` or `pkg@version`, `pip install`, `uv run`, `pnpm`/`yarn add`, `go install`, `cargo`/`gem install` | `npm run`, `npx tsc` |
| `publish` | `git push`, `npm publish`, `gh pr/release/repo/secret` writes, `gh api` writes, `eas build/submit/update/…` | `gh pr list`, `eas build:view` |
| `destructive` | `rm -r` and `find -delete` outside scratch; `git reset --hard`, `clean -f`, `checkout -- .`, `stash drop`, `branch -D`, `filter-branch`, `reflog expire` in a repository outside scratch | `rm -rf /tmp/…`, `node_modules`, `dist` |
| `protected-write` | writes, deletes and `chmod` in the `config` zone (dotfiles, `~/.local/bin`, `~/.config/systemd`, `~/.nvm`, `~/.wardend`, `~/.ssh`, `/etc`, `/usr`, harness settings) and the `secret` zone | |
| `outside-work` | writes and deletes outside `work_dirs` and scratch (only when `work_dirs` is set), and in roots (`/`, `/home`, `/mnt/<disk>`, the home itself) | |
| `secret-read` | content-printing tools (`cat`, `head`, `grep`, `jq`, `cp`, `base64`, `openssl -in`, an interpreter with a path) on the `secret` zone (`~/.ssh/id_*`, `~/.config/*token*`, `.env`, `supervisor.key`, harness secrets); `gh auth token` | `*.pub`, `known_hosts` |
| `agent-config` | the harness CLI's settings verbs, from its pack: `openclaw config set`, `cron add`, `secrets`, `plugins install`…, `claude mcp add`, `config set`… | `cron list`, `--help` |
| `guard` | the live wardend/wardenctl CLI: `pair`, `trust`, `devices`, `policy`, `keygen`, `hw`… | test builds elsewhere |
| `device` | `adb` except reads (`devices`, `logcat`, `pull`, `exec-out screencap`, `shell dumpsys/getprop/ls/pm list/settings get`); `fastboot` | |
| `cloud` | `aws`, `gcloud`, `az`, `terraform`, `helm`, `flyctl`, `vercel`, `wrangler`… | |

Rules look at the **real binary** (the realpath of the executed file) and at argv, so `./deploy.sh` is the agent's script in the journal, but the real `ssh` inside it still trips `remote`. Paths come from argv, resolved against the caller's cwd and `~`: `cat id_rsa` in `~/.ssh` is a secret read. The zones (`secret`, `config`, `scratch`, `work`) are built in, extended by harness packs and by your config (`work_dirs`, `scratch_dirs`).

**Subtrees.** An approved root is registered before `CONTINUE`, and every process whose exec passed as its descendant joins the lineage (pid plus start time, so a reused pid doesn't inherit). A launch inherits while at least one ancestor of the lineage is alive, not only the root; the end of a subtree is a `root_exit` record in the journal. A delegating spawn never inherits: an approved `npm ci` doesn't make an `ssh` from a postinstall script free, and what an approved `docker run` or `systemd-run` does next runs outside the tree, so that one signature covers whatever runs there.

**sudo.** wardend sets `no_new_privs` on the whole tree, and a setuid binary gains nothing under it, so a ticket for `sudo` would be useless. `sudo`, `su`, `doas`, `pkexec`, `sudoedit`, `newgrp` and `sg` get `EPERM` at once, without a card, even inside an approved subtree; the journal record has the class `refuse` and the reason. A `sudo` shim without the setuid bit is an ordinary card with the hint `privilege` (the [rootexec](#wardend-rootexec) shim of the hardened install is a service launch whose request gets its own card).

```console
$ wardend run --trust "$DEV:$PUB" --quiet -- sh -c 'sudo -n true; echo "sudo rc=$?"'
sh: 1: sudo: Operation not permitted
sudo rc=126
```

### Harness packs

Everything that is specific to one harness lives in a pack: its housekeeping execs (claude itself, its built-in `rg`, git probes, the shell snapshot; the OpenClaw gateway's workers and probes and the wrapper it starts children with), the zones of its settings and secrets, and the CLI verbs that change the agent's settings. A pack match is a `service` card the phone signs by rule; a launch with a risk hint never passes as service. Two packs are built in, `claude-cli` (tested with 2.1.283) and `openclaw` (2026.9.6); `wardend policy-defaults --pack <name>` prints one.

Paths in packs are variables, not `/home/…` regexes. In a regex, `${NAME}` becomes `(?:path1|path2)` built from the escaped values, so an install path can't break a rule. The same variables work in the regexes of your own policy file, and in `work_dirs` and `scratch_dirs` together with `~`:

| Variable | Where the value comes from | Default |
|---|---|---|
| `${AGENT_HOME}` | `agent_home` from the config, else the home of `child_user`, else wardend's `$HOME` | |
| `${ANY_HOME}` | regexes only: `${AGENT_HOME}`, `/home/<anyone>`, `/root` | |
| `${CLAUDE_ROOT}` (claude-cli) | detected from a command like `…/claude/versions/X.Y.Z` that wardend starts; `pack_vars` | `${AGENT_HOME}/.local/share/claude`, `/opt/claude` |
| `${CLAUDE_BIN}` (claude-cli) | `pack_vars` | `${AGENT_HOME}/.local/bin/claude`, `/usr/local/bin/claude` |
| `${OPENCLAW_ROOT}` (openclaw) | detected from `…/openclaw/dist/index.js` (or `entry.js`, `openclaw.mjs`, also after realpath) in wardend's command; `pack_vars` | `/usr/lib/node_modules/openclaw`, `/usr/local/lib/node_modules/openclaw`, `/opt/openclaw` |
| `${OPENCLAW_HOME}` (openclaw) | `pack_vars` | `${AGENT_HOME}/.openclaw` |

A detected value is added to the defaults; `pack_vars` replaces the whole list. `AGENT_HOME` and `ANY_HOME` can't be set through `pack_vars` (use `agent_home`). An unknown variable in a rule or a pack is a load error (wardend exits with code 2 before starting anything), not a rule that silently matches anything.

How a pack is chosen:

- which packs are loaded: `packs` in the config (built-in names or paths to pack files; `[]` for none), all built-in ones by default;
- which exec a pack applies to: by the process chain. A pack rule matches only inside its harness (the harness binary as caller or path, the harness runtime among the ancestors, or all ancestors being the gateway's processes);
- where the harness lives: defaults, detection from the command wardend starts (`node …/openclaw/dist/index.js gateway` gives `${OPENCLAW_ROOT}`), and `pack_vars` in the config, for example `{"CLAUDE_ROOT": ["/opt/claude"]}` in a hardened install.

**Check it on your own journal** before you take the app out of observe: [`wardend replay`](#wardend-replay) runs the journal through the same code and prints cards a day, peaks and categories. On a 25-hour journal of a coding agent (98,053 execs) that came to about 3,162 cards a day; `service_allow` rules for the housekeeping the app may sign by rule bring it down.

**What the gate honestly doesn't see.** An approved root hides it inside one card for a whole command; a hint only names what the rules recognised in argv.

1. Actions without a new exec: shell redirections (`> ~/.bashrc`, `< ~/.ssh/id_ed25519`), shell builtins (`kill`, `echo >`), the harness's own file tools (Write, Edit), network and files from inside long-running processes, MCP calls.
2. Code inside interpreters: `python3 -c`, `node -e` and the agent's own scripts can do anything; only the start is visible, and inside an approved subtree not even that. The same goes for an argv race in a multithreaded process: an inherited exec is not re-checked after `CONTINUE` (TOCTOU checks cover approved roots).
3. The browser and CDP: `openclaw browser evaluate` and requests to the CDP port on 127.0.0.1 act in sessions with your logins.
4. Execution outside the gate after an approval: what an approved `systemd-run`, `docker run` or `ssh` does next is not seen.
5. Identity by name: a copy of a binary under another name bypasses a hint (sha256 of the target is on the roadmap).
6. The meaning of arguments, and what is not in argv: `npm test` and `go test` run code the agent wrote; `curl -K file` takes the method and the body from a file, and `net-write` doesn't see them.

**Why you still need the box.** The gate looks at execs, so it guards against an agent that uses standard tools, which is what a hijacked agent and an honest mistake usually look like. It doesn't stop an agent that writes its own code: a `python3 -c` that reads a key and sends it out is one card whose hint says nothing about the key, and inside an approved root it is no card at all. That takes **the box**, limits that hold whatever the code is:

- the [hardened install](../install/): the harness runs as a separate user; `ProtectHome=true`, so your home with its SSH keys, tokens and browser profiles is not in the agent's file system at all, and there is nothing to read there by exec, by redirection or from an interpreter; `ProtectSystem=strict` with writes only to the agent's home and the listed `ReadWritePaths`; `NoNewPrivileges`;
- outbound network by allow-list: the harness reaches only the model API and the hosts you name, through a proxy with a domain allow-list. Without it, any code can send anything anywhere. The installer **doesn't set this up yet**: the hardened unit doesn't restrict the network;
- an MCP proxy for tools that act outside the host (planned).

The gate adds to the box; it doesn't replace it. The box limits what any code can reach at all; the gate asks you before each launch inside those limits.

## Config

`~/.wardend/config.json` is read by default when it exists; all fields are optional, flags override them, and `--trust` appends to `trusted_devices`. This is `deploy/config.example.json`:

```json
{
  "version": 1,
  "ticket_ttl": "120s",
  "ts_window": "60s",
  "max_pending": 64,
  "linger": "2s",
  "toctou_roots": "stop",
  "toctou_service": "off",
  "relay_url": "wss://relay.wardenclaw.dev",
  "pair_code_ttl": "5m",
  "root_exec": {"enabled": false, "socket": "", "group": "", "timeout": "10m"},
  "trusted_devices": []
}
```

| Field | Default | Meaning |
|---|---|---|
| `version` | `1` | Version of the config format. No key means 1. A config with a newer version than this wardend understands stops it at start (exit 2, "update wardend"): it may mean something this build would read wrong. |
| `agent_home` | home of `child_user`, else `$HOME` | `${AGENT_HOME}` for harness packs and zones. |
| `work_dirs` | none | Your work directories (zone `work`). Without them everything outside the other zones counts as work and `outside-work` never fires. |
| `scratch_dirs` | none | More scratch directories (zone `scratch`). |
| `packs` | all built-in | Harness packs: built-in names (`claude-cli`, `openclaw`) or paths to pack files; `[]` for none. |
| `pack_vars` | pack defaults | Pack variables, for example `{"CLAUDE_ROOT": ["/opt/claude"]}`. |
| `state_dir` | `~/.wardend` | State directory. |
| `socket`, `journal` | inside `state_dir` | Socket and journal paths. |
| `key_file` | `<state_dir>/supervisor.key` | Supervisor key that signs the journal. |
| `policy` | built-in | Path to a policy JSON. |
| `ticket_ttl` | `120s` | Ticket wait (Go duration string). |
| `ts_window` | `60s` | Allowed clock skew of a ticket's `ts`. |
| `max_pending` | `64` | Queue limit: how many cards may wait at once (`wardend replay` shows your peaks in two minutes, which is the ticket TTL). |
| `linger` | `2s` | Serve the rest of the tree after the child exits. |
| `trusted_devices` | `[]` | `{id, pubkey?, alg?, name?}`. `pubkey` is base64url or hex. `alg` is absent or `ed25519`. `wardend pair approve` adds devices here. |
| `relay_url` | `wss://relay.wardenclaw.dev` | The relay wardend dials and devices reach it through: `wss://host[:port]` without `/v1/ws` (a relay of your own), or `off` for no relay. It goes into the pairing QR. |
| `relay_key_file` | `<state_dir>/relay_enc.key` | X25519 key of the end-to-end encryption with the devices. |
| `pair_code_ttl` | `5m` | Lifetime of a one-time pairing code. |
| `toctou_roots`, `toctou_service` | `stop`, `off` | `stop`, `poll` or `off`. |
| `root_exec` | `{"enabled": false}` | The [rootexec](#wardend-rootexec) socket: `enabled`, `socket`, `group`, `timeout`. |
| `require_hardened`, `child_user` | off, none | The hardened install's flags as config keys ([Install](../install/)). |
| `host` | hostname | Host name written into envelopes. |

**Keys.** Trust comes only from this config: the `pubkey` of a `trusted_devices` entry is the only key of that device (`wardend pair approve` always writes one). A key is used only if its SHA-256 equals the device id, the same rule as pairing: a config entry whose `pubkey` does not hash to its `id` stops wardend at start. An entry without `pubkey` loads, wardend warns about it at start and refuses its tickets (`unknown_device`) until the device is paired again with `wardend pair`.

**Unknown keys.** A key wardend doesn't know in the config is an error: [`wardend config-check`](#wardend-config-check) fails with `error: config …: unknown key "…"` and `wardend run` does not start. The message names the key and the nearest known one, so a typo (`"ticket_tll"`) can't silently leave the default, and a key of a removed feature (`mode`, `policy_mode`) can't be believed to still do something. In a policy file an unknown key is a warning (`is ignored (did you mean …?)`), and the file loads.

## Policy

First match wins:

| Class | What | Decision |
|---|---|---|
| `supervised_cmd` | the first exec: your own command | allow, not a root |
| `missing` | the target doesn't exist (PATH search) | `ENOENT` immediately |
| `unreadable` | the caller's memory can't be read, the path is unknown (Yama `ptrace_scope=2` without root) | `EPERM`, the reason in the journal |
| `deny_always` | regex on argv/exe: `rm -r` on `/`, `$HOME` or system dirs, `--no-preserve-root`, `dd of=/dev/…`, `mkfs*`, `wipefs`, `fdisk`, `parted`, `shred /dev/…`, `chmod/chown -R /…` | `EPERM`, even inside an approved tree |
| `service` | harness housekeeping from a pack or `service_allow` (exe + argv pattern + caller), without a risk hint | a card, rule `pack:<pack>/<id>`; signed with `inherit: true` it is a root, otherwise it passes alone |
| `refuse` | `sudo`, `su`, `doas`, `pkexec`, `sudoedit`, `newgrp`, `sg` under `no_new_privs` | `EPERM` at once, no card |
| `delegating` | `setsid`, `systemd-run`, `systemctl`, `docker`, `podman`, `kubectl`, `bwrap`, `tmux`, `screen`, `at`, `crontab`, `nsenter`, `unshare`, `chroot`, `ssh`, `scp`… | always a new root, its own card |
| `inherit` | the caller is in the live subtree of an approved root | allow, `rootPid` |
| `root` | everything else | a card |

A `root`, `delegating` or `service` record carries the [risk hint](#policy-modes) when a category fired: `category`, `rule` and `detail`.

A policy file has lists of rules: `deny_always`, `service_allow`, `delegating`, `tripwire` (your own risk-hint rules) and `root_exec` ([rootexec](#wardend-rootexec)), plus <!-- feature:hardwareKey -->`require_hardware`, <!-- /feature -->`zones` and `guard`. A file without `zones` or `guard` gets the built-in ones. All fields set in a rule must match (AND). Regexes are Go RE2 and are **not anchored** unless you write `^…$`. `${AGENT_HOME}`, `${ANY_HOME}` and pack variables are substituted, escaped.

| Field | Matches |
|---|---|
| `id` | required, rule name (shown in cards and the journal) |
| `note` | free text |
| `path` | realpath of the executed file |
| `argv0` | basename of `argv[0]`; for deny rules also the basename of the real file (catches `exec -a innocent rm`) |
| `caller` | exe of the calling process (before exec) |
| `argv_text` | argv joined with spaces (handy for deny, ambiguous for allow) |
| `argv_json` | canonical JSON of the argv array (unambiguous, use for allow) |
| `argv_none` | no element of `argv[1:]` may match |
| `argv` | list of regexes, one per element, exact length; each is anchored `^(?:…)$` |
| `under` | the exe of the caller or of one of its ancestors (in packs: `"runtime"`, the harness runtime) |
| `chain_all`, `chain_max` | the exe of every ancestor up to wardend's command; the length of that chain |
| `inherit` | `service_allow` and packs: a signed service launch becomes a root, so the probe's own helpers inherit |
| `category` | `tripwire` rules: the risk hint on the card, `custom` by default |

Example: add a deny rule on top of the defaults and try it (in a separate file, so your real policy stays as it is).

```bash
wardend policy-defaults > no-curl.json
# add to "deny_always": {"id": "no-curl", "argv0": "^curl$", "note": "no downloads"}
wardend run --ttl 2s --policy no-curl.json -- sh -c 'curl --version; echo "curl rc=$?"'
```
```console
sh: 1: curl: Operation not permitted
curl rc=126
```

(A `deny_always` hit is refused at once, without a card; the journal record has the class `deny_always` and the rule id. An ordinary card without a trusted device would also end in `Operation not permitted`, but only after the TTL and with the reason `ttl expired`.)

A rule without `id` is refused at start: `wardend: policy rule "": id required` (exit 2).

## Envelope and ticket

**Envelope v1**, one per root exec:

```json
{
  "v": 1, "type": "exec",
  "argv": ["bash", "-c", "echo approved-root; ls -d /etc"],
  "cwd": "/home/me", "exe": "/usr/bin/bash", "uid": 1000, "gid": 1000,
  "ppidChain": [{"pid": 16367, "exe": "/usr/bin/dash"}, {"pid": 16355, "exe": "/usr/bin/dash"}],
  "envHash": "4dc7cdd5…b679f",
  "requester": {"host": "pi", "supervisorId": "bbcf051f…a15d42"},
  "pidfdCookie": "pidfs:16368",
  "ts": 1790454055103,
  "nonce": "dc54ba893701a9eb374fa125a95290a2"
}
```

- `exe` is the realpath of the file being executed; `ppidChain[0]` is the calling process, then its parents up to the supervisor.
- `envHash` is sha256 of the sorted environment (NUL-separated); `supervisorId` is sha256 of the supervisor's public key.
- `pidfdCookie` binds the ticket to this process instance (`pidfs:<inode>`, or `start:<pid>:<starttime>`).
- `ts` is milliseconds; `nonce` is 16 random bytes, hex.

**digest** = `sha256(canonicalJson(envelope))`; the pending id is `wd-` plus the first 32 hex characters of the digest. Canonical JSON follows `JSON.stringify` rules byte for byte (keys sorted by UTF-16 code units, minimal escaping, ECMAScript number formatting), so Go and the app compute the same digest; shared test vectors keep them in sync. An envelope with invalid UTF-8 can't be built and the exec gets `EPERM`.

**Ticket** (the decision):

```json
{
  "deviceId": "<hex64>",
  "payload": {"id": "wd-…", "digest": "<hex64>", "decision": "allow", "ts": 1790000000000, "nonce": "…"},
  "signature": "<base64url Ed25519>"
}
```

The signature covers `canonicalJson({deviceId, id, digest, decision, ts, nonce})`. Checks, in order: the device is trusted, its key is known, `|now - ts|` is within `ts_window`, the signature is valid, the nonce is unused (it is consumed only after a valid signature), the id is pending and the digest matches.

## Socket protocol (JSON-RPC 2.0)

`~/.wardend/wardend.sock`: mode 0600 in a 0700 directory, and `SO_PEERCRED` admits only the supervisor's uid. One JSON message per line; requests on one connection are served in parallel.

### `pending`

Long-poll for execs waiting for a ticket. `since` is the last `seq` you saw, `wait` is milliseconds (capped at 25000; `0` returns at once).

```json
{"jsonrpc":"2.0","id":1,"method":"pending","params":{"since":0,"wait":25000}}
```
```json
{"jsonrpc":"2.0","id":1,"result":{
  "ok": true, "seq": 1, "host": "pi", "supervisorId": "bbcf051f…",
  "now": 1790454056175,
  "pending": [{
    "id": "wd-b37603bafd136ae8fe9a455b60e06d36",
    "kind": "exec",
    "digest": "b37603ba…784ba9",
    "envelope": { "v": 1, "type": "exec", "argv": ["bash","-c","echo approved-root; ls -d /etc"], "…": "…" },
    "meta": {"class": "root", "rule": "", "path": "/usr/bin/bash", "syscall": "execve", "callerExe": "/usr/bin/dash"},
    "createdAt": 1790454055103,
    "expiresAt": 1790454085103
  }]
}}
```

`meta.class` is `root`, `delegating` or `service`; a service card carries the rule the app may sign by (`meta.rule`), a card with a risk hint carries `category`, `rule` and `detail`. `meta` can also carry `delegating` and `insideRoot` for delegating spawns.

### `decide`

`params` is the ticket.

```json
{"jsonrpc":"2.0","id":2,"method":"decide","params":{"deviceId":"…","payload":{…},"signature":"…"}}
```
```json
{"jsonrpc":"2.0","id":2,"result":{"ok":true,"id":"wd-b37603bafd136ae8fe9a455b60e06d36","decision":"allow"}}
```

A rejected ticket is still a successful RPC with `ok: false` and a `reason`, and is written to the journal as `decide_reject`:

```json
{"jsonrpc":"2.0","id":2,"result":{"ok":false,"reason":"nonce_invalid"}}
```

Reasons include `untrusted_device`, `unknown_device`, `bad_signature`, `signature_missing`, `digest_mismatch`, `digest_invalid`, `stale_timestamp`, `ts_invalid`, `nonce_invalid`, `nonce_reused`, `decision_invalid`, `id_missing`, `unknown_pending`, `already_decided`, `pubkey_conflict`.

### `status`

No params; returns the object shown under [`wardend status`](#wardend-status).

### `journal.tail`

```json
{"jsonrpc":"2.0","id":4,"method":"journal.tail","params":{"n":20}}
```
```json
{"jsonrpc":"2.0","id":4,"result":{"ok":true,"lines":[{…},{…}]}}
```

Unknown methods return `{"error":{"code":-32601,"message":"method not found"}}`; malformed JSON returns `-32700`.

A minimal client in Python:

```python
import json, os, socket
s = socket.socket(socket.AF_UNIX)
s.connect(os.path.expanduser("~/.wardend/wardend.sock"))
f = s.makefile("rw")
f.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "pending", "params": {"since": 0, "wait": 0}}) + "\n")
f.flush()
print(json.loads(f.readline())["result"]["pending"])
```

## Journal

`~/.wardend/journal.jsonl`, mode 0600, append-only. Each record: `hash = sha256(prevHash + canonicalJson({seq, ts, kind, data, prevHash}))`, `sig = Ed25519(supervisor key, "wardenclaw.journal.v1\n" + hash)` (the prefix keeps a journal signature apart from anything else the supervisor key signs). Kinds: `start` (harness packs, command, journal key, trusted devices), `exec` (one per exec: pid, path, argv, cwd, class, rule, the risk hint's category and detail when one fired, decision, errno, latency, reason; for cards also the digest, envelope and signed ticket), `decide_reject`, `toctou_kill`, `root_exit`, `signal`, `stop`, `panic` (see below). About 760 bytes per exec; there is no rotation yet.

**`panic`.** A bug that panics in one of wardend's long-lived goroutines (the exec handler, the notification loop, sweep, signal forwarding, the child wait, the socket server, the push loop) still ends wardend: fail-closed, the filter stays and every exec of the tree fails until systemd restarts wardend. Before exiting (code 2) wardend writes `wardend: panic in <goroutine>: <value>` and the stack to stderr (journald), then, if the journal answers within 2 s, a record `panic` with `goroutine`, `value` and the first 4 KB of `stack`. When the journal is busy, the record is skipped and stderr says so; the stack in journald is enough to report the bug.

## Running the OpenClaw gateway under wardend (systemd)

> This is the single-user setup (a drop-in for a user unit). The recommended setup is a root system unit with the harness under its own user: see [Install, hardened](../install/#hardened-install-recommended).

The gateway is a user unit. Restarting it drops current sessions, so don't run these from a chat with the agent. Put a drop-in at `~/.config/systemd/user/openclaw-gateway.service.d/wardend.conf`. Nothing runs under it until the phone is paired: every launch of the gateway is a card, and a card nobody signs expires into `EPERM`.

**The drop-in** (`deploy/wardend.conf`):

```ini
[Service]
# The empty line resets the unit's ExecStart; the second runs the same gateway through wardend.
ExecStart=
ExecStart=%h/.local/bin/wardend run --config %h/.wardend/config.json --quiet -- @GATEWAY_CMD@
KillMode=mixed
SuccessExitStatus=0 143
```

`@GATEWAY_CMD@` is a placeholder for the command in the `ExecStart` of your existing unit (`systemctl --user cat openclaw-gateway`): absolute paths, node flags such as `--max-old-space-size` included. Don't copy the template with plain `cp`: a drop-in with the placeholder left in it keeps the gateway from starting. `KillMode=mixed` sends SIGTERM to wardend only (it forwards it) and SIGKILLs the rest of the tree after the timeout.

Run this from `daemon/` of the repository (after the single-user install script, from `~/.local/share/wardend`):

```bash
mkdir -p ~/.wardend && chmod 700 ~/.wardend
# only if you have no config yet: an existing one holds your paired devices
test -e ~/.wardend/config.json || install -m 600 deploy/config.example.json ~/.wardend/config.json
GW="$(command -v node) $(npm root -g)/openclaw/dist/index.js gateway --port 18789"   # as in your ExecStart
mkdir -p ~/.config/systemd/user/openclaw-gateway.service.d
sed "s#@GATEWAY_CMD@#$GW#" deploy/wardend.conf > ~/.config/systemd/user/openclaw-gateway.service.d/wardend.conf
grep '^ExecStart=.' ~/.config/systemd/user/openclaw-gateway.service.d/wardend.conf   # both paths after -- must be absolute
chmod 600 ~/.wardend/config.json    # a group-writable config stops wardend
wardend config-check                # the same config and policy that run will read; exit code 1 = will not start
```

Then restart the gateway:

```bash
systemctl --user daemon-reload && systemctl --user restart openclaw-gateway
systemctl --user status openclaw-gateway     # Main PID is wardend, node is its child
wardend status                               # warns while no device is trusted
```

**Pair the phone** right after the restart, from your own terminal: `wardend pair start`, "Scan QR" on the Connect tab, compare the fingerprint the terminal shows with the phone screen, answer `y` (from a script: `wardend pair list`, then `wardend pair approve <id>`). The phone must be paired and online: `wardend pair list` shows it among the trusted devices; until then every card of the gateway waits for the TTL and is denied, the gateway's own workers included. The app gets the cards through the relay.

**Watch with the app in observe mode** for a few days: it signs every card while you see what the agent asks for. Then review the stream without printing argv: `wardend replay --journal ~/.wardend/journal.jsonl --config ~/.wardend/config.json` (cards a day, peaks, categories, service cards by rule). The commands themselves:

```bash
jq -r 'select(.kind=="exec" and (.data.class=="root" or .data.class=="delegating")) | .data.argv|join(" ")' \
  ~/.wardend/journal.jsonl | sort | uniq -c | sort -rn | head -50
```

Service launches the phone should sign by rule (cron jobs, the browser, `openclaw` subcommands, MCP servers, plugins) go into `service_allow` in `~/.wardend/policy.json` (`wardend policy-defaults` as a base) with `"policy"` in the config; a launch with a risk hint never passes as service. There is no stage after that: the gate always asks, and the app's mode (observe, delegate, manual) decides how much of it you see.

**Roll back:**

```bash
rm ~/.config/systemd/user/openclaw-gateway.service.d/wardend.conf
systemctl --user daemon-reload && systemctl --user restart openclaw-gateway
```

There is no rollback without a restart: a seccomp filter can't be removed from a live tree.

## Troubleshooting

**`Function not implemented` (ENOSYS) on every exec.** The supervisor died. The filter stays on the tree, and with no listener the kernel fails every `execve` with `ENOSYS`: fail-closed by design. Restart the unit (`Restart=always` does it for you).

```console
$ wardend run --trust "$DEV:$PUB" -- sh -c 'sleep 2; /bin/true; echo "true rc=$?"' &
$ wardend approve --key-file ~/.wardend/demo-device.txt --count 1    # sign the card for sleep
$ kill -KILL $!     # only this wardend, not the one that runs your gateway
sh: 1: /bin/true: Function not implemented
true rc=126
```

**`Resource temporarily unavailable` (EAGAIN).** The ticket queue is full (`max_pending`, default 64). The exec is refused immediately rather than queued or allowed. Raise `--max-pending` or approve faster.

```console
$ wardend run --ttl 2s --max-pending 1 -- sh -c '/usr/bin/ssh -V & /usr/bin/ssh -V & /usr/bin/ssh -V & wait'
sh: 1: /usr/bin/ssh: Resource temporarily unavailable
sh: 1: /usr/bin/ssh: Resource temporarily unavailable
sh: 1: /usr/bin/ssh: Operation not permitted
```

(Two overflowed the queue, the third waited and expired.)

**`Operation not permitted` (EPERM).** A `deny_always` rule matched, a device signed deny, the ticket TTL expired, or `sudo`, `su` or `pkexec` was refused (class `refuse`: setuid can't raise privileges under `no_new_privs`). `wardend journal` shows the class, rule and reason.

**`__child: seccomp(SET_MODE_FILTER, flags=0x28): operation not permitted` and `listener fd not received`.** You are starting wardend from inside a tree that is already supervised by wardend (for example, a shell of an agent running under the gateway). A nested notification listener is refused on purpose: otherwise a process could install its own filter and answer `CONTINUE` around the outer supervisor. Run it outside the supervised tree.

**Duplicate or endless exec notifications.** wardend always sets `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (kernel 5.19+). Without it, any signal to the target (including Go's runtime `SIGURG`) cancels the notification and restarts `execve`: an early spike logged 662 duplicates of one exec in 40 s. On an older kernel the filter can't be installed; upgrade the kernel.

**`setsid: Operation not permitted` inside an approved command, or a second approval request.** `setsid`, `systemd-run`, `docker`, `tmux`, `ssh` and other delegating spawns are always a new root and need their own ticket. A process orphaned before its first exec (double fork, background job whose parent already exited) also loses the link to its root and asks again. This is fail-closed. Also note: for `docker`, `ssh`, `systemd-run` and `tmux` the actual work runs in a daemon or host outside the tree, so approving that ticket approves whatever runs there.

```console
$ wardend run --ttl 2s -- sh -c 'bash -c "setsid ls -d /tmp; echo setsid rc=\$?"'
bash: line 1: /usr/bin/setsid: Operation not permitted     # bash was approved, setsid was not
setsid rc=126
```

**`toctou mode "x": stop|poll|off`**: a typo in the config or flags; wardend exits with code 2 before starting anything. **`config …: unknown key "mode"`** (or `policy_mode`): the config still sets a mode of the daemon, which no longer exists; delete the key. [`wardend config-check`](#wardend-config-check) finds these, JSON errors (with line and column) and unknown keys before a restart.

**`config …: version N is newer than this wardend understands`**: the config was written for a newer wardend. Update wardend, or bring the config back to the format of this version.

**`wardend: panic in <goroutine>: …` in journald, wardend restarted.** A bug in wardend; the exec that was in flight failed (fail-closed). The stack follows the line, and the journal has a `panic` record when it could be written. Please report it with the stack.

## Limits

- Only `execve` and `execveat` are gated. Inside an approved root, interpreters (`python -c`, `bash -c`), `LD_PRELOAD`, file writes and network are not (see [what the gate doesn't see](#policy-modes)).
- Rules and packs recognise a tool by the name of the real file, not by its sha256; the packs are written by hand for claude-cli 2.1.283 and OpenClaw 2026.9.6.
- realpath is resolved in the supervisor's mount namespace; `unshare`, `nsenter` and `chroot` are delegating and need a ticket.
- Content swapped on the same inode between check and exec is not detected; the binary hash is not in the envelope yet.
- 32-bit compat syscalls return `ENOSYS`.
- No journal rotation<!-- feature:hardwareKey -->,<!-- /feature --><!-- feature:!hardwareKey --> and<!-- /feature --> no "same as before" approval cache<!-- feature:hardwareKey -->, no hardware second signature<!-- /feature --> yet.
