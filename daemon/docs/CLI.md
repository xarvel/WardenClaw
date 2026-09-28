# wardend CLI reference (developer copy)

> **User documentation lives in the site:** [`site/src/docs/`](../../site/src/docs/) (`cli`, `install`,
> `tamper-resistance`), published under `/docs/`. This file is the older, longer
> developer reference; it still has sections the site doesn't (`wardenctl`,
> socket protocol details). When they disagree, the site is right; move sections there rather than
> editing both.
>
> **Out of date on policy:** this copy describes only the approved-root model. The default is now
> the `tripwire` policy mode (`policy_mode`, `--policy-mode tripwire|root`), with harness packs,
> `wardend replay` and `max_pending` 64: see "Policy modes" in `site/src/docs/cli.en.md` and section 2
> of [README](../README.md). The examples below behave as described with `--policy-mode root`.

`wardend` starts a process (in production: the OpenClaw gateway, or any agent harness) under a seccomp filter and decides the fate of every `execve`/`execveat` in the whole process tree. The kernel stops the call, the supervisor reads argv, cwd, the real binary and the parent chain from the stopped process, and answers `CONTINUE` or an error. Root commands wait for an **Ed25519 signature from a WardenClaw device** over a canonical envelope; children of an approved root pass on their own while its subtree is alive.

wardend doesn't depend on OpenClaw: the phone pairs with it directly (`wardend pair`, a QR code in the terminal) and reaches it through a relay ([Relay transport](#relay-transport)). The OpenClaw plugin `wardenclaw-gate` is an optional adapter.

Every command on this page was run on a Raspberry Pi 5 (arm64, Linux 6.18, Go 1.26). Outputs are real, with host names and keys shortened.

> Status: prototype (v0.3). Flags and formats can still change.

## Requirements

- Linux **5.19 or newer** (needs `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`), arm64 or x86_64.
- **No root.** wardend runs as your user: `no_new_privs` plus a seccomp filter with a notification listener. No cgo, no libseccomp.
- Go 1.26 to build from source.

## Install

```shell
curl -fsSL https://wardenclaw.dev/install.sh | sudo sh
```

By default this is the **hardened install in observe mode**: wardend as a root system service, the agent harness under its own unprivileged user. The script checks the release signature, asks for the agent user and the harness command, installs the files and prints the next steps (pair the phone, a week in observe, then `ticket`, then `redteam/hardened-check.sh`). What each step does: [README, "Installation"](../README.md) and [release.md](release.md). `--single-user` (no sudo: `| sh -s -- --single-user`) installs the trial variant described below in [Running the OpenClaw gateway under wardend](#running-the-openclaw-gateway-under-wardend-systemd).

<details>
<summary>Build from source</summary>

```bash
git clone https://github.com/xarvel/WardenClaw && cd WardenClaw/daemon
go build -o wardend .
install -D -m 0755 wardend ~/.local/bin/wardend                 # single-user trial
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
  wardend wrap [--mode ticket|deny-list|observe] [--policy rules.json] [--ttl 120s] [--state-dir d]
               [--relay-url wss://…] [--qr ansi|utf8|invert|none] [--quiet] -- <cmd...>
                                          try it: gate <cmd...> with the defaults, pair the phone on the first run
  wardend run [--config f] [--mode observe|deny-list|ticket] [--policy-mode tripwire|root] [--state-dir d]
              [--socket s] [--journal j] [--policy rules.json] [--ttl 120s] [--max-pending 64]
              [--trust <deviceId>[:<pubkey>]]...
              [--gateway-db off|auto|path] [--toctou-roots stop|poll|off] [--toctou-service off|poll|stop]
              [--relay-url wss://relay.wardenclaw.dev|off]
              [--linger 2s] [--require-hardened] [--child-user name|uid[:gid]] [--quiet] -- <cmd...>
  wardend config-check [--config f] [--state-dir d] [--policy rules.json] [-- <cmd...>]
                                          check the config and policy as run reads them, without starting anything
  wardend version
  wardend keygen
  wardend approve --key-file <file|-> [--socket s] [--match regex] [--deny] [--count N] [--timeout 30s]
  wardend status [--socket s]
  wardend journal [--socket s] [-n 20]
  wardend verify-journal [--pubkey b64url] [--expect-head seq:hash] <journal.jsonl>
  wardend policy-defaults [--pack name]   built-in rules (a base for your own --policy) or a harness pack
  wardend replay --journal <file> [--config f] [--policy-mode tripwire|root] [--from t] [--until t] [--json]
                                          run the journal through the classifier: cards per day, peaks, categories
  wardend hw-register [--config f] [--name n] [--rp-id wardenclaw] [--require-uv] [--dry-run]
              (<wchw1:…> | --attestation <b64url|@file> [--client-data <b64url|@file>]
               | --cose-key <b64url> --credential-id <b64url>)
  wardend hw-keys [--config f]            registered hardware keys and their signCount
  wardend pair start [--socket s] [--ttl 5m] [--qr ansi|utf8|invert|none] [--no-wait]
  wardend pair list [--socket s]           pending requests (key fingerprint) and trusted devices
  wardend pair approve <id> | reject <id>  approve/reject a request (writes trusted_devices to the config)
  wardend pair revoke <deviceId|prefix>    stop trusting a device

wardend <command> --help (or wardend help <command>) prints the flags of a command and does nothing else.
```

`hw-register` and `hw-keys` are listed only by a build with `-tags hwkey`; the release build hides them (see [`wardend hw-register`](#wardend-hw-register)).

Flags accept one or two dashes (`-mode` and `--mode` are the same). Every command and subcommand of `wardend` and `wardenctl` prints its usage and flags with `--help`, `-h` or `help` (`wardend pair approve --help`, `wardend help run`) to stdout with exit code 0 and does nothing else: no key, no files, no socket or network connection. `wardenctl` answers it before the safety guard, so it works anywhere. A command-line error prints the message and the usage to stderr with exit code 2.

## Commands

### `wardend wrap`

The one-command way in. It runs `<cmd...>` under the gate with defaults and asks your phone before the risky commands. No flags are needed.

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

- **Defaults.** Mode `ticket`, the built-in policy in policy mode `tripwire` (a card only when a rule fires, everything else runs and is journaled), state in `~/.wardend`, the default relay, `gateway_db` off. `~/.wardend/config.json` is read if it exists, and flags override it. Underneath it is `wardend run`: the same supervisor, the same journal. If `~/.wardend/config.json` sets another mode, wrap follows it and says so on stderr (`wardend: mode observe (from …): nothing is asked on the phone`). The example config sets no mode, so after the single-user install wrap asks without a flag.
- **Pairing on the first run.** With no trusted device, wrap prints the QR code and the link of [`wardend pair start`](#wardend-pair), waits for the phone, shows the device's name and key fingerprint and asks `Approve this device? [y/N]`. Only after `y` does the command start. After `n`, no answer, or an expired code, wrap exits with code 1 and the command is never started. The question is asked on the controlling terminal (`/dev/tty`), not on stdin, so the command gets its stdin untouched. Without a terminal (a script, a pipe) wrap does not wait: it exits and says to pair first.
- **While the command runs** it owns the terminal. wardend writes to stderr only what you must see: a card that has waited more than 5 seconds for you, a denial, an expiry.
- **At the exit** a one-line summary goes to stderr (`--quiet` drops it): commands seen, asked, allowed, denied, expired, and the journal path. PATH lookups of a shell and its retries of a denied command are not counted as commands. The exit code is the command's.
- **Fail closed.** If the relay cannot be reached within 10 seconds, wrap says so and exits before starting the command: no card could reach the phone. `--relay-url off` is not a way to get approvals: without a trusted device wrap refuses to start, and with one the decisions can only come over the socket (`wardend approve`). `--mode observe` and `--mode deny-list` ask nobody and need neither a relay nor a device.

| Flag | Default | Meaning |
|---|---|---|
| `--mode` | `ticket` | `ticket`, `deny-list` or `observe` ([Modes](#modes)). |
| `--policy f` | built-in rules | Rules JSON ([Policy](#policy)). |
| `--ttl d` | `120s` | How long a command waits for the decision. |
| `--state-dir d` | `~/.wardend` | Key, journal, socket, config. |
| `--relay-url u` | `wss://relay.wardenclaw.dev` | The relay the app reaches wardend through. |
| `--qr style` | `ansi` | QR code of the pairing step: `ansi`, `utf8`, `invert`, `none`. |
| `--quiet` | off | No summary at the exit. |

In this mode wardend runs as the same user as the command. The command cannot get past the exec gate, but it can read wardend's files and edit its config between runs. The system install (`curl -fsSL https://wardenclaw.dev/install.sh | sudo sh`) is the one with real separation: wardend as a root service, the agent as its own user.

### `wardend run`

Starts `<cmd...>` under the supervisor. Everything after `--` is the command. This is what the service runs (the systemd unit of the install) and what [`wardend wrap`](#wardend-wrap) runs underneath: every setting is a flag or a config key, nothing is asked on a terminal, and it starts without a paired device.

```
wardend run [flags] -- <cmd...>
```

| Flag | Default | Meaning |
|---|---|---|
| `--config f` | `<state-dir>/config.json` if it exists | JSON config (see [Config](#config)). Flags override config values. `wardend pair approve` writes new devices into this file (created if missing). |
| `--mode m` | `observe` | `observe`, `deny-list` or `ticket` (see [Modes](#modes)). |
| `--state-dir d` | `~/.wardend` | State directory, created with mode 0700. |
| `--socket s` | `<state-dir>/wardend.sock` | Unix socket for JSON-RPC. |
| `--journal j` | `<state-dir>/journal.jsonl` | Append-only journal. |
| `--policy f` | built-in rules | Policy JSON (see [Policy](#policy)). |
| `--ttl d` | `120s` | How long a root waits for a ticket before `EPERM`. |
| `--max-pending n` | `16` | Queue limit for roots waiting for a ticket; overflow gets `EAGAIN`. |
| `--trust id[:pubkey]` | none | Trusted device, repeatable. Appended to `trusted_devices` from the config. |
| `--gateway-db v` | `off` | Legacy OpenClaw pairing: also look up device public keys in `auto` (`~/.openclaw/state/openclaw.sqlite`, read-only) or a path. Not needed with `wardend pair`. |
| `--relay-url u` | `wss://relay.wardenclaw.dev` | The relay the app reaches wardend through (`relay_url`); `off` runs wardend without it. |
| `--toctou-roots m` | `stop` | Post-exec check for approved roots: `stop`, `poll` or `off`. |
| `--toctou-service m` | `off` | Same for allow-listed service execs. |
| `--linger d` | `2s` | After the main child exits, keep serving the rest of the tree this long. |
| `--quiet` | off | No start and summary lines on stderr. |

The exit code is the child's exit code; death by signal N is `128+N` (SIGTERM gives 143). SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGUSR1 and SIGUSR2 are forwarded to the child.

**Observe** a command: everything runs, the journal records what each exec would need in `ticket` mode.

```console
$ wardend run --mode observe --gateway-db off -- sh -c 'ls -d /tmp; git --version'
wardend: mode=observe pid=16306 child=16313 socket=/home/me/.wardend/wardend.sock journal=/home/me/.wardend/journal.jsonl
/tmp
git version 2.47.3
wardend: mode=observe execs=3 denied=0 latency p50=513us p95=725us max=725us exit=0
```

**Deny-list** only: the built-in `deny_always` rules apply, everything else runs.

```console
$ wardend run --mode deny-list --gateway-db off --quiet -- sh -c 'dd if=/dev/zero of=/dev/null count=1; echo "dd rc=$?"; echo ok'
sh: 1: dd: Operation not permitted
dd rc=126
ok
```

(`dd of=/dev/…` is one of the `deny_always` rules. The example writes to `/dev/null`, so it stays harmless even where the rule doesn't apply.)

**Ticket** mode: each root waits for a signed decision. With the phone app: pair it once ([`wardend pair`](#wardend-pair)), and cards show up on the phone. Without a phone, a test key in a terminal works the same way. In one terminal:

```bash
umask 077
mkdir -p ~/.wardend
wardend keygen > ~/.wardend/demo-device.txt   # test device, outside the command's directory
DEV=$(sed -n 's/^deviceId=//p' ~/.wardend/demo-device.txt)
PUB=$(sed -n 's/^pubkey=//p' ~/.wardend/demo-device.txt)
cd /tmp
wardend run --mode ticket --gateway-db off --trust "$DEV:$PUB" --ttl 30s --quiet \
  -- sh -c 'bash -c "echo approved-root; ls -d /etc"'
```

`bash` now waits in the kernel. In another terminal, outside that command, sign it with the test key:

```console
$ wardend approve --key-file ~/.wardend/demo-device.txt --count 1 --timeout 10s
allow wd-b37603bafd136ae8fe9a455b60e06d36 argv=[bash -c echo approved-root; ls -d /etc] -> map[decision:allow id:wd-b37603bafd136ae8fe9a455b60e06d36 ok:true]
```

and the first terminal prints `approved-root` and `/etc` (`ls` inherits the approval). Without a ticket within the TTL, or with a signed deny:

```console
sh: 1: bash: Operation not permitted
bash rc=126
```

### `wardend config-check`

Checks the config and the policy the way `wardend run` reads them at start, and starts nothing: no key, no journal, no socket, no state directory. Run it after every edit and before a restart, since a config wardend can't read stops wardend, and the agent with it:

```sh
sudo wardend config-check --config /etc/wardend/config.json && sudo systemctl restart wardend
```

Flags are the path flags of `run`, with the same defaults: `--config` (else `<state-dir>/config.json` if it exists), `--state-dir`, `--policy` (else `policy` from the config, else the built-in rules). A command after `--` is optional and only feeds harness pack detection, as in `run`. It prints every error and warning and exits with 0 if `wardend run` would start with these files, 1 if not (2 for a command-line error). It catches:

- JSON errors in the config or the policy, with line and column (`config /etc/wardend/config.json: line 4, column 3: invalid character '"' after object key:value pair`);
- unknown keys in the config and the policy, nested ones too, as warnings with a hint (`unknown key "moed" is ignored (did you mean "mode"?)`): `run` ignores them, so a typo in a key leaves the default value;
- values `run` rejects: `mode`, `policy_mode`, `toctou_*`, a `trusted_devices` entry whose key doesn't hash to its id, policy rules that don't compile, the install checks of selfcheck;
- `hardware_keys` (or `require_hardware` in the policy) in a build without the `hwkey` tag: the error `run` stops with, explained, with a pointer to [docs/hwkey.md](hwkey.md);
- `mode` `ticket` without `trusted_devices` (a warning: every root is denied until a phone is paired);
- a config `version` newer than this wardend understands (an error, see [Config](#config)).

```console
$ wardend config-check --config ./config.json
warning: config ./config.json: unknown key "mdoe" is ignored (did you mean "mode"?)
mode observe, policy_mode tripwire, policy built-in, trusted devices 0
config-check: ok
```

### `wardend pair`

Pairs the WardenClaw app with a running supervisor, over its socket. The phone never needs OpenClaw.

1. `wardend pair start` asks the supervisor for a one-time code (5 minutes, `pair_code_ttl`), opens a pairing window on the relay for the lifetime of the code (at most 15 minutes) and prints a QR code with the link `wardenclaw://pair?code=…&enc=<supervisor X25519 key>&host=…&key=<supervisor public key>&relay=<relay_url>/v1/ws&sid=<supervisor id>&v=1`, then the link itself for manual input. If the relay is unreachable or refuses, the command fails and the code is withdrawn rather than printing a QR that leads nowhere.
2. The app scans it, pins both supervisor keys and sends its own public key together with the code through the relay, encrypted for the supervisor. The code burns on the first valid request.
3. On the server, `pair start` waits for the request, shows the device's name and key fingerprint (first 16 hex digits of the device id; the app shows the same one) and asks `Approve this device? [y/N]`. Compare, then answer `y`; anything else rejects the request. Without a terminal (stdin is a pipe or a script) it prints the request id instead of asking, and with `--no-wait` it returns right after the code: then `wardend pair list` shows the request and `wardend pair approve <id>` approves it. Either way the device and its public key go into `trusted_devices` of the config, and the running supervisor trusts it at once, without a restart.
4. The app learns the outcome (`pending`, `approved`, `rejected`, `refused`) from the supervisor through the relay. From then on it only accepts messages that open with the keys from the QR code.

The pairing exchange is specified in protocol/README.md, section 6. `wardenctl pair` takes the same link.

```console
$ wardend pair start                  # one step, on a terminal
(the QR code, the link, the code)
Waiting for the request from the phone (Ctrl+C to stop waiting; then wardend pair list)…

Request p-2gxn89: "Pixel 9", fingerprint b14c d1c6 b439 44df, from relay
Compare the fingerprint with the phone screen.
Approve this device? [y/N] y
Approved: "Pixel 9", fingerprint b14c d1c6 b439 44df, deviceId b14cd1c6b43944df…63aed9
Written to /home/me/.wardend/config.json (trusted_devices); the supervisor trusts the device right away.
```

For scripts, or to approve later:

```console
$ wardend pair start --no-wait        # the QR code comes first (black on white via ANSI colors)

Scan the QR in the WardenClaw app (Connect tab) or paste the link:
  wardenclaw://pair?code=3M73AW54&host=pi&key=3J0P1SWp…Xzc8&url=https%3A%2F%2Fwardend.example.com&v=1

Code:       3M73-AW54 (one-time, until 02:03:02)
Endpoint:   https://wardend.example.com
Supervisor: pi, key fingerprint b5d6 5f91 c874 b635
Then: wardend pair list → wardend pair approve <id>

$ wardend pair list
Pairing requests: 1 pending, active codes: 0
  p-2gxn89  pending  "Pixel 9"  fingerprint b14c d1c6 b439 44df  key ed25519  from 127.0.0.1:38768, expires in 10m0s
  Compare the fingerprint with the phone screen: wardend pair approve <id> (or reject <id>)
Trusted devices (/home/me/.wardend/config.json): 0

$ wardend pair approve p-2gxn89
Approved: "Pixel 9", fingerprint b14c d1c6 b439 44df, deviceId b14cd1c6b43944df…63aed9
Written to /home/me/.wardend/config.json (trusted_devices); the supervisor trusts the device right away.

$ wardend pair revoke b14cd1c6
Device b14cd1c6b43944df…63aed9 ("Pixel 9") is no longer trusted; removed from /home/me/.wardend/config.json.
```

| Subcommand / flag | Meaning |
|---|---|
| `start --ttl d` | Code lifetime (default `pair_code_ttl`, max 1 h). |
| `start --qr m` | `ansi` (default: black modules on a white background via ANSI colors, readable on any terminal theme), `utf8` (no colors, dark modules as blocks: for a light background or a file), `invert` (no colors, for a dark background), `none`. |
| `start --no-wait` | Don't wait. By default `start` waits for the phone's request and prints the `approve` command with the fingerprint. |
| `list` | Pending and recently decided requests (fingerprint, name, source), trusted devices, and a note when wardend is not connected to the relay. |
| `approve <id>`, `reject <id>` | Decide a pending request. A request expires after 10 minutes. |
| `revoke <id or prefix>` | Remove a device from `trusted_devices` and from the running supervisor (a prefix must have at least 8 hex digits and be unique). Only wardend: the gateway plugin keeps its own list (see below). |

**`revoke` and the gateway plugin.** `wardend pair revoke` changes wardend only. The OpenClaw plugin `wardenclaw-gate`, if you run it, trusts devices from its own `trustedDeviceIds` in `~/.openclaw/openclaw.json`, and a device revoked here stays there: it still sees the plugin's cards (the plugin's tool calls and the wardend exec records it relays) and can still decide the plugin's own tool calls; wardend refuses its decisions on exec records. Remove it from the plugin too: delete its id from `plugins.entries.wardenclaw-gate.config.trustedDeviceIds` (and from `devices`, if you listed it there), save the file, and the gateway's hybrid reload applies it; `[wardenclaw-gate] start: … trusted=[…]` in the gateway log shows the new list. To cut the phone off the gateway entirely, also run `openclaw devices remove <deviceId>`. Details: [plugin/README.md](../../plugin/README.md), "Revoking a device".

Flags may come before or after the id. `start`, `approve`, `reject` and `revoke` are refused when the caller runs under this wardend's seccomp filter (it has more seccomp filters than the supervisor, or it descends from the supervised child): the agent can't pair a device for itself. Run them from your own terminal on the server.

```console
$ wardend pair approve p-x          # from a shell inside the supervised gateway
rpc pair.approve: refused: called from under the wardend filter (the agent can't manage pairing itself); run the command in your own terminal on the server
```

Limits: 10 wrong codes in a row kill all active codes; at most 8 pending requests; a device name is up to 64 characters without control characters.

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

Supervisor state over the socket: mode, queue, tracker, trusted devices, journal key and metrics.

```console
$ wardend status
{
  "host": "pi",
  "journal": "/home/me/.wardend/journal.jsonl",
  "journalHead": { "hash": "3454679b…", "seq": 49 },
  "journalKey": "8bnwSh-K…811T8A",
  "maxPending": 16,
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
  "mode": "ticket",
  "now": 1790454056134,
  "ok": true,
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

`protocol` is the version of the WardenClaw protocol this wardend speaks; the status sent to devices carries it too, and clients refuse a wardend that speaks another one (protocol/README.md, section 10). `warnings` is a list of codes, empty when all is well: `no_trusted_devices` means the mode is `ticket` and no device is trusted, so every root command waits for a ticket nobody can sign and is denied after the TTL (pair a phone: `wardend pair start`; the warning goes away without a restart). `wardend status` prints each warning in words to stderr after the JSON, so stdout stays plain JSON:

```console
wardend: warning: ticket mode and no trusted devices: pending roots wait for a ticket nobody can sign and are denied after the TTL. Pair a phone: wardend pair start
```

The object also has `relay` (`{url, enabled, connected?, encKey?, encFingerprint?, devices?, endpoint?, error?}`) and `pairing` (`{activeCodes, pendingRequests}`). With the second factor it also has `hardwareKeys` (`[{id, name, alg, rpId}]`), `requireHardwareRules` (the number of rules) and `requireHardware` (`[{id, note?, class?, category?, minScore?}]`: the rules in policy order, without their argv and path matchers, so the app can say what the key is required for). An exec record in the journal gets `hardware: {required, rule, escalated?, minScore?, verified?: {credentialId, signCount, uv}}`. Not in the first release: these fields exist only in a build with `-tags hwkey` ([docs/hwkey.md](hwkey.md)); a release build has no `hardwareKeys`, `requireHardwareRules` or `requireHardware`, neither here (`wardend status`, the status sent to devices) nor in the journal's `start` record.

### `wardend journal`

The last N journal records (JSON lines) over the socket; `-n` defaults to 20, and values outside 1 to 1000 fall back to 20.

```console
$ wardend journal -n 1
{"data":{"argv":["sleep","1.5"],"callerExe":"/usr/bin/dash","chain":[…],"class":"root","cwd":"/home/me","decision":"allow","exe":"/usr/bin/sleep","latencyUs":445,"reason":"observe: would require ticket","syscall":"execve",…},"hash":"3454679b…","kind":"exec","prevHash":"36557f10…","seq":48,"sig":"feGmW5ib…","ts":1790454062696}
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

A journal whose **last** lines were deleted still verifies: every remaining record is intact and the chain has no gap. To catch a cut tail, pin the head. `wardend status` and the status sent to devices carry `journalHead`, the `seq` and `hash` of the last record, and `verify-journal` prints the file's head as `head`; pass the pinned one as `--expect-head seq:hash` and the check fails with `head_mismatch` when the file ends anywhere else:

```console
$ wardend verify-journal --pubkey 8bnwSh-K…811T8A --expect-head 49:3454679b… ~/.wardend/journal.jsonl
{"ok":true,"entries":49,"key":"8bnwSh-K…811T8A","head":{"seq":49,"hash":"3454679b…"}}

$ wardend verify-journal --pubkey 8bnwSh-K…811T8A --expect-head 49:3454679b… cut-tail.jsonl   # the last two lines deleted
{"ok":false,"entries":47,"error":"head_mismatch","badSeq":47,"key":"8bnwSh-K…811T8A","head":{"seq":47,"hash":"9c01e2d4…"}}
```

Every number in a record must be an integer within the JS safe range (plus or minus 2^53 minus 1): wardend refuses to append anything else instead of hashing it rounded, and `verify-journal` reports such a line as `bad_number`.

### `wardend policy-defaults`

Prints the built-in rules as JSON: the starting point for your own `--policy` file.

```bash
# only if you have no policy file yet: never overwrite the rules you have added
test -e ~/.wardend/policy.json || wardend policy-defaults > ~/.wardend/policy.json
```

### `wardend hw-register`

Registers a hardware key (YubiKey, FIDO2) as a trusted second factor: adds or replaces, by credential id, an entry in `hardware_keys` of the config. The protocol is in [HARDWARE.md](../../protocol/HARDWARE.md).

> Not in the first release: built only with `-tags hwkey`, see [docs/hwkey.md](hwkey.md). A release build (`scripts/release.sh`, CI) hides `hw-register` and `hw-keys` from the help and answers them on stderr with "second factor (FIDO2 hardware keys, YubiKey) is not included in this release; build with the tag: go build -tags hwkey (docs/hwkey.md)", exit code 2.

```
wardend hw-register [--config ~/.wardend/config.json] [--name n] [--rp-id wardenclaw] [--require-uv] [--dry-run]
                    (<wchw1:…> | --attestation <b64url|@file> [--client-data <b64url|@file>]
                     | --cose-key <b64url> --credential-id <b64url>)
```

| Input | Meaning |
|---|---|
| `wchw1:…` | the blob the app shows after "Tap your YubiKey" (attestationObject + clientDataJSON + rpId + name) |
| `--attestation`, `--client-data` | raw WebAuthn/CTAP2 registration output, base64url or `@file` |
| `--cose-key`, `--credential-id` | a bare public key (COSE_Key, EdDSA or ES256) without attestation |
| `--require-uv` | every assertion must have the UV flag set (the key's FIDO2 PIN) |
| `--dry-run` | parse and print the entry, leave the config alone |

The attestation is checked (rpIdHash, UP/AT flags, COSE key EdDSA/ES256, clientDataJSON `webauthn.create` with origin `wardenclaw:app`, the `packed` signature by x5c or self, and AAGUID). The chain to the Yubico root is not. Other config fields are kept: the file is rewritten atomically with its permissions, top-level keys sorted. wardend reads the config at start, so **restart it** afterwards.

```console
$ wardend hw-register --config /tmp/hw/config.json "$(cat blob.txt)"
added hardware key E4cRA0BaXWcvxV28onR6iy-a1Fuil-2ij370G3BUQ9Z5iOpojhbwkyRhJO97GHoO (EdDSA, YubiKey 5 NFC) in /tmp/hw/config.json
{
  "id": "E4cRA0BaXWcvxV28onR6iy-a1Fuil-2ij370G3BUQ9Z5iOpojhbwkyRhJO97GHoO",
  "name": "YubiKey 5 NFC",
  "rp_id": "wardenclaw",
  "alg": "EdDSA",
  "public_key": "pAEBAycgBiFYINvpBWacN52OZ-5Za139h6inlDPag6wQTE0Nec5EUtqm",
  "aaguid": "ee882879721c491397753dfcce97072a",
  "attestation": "packed-x5c (chain not verified): CN=Soft FIDO EE Serial 1,O=hwkeytest",
  "added_at": "2026-09-26T21:21:17Z"
}
restart wardend to apply

$ wardend hw-register --config /tmp/hw/config.json 'wchw1:AAAA'
hw-register: blob: invalid character '\x00' looking for beginning of value      # exit 1
```

(The blob above came from the software authenticator used in the tests, hence `hwkeytest` in the certificate. A real YubiKey 5 shows `CN=Yubico U2F EE Serial …`.)

### `wardend hw-keys`

Lists the registered keys and their last seen `signCount` (from `hardware_counters`).

> Not in the first release: like `hw-register`, built only with `-tags hwkey` ([docs/hwkey.md](hwkey.md)); a release build answers with the same message and exit code 2.

```console
$ wardend hw-keys --config /tmp/hw/config.json
1 hardware key(s) in /tmp/hw/config.json
  E4cRA0BaXWcvxV28onR6iy-a1Fuil-2ij370G3BUQ9Z5iOpojhbwkyRhJO97GHoO  EdDSA rp=wardenclaw name="YubiKey 5 NFC" uv=false signCount=0 added=2026-09-26T21:21:17Z
    attestation: packed-x5c (chain not verified): CN=Soft FIDO EE Serial 1,O=hwkeytest
```

### `wardend rootexec`

```
wardend rootexec [--socket s] [--cwd d] [--quiet] -- <cmd...>
```

From under the gate (the agent, in the hardened install): asks wardend to run `<cmd...>` as
wardend's own user, root, after a card on the phone ([docs/rootexec.md](rootexec.md)). The
command runs with this process's stdin/stdout/stderr and working directory, a clean environment,
and the file resolved and pinned by wardend before the card. The socket is
`$WARDEND_ROOTEXEC_SOCKET`, else `/run/wardend/rootexec.sock`; the agent cannot read the config,
so the path is not taken from it.

Exit code: the command's own; `124` the card expired or `root_exec.timeout` hit; `125` refused
before a card (no `root_exec` rule, `mode` not `ticket`, the built-in guard, a file wardend
would not run as root, no socket); `126` denied on the phone. Progress goes to stderr:
`card wd-… is on the phone, waiting for the decision (expires in 118s)`, `approved, running
(pid 4242)`; `--quiet` silences it, the reason of a refusal is always printed.

```console
$ wardend rootexec -- docker restart searxng
wardend rootexec: card wd-02346720465858b52afbe3c90f349c67 is on the phone, waiting for the decision (expires in 2m0s)
wardend rootexec: approved, running (pid 4242)
searxng
$ wardend rootexec -- gpasswd -a agent docker
wardend rootexec: refused: gpasswd: accounts, groups and sudoers are not changed through rootexec
$ echo $?
125
```

Signals to `wardend rootexec` (Ctrl-C, SIGTERM, SIGHUP, SIGWINCH …) go to the command's process
group through wardend; when the client disappears the command gets SIGTERM and, 5 s later,
SIGKILL. Only with `"root_exec": {"enabled": true}` in the config. In `observe` and `deny-list`
a request the policy allows runs without a card and the journal says what a ticket would have
asked; a rule with `"ticket": false` runs without a card in `ticket` mode too.

**`sudo` and `docker` for the agent.** With root_exec the installer puts symlinks named `sudo`
and `docker` to the wardend binary into `/usr/local/libexec/wardend/bin`, first on the harness
PATH: the agent's `sudo docker restart x` and `docker ps` are `wardend rootexec -- …` (same policy,
same card; the shim's own exec is a service launch `rootexec-client`, not a card). Accepted: `-n -H -k -K -S -A -p -u root --`;
refused with a message (125): `-i -s -E -g -D -e`, `-u <other>`, `VAR=value`; `-l`, `--help`,
`-V` answer without a request. Outside the gate the shim execs the real `/usr/bin/sudo`
(`WARDEND_SUDO_REAL` overrides the path).

## Modes

| Mode | Behaviour |
|---|---|
| `observe` | Everything is allowed. The journal records the class each exec would get and roots are "approved" automatically, so you can see the real ticket volume. |
| `deny-list` | Only `deny_always` rules apply (`EPERM`); everything else runs. |
| `ticket` | Production. Roots and delegating spawns wait for a signed ticket; `deny_always` still wins, even inside an approved tree. |

## Config

`~/.wardend/config.json` is read by default when it exists; all fields are optional, flags override them, and `--trust` appends to `trusted_devices`. This is `deploy/config.example.json` (it sets no `mode`: `wardend run` then observes, `wardend wrap` asks):

```json
{
  "version": 1,
  "ticket_ttl": "120s",
  "ts_window": "60s",
  "max_pending": 16,
  "linger": "2s",
  "toctou_roots": "stop",
  "toctou_service": "off",
  "pair_code_ttl": "5m",
  "gateway_db": "off",
  "trusted_devices": []
}
```

`trusted_devices` fills itself through `wardend pair approve`.

**Unknown keys.** A key wardend doesn't know, in the config or in the policy file, is ignored with a warning in stderr at start (journald under systemd) and in [`wardend config-check`](#wardend-config-check), not an error: a config written for a newer wardend with a new optional field still starts an older one. A typo in a key therefore leaves the default value (`"moed": "ticket"` runs in `observe`); the warning names the key and the nearest known one. A change that an older wardend would read wrong raises `version` instead.

| Field | Default | Meaning |
|---|---|---|
| `version` | `1` | Version of the config format. No key means 1. A config with a newer version than this wardend understands stops it at start (exit 2, "update wardend"): it may mean something this build would read wrong. |
| `mode` | `observe` | `observe`, `deny-list`, `ticket`. |
| `state_dir` | `~/.wardend` | State directory. |
| `socket`, `journal` | inside `state_dir` | Socket and journal paths. |
| `key_file` | `<state_dir>/supervisor.key` | Supervisor key that signs the journal. |
| `policy` | built-in | Path to a policy JSON. |
| `ticket_ttl` | `120s` | Ticket wait (Go duration string). |
| `ts_window` | `60s` | Allowed clock skew of a ticket's `ts`. |
| `max_pending` | `16` | Queue limit. |
| `linger` | `2s` | Serve the rest of the tree after the child exits. |
| `trusted_devices` | `[]` | `{id, pubkey?, alg?, name?, added_at?}`. `pubkey` is base64url or hex. `alg`: absent or `ed25519`, or `es256` (P-256 SEC1 key). Written by `wardend pair approve`. |
| `pair_code_ttl` | `5m` | Lifetime of a pairing code. |
| `relay_url` | `wss://relay.wardenclaw.dev` | The relay the app reaches wardend through (protocol/README.md, section 5): `wss://host[:port]`, the default or a self-hosted one. wardend keeps an outbound WebSocket to it and shows the connection under `relay` in `wardend status`. `off`: no relay, for a wardend that no device approves for (observe mode, a local test key). Plain `ws://` is accepted for a loopback relay only. |
| `relay_key_file` | `<state_dir>/relay_enc.key` | X25519 encryption key of the supervisor for the relay transport, created on the first start unless `relay_url` is `off`, mode 0600. |
| `gateway_db` | `off` | Legacy: `auto` or a path to the OpenClaw state DB to look up keys of devices paired with the gateway. |
| `toctou_roots`, `toctou_service` | `stop`, `off` | `stop`, `poll` or `off`. |
| `host` | hostname | Host name written into envelopes. |
| `hardware_keys` | `[]` | Trusted hardware keys for the second factor, written by `wardend hw-register`: `{id, name, rp_id, alg, public_key, aaguid, require_uv, attestation, added_at}`. An invalid entry stops wardend at start (exit 2). Not in the first release: only with `-tags hwkey` ([docs/hwkey.md](hwkey.md)); a release build refuses to start (exit 2) when the list is not empty (see [Policy](#policy), `require_hardware`). |
| `hardware_counters` | `<state_dir>/hw_counters.json` | Last accepted `signCount` per key (replay protection). A corrupt file stops wardend at start. |
| `root_exec` | off | `{enabled, socket, group, timeout}`: the [`wardend rootexec`](#wardend-rootexec) socket. `socket` defaults to `/run/wardend/rootexec.sock` as root (the unit's `RuntimeDirectory`), else `<state_dir>/rootexec.sock`; `group` to the primary group of `child_user`; `timeout` to `10m`. What may be asked for is the policy's `root_exec` list ([docs/rootexec.md](rootexec.md)). |

**Keys.** Trust comes only from this config. A `pubkey` in the config is pinned (`wardend pair approve` always writes one). Only with `gateway_db` set (`auto` or a path) and an entry without `pubkey`, wardend reads the key of that device id from the OpenClaw gateway's paired-devices table (read-only, cached 30 s). Any key, from the config or the gateway DB, is used only if its SHA-256 equals the device id, the same rule as pairing: the agent's uid can write the gateway DB, so a foreign key under a trusted id is ignored (`gateway_pubkey_mismatch` when there is no other key), and a config entry whose `pubkey` does not hash to its `id` stops wardend at start. wardend warns at start whenever `gateway_db` is on. If both keys exist and differ, decisions are rejected with `pubkey_conflict` instead of silently picking one. Before this release `gateway_db` defaulted to `auto`: a config that relied on it needs `"gateway_db": "auto"` or a re-pairing with `wardend pair`.

## Policy

First match wins:

| Class | What | Decision |
|---|---|---|
| `supervised_cmd` | the first exec: your own command | allow, not a root |
| `missing` | the target doesn't exist (PATH search) | `ENOENT` immediately |
| `unreadable` | the caller's memory can't be read, the path is unknown (Yama `ptrace_scope=2` without root) | `EPERM`, the reason in the journal |
| `deny_always` | regex on argv/exe: `rm -r` on `/`, `$HOME` or system dirs, `--no-preserve-root`, `dd of=/dev/…`, `mkfs*`, `wipefs`, `fdisk`, `parted`, `shred /dev/…`, `chmod/chown -R /…` | `EPERM`, even inside an approved tree |
| `service` | allow-list of harness housekeeping by exe + argv pattern + caller | allow, logged, no inheritance |
| `delegating` | `setsid`, `systemd-run`, `systemctl`, `docker`, `podman`, `kubectl`, `bwrap`, `tmux`, `screen`, `at`, `crontab`, `sudo`, `su`, `nsenter`, `unshare`, `chroot`, `ssh`, `scp`… | always a new root, needs a ticket |
| `inherit` | the caller is in the live subtree of an approved root | allow |
| `root` | everything else | needs a ticket |

A policy file has three lists, `deny_always`, `service_allow` and `delegating`, of rules, plus two optional ones: `require_hardware` (see below) and `root_exec`, what [`wardend rootexec`](#wardend-rootexec) may ask to run as root (first match; an empty or absent list refuses every request without a card; `argv0` matches `basename(argv[0])` strictly, the real file is the pinned `exe` on the card; [docs/rootexec.md](rootexec.md)). All fields set in a rule must match (AND). Regexes are Go RE2 and are **not anchored** unless you write `^…$`.

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
| `ticket` | `root_exec` only: `false` runs the matching request at once, as root, journaled, no card (the built-in `docker-read` and `systemctl-read`); absent or `true`: a card |

Example: add a deny rule on top of the defaults and try it (in a separate file, so your real policy stays as it is).

```bash
wardend policy-defaults > no-curl.json
# add to "deny_always": {"id": "no-curl", "argv0": "^curl$", "note": "no downloads"}
wardend run --mode deny-list --policy no-curl.json -- sh -c 'curl --version; echo "curl rc=$?"'
```
```console
sh: 1: curl: Operation not permitted
curl rc=126
```

A rule without `id` is refused at start: `wardend: policy rule "": id required` (exit 2).

**`require_hardware`** isn't a class. It sits on top of the ticket: a root that matches one of these rules is approved only by a ticket with a valid second signature from a registered hardware key ([HARDWARE.md](../../protocol/HARDWARE.md)). A rule has the fields above plus:

| Field | Matches |
|---|---|
| `class` | anchored regex over the verdict class: `root`, `delegating`, `inherit`, `tripwire`, `implied`, `rootexec` (empty: any of them; `service`/`deny_always` never need a key) |
| `min_score` | 0..100: fire only if the ticket's signed `payload.risk` (the app judge's score) is at least this. Without it the rule is static and known at queue time |

```json
"require_hardware": [
  {"id": "hw-delegating", "class": "delegating"},
  {"id": "hw-force-push", "argv0": "^git$", "argv_text": " push( .*)? (-f|--force)( |$)"},
  {"id": "hw-high-risk", "class": "root|delegating", "min_score": 80}
]
```

An exec inside an approved tree that matches a static rule does not inherit when that root was approved without the key: it becomes a new root that needs the key. `argv0` also matches the real file's basename, as for deny rules. The defaults have no such rules. In `ticket` mode with rules but no `hardware_keys`, wardend warns at start and matching roots are rejected.

**Not in the first release:** `require_hardware` and `hardware_keys` work only in a build with `-tags hwkey` ([docs/hwkey.md](hwkey.md)). A release build refuses to start (exit 2) when either is not empty: the error names the field and says to remove it or to build with `-tags hwkey`. It is not ignored silently, so nobody thinks they are protected by a rule that doesn't run.

## Envelope and ticket

**Envelope v1**, one per root exec:

```json
{
  "v": 1, "type": "exec",
  "argv": ["bash", "-c", "echo approved-root; ls -d /etc"],
  "cwd": "/home/me", "exe": "/usr/bin/bash", "uid": 1000, "gid": 1000,
  "ppidChain": [{"pid": 16367, "exe": "/usr/bin/dash"}, {"pid": 16355, "exe": "/usr/bin/dash"}],
  "env": [{"name": "HOME", "value": "/home/me"}, {"name": "PATH", "value": "/usr/local/bin:/usr/bin:/bin"}],
  "envHash": "4dc7cdd5…b679f",
  "requester": {"host": "pi", "supervisorId": "bbcf051f…a15d42"},
  "pidfdCookie": "pidfs:16368",
  "ts": 1790454055103,
  "nonce": "dc54ba893701a9eb374fa125a95290a2"
}
```

- `exe` is the realpath of the file being executed; `ppidChain[0]` is the calling process, then its parents up to the supervisor.
- `env` lists the variables that change what the program does (the loader `LD_*`, shell start-up files and exported functions, interpreter paths and options, `GIT_*`, configuration files and directories, pager, editor, proxies; the exact rule is in `protocol/README.md`, section 3), in `envp` order with repeats, values cut at 1024 code points (`cut` says how many were removed); names that look like secrets are left out. They are signed and shown on the card in an Environment block. `envHash` is sha256 of the whole sorted environment (NUL-separated); `supervisorId` is sha256 of the supervisor's public key.
- `LD_PRELOAD`, `LD_AUDIT` or `LD_LIBRARY_PATH` with a value on an exec outside an approved root that would otherwise pass without a card (`logged`, `service`) makes it a card of the tripwire category `loader-env` (the rule is the variable, e.g. `loader-env/ld_preload`); a card anyway (`root`, `delegating`, another tripwire category) keeps its class and category, and a hardware rule for `loader-env` applies to it too. The journal records the names as `loaderEnv`. The app never lets its autopilot allow such a card: it reads the signed `env`.
- `pidfdCookie` binds the ticket to this process instance (`pidfs:<inode>`, or `start:<pid>:<starttime>`).
- `ts` is milliseconds; `nonce` is 16 random bytes, hex.

**digest** = `sha256(canonicalJson(envelope))`; the pending id is `wd-` plus the first 32 hex characters of the digest. Canonical JSON follows `JSON.stringify` rules byte for byte (keys sorted by UTF-16 code units, minimal escaping, ECMAScript number formatting), so Go, the plugin and the app compute the same digest; shared test vectors keep them in sync. An envelope with invalid UTF-8 can't be built and the exec gets `EPERM`.

**Ticket** (the decision):

```json
{
  "deviceId": "<hex64>",
  "payload": {"type": "wardenclaw.ticket.exec.v1", "supervisorId": "<hex64>", "id": "wd-…", "digest": "<hex64>", "decision": "allow", "ts": 1790000000000, "nonce": "…"},
  "signature": "<base64url Ed25519>"
}
```

Two optional fields, for the second factor ([HARDWARE.md](../../protocol/HARDWARE.md)): `payload.risk` (integer 0..100; when present it is part of the signed string) and `hw` (a FIDO2 assertion `{credentialId, clientDataJSON, authenticatorData, signature}`, bound to this ticket by its challenge `sha256(canonicalJson({type:"wardenclaw.hw.v1", ticket, deviceId, id, digest, decision, ts, nonce, supervisorId[, risk]}))`, where `ticket` is `payload.type`). Not in the first release: a build without `-tags hwkey` ([docs/hwkey.md](hwkey.md)) rejects a decision with `hw` as `hardware_not_configured`.

The signature covers `canonicalJson({type, deviceId, id, digest, decision, ts, nonce, supervisorId[, risk]})`. `type` must be `wardenclaw.ticket.exec.v1` and `supervisorId` this wardend's (`wardend status`): a decision the phone signed for a tool call of the gateway plugin (`wardenclaw.ticket.tool.v1`) or for another wardend is refused before the signature is checked. Checks, in order: the type and supervisor, the device is trusted, its key is known, `|now - ts|` is within `ts_window`, the signature is valid, the nonce is unused (it is consumed only after a valid signature), the id is pending and the digest matches. For `allow`: if a `require_hardware` rule applies (or `hw` is present anyway), the assertion is checked, with its signCount, as described in protocol/HARDWARE.md.

## Socket protocol (JSON-RPC 2.0)

`~/.wardend/wardend.sock`: mode 0600 in a 0700 directory, and `SO_PEERCRED` admits only the supervisor's uid. One JSON message per line; requests on one connection are served in parallel.

### `pending`

Long-poll for execs waiting for a ticket. `since` is the last `seq` you saw, `wait` is milliseconds (capped at 25000; `0` returns at once).

```json
{"jsonrpc":"2.0","id":1,"method":"pending","params":{"since":0,"wait":25000}}
```
```json
{"jsonrpc":"2.0","id":1,"result":{
  "ok": true, "seq": 1, "mode": "ticket", "host": "pi", "supervisorId": "bbcf051f…",
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

`meta` can also carry `delegating` and `insideRoot` for delegating spawns, and `hardware` when a `require_hardware` rule applies: `{required, rule, escalated?, minScore?, challenge, origin, credentials: [{id, name, alg, rpId}]}`. With `required: true` the app has to ask for a key tap. With only `minScore` it asks when its own risk score is at least that. Not in the first release: a build without `-tags hwkey` never sets `meta.hardware`.

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

Reasons include `type_invalid`, `supervisor_id_invalid`, `ticket_type_mismatch`, `supervisor_mismatch`, `untrusted_device`, `unknown_device`, `bad_signature`, `signature_missing`, `digest_mismatch`, `digest_invalid`, `stale_timestamp`, `ts_invalid`, `nonce_invalid`, `nonce_reused`, `decision_invalid`, `id_missing`, `unknown_pending`, `already_decided`, `pubkey_conflict`, `config_pubkey_invalid`, `gateway_pubkey_mismatch`, `risk_invalid`, `hw_invalid`. For the second factor (the response then also has `hardwareRule`): `hardware_required`, `hardware_not_configured`, `hw_unknown_credential`, `hw_bad_encoding`, `hw_client_data_invalid`, `hw_client_data_type`, `hw_origin`, `hw_challenge_mismatch`, `hw_auth_data_invalid`, `hw_rpid_mismatch`, `hw_user_presence`, `hw_user_verification`, `hw_bad_signature`, `hw_counter_replay`, `hw_counter_persist`. A rejected second factor keeps the exec pending, so the app can retry within the TTL.

### `status`

No params; returns the object shown under [`wardend status`](#wardend-status).

### `pair.*`

`pair.start {ttl?, url?}` → `{code, codeDisplay, expiresAt, url, link, supervisorKey, supervisorId, supervisorFingerprint, host}`; `pair.list {}` → `{requests, devices, activeCodes, http, config}`; `pair.approve {id}`, `pair.reject {id}` → `{request, config}`; `pair.revoke {device}` → `{deviceId, name, config}`. All but `pair.list` are refused for callers under this wardend's filter (see [`wardend pair`](#wardend-pair)); the refusal is journaled as `pair_refused`.

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

## Relay transport

wardend has no listening network port. It keeps one outbound WebSocket to the relay (`relay_url`, default `wss://relay.wardenclaw.dev`; `off` runs without it), and the app and `wardenctl` are devices on the same relay. The relay is an untrusted carrier: every message is encrypted end to end (X25519 + XChaCha20-Poly1305) between the supervisor's key (`relay_key_file`) and the device's, and a ticket that arrives through it passes the same check as `decide` over the socket. Pushes (APNs, FCM) are sent by the relay, not by wardend. The wire format is in protocol/README.md, section 5; shared fixtures are in `protocol/vectors/relay_vectors.json`.

## `wardenctl`: approving from a laptop

`wardenctl` is the terminal counterpart of the phone app: a separate binary (`cmd/wardenctl`, same Go module, so it uses the `envelope` and `hwkey` packages instead of re-implementing them) that pairs with wardend over the same relay transport and signs tickets with its own Ed25519 device key. It builds without cgo for darwin/arm64, darwin/amd64, linux/arm64 and linux/amd64. Full guide: [cmd/wardenctl/README.md](../cmd/wardenctl/README.md).

**Run it on a different machine** (the owner's laptop), never on the agent's host as the agent's user: there the agent could read the device key or just run `wardenctl approve` itself. A laptop where other AI agents run as the same user is "next to an agent" too. wardenctl refuses to start, with exit code 3, when it runs under a seccomp filter and a wardend is nearby (a wardend ancestor, `~/.wardend`, or a `wardend` process of the same uid); that refusal can't be overridden. When it isn't filtered but `~/.wardend` exists or wardend runs as the same user, it also refuses, unless `WARDENCTL_ALLOW_SAME_HOST=1` is set for demos and tests.

Get the binary on the Mac itself, not from the agent's host: either `wardenctl_darwin_arm64.tar.gz` (or `_amd64`) from a daemon release, checked against the release's `checksums.txt` before you unpack it, or a build on the Mac from a signed tag (`git verify-tag` against `allowed_signers`). Commands for both: [cmd/wardenctl/README.md](../cmd/wardenctl/README.md), "Installing on a Mac". Remove the Gatekeeper quarantine only from a file whose checksum matched. For a YubiKey (only in a build with `-tags hwkey`): `brew install libfido2`.

```
wardenctl pair '<wardenclaw://pair?…>' [--name n] [--keystore auto|keychain|file] [--no-wait] [--timeout 10m]
wardenctl pending | show <id> | approve <id> [--no-hw] [--uv] [--device d] [--yes] | deny <id>
wardenctl watch [--no-hw] [--uv] [--device d]
wardenctl status | forget [--yes] | version
wardenctl hw-register [--device d] [--name n] [--alg auto|eddsa|es256] [--uv] [--require-uv]
wardenctl hw-check [--device d] [--uv]
```

Not in the first release: `--hw`, `--no-hw`, `--uv`, `--device`, `hw-register` and `hw-check` exist only in a build with `-tags hwkey` ([docs/hwkey.md](hwkey.md)). A release build hides them from the help and answers "second factor (FIDO2 hardware keys, YubiKey) is not included in this release…" with exit code 2; its `status` has no YubiKey line.

- **`pair`** takes the link printed by `wardend pair start`, pins the supervisor keys from it, connects to the relay named in it, creates the device key (macOS Keychain via `/usr/bin/security`, with the seed passed on stdin to `security -i` rather than in argv; elsewhere `~/.config/wardenctl/device.key`, mode 0600), sends the pairing request through the relay, prints the device fingerprint and waits for the answer. Compare the fingerprint with `wardend pair list`, then run `wardend pair approve <id>` on the server. The Keychain item trusts no application (`-T ""`), so every read of the key, that is every command that talks to the server, shows a macOS prompt: answer Allow, never Always Allow, which would let any process of the user read the key again without asking. An item made by an older version is re-created once, on the first command.
- **`approve`** shows the card and asks before it signs: `y` allows an ordinary card, a dangerous one only the word `allow` in full, anything else cancels. The release build signs with the device key alone (as `--no-hw` did); only a build with `-tags hwkey` signs with a YubiKey touch by default, and there `--no-hw` drops the touch when wardend doesn't require one. From a script (stdin not a terminal, or `--yes`) nothing is asked, and the id must have at least 12 characters. The real boundary stays on the server: without a `require_hardware` rule wardend accepts an allow signed by the device key alone.
- **Protocol version.** wardenctl checks the `protocol` that wardend reports (protocol/README.md, section 10). A wardend without the field or of a lower version gets "…: update wardend", a wardend of a higher version gets "…: update wardenctl"; both exit with code 4. A card whose envelope is newer than wardenctl (`v` above 1) is listed as "NOT VERIFIED: request from a newer protocol version, update wardenctl (envelope v2, wardenctl understands v1). Must not be signed.": it is not dropped, and it can't be signed.
- **`pending`, `show`, `approve`, `deny`** work through the relay. Before signing, wardenctl checks every card the way the app does: exactly the 14 v1 fields (with the `env` entries), `requester.supervisorId` equal to the pinned one, the digest recomputed from the envelope, and `id == "wd-" + digest[:32]`. It never signs `payload.risk`. `show` prints argv, exe, cwd, uid/gid, class and rule, the process chain, callerExe, envHash, pidfd cookie and digest.
- **`watch`** waits for cards and asks about one card at a time: `y` allows (with the device key; in a build with `-tags hwkey` also with a YubiKey touch unless started with `--no-hw`), `n` denies, `d` shows the full card, and **an empty line does nothing** (there's no default answer: the card stays pending for the phone or the TTL). A **dangerous** card (the `!!! DANGEROUS` line: a blocklist or injection rule, invisible characters, homoglyphs, a delegating launch) is not allowed by `y`: type the word `allow` in full, the terminal counterpart of the hold on the phone and the watch. A card that is decided elsewhere or expires while you are asked is withdrawn.
- **YubiKey over USB** (not in the first release: `fido.go` is compiled only with `-tags hwkey`, see [docs/hwkey.md](hwkey.md)) uses the libfido2 tools as external programs (`fido2-token -L`, `fido2-cred -M`, `fido2-assert -G -p [-v]`), so no cgo is needed. The challenge and `clientDataJSON` are exactly those in [HARDWARE.md](../../protocol/HARDWARE.md). The tools return `authenticatorData` as a CBOR byte string; wardenctl unwraps it and checks the assertion against the registered COSE key before sending it. `hw-register` creates an EdDSA credential for rpId `wardenclaw` (ES256 if the key can't do EdDSA), verifies the result with `hwkey.ParseRegistration`, and prints `wardend hw-register 'wchw1:…'` (`--cose-key … --credential-id …` for `fido-u2f` keys) for you to run on the server, followed by a wardend restart. Cards with `meta.hardware.required` then ask for a touch when approved. Without the tools the error names the package to install (`brew install libfido2`, `apt install fido2-tools`).

Tests (`go test -p 1 ./cmd/wardenctl`): byte-for-byte compatibility with `transport_vectors.json` and `hw_vectors.json` (the single copy in `protocol/vectors/` at the repository root, also read by the app's tests), card checks, fake `fido2-*` and `security` tools, and the guard rules. On Linux there are also e2e tests against a real `wardend run --mode ticket`: pairing, `show`/`approve`/`deny` → exec or `EPERM`, `watch`, the YubiKey path through the real `wardend hw-register` and `require_hardware`, and the refusal of a wardenctl started under wardend's filter. Inside a wardend tree they are skipped. Like the other integration tests, you run them from your own terminal outside wardend, not from an agent's session, or leave them to CI; wrapping them in `systemd-run --user` for an agent would run code outside the gate.

## Journal

`~/.wardend/journal.jsonl`, mode 0600, append-only. Each record: `hash = sha256(prevHash + canonicalJson({seq, ts, kind, data, prevHash}))`, `sig = Ed25519(supervisor key, "wardenclaw.journal.v1\n" + hash)` (the prefix keeps a journal signature apart from anything else the supervisor key signs; journals written before this prefix fail `verify-journal` with `bad_signature`). Kinds: `start` (mode, command, journal key, trusted devices, relay), `exec` (one per exec: pid, path, argv, cwd, class, rule, decision, errno, latency; for roots also the digest, envelope and signed ticket), `decide_reject`, `toctou_kill`, `root_exit`, `signal`, `stop`, `panic` (see below), and for pairing `pair_start`, `pair_request`, `pair_reject_request`, `pair_approved`, `pair_rejected`, `pair_refused`, `device_revoked`. About 760 bytes per exec; there is no rotation yet.

**`panic`.** A bug that panics in one of wardend's long-lived goroutines (the exec handler, the notification loop, sweep, signal forwarding, the child wait, the socket server, the push loop) still ends wardend, as before: fail-closed, the filter stays and every exec of the tree fails until systemd restarts wardend. Before exiting (code 2) wardend writes `wardend: panic in <goroutine>: <value>` and the stack to stderr (journald), then, if the journal answers within 2 s, a record `panic` with `goroutine`, `value` and the first 4 KB of `stack`. When the panic left the journal (or a lock held around it) busy, the record is skipped and stderr says so; the stack in journald is enough to report the bug.

## Running the OpenClaw gateway under wardend (systemd)

The gateway is a user unit. Restarting it drops current sessions, so don't run these from a chat with the agent. Put a drop-in at `~/.config/systemd/user/openclaw-gateway.service.d/wardend.conf`.

**Stage 1, observe** (`deploy/wardend-observe.conf`):

```ini
[Service]
# The empty line resets the unit's ExecStart; the second runs the same gateway through wardend.
ExecStart=
ExecStart=%h/.local/bin/wardend run --mode observe --config %h/.wardend/config.json --quiet -- @GATEWAY_CMD@
KillMode=mixed
SuccessExitStatus=0 143
```

`@GATEWAY_CMD@` is a placeholder for the command in the `ExecStart` of your existing unit (`systemctl --user cat openclaw-gateway`): absolute paths, node flags such as `--max-old-space-size` included. Don't copy the template with plain `cp`: a drop-in with the placeholder left in it keeps the gateway from starting. `KillMode=mixed` sends SIGTERM to wardend only (it forwards it) and SIGKILLs the rest of the tree after the timeout.

Run this from `daemon/` (after the single-user install script, from `~/.local/share/wardend`):

```bash
mkdir -p ~/.wardend && chmod 700 ~/.wardend
# only if you have no config yet: an existing one holds your paired devices
test -e ~/.wardend/config.json || install -m 600 deploy/config.example.json ~/.wardend/config.json
GW="$(command -v node) $(npm root -g)/openclaw/dist/index.js gateway --port 18789"   # as in your ExecStart
mkdir -p ~/.config/systemd/user/openclaw-gateway.service.d
sed "s#@GATEWAY_CMD@#$GW#" deploy/wardend-observe.conf > ~/.config/systemd/user/openclaw-gateway.service.d/wardend.conf
grep '^ExecStart=.' ~/.config/systemd/user/openclaw-gateway.service.d/wardend.conf   # both paths after -- must be absolute
```

Devices get into the config through `wardend pair`. Then restart the gateway:

```bash
systemctl --user daemon-reload && systemctl --user restart openclaw-gateway
systemctl --user status openclaw-gateway     # Main PID is wardend, node is its child
wardend status
```

Observe for a few days, then list what would have needed a ticket:

```bash
jq -r 'select(.kind=="exec" and (.data.class=="root" or .data.class=="delegating")) | .data.argv|join(" ")' \
  ~/.wardend/journal.jsonl | sort | uniq -c | sort -rn | head -50
```

Add everything that is housekeeping (cron jobs, browser, `openclaw` subcommands, MCP servers, plugins) to `~/.wardend/policy.json` and set `"policy"` in the config.

**Stage 2, ticket**: the same drop-in with `--mode ticket` (as in `deploy/wardend-ticket.conf`). First make sure the phone is paired (`wardend pair start` / `approve`) and online: in `ticket` every new command of the agent waits for a signature, and without a trusted device it fails after the TTL.

```bash
wardend pair list     # your phone must be listed under trusted devices
```

Then switch the mode in place, so the gateway command you checked in stage 1 stays as it is:

```bash
chmod 600 ~/.wardend/config.json    # a group-writable config stops wardend in ticket mode
sed -i 's/--mode observe/--mode ticket/' ~/.config/systemd/user/openclaw-gateway.service.d/wardend.conf
systemctl --user daemon-reload && systemctl --user restart openclaw-gateway
```

To go back to observe, run the same `sed` with the two modes swapped and restart. The app gets cards through the relay. The OpenClaw plugin `wardenclaw-gate` can also relay pending execs through the gateway when the app's OpenClaw adapter is on; that path is optional.

**Roll back** (either stage):

```bash
rm ~/.config/systemd/user/openclaw-gateway.service.d/wardend.conf
systemctl --user daemon-reload && systemctl --user restart openclaw-gateway
```

There is no rollback without a restart: a seccomp filter can't be removed from a live tree.

## Troubleshooting

**`Function not implemented` (ENOSYS) on every exec.** The supervisor died. The filter stays on the tree, and with no listener the kernel fails every `execve` with `ENOSYS`: fail-closed by design. Restart the unit (`Restart=always` does it for you).

```console
$ wardend run --mode observe -- sh -c 'sleep 2; /bin/true; echo "true rc=$?"' &
$ kill -KILL $!     # only this wardend, not the one that runs your gateway
sh: 1: /bin/true: Function not implemented
true rc=126
```

**`Resource temporarily unavailable` (EAGAIN).** The ticket queue is full (`max_pending`, default 16). The exec is refused immediately rather than queued or allowed. Raise `--max-pending` or approve faster.

```console
$ wardend run --mode ticket --ttl 2s --max-pending 1 -- sh -c '/bin/echo a & /bin/echo b & /bin/echo c & wait'
sh: 1: /bin/echo: Resource temporarily unavailable
sh: 1: /bin/echo: Resource temporarily unavailable
sh: 1: /bin/echo: Operation not permitted
```

(Two overflowed the queue, the third waited and expired.)

**`Operation not permitted` (EPERM).** A `deny_always` rule matched, a device signed deny, or the ticket TTL expired. `wardend journal` shows the class, rule and reason.

**`__child: seccomp(SET_MODE_FILTER, flags=0x28): operation not permitted` and `listener fd not received`.** You are starting wardend from inside a tree that is already supervised by wardend (for example, a shell of an agent running under the gateway). A nested notification listener is refused on purpose: otherwise a process could install its own filter and answer `CONTINUE` around the outer supervisor. Run it outside the supervised tree.

**Duplicate or endless exec notifications.** wardend always sets `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (kernel 5.19+). Without it, any signal to the target (including Go's runtime `SIGURG`) cancels the notification and restarts `execve`: an early spike logged 662 duplicates of one exec in 40 s. On an older kernel the filter can't be installed; upgrade the kernel.

**`setsid: Operation not permitted` inside an approved command, or a second approval request.** `setsid`, `systemd-run`, `docker`, `tmux`, `ssh` and other delegating spawns are always a new root and need their own ticket. A process orphaned before its first exec (double fork, background job whose parent already exited) also loses the link to its root and asks again. This is fail-closed. Also note: for `docker`, `ssh`, `systemd-run` and `tmux` the actual work runs in a daemon or host outside the tree, so approving that ticket approves whatever runs there.

```console
$ wardend run --mode ticket --ttl 2s -- sh -c 'bash -c "setsid ls -d /tmp; echo setsid rc=\$?"'
bash: line 1: /usr/bin/setsid: Operation not permitted     # bash was approved, setsid was not
setsid rc=126
```

**Two cards for one action.** A Bash call from claude-cli can be seen both by the OpenClaw plugin hook and by wardend (as a root). Linking the two is on the roadmap.

**`rpc pair.approve: refused: called from under the wardend filter …`.** You ran `wardend pair start/approve/reject/revoke` from a shell inside the supervised tree (for example, the agent's). Run it from your own SSH session or terminal on the server.

**`mode "x": observe|deny-list|ticket`** or **`toctou mode "x": stop|poll|off`**: a typo in the config or flags; wardend exits with code 2 before starting anything. [`wardend config-check`](#wardend-config-check) finds these, JSON errors (with line and column) and unknown keys before a restart.

**`config …: version N is newer than this wardend understands`**: the config was written for a newer wardend. Update wardend, or bring the config back to the format of this version.

**`wardend: panic in <goroutine>: …` in journald, wardend restarted.** A bug in wardend; the exec that was in flight failed (fail-closed). The stack follows the line, and the journal has a `panic` record when it could be written. Please report it with the stack.

## Limits

- Only `execve` and `execveat` are gated. Inside an approved root, interpreters (`python -c`, `bash -c`), `LD_PRELOAD`, file writes and network are not. The root itself is approved with its environment on the card (the `env` list), but only the variables of that list are shown: the rest is signed through `envHash` alone.
- realpath is resolved in the supervisor's mount namespace; `unshare`, `nsenter` and `chroot` are delegating and need a ticket.
- Content swapped on the same inode between check and exec is not detected; the binary hash is not in the envelope yet.
- 32-bit compat syscalls return `ENOSYS`.
- No journal rotation, no "same as before" approval cache.
- The hardware second factor (not in the first release: only with `-tags hwkey`, [docs/hwkey.md](hwkey.md)) doesn't verify the attestation chain up to the Yubico root, and the `min_score` rules rely on a score the phone reports (static `require_hardware` rules don't). See [HARDWARE.md](../../protocol/HARDWARE.md).
