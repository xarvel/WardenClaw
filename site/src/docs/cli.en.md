---
title: wardend CLI reference
description: Install, run and operate wardend, the seccomp exec gate of WardenClaw. Every command, flag, file format and RPC method, verified on a Raspberry Pi 5.
---

# wardend CLI reference

`wardend` starts a process (in production: the OpenClaw gateway) under a seccomp filter and decides the fate of every `execve`/`execveat` in the whole process tree. The kernel stops the call, the supervisor reads argv, cwd, the real binary and the parent chain from the stopped process, and answers `CONTINUE` or an error. By default (the `tripwire` [policy mode](#policy-modes)) every exec is checked against rules: risky ones (remote execution, leaving the gate, package installs, publishing, secrets, destructive commands) wait for an **Ed25519 signature from a WardenClaw device** over a canonical envelope, and the rest runs and is journaled. In the older `root` mode, root commands wait for a signature and children of an approved root pass on their own while its subtree is alive.

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

<div class="callout callout-danger" role="note" data-if="test-key"><strong>Test key, not for production systems.</strong> Until the first release this site shows a test signing key, and the installer refuses to download anything signed with it. <a href="/docs/verify/">Verify releases</a></div>

The default is the **hardened install in observe mode**: wardend as a root system service, the harness under its own user, the release signature checked before anything is written. What the script does step by step, how to check it before piping it into `sudo`, and the flags: [Install wardend](../install/).

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
  wardend run [--config f] [--mode observe|deny-list|ticket] [--state-dir d] [--socket s] [--journal j]
              [--policy rules.json] [--ttl 120s] [--max-pending 16] [--trust <deviceId>[:<pubkey>]]...
              [--gateway-db auto|off|path] [--toctou-roots stop|poll|off] [--toctou-service off|poll|stop]
              [--linger 2s] [--quiet] -- <cmd...>
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

`pending` returns `{ok, host, mode, seq, now, pending}`. Every item contains `id`, `digest`,
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

**Protocol version.** `pair` and `status` compare `protocol` and `minClient` in the answers of `/v1/ping` and `/v1/status` with their own. A wardend without these fields or older than wardenctl supports gets a message to update wardend, a wardend that needs a newer client gets a message to update wardenctl, and both exit with code 4. A request whose envelope is newer than wardenctl (`v` above 1) is not dropped: it stays in the list with `verified: false` and a `verificationError` that asks to update wardenctl, and it can't be signed.

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

Flags accept one or two dashes (`-mode` and `--mode` are the same). Every command and subcommand of `wardend` and `wardenctl` prints its usage and flags with `--help`, `-h` or `help` (`wardend pair approve --help`, `wardend help run`) to stdout with exit code 0 and does nothing else: no key, no files, no socket or network connection. `wardenctl` answers it before the safety guard, so it works anywhere. A command-line error prints the message and the usage to stderr with exit code 2.

## Commands

### `wardend run`

Starts `<cmd...>` under the supervisor. Everything after `--` is the command.

```
wardend run [flags] -- <cmd...>
```

| Flag | Default | Meaning |
|---|---|---|
| `--config f` | `~/.wardend/config.json` if it exists | JSON config (see [Config](#config)). Flags override config values. |
| `--mode m` | `observe` | `observe`, `deny-list` or `ticket` (see [Modes](#modes)). |
| `--policy-mode p` | `tripwire` | `tripwire` or `root`: which execs need a signature (see [Policy modes](#policy-modes)). |
| `--state-dir d` | `~/.wardend` | State directory, created with mode 0700. |
| `--socket s` | `<state-dir>/wardend.sock` | Unix socket for JSON-RPC. |
| `--journal j` | `<state-dir>/journal.jsonl` | Append-only journal. |
| `--policy f` | built-in rules | Policy JSON (see [Policy](#policy)). |
| `--ttl d` | `120s` | How long an exec waits for a ticket before `EPERM`. |
| `--max-pending n` | `64` | Queue limit for execs waiting for a ticket; overflow gets `EAGAIN`. |
| `--trust id[:pubkey]` | none | Trusted device, repeatable. Appended to `trusted_devices` from the config. |
| `--gateway-db v` | `off` | Where else to look up device public keys: `off`, `auto` (`~/.openclaw/state/openclaw.sqlite`, read-only) or a path. |
| `--toctou-roots m` | `stop` | Post-exec check for approved roots: `stop`, `poll` or `off`. |
| `--toctou-service m` | `off` | Same for allow-listed service execs. |
| `--linger d` | `2s` | After the main child exits, keep serving the rest of the tree this long. |
| `--quiet` | off | No start and summary lines on stderr. |

The exit code is the child's exit code; death by signal N is `128+N` (SIGTERM gives 143). SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGUSR1 and SIGUSR2 are forwarded to the child.

**Observe** a command: everything runs, the journal records what each exec would need in `ticket` mode.

```console
$ wardend run --mode observe --gateway-db off -- sh -c 'ls -d /tmp; git --version'
wardend: mode=observe policy=tripwire pid=767159 child=767168 socket=/home/me/.wardend/wardend.sock journal=/home/me/.wardend/journal.jsonl
/tmp
git version 2.47.3
wardend: mode=observe execs=3 denied=0 latency p50=433us p95=518us max=518us exit=0
```

**Deny-list** only: the built-in `deny_always` rules apply, everything else runs.

```console
$ wardend run --mode deny-list --gateway-db off --quiet -- sh -c 'dd if=/dev/zero of=/dev/null count=1; echo "dd rc=$?"; echo ok'
sh: 1: dd: Operation not permitted
dd rc=126
ok
```

(`dd of=/dev/…` is one of the `deny_always` rules. The example writes to `/dev/null`, so it stays harmless even where the rule doesn't apply.)

**Ticket** mode: an exec that trips a rule waits for a signed decision, the rest runs at once. In one terminal:

```bash
umask 077
mkdir -p ~/.wardend
wardend keygen > ~/.wardend/demo-device.txt   # test device, outside the command's directory
DEV=$(sed -n 's/^deviceId=//p' ~/.wardend/demo-device.txt)
PUB=$(sed -n 's/^pubkey=//p' ~/.wardend/demo-device.txt)
cd /tmp
wardend run --mode ticket --gateway-db off --trust "$DEV:$PUB" --ttl 30s --quiet \
  -- sh -c 'ls -d /etc; ssh -V; echo "ssh rc=$?"'
```

`ls` prints `/etc` at once; `ssh` (remote execution) now waits in the kernel. In another terminal, outside that command, sign it with the test key:

```console
$ wardend approve --key-file ~/.wardend/demo-device.txt --count 1 --timeout 10s
allow wd-805763d1887fcfb8a26269e7d38f1db9 argv=[ssh -V] -> map[decision:allow id:wd-805763d1887fcfb8a26269e7d38f1db9 ok:true]
```

and the first terminal prints the OpenSSH version and `ssh rc=0`. Without a ticket within the TTL, or with a signed deny:

```console
/etc
sh: 1: ssh: Operation not permitted
ssh rc=126
```

With `--policy-mode root` the same command asks twice: for `ls` (a root) and for `ssh` (a delegating spawn), and children of an approved root pass on their own.

### `wardend config-check`

Checks the config and the policy the way `wardend run` reads them at start, and starts nothing: no key, no journal, no socket, no state directory. Run it after every edit and before a restart, since a config wardend can't read stops wardend, and the agent with it:

```bash
sudo wardend config-check --config /etc/wardend/config.json && sudo systemctl restart wardend
```

Flags are the path flags of `run`, with the same defaults: `--config` (else `<state-dir>/config.json` if it exists), `--state-dir`, `--policy` (else `policy` from the config, else the built-in rules). A command after `--` is optional and only feeds harness pack detection, as in `run`. It prints every error and warning and exits with 0 if `wardend run` would start with these files, 1 if not (2 for a command-line error). It catches:

- JSON errors in the config or the policy, with line and column (`config /etc/wardend/config.json: line 4, column 3: invalid character '"' after object key:value pair`);
- unknown keys in the config and the policy, nested ones too, as warnings with a hint (`unknown key "moed" is ignored (did you mean "mode"?)`): `run` ignores them, so a typo in a key leaves the default value;
- values `run` rejects: `mode`, `policy_mode`, `toctou_*`, a `trusted_devices` entry whose key doesn't hash to its id, policy rules that don't compile, the install checks of selfcheck;
- `hardware_keys` (or `require_hardware` in the policy) in a build without the second factor: the error `run` stops with, explained; <!-- feature-item:hardwareKey -->
- `mode` `ticket` without `trusted_devices` (a warning: every command that needs a signature is denied until a phone is paired);
- a config `version` newer than this wardend understands (an error, see [Config](#config)).

```console
$ wardend config-check --config ./config.json
warning: config ./config.json: unknown key "mdoe" is ignored (did you mean "mode"?)
mode observe, policy_mode tripwire, policy built-in, trusted devices 0
config-check: ok
```

### `wardend keygen`

Creates a **test** device key pair: the 32-byte Ed25519 seed (hex), the public key (base64url, raw 32 bytes) and the device id (sha256 of the public key, hex).

```console
$ wardend keygen
seed=22e5e1…6f66
pubkey=fEm6ZDoB…nmr8Y
deviceId=9362e2a4…188d5a
```

In production the phone app holds the key; `keygen` and `approve` exist for demos and tests. The seed is a secret from the process you supervise: that process runs as you and can read any file you can read. Keep the file out of its working directory, do not pass the seed on the command line, and do not leave the test key trusted for a real agent.

### `wardend approve`

A "device in a terminal": long-polls `pending` on the socket, recomputes each digest from the envelope (like the app does), and signs decisions with a seed.

| Flag | Default | Meaning |
|---|---|---|
| `--key-file path` | required | File from `wardend keygen`, or `-` to read that output from stdin. Must be mode 0600. |
| `--socket s` | `~/.wardend/wardend.sock` | Supervisor socket. |
| `--match re` | none | Only sign execs whose argv, joined with spaces, matches this Go regex. |
| `--deny` | off | Sign `deny` instead of `allow`. |
| `--count n` | `1` | How many decisions to send; `0` means no limit until `--timeout`. |
| `--timeout d` | `30s` | How long to wait. |

`--key` is rejected: the seed would show up in the process list. `approve` also refuses to run when this process is already under a seccomp filter, which is what happens inside the command `wardend run` started.

Exit code 1 and `nothing approved` when no decision was sent.

### `wardend status`

Supervisor state over the socket: mode, policy mode, harness packs, queue, tracker, trusted devices, journal key and metrics.

```console
$ wardend status --socket /path/to/wardend.sock
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
  "minClient": 1,
  "mode": "ticket",
  "now": 1790454056134,
  "ok": true,
  "packs": ["claude-cli", "openclaw"],
  "pending": 1,
  "pid": 16346,
  "policyMode": "tripwire",
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

`protocol` is the version of the WardenClaw protocol this wardend speaks and `minClient` the oldest client version it still supports; `GET /v1/ping` and `GET /v1/status` carry them too, and the app, the plugin and `wardenctl` compare them with their own. `warnings` is a list of codes, empty when all is well: `no_trusted_devices` means the mode is `ticket` and no device is trusted, so every command that needs a signature waits for a ticket nobody can sign and is denied after the TTL (pair a phone: `wardend pair start`; the warning goes away without a restart). `wardend status` prints each warning in words to stderr after the JSON, so stdout stays plain JSON:

```console
wardend: warning: ticket mode and no trusted devices: pending roots wait for a ticket nobody can sign and are denied after the TTL. Pair a phone: wardend pair start
```

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

### `wardend policy-defaults`

Prints the built-in rules as JSON: the starting point for your own `--policy` file. `--pack claude-cli` or `--pack openclaw` prints a built-in [harness pack](#policy-modes) instead.

```bash
# only if you have no policy file yet: never overwrite the rules you have added
test -e ~/.wardend/policy.json || wardend policy-defaults > ~/.wardend/policy.json
```

### `wardend replay`

Runs the exec records of a journal through this build's classifier, the same code the supervisor uses (policy mode, harness packs, path zones), and prints aggregates only: classes, categories, rules, cards a day and the peaks. Every card is counted as approved, as in `observe`, so pairs such as `ssh` under an approved `scp` count the way they would after a signature. Nothing from argv is printed.

| Flag | Default | Meaning |
|---|---|---|
| `--journal f` | required | Journal to read. It is only read; a copy of a live journal works, a cut last line is skipped. |
| `--config f` | none | Install config: `policy_mode`, `agent_home`, `work_dirs`, `scratch_dirs`, `packs`, `pack_vars`, `policy`. |
| `--policy-mode p` | config, else `tripwire` | `tripwire` or `root`. |
| `--policy f` | config, else built-in | Policy JSON. |
| `--agent-home d` | config, else `$HOME` | `${AGENT_HOME}`. |
| `--packs a,b` | config, else all built-in | Harness packs; `none` for none. |
| `--work-dir d`, `--scratch-dir d` | none | Repeatable; added to the config's lists. |
| `--from t`, `--until t` | whole journal | Unix milliseconds or RFC 3339. |
| `--json` | off | One JSON object instead of text. |
| `--dump f` | none | One line per exec: seq, class, rule and detail. No argv; the file gets mode 0600. |
| `--top n` | `25` | How many rules to list. |

On a short run (a real journal of weeks gives the rates per hour and per day):

```console
$ wardend run --mode observe --quiet -- sh -c 'ls -d /tmp >/dev/null; git --version >/dev/null; ssh -V 2>/dev/null; sudo -n true 2>/dev/null; rm -rf /tmp/wd-demo; touch ~/.bashrc; echo done'
done
$ wardend replay --journal ~/.wardend/journal.jsonl
journal     /home/me/.wardend/journal.jsonl
window      2026-09-28T02:03:48 .. 2026-09-28T02:03:48 (0.00 h), records 9, wardend starts 1
policy      tripwire, packs claude-cli,openclaw, agent_home /home/me, work_dirs 0
execs       6 classified, skipped supervised_cmd 1
classes     logged 3, tripwire 2, refuse 1
cards       2 (window shorter than an hour: no rates)
peaks       2 min 2, 10 min 2, 60 min 2 (2 min = ticket TTL: pending if nobody answers); night 00-07 2 (100.0 %)
categories  protected-write 1, remote 1
refused     1: privilege/sudo 1
night       protected-write 1, remote 1
top rules (cards):
       1  protected-write/touch write config
       1  remote/ssh
service rules (packs, service_allow): 0, top: -
```

`ls`, `git --version` and `rm -rf /tmp/wd-demo` (scratch) are `logged`; `ssh` and `touch ~/.bashrc` (a dotfile) would each need a card; `sudo` would be refused. The same journal with `--policy-mode root` shows what the older mode would ask for.

## Modes

| Mode | Behaviour |
|---|---|
| `observe` | Everything is allowed. The journal records the class each exec would get and roots are "approved" automatically, so you can see the real ticket volume. |
| `deny-list` | Only `deny_always` rules apply (`EPERM`); everything else runs. |
| `ticket` | Production. Execs that need a signature (in `tripwire`: those that trip a rule; in `root`: roots and delegating spawns) wait for a signed ticket; `deny_always` still wins. |

### Policy modes

`mode` decides whether a decision is enforced; the **policy mode** (`policy_mode`, `--policy-mode`) decides which execs need a decision at all.

| `policy_mode` | Who needs a signature | Children of an approved exec |
|---|---|---|
| `tripwire` (default) | only an exec that trips a rule: remote execution, leaving the gate, package installs, publishing, destructive commands, protected paths and secrets, agent settings, adb, cloud CLIs | pass without a card only if they trip a rule of the same tool family (`ssh` under `scp`, `eas` under `npx eas-cli`), for at most 10 minutes; everything else is checked on its own |
| `root` | every exec that is not inside an approved tree ("root"), and every delegating spawn | the whole live subtree |

**Tripwire.** Every exec is checked against rules; there is no trust on a subtree. Order: `deny_always` → verbs of a harness CLI that change the agent's settings → harness housekeeping (packs, `service_allow`) → your own `tripwire` rules → the built-in categories → the `sudo` refusal → the pair of an approved parent → a card. Whatever no rule catches runs and is journaled with the class `logged`.

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

**Pairs.** An approved exec is registered with its tool family. The families are `ssh` (ssh, scp, sftp, sshpass, mosh, rsync to a host), `npm` (npm, npx, pnpm, yarn, bun), `eas` (`npx eas-cli`, eas), `docker` (docker, podman, compose), `systemd` (systemd-run, systemctl, loginctl, busctl, D-Bus), `adb` (adb, fastboot), `git`, `gh`, `pip` and the harness CLI; any other tool, and each of your own `tripwire` rules, is a family of its own. An exec in the subtree of an approved one passes without a card (class `implied`) only if it trips a rule of the same family (or it is the `ssh` transport under `git push`) and the approval is at most 10 minutes old: the `ssh` transport under `scp`, `eas` under `npx eas-cli`, the `docker-compose` plugin under `docker compose`, a harness CLI restarting itself. Everything else in the subtree is checked on its own: an approved `npm ci` doesn't make a `curl -d` or an `ssh` from a postinstall script free. The package-manager families (`npm`, `pip`, `go`, `cargo`, `gem`, `brew`) never imply their children either: another `npm install` or `npx -y` from that postinstall is a card of its own.

**sudo.** wardend sets `no_new_privs` on the whole tree, and a setuid binary gains nothing under it, so a ticket for `sudo` would be useless. `sudo`, `su`, `doas`, `pkexec`, `sudoedit`, `newgrp` and `sg` get `EPERM` at once, without a card; the journal record has the class `refuse` and the reason. A `sudo` shim without the setuid bit is an ordinary `privilege` card.

```console
$ wardend run --mode ticket --gateway-db off --trust "$DEV:$PUB" --quiet -- sh -c 'sudo -n true; echo "sudo rc=$?"'
sh: 1: sudo: Operation not permitted
sudo rc=126
```

**Harness packs.** Everything that is specific to one harness lives in a pack: its housekeeping execs (claude itself, its built-in `rg`, git probes, the shell snapshot; the OpenClaw gateway's workers and probes and the wrapper it starts children with), the zones of its settings and secrets, and the CLI verbs that change the agent's settings. Two packs are built in, `claude-cli` (tested with 2.1.283) and `openclaw` (2026.9.6); `wardend policy-defaults --pack <name>` prints one.

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

**Check it on your own journal** before you switch: [`wardend replay`](#wardend-replay) runs the journal through the same code and prints cards a day, peaks and categories. On a 25-hour journal of a coding agent (98,053 execs) that gave 3,162 cards a day in `root` mode and 819 in `tripwire`, with a peak of 34 in two minutes.

**What tripwire honestly doesn't see.** `root` doesn't see it either; it only hides it inside one card for a whole command.

1. Actions without a new exec: shell redirections (`> ~/.bashrc`, `< ~/.ssh/id_ed25519`), shell builtins (`kill`, `echo >`), the harness's own file tools (Write, Edit), network and files from inside long-running processes, MCP calls.
2. Code inside interpreters: `python3 -c`, `node -e` and the agent's own scripts can do anything; only the start is visible. The same goes for an argv race in a multithreaded process: an exec that needed no card is not re-checked after `CONTINUE` (TOCTOU checks cover approved execs).
3. The browser and CDP: `openclaw browser evaluate` and requests to the CDP port on 127.0.0.1 act in sessions with your logins.
4. Execution outside the gate after an approval: what an approved `systemd-run`, `docker run` or `ssh` does next is not seen.
5. Identity by name: a copy of a binary under another name bypasses a rule (sha256 of the target is on the roadmap).
6. The meaning of arguments, and what is not in argv: `npm test` and `go test` run code the agent wrote; `curl -K file` takes the method and the body from a file, and `net-write` doesn't see them.

**Why you still need the box.** Tripwire looks at execs, so it guards against an agent that uses standard tools, which is what a hijacked agent and an honest mistake usually look like. It doesn't stop an agent that writes its own code: a `python3 -c` that reads a key and sends it out runs as `logged`. That takes **the box**, limits that hold whatever the code is:

- the [hardened install](../install/): the harness runs as a separate user; `ProtectHome=true`, so your home with its SSH keys, tokens and browser profiles is not in the agent's file system at all, and there is nothing to read there by exec, by redirection or from an interpreter; `ProtectSystem=strict` with writes only to the agent's home and the listed `ReadWritePaths`; `NoNewPrivileges`;
- outbound network by allow-list: the harness reaches only the model API and the hosts you name, through a proxy with a domain allow-list. Without it, any code can send anything anywhere. The installer **doesn't set this up yet**: the hardened unit doesn't restrict the network;
- an MCP proxy for tools that act outside the host (planned).

Tripwire adds to the box; it doesn't replace it. The box limits what any code can reach at all; tripwire asks you about the risky steps inside those limits.

**Root mode.** `--policy-mode root` keeps the approved-root model: every exec outside an approved tree waits for a ticket, delegating spawns always do, and children of an approved root pass while its subtree is alive (the class table in [Policy](#policy)). It needs more signatures (3,162 a day on the journal above) and a signature covers everything a command starts.

## Config

`~/.wardend/config.json` is read by default when it exists; all fields are optional, flags override them, and `--trust` appends to `trusted_devices`. This is `deploy/config.example.json`:

```json
{
  "version": 1,
  "mode": "observe",
  "policy_mode": "tripwire",
  "ticket_ttl": "120s",
  "ts_window": "60s",
  "max_pending": 64,
  "linger": "2s",
  "toctou_roots": "stop",
  "toctou_service": "off",
  "http_listen": "127.0.0.1:8787",
  "public_url": "https://wardend.example.com",
  "pair_code_ttl": "5m",
  "ntfy_url": "",
  "gateway_db": "off",
  "trusted_devices": []
}
```

| Field | Default | Meaning |
|---|---|---|
| `version` | `1` | Version of the config format. No key means 1. A config with a newer version than this wardend understands stops it at start (exit 2, "update wardend"): it may mean something this build would read wrong. |
| `mode` | `observe` | `observe`, `deny-list`, `ticket`. |
| `policy_mode` | `tripwire` | `tripwire` or `root` ([Policy modes](#policy-modes)). |
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
| `max_pending` | `64` | Queue limit (the tripwire replay peaked at 34 cards in two minutes, which is the ticket TTL). |
| `linger` | `2s` | Serve the rest of the tree after the child exits. |
| `trusted_devices` | `[]` | `{id, pubkey?, alg?, name?}`. `pubkey` is base64url or hex. `alg` is absent (Ed25519)<!-- feature:appleWatch --> or `es256` (Apple Watch)<!-- /feature -->. `wardend pair approve` adds devices here. |
| `http_listen` | `127.0.0.1:8787` | wardend's own HTTP endpoint for the apps and pairing; `off` turns it off. |
| `public_url` | `http://<http_listen>` | The address of that endpoint as the phone sees it (it goes into the pairing QR). |
| `pair_code_ttl` | `5m` | Lifetime of a one-time pairing code. |
| `ntfy_url`, `ntfy_token` | none | `https://ntfy.sh/<secret topic>`: a "new card" notification, at most once every 10 s; optional Bearer token for a private ntfy server. See **ntfy** below. |
| `gateway_db` | `off` | `off`, `auto` (`~/.openclaw/state/openclaw.sqlite`, read-only) or a path to the OpenClaw state DB. |
| `toctou_roots`, `toctou_service` | `stop`, `off` | `stop`, `poll` or `off`. |
| `host` | hostname | Host name written into envelopes. |
| `apns` | none | <!-- feature:appleWatch -->`{key_file, key_id, team_id, topic_ios, topic_watch}`<!-- /feature --><!-- feature:!appleWatch -->`{key_file, key_id, team_id, topic_ios}`<!-- /feature -->: push notifications through APNs, see [<!-- feature:appleWatch -->Apple Watch and APNs<!-- /feature --><!-- feature:!appleWatch -->Push notifications (APNs)<!-- /feature -->](../apns/). |
| `push_tokens` | `<state_dir>/push_tokens.json` | Push tokens registered by the apps. |

**Keys.** Trust comes only from this config. A `pubkey` in the config is pinned. Without one, and with `gateway_db` set to `auto` or a path, wardend reads the key of that device id from the gateway's paired-devices table (read-only, cached 30 s); with the default `off` there is no such lookup. If both exist and differ, decisions are rejected with `pubkey_conflict` instead of silently picking one.

**Unknown keys.** A key wardend doesn't know, in the config or in the policy file, is ignored with a warning in stderr at start (journald under systemd) and in [`wardend config-check`](#wardend-config-check), not an error: a config written for a newer wardend with a new optional field still starts an older one. A typo in a key therefore leaves the default value (`"moed": "ticket"` runs in `observe`); the warning names the key and the nearest known one. A change that an older wardend would read wrong raises `version` instead.

**ntfy.** With `ntfy_url`, each new card triggers a push to the topic with the body "New request to approve" and the title `WardenClaw`; bursts are merged (one push per 10 s). Nothing about the command goes to the topic. But whoever knows the topic name sees when cards appear and can send pushes to that topic. Use a long random topic name, or your own ntfy server with `ntfy_token`.

## Policy

In `root` mode, first match wins:

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

In `tripwire` mode ([Policy modes](#policy-modes)):

| Class | What | Decision |
|---|---|---|
| `logged` | no rule fired | allow, journaled |
| `service` | harness housekeeping from a pack or `service_allow` | allow, rule `pack:<pack>/<id>` |
| `tripwire` | a rule fired; the record has `category`, `rule` and `detail` | needs a ticket |
| `implied` | a rule of the same family fired under an approved exec, at most 10 minutes after the approval | allow, `rootPid` |
| `refuse` | `sudo` and friends under `no_new_privs` | `EPERM` at once, no card |
| `deny_always` | as above | `EPERM` |

A policy file has lists of rules: `deny_always`, `service_allow`, `delegating` (used in `root` mode) and `tripwire` (your own trip rules, used in `tripwire` mode), plus <!-- feature:hardwareKey -->`require_hardware`, <!-- /feature -->`zones` and `guard`. A file without `zones` or `guard` gets the built-in ones. All fields set in a rule must match (AND). Regexes are Go RE2 and are **not anchored** unless you write `^…$`. `${AGENT_HOME}`, `${ANY_HOME}` and pack variables are substituted, escaped.

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
| `inherit` | `service_allow` and packs, `root` mode: the probe's own helpers inherit |
| `category` | `tripwire` rules: the category of the card, `custom` by default |

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

**digest** = `sha256(canonicalJson(envelope))`; the pending id is `wd-` plus the first 32 hex characters of the digest. Canonical JSON follows `JSON.stringify` rules byte for byte (keys sorted by UTF-16 code units, minimal escaping, ECMAScript number formatting), so Go, the plugin and the app compute the same digest; shared test vectors keep them in sync. An envelope with invalid UTF-8 can't be built and the exec gets `EPERM`.

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

`meta` can also carry `delegating` and `insideRoot` for delegating spawns.

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

`~/.wardend/journal.jsonl`, mode 0600, append-only. Each record: `hash = sha256(prevHash + canonicalJson({seq, ts, kind, data, prevHash}))`, `sig = Ed25519(supervisor key, "wardenclaw.journal.v1\n" + hash)` (the prefix keeps a journal signature apart from anything else the supervisor key signs). Kinds: `start` (mode, policy mode, harness packs, command, journal key, trusted devices), `exec` (one per exec: pid, path, argv, cwd, class, rule, in `tripwire` also category and detail, decision, errno, latency; for tickets also the digest, envelope and signed ticket), `decide_reject`, `toctou_kill`, `root_exit`, `signal`, `stop`, `panic` (see below). About 760 bytes per exec; there is no rotation yet.

**`panic`.** A bug that panics in one of wardend's long-lived goroutines (the exec handler, the notification loop, sweep, signal forwarding, the child wait, the socket server, the ntfy and push loops) still ends wardend: fail-closed, the filter stays and every exec of the tree fails until systemd restarts wardend. Before exiting (code 2) wardend writes `wardend: panic in <goroutine>: <value>` and the stack to stderr (journald), then, if the journal answers within 2 s, a record `panic` with `goroutine`, `value` and the first 4 KB of `stack`. When the journal is busy, the record is skipped and stderr says so; the stack in journald is enough to report the bug.

## Running the OpenClaw gateway under wardend (systemd)

> This is the single-user setup (a drop-in for a user unit). The recommended setup is a root system unit with the harness under its own user: see [Install, hardened](../install/#hardened-install-recommended).

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

Run this from `daemon/` of the repository (after the single-user install script, from `~/.local/share/wardend`):

```bash
mkdir -p ~/.wardend && chmod 700 ~/.wardend
# only if you have no config yet: an existing one holds your paired devices
test -e ~/.wardend/config.json || install -m 600 deploy/config.example.json ~/.wardend/config.json
GW="$(command -v node) $(npm root -g)/openclaw/dist/index.js gateway --port 18789"   # as in your ExecStart
mkdir -p ~/.config/systemd/user/openclaw-gateway.service.d
sed "s#@GATEWAY_CMD@#$GW#" deploy/wardend-observe.conf > ~/.config/systemd/user/openclaw-gateway.service.d/wardend.conf
grep '^ExecStart=.' ~/.config/systemd/user/openclaw-gateway.service.d/wardend.conf   # both paths after -- must be absolute
```

Put the address of your endpoint into `public_url` of the config; devices get into it through `wardend pair`. Then restart the gateway:

```bash
systemctl --user daemon-reload && systemctl --user restart openclaw-gateway
systemctl --user status openclaw-gateway     # Main PID is wardend, node is its child
wardend status
```

Observe for a few days, then list what would have needed a ticket. In the default `tripwire` policy mode that is the class `tripwire`:

```bash
jq -r 'select(.kind=="exec" and .data.class=="tripwire") | "\(.data.category)  \(.data.argv|join(" "))"' \
  ~/.wardend/journal.jsonl | sort | uniq -c | sort -rn | head -50
```

In `root` policy mode the journal has the classes `root` and `delegating` instead: select `(.data.class=="root" or .data.class=="delegating")` in the same command. Or let wardend count it without printing any argv: `wardend replay --journal ~/.wardend/journal.jsonl --config ~/.wardend/config.json` (cards a day, peaks, categories; add `--policy-mode root` to compare). In `tripwire` mode housekeeping rarely needs a card; in `root` mode add everything that is housekeeping (cron jobs, browser, `openclaw` subcommands, MCP servers, plugins) to `~/.wardend/policy.json` and set `"policy"` in the config.

**Stage 2, ticket**: the same drop-in with `--mode ticket` (as in `deploy/wardend-ticket.conf`). First make sure the phone is paired and online: in `ticket` every command that trips a rule (every new root in `root` mode) waits for a signature, and without a trusted device it fails after the TTL.

```bash
wardend pair list     # your phone must be listed under trusted devices
```

Then switch the mode in place, so the gateway command you checked in stage 1 stays as it is:

```bash
chmod 600 ~/.wardend/config.json    # a group-writable config stops wardend in ticket mode
sed -i 's/--mode observe/--mode ticket/' ~/.config/systemd/user/openclaw-gateway.service.d/wardend.conf
systemctl --user daemon-reload && systemctl --user restart openclaw-gateway
```

To go back to observe, run the same `sed` with the two modes swapped and restart. The app long-polls the HTTP endpoint directly; the OpenClaw plugin `wardenclaw-gate` can also relay pending execs through the gateway when the app's OpenClaw adapter is on, but that path is optional.

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

**`Resource temporarily unavailable` (EAGAIN).** The ticket queue is full (`max_pending`, default 64). The exec is refused immediately rather than queued or allowed. Raise `--max-pending` or approve faster.

```console
$ wardend run --mode ticket --ttl 2s --max-pending 1 -- sh -c '/usr/bin/ssh -V & /usr/bin/ssh -V & /usr/bin/ssh -V & wait'
sh: 1: /usr/bin/ssh: Resource temporarily unavailable
sh: 1: /usr/bin/ssh: Resource temporarily unavailable
sh: 1: /usr/bin/ssh: Operation not permitted
```

(Two overflowed the queue, the third waited and expired.)

**`Operation not permitted` (EPERM).** A `deny_always` rule matched, a device signed deny, the ticket TTL expired, or `sudo`, `su` or `pkexec` was refused (class `refuse`: setuid can't raise privileges under `no_new_privs`). `wardend journal` shows the class, rule and reason.

**`__child: seccomp(SET_MODE_FILTER, flags=0x28): operation not permitted` and `listener fd not received`.** You are starting wardend from inside a tree that is already supervised by wardend (for example, a shell of an agent running under the gateway). A nested notification listener is refused on purpose: otherwise a process could install its own filter and answer `CONTINUE` around the outer supervisor. Run it outside the supervised tree.

**Duplicate or endless exec notifications.** wardend always sets `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (kernel 5.19+). Without it, any signal to the target (including Go's runtime `SIGURG`) cancels the notification and restarts `execve`: an early spike logged 662 duplicates of one exec in 40 s. On an older kernel the filter can't be installed; upgrade the kernel.

**`setsid: Operation not permitted` inside an approved command, or a second approval request** (`root` mode; in `tripwire` `setsid` itself needs no card). `setsid`, `systemd-run`, `docker`, `tmux`, `ssh` and other delegating spawns are always a new root and need their own ticket. A process orphaned before its first exec (double fork, background job whose parent already exited) also loses the link to its root and asks again. This is fail-closed. Also note: for `docker`, `ssh`, `systemd-run` and `tmux` the actual work runs in a daemon or host outside the tree, so approving that ticket approves whatever runs there.

```console
$ wardend run --mode ticket --policy-mode root --ttl 2s -- sh -c 'bash -c "setsid ls -d /tmp; echo setsid rc=\$?"'
bash: line 1: /usr/bin/setsid: Operation not permitted     # bash was approved, setsid was not
setsid rc=126
```

**Two cards for one action.** A Bash call from claude-cli can be seen both by the OpenClaw plugin hook and by wardend (as a root). Linking the two is on the roadmap.

**`mode "x": observe|deny-list|ticket`**, **`policy_mode "x": tripwire|root`** or **`toctou mode "x": stop|poll|off`**: a typo in the config or flags; wardend exits with code 2 before starting anything. [`wardend config-check`](#wardend-config-check) finds these, JSON errors (with line and column) and unknown keys before a restart.

**`config …: version N is newer than this wardend understands`**: the config was written for a newer wardend. Update wardend, or bring the config back to the format of this version.

**`wardend: panic in <goroutine>: …` in journald, wardend restarted.** A bug in wardend; the exec that was in flight failed (fail-closed). The stack follows the line, and the journal has a `panic` record when it could be written. Please report it with the stack.

## Limits

- Only `execve` and `execveat` are gated. Inside an approved root, interpreters (`python -c`, `bash -c`), `LD_PRELOAD`, file writes and network are not; in `tripwire` everything no rule catches runs (see [what tripwire doesn't see](#policy-modes)).
- Rules and packs recognise a tool by the name of the real file, not by its sha256; the packs are written by hand for claude-cli 2.1.283 and OpenClaw 2026.9.6.
- realpath is resolved in the supervisor's mount namespace; `unshare`, `nsenter` and `chroot` are delegating and need a ticket.
- Content swapped on the same inode between check and exec is not detected; the binary hash is not in the envelope yet.
- 32-bit compat syscalls return `ENOSYS`.
- No journal rotation<!-- feature:hardwareKey -->,<!-- /feature --><!-- feature:!hardwareKey --> and<!-- /feature --> no "same as before" approval cache<!-- feature:hardwareKey -->, no hardware second signature<!-- /feature --> yet.
