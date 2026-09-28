---
title: Try it in 5 minutes
description: Run a command under wardend without root and approve it from a second terminal with a test key. What the kernel stops, what a signed decision does, what the journal keeps.
---

# Try it in 5 minutes

**Time:** 5 minutes · **Needs:** Linux 5.19 or newer (arm64 or x86_64), `ssh` installed, no root · **Result:** a command waits in the kernel and runs only after a signed approval

The quickest honest look at the gate. There is no agent and no phone here: wardend supervises a small shell command, and a second terminal plays the phone with a test key. Nothing on this page protects a real agent; for that, use the [hardened install](../install/).

<div class="callout" role="note" data-if="no-release"><strong>No installer yet.</strong> The source is on <a href="%REPO_URL%">GitHub</a>. This site serves <code>install.sh</code> only after the first daemon release is published. The steps below are what you will run then; the outputs are real, from a Raspberry Pi 5.</div>

<div class="callout" role="note"><strong>Releases are not signed.</strong> The installer checks the downloaded archive against the release's <code>checksums.txt</code>, both fetched from GitHub over TLS, and nothing more: it trusts GitHub and the TLS path, like any <code>curl | sh</code>.</div>

If you have the WardenClaw app on a phone, the whole trial is one command after the install of step 1:

```shell
wardend wrap -- sh -c 'ls -d /tmp; ssh -V'
```

The first run prints a pairing QR code, waits for the phone, shows the device's name and key fingerprint and asks `Approve this device? [y/N]`; the command starts only after `y`. Every launch outside an approved subtree then waits for a signature from the phone (in the app's observe mode it signs them all while you watch; in manual you decide), and at the exit wardend prints one line: commands seen, asked, allowed, denied, expired, and where the journal is. Put your agent in place of the shell command: `wardend wrap -- claude "fix the failing test"`. Reference: [`wardend wrap`](../cli/#wardend-wrap).

Here wardend runs as the same user as the command. The command cannot get past the exec gate, but it can read wardend's files and edit its config between runs. The system install ([hardened install](../install/), `curl … | sudo sh`) is the one with real separation: wardend as a root service, the agent as its own user.

The steps below need no phone: a second terminal signs with a test key.

## 1. Install for your own user

```shell
curl -fsSL %INSTALL_URL% | sh -s -- --single-user
```

The script checks the archive against the release's checksums, asks for a confirmation and puts `wardend` into `~/.local/bin`, the reference files and `uninstall.sh` into `~/.local/share/wardend`, and an example config into `~/.wardend/config.json`. It warns when `~/.local/bin` is not in your `PATH`.

Check: `wardend --help` prints the usage and exits with code 0.

## 2. Run a command under the gate

wardend never decides on its own: every launch outside an approved subtree is a card, and a card nobody signs expires into `EPERM`. So the first step is a test device that can sign. Create it, then run a command that trusts it:

```bash
umask 077
mkdir -p ~/.wardend
wardend keygen > ~/.wardend/demo-device.txt   # test device; not in this shell's working directory
DEV=$(sed -n 's/^deviceId=//p' ~/.wardend/demo-device.txt)
PUB=$(sed -n 's/^pubkey=//p' ~/.wardend/demo-device.txt)
cd /tmp   # the command below must not start in the directory that holds the seed
wardend run --trust "$DEV:$PUB" --ttl 30s -- sh -c 'ls -d /tmp; git --version'
```

The `sh -c` is the supervised command itself and starts at once. `ls` is the first launch outside an approved subtree, a root card: it waits in the kernel, for 30 seconds at most (`--ttl`). In a second terminal that is not inside that command, sign every card with the test key as it comes, the way the app does in its observe mode:

```bash
wardend approve --key-file ~/.wardend/demo-device.txt --count 0 --timeout 60s
```

The first terminal prints `/tmp` and the git version, and at the exit a summary line, `wardend: execs=… denied=0 latency p50=… p95=… max=… exit=0` (the start line before it names the pid, the child, the socket and the journal). `wardend approve` is a "device in a terminal": it reads each waiting request from the socket, recomputes its digest from the envelope as the app does and signs the decision; `--count 0` keeps signing until `--timeout`.

## 3. Make a command wait for a signature

In the first terminal, run a command that trusts the test device, with a launch that leaves the gate:

```bash
wardend run --trust "$DEV:$PUB" --ttl 30s --quiet \
  -- sh -c 'ls -d /etc; ssh -V; echo "ssh rc=$?"'
```

`ls` is a root card again. `ssh` is a delegating spawn (execution leaves the gate), so it is a card of its own even after `ls` was approved, with the risk hint `remote` on it. Within the 30 seconds, in the second terminal, sign both:

```console
$ wardend approve --key-file ~/.wardend/demo-device.txt --count 2 --timeout 30s
allow wd-… argv=[ls -d /etc] -> map[decision:allow id:wd-… ok:true]
allow wd-805763d1887fcfb8a26269e7d38f1db9 argv=[ssh -V] -> map[decision:allow id:wd-805763d1887fcfb8a26269e7d38f1db9 ok:true]
```

The first terminal prints `/etc`, the OpenSSH version and `ssh rc=0`.

## 4. Deny it

Run the same `wardend run` command again. In the second terminal approve the first card and sign a deny for the second:

```bash
wardend approve --key-file ~/.wardend/demo-device.txt --match '^ls ' --count 1 --timeout 10s
wardend approve --key-file ~/.wardend/demo-device.txt --match '^ssh ' --deny --count 1 --timeout 10s
```

The first terminal prints:

```console
/etc
sh: 1: ssh: Operation not permitted
ssh rc=126
```

The same happens when no answer comes within the TTL (journal reason `ttl expired`): without a signature the command does not run. There is no mode in which wardend asks nobody.

## 5. Check the journal

Every exec and every decision lands in an append-only journal. Each record is hashed into a chain and signed by the supervisor's key:

```bash
wardend verify-journal ~/.wardend/journal.jsonl
```

On a valid chain it exits with code 0 and warns that the key came from the journal itself. To check authorship too, pass the supervisor's public key with `--pubkey`: [`wardend verify-journal`](../cli/#wardend-verify-journal).

## 6. Clean up

```bash
rm ~/.wardend/demo-device.txt                        # the test seed
~/.local/share/wardend/uninstall.sh --single-user
```

Details: [Uninstall the trial install](../uninstall/#uninstall-the-trial-install).

## What you saw, and what you did not

- The kernel held every launch outside an approved subtree until a signed decision came; children of an approved root run on their own while its subtree is alive, and a launch that leaves the gate (`ssh`, `docker`, `systemd-run`) is always a card of its own. The risky categories (remote execution, leaving the gate, package installs, publishing, secrets, destructive commands) are hints on the card, not a reason to pass. With the app, observe (sign everything, watch), delegate (a judge decides) or deciding by hand is the phone's choice. See [Cards, classes and risk hints](../cli/#policy-modes).
- The test seed was in `~/.wardend/demo-device.txt`, outside the command's directory, and it was not passed on the command line. The command still runs as you, so it can read that file if it is told the path. Do not point this demo at a real agent, and delete the file when you are done. A real approver is the phone or a laptop, and its key never sits on the server. `keygen` and `approve` exist for demos and tests.
- In this trial install a model running as the same user could turn wardend off. The hardened install closes that: [Why the model can't turn it off](../tamper-resistance/).

## Next

1. [Install wardend](../install/) on the server for real.
2. [Get the app](../app/) and [connect the phone](../connect-phone/).
