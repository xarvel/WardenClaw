---
title: Try it in 5 minutes
description: Run a command under wardend without root and approve it from a second terminal with a test key. What the kernel stops, what a signed decision does, what the journal keeps.
---

# Try it in 5 minutes

**Time:** 5 minutes · **Needs:** Linux 5.19 or newer (arm64 or x86_64), `ssh` installed, no root · **Result:** a command waits in the kernel and runs only after a signed approval

The quickest honest look at the gate. There is no agent and no phone here: wardend supervises a small shell command, and a second terminal plays the phone with a test key. Nothing on this page protects a real agent; for that, use the [hardened install](../install/).

<div class="callout" role="note" data-if="no-release"><strong>No installer yet.</strong> The source is on <a href="%REPO_URL%">GitHub</a>. This site serves <code>install.sh</code> only after the first signed daemon release. The steps below are what you will run then; the outputs are real, from a Raspberry Pi 5.</div>

<div class="callout callout-danger" role="note" data-if="test-key"><strong>Test key, not for production systems.</strong> Until the first release this site shows a test signing key, and the installer refuses to download anything signed with it. <a href="/docs/verify/">Verify releases</a></div>

## 1. Install for your own user

```shell
curl -fsSL %INSTALL_URL% | sh -s -- --single-user
```

The script checks the release signature, asks for a confirmation and puts `wardend` into `~/.local/bin`, the reference files and `uninstall.sh` into `~/.local/share/wardend`, and an example config into `~/.wardend/config.json`. It warns when `~/.local/bin` is not in your `PATH`.

Check: `wardend --help` prints the usage and exits with code 0.

## 2. Watch a command in observe

```console
$ wardend run --mode observe --gateway-db off -- sh -c 'ls -d /tmp; git --version'
wardend: mode=observe policy=tripwire pid=767159 child=767168 socket=/home/me/.wardend/wardend.sock journal=/home/me/.wardend/journal.jsonl
/tmp
git version 2.47.3
wardend: mode=observe execs=3 denied=0 latency p50=433us p95=518us max=518us exit=0
```

Everything runs. wardend counted the execs (`execs=3`) and wrote to the journal what each would need in `ticket` mode.

## 3. Make a command wait for a signature

In the first terminal, create a test device and run a command in `ticket` mode that trusts it:

```bash
umask 077
mkdir -p ~/.wardend
wardend keygen > ~/.wardend/demo-device.txt   # test device; not in this shell's working directory
DEV=$(sed -n 's/^deviceId=//p' ~/.wardend/demo-device.txt)
PUB=$(sed -n 's/^pubkey=//p' ~/.wardend/demo-device.txt)
cd /tmp   # the command below must not start in the directory that holds the seed
wardend run --mode ticket --gateway-db off --trust "$DEV:$PUB" --ttl 30s --quiet \
  -- sh -c 'ls -d /etc; ssh -V; echo "ssh rc=$?"'
```

`ls` prints `/etc` at once. `ssh` is remote execution, one of the rules of the default `tripwire` policy, so it now waits in the kernel, for 30 seconds at most (`--ttl`).

Within those 30 seconds, in a second terminal that is not inside that command, sign it with the test key:

```console
$ wardend approve --key-file ~/.wardend/demo-device.txt --count 1 --timeout 10s
allow wd-805763d1887fcfb8a26269e7d38f1db9 argv=[ssh -V] -> map[decision:allow id:wd-805763d1887fcfb8a26269e7d38f1db9 ok:true]
```

The first terminal prints the OpenSSH version and `ssh rc=0`. `wardend approve` is a "device in a terminal": it reads the waiting request from the socket, recomputes its digest from the envelope as the app does and signs the decision.

## 4. Deny it

Run the same `wardend run` command again, and in the second terminal sign a deny:

```bash
wardend approve --key-file ~/.wardend/demo-device.txt --deny --count 1 --timeout 10s
```

The first terminal prints:

```console
/etc
sh: 1: ssh: Operation not permitted
ssh rc=126
```

The same happens when no answer comes within the TTL: without a signature the command does not run.

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

- The kernel held `ssh` until a signed decision came, and `ls` ran at once. In the default `tripwire` policy mode only the execs that trip a rule wait: remote execution, leaving the gate, package installs, publishing, secrets, destructive commands. See [Policy modes](../cli/#policy-modes).
- The test seed was in `~/.wardend/demo-device.txt`, outside the command's directory, and it was not passed on the command line. The command still runs as you, so it can read that file if it is told the path. Do not point this demo at a real agent, and delete the file when you are done. A real approver is the phone<!-- feature:appleWatch -->, the watch<!-- /feature --> or a laptop, and its key never sits on the server. `keygen` and `approve` exist for demos and tests.
- In this trial install a model running as the same user could turn wardend off. The hardened install closes that: [Why the model can't turn it off](../tamper-resistance/).

## Next

1. [Install wardend](../install/) on the server for real.
2. [Get the app](../app/) and [connect the phone](../connect-phone/).
