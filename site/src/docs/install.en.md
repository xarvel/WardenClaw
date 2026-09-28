---
title: Install wardend
description: Install wardend with one command. The default hardened install runs wardend as a root system service and the agent harness as a separate unprivileged user, so the model cannot turn the guard off. Single-user is for a quick try only.
---

# Install wardend

```shell
%INSTALL_CMD%
```

One command, one question. The script finds the OpenClaw gateway service of the user who ran `sudo` (`~/.config/systemd/user/openclaw-gateway.service`), shows what it is about to do and, after a `y`, **wraps that gateway in place**: the same user, the same home, the same command and environment, now started by wardend as root's child under the exec gate. Every launch outside an approved subtree is a card on your phone, and until a phone is paired nothing the agent launches will run, so the install ends with the pairing. Your chat with the agent does not change; with the app in observe mode it signs every card while you watch what the agent asks for.

What changes on the machine, so that the model cannot turn the guard off: the old user service is disabled and `wardend` (a root system service) starts the same command; the user leaves the `sudo` and `docker` groups, and root stays with a human account (an existing sudoer, else `<user>-admin` created with the same ssh keys and sudo without a password: log in as that account from now on); the agent's `sudo` and `docker` become requests through [rootexec](../cli/#wardend-rootexec): every request is a card on your phone (the read-only docker and systemctl verbs are rules the app may sign by itself). It starts wardend, prints the pairing QR and returns when the phone is approved. What it does, step by step: [Hardened install](#hardened-install-recommended).

The same command run again over a wrapped gateway wraps it again: the unit is re-rendered from the new release's template (the previous one is kept as `wardend.service.wardend-bak` and the changed lines are printed, so you see what the new template does before it is written), the user leaves the privileged groups again if he got them back, the old user service stays disabled, and wardend restarts (with the gateway) only if the unit or the binary changed. That is the upgrade of a wrapping install, and the way back after a rollback to the user service. To update the binaries only and leave the unit as it is, add `--no-unit`.

A dry run that changes nothing and needs no root:

```shell
curl -fsSL %INSTALL_URL% | sudo sh -s -- --dry-run
```

No OpenClaw service found, or another harness? The flags describe it; `--yes` asks nothing:

```shell
curl -fsSL %INSTALL_URL% | sudo sh -s -- --agent-user agent --rw-paths /srv/projects \
  --harness-cmd "/usr/bin/node /opt/openclaw/dist/index.js gateway --port 18789" --yes
```

`--uninstall` removes wardend and keeps the journal ([Uninstall](../uninstall/)), `--version vX.Y.Z` pins a release, `--single-user` is the trial variant below, `--help` lists the rest.

### Before you pipe into sudo

wardend is a security tool, so don't take the one-liner on faith. The script refuses any archive that doesn't match the release's checksums, but the script itself reaches you over TLS from this domain. The file here is a copy of `install.sh` from the latest release, so its checksum is in that release's `checksums.txt`. To check it, download it from here and the checksums from GitHub, compare them, read the script, run it. Each step runs only if the one before it succeeded:

```shell
U=%RELEASES_URL%/latest/download
curl --proto '=https' --tlsv1.2 -fsSLO %INSTALL_URL% &&
  curl --proto '=https' --tlsv1.2 -fsSLO $U/checksums.txt &&
  sha256sum --ignore-missing -c checksums.txt &&
  less install.sh &&
  sudo sh install.sh
```

Releases are not signed, so this check tells you that the script is the one listed in the release's `checksums.txt` and lets you read it before it runs; it does not tell you who built the release. For a few minutes after a new release the site may still serve the previous `install.sh`, and `sha256sum` reports `FAILED`: try again a bit later. At any other time a mismatch means the file here is not the one from the release: don't run it, and [report it privately](../../security/).

Both files come from GitHub, so the check above catches a tampered copy of the script on this site or on the way to you, not a takeover of the repository or of the GitHub account: that is the trust boundary. An upgrade doesn't need this site at all (below).

<details>
<summary><strong>Build from source</strong></summary>

Go 1.26, no cgo. Then run the same root-side script by hand in [Step 2](#step-2-run-the-installer):

```bash
git clone %REPO_URL%
cd wardenclaw/daemon
go build -o wardend .
```

</details>

## Hardened or single-user

There are two ways to run wardend. They differ in one thing that decides everything: whether the agent harness runs as the same Linux user as wardend.

| | **Hardened (recommended)** | Single-user (dev / quick try) |
|---|---|---|
| wardend runs as | root, system service | your user |
| harness runs as | a separate unprivileged user, child of wardend | your user |
| binary, config, key, journal, unit | owned by root | owned by your user |
| can the model turn wardend off? | **no**, the kernel refuses by UID | **yes**, without a single `execve` |
| use it for | any real agent with a shell | trying wardend out for an evening |

The reason is simple. wardend gates `execve`/`execveat`. Signals, `ptrace`, `/proc/<pid>/mem` and file writes are decided by the kernel from the UID. If the model runs as the user that owns wardend, it can `kill` the supervisor or rewrite its config without running any program. The full analysis is in [Why the model can't turn wardend off](../tamper-resistance/).

## Requirements

- Linux **5.19 or newer**. wardend needs `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`, which appeared in 5.19; without it every signal to a waiting process restarts `execve` and floods you with duplicate cards. x86_64 or arm64 (32-bit ARM is not supported yet).
- systemd.
- root on the host (for the hardened install).
- `curl` or `wget`.
- Optional: the Yama LSM, for `kernel.yama.ptrace_scope=2` as a second layer. Check with `ls /proc/sys/kernel/yama`. Without it the UID boundary still holds.

The installer checks all of this and stops with a clear message.

```bash
uname -r                               # 5.19 or newer
ls /proc/sys/kernel/yama 2>/dev/null   # present = Yama available
```

## Hardened install (recommended)

### What you end up with

```
systemd
 └─ wardend  (root)            /usr/local/bin/wardend, system unit, --require-hardened
     └─ harness  (agent)       seccomp filter installed, then uid/gid dropped by wardend
         └─ tools the agent runs (agent), every execve gated
```

| Path | Owner, mode | What |
|---|---|---|
| `/usr/local/bin/wardend` | root, 0755 | binary |
| `/etc/wardend/` | root, 0700 | `config.json` (0600), your `policy.json` |
| `/var/lib/wardend/` | root, 0700 | `supervisor.key`, `journal.jsonl`, `wardend.sock` |
| `/etc/systemd/system/wardend.service` | root, 0644 | system unit |
| `/usr/local/share/wardend/` | root, 0755 | `deploy/`, `redteam/`, `uninstall.sh` of the installed release |
| `/var/lib/agent/` | agent | the harness's home and data |

What makes it hold:

- **`--child-user agent`.** wardend starts as root, installs the seccomp filter on its helper, resets its `oom_score_adj` to 0, then calls `setgroups`, `setgid`, `setuid` (uid last, uid 0 refused) and only then `exec`s the harness. wardend itself stays root, out of the agent's reach.
- **`--require-hardened`.** At startup wardend refuses to run unless its binary, config and key are owned by root and not group- or world-writable, and the state directory is not wider than 0700. A broken install becomes a hard failure, not a silent weakness. An environment variable cannot turn this check off.
- **systemd sandboxing:** `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, `LockPersonality`. Writable paths are listed explicitly in `ReadWritePaths`. `RestrictSUIDSGID` is deliberately absent: systemd implements it with a seccomp filter that answers `openat2` with `ENOSYS`, and OpenClaw takes its gateway lock with `openat2` without a fallback, so the gateway would not start. The one-command install that wraps an existing OpenClaw in place also drops `ProtectHome`, `PrivateTmp`, `ProtectSystem` and `ProtectKernelTunables`: they would bind the root commands the agent runs through the gate, and the uid and the filter are the boundary.
- **`OOMScoreAdjust=-500`.** Under memory pressure the kernel kills the harness before the supervisor. The value is inherited on fork, so wardend resets the child back to 0.
- **`kernel.yama.ptrace_scope=2`** (if the kernel has Yama): `ptrace` only with `CAP_SYS_PTRACE`. wardend as root keeps working; the agent cannot trace anything at all.
- **The agent user has no `sudo` and is not in `sudo`, `wheel`, `admin`, `docker`, `lxd`, `incus`, `libvirt` or `disk`.** Each of these is root in disguise (`docker run -v /:/host` is enough), and the whole boundary rests on the agent not being root.
- **No systemd --user manager for the agent.** By default logind lets any user enable linger for itself over D-Bus, without running a single program. The user manager systemd then starts for it is a child of PID 1, not of wardend, so whatever it runs (`systemd-run --user`, units in `~/.config/systemd/user`) is outside the gate. The installer adds a polkit rule, `/etc/polkit-1/rules.d/60-wardend-agent.rules`, that refuses the agent user every polkit action, and turns linger off if it was on.

The sandbox options apply to the whole unit, including the harness. That is on purpose, and it has two consequences you'll meet below: the harness can write only to its home and the paths you list, and nothing it needs may live under `/home` or `/root`.

### Step 1. Install the harness system-wide

The unit hides `/home` and `/root` from the harness (`ProtectHome`), so the harness program itself must live elsewhere, for example under `/opt/<harness>` or `/usr/local`, owned by root. If it lives in your home (nvm, `~/.local`), reinstall it there: the agent had better not be able to rewrite its own harness anyway. The installer refuses a harness command with paths under `/home` or `/root`.

Create the shared working directories you want to give the agent (for example `/srv/projects`) now: every path in `--rw-paths` must exist.

### Step 2. Run the installer

```shell
%INSTALL_CMD%
```

In order, the script:

1. checks Linux, the CPU architecture, the kernel (5.19+), systemd and root;
2. downloads `checksums.txt` and the archive for your architecture from the GitHub release, checks the archive's SHA-256 against the list, and checks that the archive's version is the one you asked for and not older than the installed one. Any mismatch stops it before anything is written;
3. asks for the agent user (default `agent`), the harness command and extra writable directories, then shows a summary and asks to confirm;
4. copies `deploy/`, `redteam/` and `uninstall.sh` of the release to `/usr/local/share/wardend/` and runs `deploy/hardened-install.sh` from it: creates the user if needed (`useradd --system --home-dir /var/lib/agent --shell /usr/sbin/nologin`), stops if it has privileged groups or sudo rights, installs the binary, creates `/etc/wardend` and `/var/lib/wardend` (root, 0700), writes `config.json` (0600, `"require_hardened": true`, `"child_user"`), renders the unit, sets `ptrace_scope`, writes the polkit rule that keeps the agent from starting its own systemd --user manager and runs `daemon-reload`;
5. when it wraps an existing gateway, starts wardend and pairs the phone: it prints the QR of `wardend pair start` and returns only after the phone is approved (skipped on an upgrade whose config already names a trusted device; without a terminal it prints `sudo wardend pair start` for you to run from your own terminal). With flags it prints the next steps instead: start wardend, then pair.

The flag install does **not** move data, stop your old service or start wardend. Run it again at any time: an existing config is left as is, and with an existing flag install and no `--harness-cmd` it only upgrades the binary (a `systemctl restart wardend` applies it); a changed unit template is reported and re-rendered only with `--harness-cmd` again. A re-run over a wrapping install re-renders the unit itself (above).

**Upgrades.** Run the copy the install left behind, not a new download:

```shell
sudo /usr/local/share/wardend/install.sh
```

It fetches the latest release from GitHub and checks it the way a first install does. It doesn't depend on this site: whoever changed `install.sh` here would not touch the installed copy, and a piped script checks only itself. A release older than the installed one is refused; going back on purpose takes `--version vX.Y.Z --allow-downgrade`.

The upgrade takes effect on `systemctl restart wardend`, and that restarts the agent: wardend runs the harness as its child, so every session of the agent ends, and requests still waiting for a decision are denied (the command gets `EPERM`). Upgrade at a quiet moment, and check the config before the restart:

```bash
sudo wardend status | jq .pending   # 0: nothing waits for a decision
sudo wardend config-check --config /etc/wardend/config.json && sudo systemctl restart wardend
```

Upgrade wardend and the app together. The app checks the protocol version of the server: after a protocol change it says which part to update and signs no decisions until it is updated. `wardenctl` checks the same and exits with code 4 ([External approvers](../cli/#external-approvers-and-test-automation)).

| Flag | Default | Meaning |
|---|---|---|
| `--harness-cmd` | asked | harness command, absolute paths, nothing under `/home` or `/root` |
| `--agent-user` | `agent` (asked) | harness user, created if missing |
| `--agent-home` | existing home or `/var/lib/<user>` | must exist; under `/home` the unit gets `ProtectHome=tmpfs` and binds only that directory in |
| `--rw-paths` | empty (asked) | extra writable directories, space-separated, must exist |
| `--ptrace-scope` | `2` | `skip` to leave the sysctl alone |
| `--root-exec` | on for the wrapping install, off with flags | the rootexec socket: the agent may ask wardend to run one command as root (`wardend rootexec -- …`, or plain `sudo …` and `docker …` through shims on the harness PATH), judged by the policy's `root_exec` list (every request is a card; the built-in read-only docker and systemctl rules are ones the app may sign by rule); `--no-root-exec` turns it off for the wrapping install; `daemon/docs/rootexec.md` |
| `--admin-user` | an existing sudoer, else `<user>-admin` | the human account that keeps root when the agent user leaves the sudo and docker groups (wrapping install) |
| `--with-wardenctl` | off | also install the terminal approver (keep it on another machine if you can) |
| `--no-unit` | off | on a re-run over an installed wrapping install: update the binaries only, keep the systemd unit as it is (by default the unit is re-rendered from the new template, the previous one is kept as `.wardend-bak`) |
| `--dry-run` | off | print every step, change nothing, no root needed |
| `--yes` | off | no questions; a missing `--harness-cmd` is an error |
| `--allow-downgrade` | off | install a release older than the installed one |

The script stops with an error if the kernel is older than 5.19, the harness or its home is under `/home`, a writable path doesn't exist, or the agent user is in a privileged group or has sudo rights.

**From source**, the same root-side script takes environment variables (`HARNESS_CMD`, `AGENT_USER`, `AGENT_HOME`, `RW_PATHS`, `PTRACE_SCOPE`, `ROOT_EXEC`) and the path to your build. Dry run first:

```bash
DRY_RUN=1 AGENT_USER=agent RW_PATHS="/srv/projects" \
  HARNESS_CMD="/usr/bin/node /opt/openclaw/dist/index.js gateway --port 18789" \
  deploy/hardened-install.sh ./wardend
```

If the output looks right, run the same with `sudo` and without `DRY_RUN=1`, as a separate step:

```bash
sudo AGENT_USER=agent RW_PATHS="/srv/projects" \
  HARNESS_CMD="/usr/bin/node /opt/openclaw/dist/index.js gateway --port 18789" \
  deploy/hardened-install.sh ./wardend
```

To check the user by hand:

```bash
id agent               # only its own group
sudo -l -U agent       # "not allowed to run sudo"
```

### Step 3. Move the harness data (manual)

This step is not automated: every harness keeps its state differently. The goal is to give the agent user exactly what the harness needs and nothing that belongs to you.

1. **Stop the harness** and disable its current service so it can't come back around wardend (for a user unit: `systemctl --user disable --now <unit>`; also remove a single-user wardend drop-in if you had one, [like this](../uninstall/#uninstall-the-trial-install)).
2. **Copy the harness state** into the agent's home and give it to the agent. With OpenClaw as an example:

   ```bash
   # once: a second copy would overwrite what the agent's harness has written since
   sudo test -e /var/lib/agent/.openclaw || sudo rsync -a ~/.openclaw/ /var/lib/agent/.openclaw/
   sudo chown -R agent:agent /var/lib/agent
   sudo grep -rn --include='*.json' "$HOME" /var/lib/agent/.openclaw/   # fix absolute paths to your old home
   ```

   API keys and tokens go with it, mode 0600. The harness needs them, so the agent can read them anyway; what changes is that it no longer reads *your* keys.
3. **Shared working directories.** Grant access to exactly the directories the agent works in, without handing over ownership. Either a group:

   ```bash
   sudo groupadd agentwork
   sudo usermod -aG agentwork agent
   sudo usermod -aG agentwork "$USER"          # if you edit the same files
   sudo chgrp -R agentwork /srv/projects
   sudo chmod -R g+rwX /srv/projects
   sudo find /srv/projects -type d -exec chmod g+s {} +
   ```

   or ACLs:

   ```bash
   sudo setfacl -R -m u:agent:rwX -m d:u:agent:rwX /srv/projects
   ```

   Don't share a repository you also work in as yourself. Anything the agent can write there can later run as you: `.git/hooks`, `.git/config`, `.envrc`, a `Makefile`, npm or pip scripts, editor tasks. That is the escape step 4 forbids. Give the agent its own clone, take its work through a bare repository that you own (the agent pushes, you fetch), and review the changes before you run anything from them. Shared directories are for data, not for code you execute.

   These directories must be in `--rw-paths` (they become `ReadWritePaths`). Added one later? Run the installer again with the full `--harness-cmd` and `--rw-paths` to re-render the unit.
4. **Never give the agent write access** to anything that runs as you or as root: your home, dotfiles (`~/.bashrc`, `~/.profile`), `~/.local/bin`, directories on your `PATH`, `~/.config/systemd/user`, crontabs, git hooks of repositories you work in as yourself. A write there is code that runs as you next time you log in, and you have `sudo`. That is the same escape as the single-user install, just one step longer.

The agent's own home may be under `/home` (`--agent-home /home/<user>`, or an existing account's home): the installer then renders `ProtectHome=tmpfs` plus `BindPaths=` for that one directory, and every other home stays hidden. Any other data that must stay under `/home`: move it (for example to `/srv`, or under the agent's home), or edit the unit by hand to add it to `BindPaths=`.

### Step 4. Start and pair

```bash
sudo systemctl enable --now wardend
systemctl status wardend                              # Main PID is wardend
ps -o user,pid,args --ppid "$(systemctl show -p MainPID --value wardend)"   # harness as agent
sudo journalctl -u wardend -n 50 | grep selfcheck     # no FATAL, no warnings
sudo wardend status
```

Until a phone is paired nothing the agent launches will run: every launch is a card, and a card nobody signs expires into `EPERM` after the TTL (`wardend status` warns about it). The wrapping install pairs the phone itself at the end; after a flag install, pair from your own terminal, never from a chat with the agent. The socket belongs to root, so the client commands run with `sudo`:

```bash
sudo wardend pair start
```

It prints the QR code, waits for the phone, shows the device's name and key fingerprint and asks `Approve this device? [y/N]`. Compare the fingerprint with the phone screen and answer `y`. From a script, or to approve later: `sudo wardend pair list`, then `sudo wardend pair approve <id>`.

The app reaches wardend through the relay, exactly as in the single-user setup: wardend dials out, no port or tunnel is needed. Where to get the app: [Get the app](../app/); pairing, a check and troubleshooting: [Connect the phone](../connect-phone/).

### Step 5. Watch with the app in observe, then choose its mode

The gate always asks; what changes is who signs. Put the app in **observe** for the first days: it signs every card automatically, and the feed and the journal show what the agent launches and which risk hints come with it (remote execution, leaving the gate, package installs, publishing, secrets, destructive commands). Let the agent do its normal work, then let wardend count what the app signed. [`wardend replay`](../cli/#wardend-replay) runs the journal through the same classifier and prints aggregates only, no argv:

```bash
sudo wardend replay --journal /var/lib/wardend/journal.jsonl --config /etc/wardend/config.json
```

Read `cards` (how many a day you would answer by hand), `peaks` (how many arrive within 2 minutes, the ticket TTL, and how many at night), `categories` (why) and `top rules (cards)` (which hints fire most). To see the commands themselves:

```bash
sudo jq -r 'select(.kind=="exec" and (.data.class=="root" or .data.class=="delegating")) | "\(.data.category)  \(.data.argv|join(" "))"' \
  /var/lib/wardend/journal.jsonl | sort | uniq -c | sort -rn | head -50
```

If a card comes up for routine you trust (a scheduled job, a script of the harness), name it by exact pattern in `service_allow` of a policy file in `/etc/wardend`, so it stays root-owned: such a launch is a `service` card the app signs by rule, in every mode; a launch with a risk hint never passes as service. Your own hint rules go to `tripwire` in the same file ([Policy](../cli/#policy)):

```bash
# only if there is no policy yet: never overwrite the rules you have added
sudo test -e /etc/wardend/policy.json ||
  sudo sh -c 'umask 077; /usr/local/bin/wardend policy-defaults > /etc/wardend/policy.json'
sudoedit /etc/wardend/policy.json
```

Set `"policy": "/etc/wardend/policy.json"` in `/etc/wardend/config.json` and restart:

```bash
sudoedit /etc/wardend/config.json
# a config wardend can't read would stop it, and the agent with it: check before the restart
sudo wardend config-check --config /etc/wardend/config.json && sudo systemctl restart wardend
```

[`wardend config-check`](../cli/#wardend-config-check) reads the config and the policy it names the way wardend does at start, and starts nothing. It reports JSON errors with line and column, unknown config keys (an error: wardend would not start, so a typo can't silently leave the default; in the policy file an unknown key is a warning), values wardend would refuse<!-- feature:hardwareKey -->, `hardware_keys` in a build without the second factor<!-- /feature --> and a config without a trusted device. Exit code 0 means wardend will start with these files.

Once the stream looks like something you can answer, switch the app: **delegate** lets its on-device judge sign by its rules and brings the rest to you; **manual** brings every card to you. Nothing changes on the server for that, and no restart is needed. The phone must stay paired and online: a card nobody signs expires into `EPERM`.

### Step 6. Verify: redteam as the agent

`redteam/hardened-check.sh` runs **as the agent user** and tries every cross-process and file vector against the installed wardend. It is harmless: signal 0 instead of SIGKILL, open-for-append without writing, reads without printing.

```bash
sudo -u agent bash -s < /usr/local/share/wardend/redteam/hardened-check.sh
```

```console
=== Signals, ptrace, supervisor memory ===
  PASS: kill -0 812: Operation not permitted
  PASS: /proc/812/mem: denied (kernel ptrace check)
  PASS: systemctl kill wardend: Interactive authentication required.
=== wardend files ===
  PASS: /usr/local/bin/wardend: write denied
  PASS: /etc/wardend/config.json: directory closed
  PASS: /var/lib/wardend/supervisor.key: directory closed
  ...
=== Own systemd --user manager (runs commands outside the gate) ===
  PASS: linger is off for agent
  PASS: no systemd --user manager for agent
  PASS: loginctl enable-linger: Could not enable linger: Access denied
total: PASS=30 FAIL=0 SKIP=0
```

Every attack must be refused: `FAIL=0`. Any `FAIL` names the exact point where the install is not hardened. For extra confidence, ask the agent itself to run the script from inside the harness: the result must be the same.

### Rollback

A seccomp filter cannot be removed from a running tree, so every rollback restarts the harness. There are two:

- **Too many cards, or the phone is gone**: switch the app to observe, or pair a new phone; wardend stays and nothing restarts. The daemon has no mode to step back to: until a phone signs, every card expires into `EPERM`. See [Too many cards, or the phone is gone](../uninstall/#too-many-cards-or-the-phone-is-gone).
- **Remove wardend.** One command. It keeps the journal and a copy of the config in `/var/lib/wardend` and doesn't touch the agent user, its data or your working directories:

```shell
sudo /usr/local/share/wardend/uninstall.sh
```

What stays and why, `--purge`, running the harness again without wardend, the agent user and paired devices: [Uninstall](../uninstall/).

### Troubleshooting

- **`status=226/NAMESPACE`**: a path in `ReadWritePaths` doesn't exist. Create it or remove it from the unit.
- **`selfcheck FATAL` about a file owner**: the binary, config or key is not owned by root. `sudo chown root:root` it and make it not group- or world-writable.
- **The harness can't write somewhere**: that directory is not in `ReadWritePaths` (everything else is read-only under `ProtectSystem=strict`). Add it with group or ACL access for the agent.
- **The harness can't find its files**: they are under `/home` or `/root` (hidden by `ProtectHome`), or `HOME` points to the wrong place. The unit sets `HOME`, `USER` and `LOGNAME` to the agent's.

## Single-user install (dev / quick try)

> **Only for trying wardend out.** A model running with the same user's rights can turn wardend off: kill it, trace it, rewrite its config or unit, and restart the harness without the gate, all without a single `execve`. In this mode wardend is defense in depth against unwanted exec, not a guard the model cannot remove.

What stays open, compared with the hardened install:

| Vector | Single-user | Hardened |
|---|---|---|
| `kill` / `ptrace` / `process_vm_writev` the supervisor | **open** | closed by the kernel (different UID) |
| write the binary, config, key, journal | **open** | closed (root-owned, 0700 directories) |
| write `/proc/<supervisor>/mem` | **open** | closed by the kernel |
| rewrite the service unit, restart without the gate | **open** (user unit) | closed (root-owned system unit) |
| read the supervisor key and forge its signatures | **open** | closed |
| OOM-kill the supervisor | **open** | reduced (`OOMScoreAdjust`) |

Setup takes a minute and needs no root:

```shell
curl -fsSL %INSTALL_URL% | sh -s -- --single-user
```

or from source:

```bash
go build -o wardend . && install -D -m 0755 wardend ~/.local/bin/wardend
mkdir -p ~/.wardend && chmod 700 ~/.wardend
wardend run -- <harness command>
wardend pair start           # from another terminal: until a phone is paired nothing the harness launches will run
```

The installer pairs the phone itself at the end (`wardend pair start`, no `sudo` here). To wrap a systemd user service with it, see [Running the OpenClaw gateway under wardend](../cli/#running-the-openclaw-gateway-under-wardend-systemd) in the CLI reference. Don't set `ptrace_scope=2` here: a non-root wardend would lose access to `/proc/<pid>/mem` of its own children. When you're done trying, [remove it](../uninstall/#uninstall-the-trial-install) (`~/.local/share/wardend/uninstall.sh --single-user`, or `sh uninstall.sh --single-user` in `daemon/` of the source tree) and do the hardened install.

## Comparison

| Vector | Single-user | Hardened |
|---|---|---|
| Run a command around the gate (`execve`/`execveat`) | closed | closed |
| Nested seccomp notify filter answering "yes" | closed | closed |
| 32-bit / compat exec | closed | closed |
| `memfd_create` + `execveat`, `fexecve`, `ld.so` directly | closed | closed |
| TOCTOU: swap argv or the file after CONTINUE | closed | closed |
| Approve its own card over the socket or the relay | closed | closed |
| Forge or replay a ticket (the device key lives on the phone) | closed | closed |
| Read the supervisor key, forge journal and response signatures | **open** | closed |
| Flood the card queue | closed | closed |
| `kill` / `ptrace` / `process_vm_writev` the supervisor | **open** | closed by the kernel |
| Write the binary / config / key / journal | **open** | closed |
| Write `/proc/<supervisor>/mem` | **open** | closed by the kernel |
| Rewrite the unit and restart without the gate | **open** | closed |
| OOM-kill the supervisor | **open** | reduced |

What neither variant covers (work started outside wardend's process tree, what an approved root does with interpreters, files and network) is listed in [Why the model can't turn wardend off](../tamper-resistance/#honest-premises-and-out-of-scope).
