---
title: Uninstall wardend
description: "Remove wardend with one command, or step back from ticket to observe. What the uninstaller removes, what it keeps for the audit trail and why, how to run the agent's harness again without wardend, and how to clean up phones, <!-- feature:appleWatch -->watches, <!-- /feature -->wardenctl, <!-- feature:hardwareKey -->the YubiKey, <!-- /feature -->APNs and the tunnel."
---

# Uninstall wardend

```shell
sudo /usr/local/share/wardend/uninstall.sh
```

The uninstaller removes everything the [installer](../install/) put on the machine. It keeps the journal and a copy of the config for the audit trail, and it never touches the harness data or your working directories. Paired devices, the APNs key and the tunnel live outside the machine: they have <!-- feature:appleWatch -->[their own sections](#phones-watches-wardenctl-and-keys)<!-- /feature --><!-- feature:!appleWatch -->[their own sections](#phones-wardenctl-and-keys)<!-- /feature --> below.

Too many cards, or the phone is gone? [Step back to observe](#step-back-to-observe-instead): wardend stays, and it takes one restart.

## Before you start

- **Every removal restarts the harness.** A seccomp filter can't be taken off a running process tree, so the agent's harness stops together with wardend and starts again without it. The agent's current sessions end.
- **Run the commands from your own terminal**, not from a chat with the agent. In the hardened install the agent can't run them anyway (no sudo); in the single-user install the uninstaller refuses to restart the unit it runs in.
- **Revoke paired devices first**, while wardend still runs: `wardend pair revoke` goes through its socket. See [Revoke devices on the server](#revoke-devices-on-the-server).
- **Look first.** `--dry-run` prints every step and changes nothing. Run it with `sudo`: without root the contents of `/etc/wardend` and `/var/lib/wardend` stay closed and the list comes out short.

```shell
sudo /usr/local/share/wardend/uninstall.sh --dry-run
```

## Hardened install

### Uninstall with one command

```shell
sudo /usr/local/share/wardend/uninstall.sh
```

The installer put this script on the machine from the same signed release archive as the binaries. It needs no network and downloads nothing. It removes its own copy together with the rest.

Where there is no copy (the install is older than the script, or wardend is gone already and you want `--purge` or `--remove-agent-user`), the installer does the same, with the same flags:

```shell
curl -fsSL %INSTALL_URL% | sudo sh -s -- --uninstall
```

It runs the copy on the machine if there is one. Otherwise it downloads the release, checks the signature and the checksums with the same code as for an install, and only then runs `uninstall.sh` from the checked archive. It never runs unchecked code: a copy that anyone but root could have rewritten is skipped as well, in favour of the signed release.

The script lists what it will stop, remove and keep, asks to confirm (`--yes` skips the question), then:

1. stops and disables `wardend.service`, and the harness with it. If wardend doesn't stop, the script quits before removing anything;
2. copies `/etc/wardend` and the unit, with your `systemctl edit` overrides, to `/var/lib/wardend/config-backup`, leaving out APNs keys;
3. renames the journal to `journal.<time>.jsonl` and writes its public key next to it, `journal.<time>.pub` (the key needs OpenSSL);
4. removes the unit and its overrides and reloads systemd;
5. removes the sysctl file and sets `kernel.yama.ptrace_scope` back to the value it had before the install, removes the polkit rule;
6. removes the binaries, `/usr/local/share/wardend`, `/etc/wardend`, and the key, socket and push state in `/var/lib/wardend`;
7. prints what it kept and how to start the harness without wardend.

Running it again is safe: it removes what is left and says `Nothing to remove` when nothing is.

### What is removed and what stays

| Path | What it is | uninstall | `--purge` too |
|---|---|---|---|
| `/usr/local/bin/wardend`, `/usr/local/bin/wardenctl` | binaries | removed | removed |
| `/usr/local/share/wardend/` | `deploy/`, `redteam/`, `install.sh` and `uninstall.sh` of the release | removed | removed |
| `/etc/systemd/system/wardend.service`, `wardend.service.d/` | the unit and your overrides | stopped, disabled, removed; copy kept | removed |
| `/etc/wardend/` | `config.json`, `policy.json`, the APNs key | removed; copy kept, without `*.p8` | removed |
| `/etc/sysctl.d/60-wardend-ptrace.conf` | `ptrace_scope=2` | removed, the previous value restored | same |
| `/etc/polkit-1/rules.d/60-wardend-agent.rules` | no polkit actions for the agent | removed | removed |
| `/var/lib/wardend/`: `supervisor.key`, `wardend.sock`, `push_tokens.json`, <!-- feature:hardwareKey -->`hw_counters.json`, <!-- /feature -->`ptrace_scope.before` | supervisor key, socket, push tokens<!-- feature:hardwareKey -->, YubiKey counters<!-- /feature --> | removed | removed |
| `/var/lib/wardend/journal.jsonl` | the signed journal | kept as `journal.<time>.jsonl` and `.pub` | deleted |
| `/var/lib/wardend/config-backup/` | the copy of `/etc/wardend` and the unit | kept | deleted |
| the agent user, its group, its home (`/var/lib/agent`) | the harness and its data | not touched | not touched |
| your working directories, their ACLs and groups | your data | not touched | not touched |

**Why the journal stays.** It is the signed record of every command the agent started, what wardend decided and who approved it. It stays readable only by root. It is renamed so that a later install starts a new journal with a new key: appending to the old file with another key would break `wardend verify-journal`. Any wardend binary can check it later, for example one from a release archive you [verified](../install/#before-you-pipe-into-sudo) (it only reads the file):

```bash
sudo ./wardend verify-journal --pubkey "$(sudo cat /var/lib/wardend/journal.<time>.pub)" \
  /var/lib/wardend/journal.<time>.jsonl        # {"ok":true,"entries":…,"key":"…"}
```

The `.pub` file lies next to the journal, so whoever can rewrite one can rewrite the other. To be able to prove later that this wardend wrote the journal, copy the key off the machine: the uninstaller prints it.

**Why the config copy stays.** `config.json` and `policy.json` hold the mode, the trusted devices and the rules you wrote while in observe. To install again with them, copy them back to `/etc/wardend` before the first start; phones pair again anyway, because the new install has a new supervisor key.

**Why the APNs key goes.** It signs push notifications to your devices. Apple lets you download it once: the copy you saved then, or a new key, is the way back. See [APNs key and push tokens](#apns-key-and-push-tokens).

An install made by an older installer (before `--purge` existed) did not save the previous `ptrace_scope`: the kernel keeps 2 until reboot, and `sudo sysctl --system` applies the configured value now (it re-reads every sysctl file, as a reboot does). It also did not note that it created the agent user, so `--remove-agent-user` leaves that user to you.

systemd keeps its own log of the service, which includes what the harness printed (`sudo journalctl -u wardend`), until journald rotates it. It is not the wardend journal, and nothing here deletes it.

### Delete the journal and the config copy

```shell
sudo /usr/local/share/wardend/uninstall.sh --purge
```

The same uninstall, and `/var/lib/wardend` goes too, with every journal and config copy in it. The script lists what is there and asks you to type `purge`; `--yes` answers for you, for scripts. There is no undo. After a plain uninstall the copy of the script is gone from the machine, and the installer deletes what that one kept: `curl -fsSL %INSTALL_URL% | sudo sh -s -- --uninstall --purge`.

`/var/lib/wardend` also holds the note that the installer created the agent user. Delete the user first, or in the same run with `--remove-agent-user`; after the purge the user is yours to delete by hand.

### Bring the harness back

wardend ran the harness as the agent user, with its data in the agent's home (`/var/lib/agent` unless you chose another). The uninstaller prints the harness command it ran. Two ways back:

**Under your own account, as before wardend.** With OpenClaw as the example:

```bash
# once: move your pre-wardend copy aside; the agent's copy is the current one
test -e ~/.openclaw.before-wardend || mv ~/.openclaw ~/.openclaw.before-wardend
sudo rsync -au /var/lib/agent/.openclaw/ ~/.openclaw/    # -u: never overwrites a newer file of yours
sudo chown -R "$USER": ~/.openclaw
grep -rn --include='*.json' /var/lib/agent ~/.openclaw/  # paths to change back to your home
```

Look through it before you start the harness as yourself. The agent could write anything in its state, and from now on that state runs with your rights: for OpenClaw check `openclaw.json` (commands, hooks, plugin paths) and `extensions/`. Then enable the service you disabled during the install, for example `systemctl --user enable --now openclaw-gateway`. If you moved the harness program to `/opt` back then, check which path the old unit starts: `systemctl --user cat openclaw-gateway`.

**Under the agent user, without the gate.** The separate user still keeps the harness away from your files. Write a plain system unit with `User=agent`, the harness command and the sandbox options of the old one; the copy in `/var/lib/wardend/config-backup/wardend.service` shows what it had.

### Remove the agent user

The uninstaller keeps the agent user and its group. Its home holds the harness data, and your working directories carry its ACL entries and the files it created. `userdel` would leave all of that to a bare uid, and the next system account created on the machine usually gets the same uid: a package's service user would then own your project files and the agent's API keys. So the user goes last, in its own step.

1. Copy the harness data you need, as in [Bring the harness back](#bring-the-harness-back).
2. Take the working directories back. If you gave access by ACL:

   ```bash
   sudo setfacl -R -x u:agent -x d:u:agent /srv/projects
   ```

   If you used a group (`agentwork` in the install guide):

   ```bash
   sudo find /srv/projects -group agentwork -exec chgrp "$(id -gn)" {} +
   sudo groupdel agentwork
   ```

   In both cases the files the agent created become yours, with your group (GNU `chown`, files of other owners are left alone):

   ```bash
   sudo chown -R --from=agent "$USER": /srv/projects
   ```

   What still belongs to the agent's user or group outside its home, on the root file system (other file systems need their own run):

   ```bash
   sudo find / -xdev \( -user agent -o -group agent \) -not -path '/var/lib/agent/*' 2>/dev/null | head -20
   ```

3. Remove the user:

   ```shell
   curl -fsSL %INSTALL_URL% | sudo sh -s -- --uninstall --remove-agent-user
   ```

   While wardend is still installed, `sudo /usr/local/share/wardend/uninstall.sh --remove-agent-user` does the same. It deletes the user only if the installer created it (`/var/lib/wardend/created-agent-user` says so) and it is a system account. It stops with a list, before changing anything, while the working directories still carry the agent's ACL entries or files or the agent has a crontab, and it refuses while processes of the agent still run. Then it makes the home root-only, with the data left in it, and deletes the user and its group.
4. Delete the home once you no longer need the data in it:

   ```bash
   sudo rm -rf /var/lib/agent    # the agent's home the uninstaller printed, not yours
   ```

A user that existed before the install, or one created by an older installer, is left to you: the same steps 1 and 2, then

```bash
sudo chown root:root /var/lib/agent && sudo chmod 700 /var/lib/agent   # the data stays, root only
sudo userdel agent
```

### Uninstall by hand

The same steps without the script, in this order; each command is safe to repeat. For the exact list on your machine run the uninstaller with `--dry-run` under `sudo`.

```bash
sudo systemctl disable --now wardend                       # stops the harness too
sudo install -d -m 700 /var/lib/wardend/config-backup
sudo cp -a /etc/wardend/. /var/lib/wardend/config-backup/  # config and policy
sudo cp -a /etc/systemd/system/wardend.service /var/lib/wardend/config-backup/
sudo find /var/lib/wardend/config-backup -name '*.p8' -delete
sudo mv /var/lib/wardend/journal.jsonl "/var/lib/wardend/journal.$(date -u +%Y%m%dT%H%M%SZ).jsonl"
sudo rm -rf /etc/systemd/system/wardend.service /etc/systemd/system/wardend.service.d
sudo systemctl daemon-reload
sudo rm -f /etc/sysctl.d/60-wardend-ptrace.conf /etc/polkit-1/rules.d/60-wardend-agent.rules
sudo cat /var/lib/wardend/ptrace_scope.before              # the value from before the install
sudo sysctl -w kernel.yama.ptrace_scope=<value>            # that value, or: sudo sysctl --system
sudo rm -rf /usr/local/bin/wardend /usr/local/bin/wardenctl /usr/local/share/wardend /etc/wardend
sudo rm -f /var/lib/wardend/supervisor.key /var/lib/wardend/wardend.sock /var/lib/wardend/push_tokens.json \
  <!-- feature:hardwareKey -->/var/lib/wardend/hw_counters.json <!-- /feature -->/var/lib/wardend/ptrace_scope.before
```

## Single-user install

### Uninstall the trial install

```shell
~/.local/share/wardend/uninstall.sh --single-user
```

No sudo: run it as the user the harness runs as, from your own terminal. It finds the drop-ins `~/.config/systemd/user/<unit>.service.d/wardend.conf` that start a harness through wardend, and then:

1. removes the drop-in, reloads systemd and restarts the unit if it runs: the harness starts again without wardend, and its current sessions end;
2. renames the journal in `~/.wardend` and writes its public key next to it;
3. removes `~/.local/bin/wardend`, `~/.local/share/wardend`, and the key, socket, push state and APNs keys in `~/.wardend`.

`~/.wardend/config.json`, your `policy.json` and the journal stay. `--purge` deletes `~/.wardend` as well, after you type `purge`.

Where there is no copy of the script (the install is older than it, or already removed), the installer does the same and checks the signed release just as for the hardened install: `curl -fsSL %INSTALL_URL% | sh -s -- --single-user --uninstall`.

The order matters: the binary goes only after the harness runs without it. A drop-in that points to a deleted binary keeps the harness from starting at all.

The script stops without changing anything when:

- a unit starts wardend some other way (you edited its `ExecStart` or used another drop-in file): take wardend out of it by hand, run `systemctl --user daemon-reload`, restart the unit and run the uninstall again;
- it runs inside the unit it would restart, for example in a chat with the agent;
- a wardend you started by hand (`wardend run -- …`) is still running: stop it and the harness it wraps first.

### Remove the trial install by hand

```bash
rm -f ~/.config/systemd/user/openclaw-gateway.service.d/wardend.conf
systemctl --user daemon-reload
systemctl --user restart openclaw-gateway      # current sessions end; not from a chat with the agent
systemctl --user status openclaw-gateway       # Main PID is your harness (node), not wardend
rm -f ~/.local/bin/wardend ~/.wardend/supervisor.key ~/.wardend/wardend.sock \
  ~/.wardend/push_tokens.json <!-- feature:hardwareKey -->~/.wardend/hw_counters.json <!-- /feature -->~/.wardend/*.p8
rm -rf ~/.local/share/wardend
```

Only if you need neither the journal nor the config any more:

```bash
rm -rf ~/.wardend
```

## Phones, <!-- feature:appleWatch -->watches, <!-- /feature -->wardenctl and keys

### Revoke devices on the server

Do this before the uninstall, while wardend still runs:

```bash
sudo wardend pair list --socket /var/lib/wardend/wardend.sock
sudo wardend pair revoke <deviceId prefix> --socket /var/lib/wardend/wardend.sock   # for each device
```

In the single-user install the same commands run without `sudo` and `--socket`. `revoke` takes the device out of `trusted_devices` and out of the running wardend, deletes its push tokens and writes `device_revoked` to the journal. The config copy the uninstaller keeps then no longer trusts the device, and the journal you keep ends with the revocations.

In `ticket` mode the last revoked device leaves nobody to approve, and every command of the agent that needs a signature waits for the TTL and fails. Revoke right before the uninstall.

### Phone<!-- feature:appleWatch --> and watch apps<!-- /feature --><!-- feature:!appleWatch --> app<!-- /feature -->

On the phone: **Connect → Forget server**<!-- feature:hardwareKey -->, and if a YubiKey is bound, **Mode → Hardware key → Unbind**<!-- /feature -->. Then delete the app. Android deletes the app's device key and its own journal with it. iOS can keep the app's Keychain entries after the app is deleted; once the server no longer trusts the device, they sign nothing it accepts.

<!-- feature:appleWatch -->

On the Apple Watch: **Settings → Unpair** in the WardenClaw app. It deletes the watch key and the server and unregisters the watch's push token. Then delete the app from the watch.

<!-- /feature -->

### wardenctl

On every machine where you paired it, as the user that paired it:

```bash
wardenctl forget
```

It asks first (`--yes` skips the question) and deletes the server record<!-- feature:hardwareKey -->,<!-- /feature --><!-- feature:!hardwareKey --> and<!-- /feature --> the device key (the file `~/.config/wardenctl/device.key`, or the macOS Keychain item of the service `wardenctl`)<!-- feature:hardwareKey --> and its YubiKey record<!-- /feature -->. On the server run it before the uninstall, which removes `/usr/local/bin/wardenctl`; elsewhere delete the binary where you put it, and the empty directory `~/.config/wardenctl`.

<!-- feature:hardwareKey -->

### YubiKey

WardenClaw registers the YubiKey with a non-discoverable credential for the rpId `wardenclaw`: the app and `wardenctl hw-register` both ask for `rk=false`. Such a credential stores nothing on the key. The YubiKey recovers the private key from the credential id, which only wardend (`hardware_keys` in the config), the app and wardenctl keep. With the config gone, the credential signs nothing anyone accepts, so there is nothing to delete on the key.

`ykman fido credentials list` shows only discoverable credentials and won't list it. If an entry for `wardenclaw` does show up there (made by some other tool), delete just that one:

```bash
ykman fido credentials list                        # asks for the FIDO2 PIN
ykman fido credentials delete <credential id>      # a unique part of the id from the list
```

Don't use `ykman fido reset` for this: it wipes every FIDO credential on the key, for every site.

<!-- /feature -->

### APNs key and push tokens

Push tokens live in `/var/lib/wardend/push_tokens.json`: `pair revoke` deletes a device's tokens, the uninstaller deletes the file. The APNs key (`/etc/wardend/AuthKey_*.p8`, or `~/.wardend/` in the single-user install) is deleted and not copied into the config backup; a key you put somewhere else stays where it is.

At Apple: **Certificates, Identifiers & Profiles → Keys** → the key → **Revoke**, but only if no other app of your team uses it: one key serves all of them. Delete the copy you kept in your password manager as well.

### ntfy and the OpenClaw plugin

- **ntfy.** If `ntfy_url` was set, unsubscribe from the topic in the ntfy app. On your own ntfy server, delete the user or token behind `ntfy_token`.
- **The OpenClaw plugin `wardenclaw-gate`** (optional). If you set up its Claude Code PreToolUse hook, remove the hook from `settings.json` of Claude Code first: the hook is fail-closed and denies every Bash, Write and Edit once the plugin is gone. Then `openclaw plugins disable wardenclaw-gate`, or remove it from `plugins.load.paths` and `plugins.entries` in `openclaw.json`. Its own journal stays in `~/.openclaw/wardenclaw-gate/`.

## Cloudflare Tunnel and DNS

Only if you exposed the phone endpoint through a tunnel (`deploy/CLOUDFLARE.md`).

- **Tunnel managed in the dashboard:** Zero Trust → Networks → Tunnels → your tunnel → Public Hostname: delete `wardend.example.com`.
- **Tunnel with a local `config.yml`:** remove the rule `hostname: wardend.example.com` (the catch-all `service: http_status:404` stays last) and restart cloudflared.
- **DNS → Records:** delete the CNAME `wardend` → `<tunnel-id>.cfargotunnel.com` if it is still there. Deleting the hostname doesn't always remove it, and `cloudflared` creates DNS routes but can't delete them.
- If you added a WAF skip rule for the hostname, or turned Bot Fight Mode off for it, undo that.
- Delete the tunnel itself and cloudflared only if they serve nothing else.

```bash
curl -sI https://wardend.example.com/v1/ping    # no answer from wardend: a DNS error, or 404 or 530 from Cloudflare
```

## Check that everything is gone

Hardened install:

```bash
systemctl status wardend      # Unit wardend.service could not be found.
ls -d /usr/local/bin/wardend /usr/local/bin/wardenctl /usr/local/share/wardend /etc/wardend \
  /etc/systemd/system/wardend.service /etc/systemd/system/wardend.service.d \
  /etc/sysctl.d/60-wardend-ptrace.conf /etc/polkit-1/rules.d/60-wardend-agent.rules
                              # No such file or directory, for each of them
sudo ls -la /var/lib/wardend  # journal.<time>.jsonl and .pub, config-backup; after --purge: No such file
sysctl kernel.yama.ptrace_scope   # the value from before the install (no such key without Yama)
pgrep -a -u agent             # nothing: no process of the agent is left (before you delete the user)
ss -ltn | grep ':8787 '       # nothing listens on the phone endpoint
id agent                      # after --remove-agent-user: no such user
```

Single-user install:

```bash
systemctl --user cat openclaw-gateway | grep wardend   # nothing
systemctl --user status openclaw-gateway               # Main PID is your harness, not wardend
ls -d ~/.local/bin/wardend ~/.local/share/wardend ~/.config/systemd/user/*.service.d/wardend.conf
                                                       # No such file or directory
pgrep -a -x wardend                                    # nothing
ls -la ~/.wardend        # journal.<time>.jsonl and .pub, config.json; after --purge: No such file
```

Devices: `security find-generic-password -s wardenctl` on a Mac answers `The specified item could not be found in the keychain`; `ls ~/.config/wardenctl` shows nothing; the WardenClaw app is gone from the phone<!-- feature:appleWatch --> and the watch<!-- /feature -->.

## Step back to observe instead

If the reason is too many cards, or a phone that is lost or out of reach, you don't have to uninstall. In `observe` wardend lets every command run and keeps writing the journal; nothing waits for a signature. It takes one restart, which restarts the harness too. In the hardened install the agent can't do this for you: the config belongs to root.

```bash
sudo sed -i 's/"mode": *"ticket"/"mode": "observe"/' /etc/wardend/config.json
sudo wardend config-check --config /etc/wardend/config.json && sudo systemctl restart wardend
sudo wardend status --socket /var/lib/wardend/wardend.sock | grep '"mode"'   # "mode": "observe"
```

Single-user install:

```bash
sed -i 's/--mode ticket/--mode observe/' ~/.config/systemd/user/openclaw-gateway.service.d/wardend.conf
systemctl --user daemon-reload && systemctl --user restart openclaw-gateway
wardend status | grep '"mode"'
```

Lost the phone? Revoke it right away as well (`sudo wardend pair revoke <deviceId prefix> --socket /var/lib/wardend/wardend.sock`): it holds a device key that can approve commands. A new phone is paired from your terminal on the server, with no second device: [If the phone is lost](../connect-phone/#if-the-phone-is-lost). Back to `ticket`: the same commands with the two modes swapped, once a paired device is online again. To stop the agent without removing anything: `sudo systemctl stop wardend` (the harness stops with it, `start` brings both back).
