# rootexec: one command as root, after a card

The hardened install takes root away from the agent: no `sudo`, no `docker` group, no way to reach
wardend's socket, `sudo`/`su`/`pkexec` refused under `no_new_privs`. That is the point of the
install, and it leaves a hole in daily work: restarting a container, reading a service log,
mounting a disk. rootexec closes it without giving anything back: the agent may *ask* for one
command, wardend (root) shows it on the phone, and after a signed ticket runs exactly that command
itself, as its own user, with the agent's terminal.

```
agent (under the filter)                          wardend (root)
  wardend rootexec -- docker restart searxng  ─▶  /run/wardend/rootexec.sock
      one JSON line + SCM_RIGHTS [0, 1, 2]            SO_PEERCRED: the agent uid, under the filter,
                                                      a descendant of the supervised command
                                                      argv[0] resolved on a fixed root PATH, the
                                                      file pinned (open; root-owned, not writable
                                                      by others, not the agent's, not in its home)
                                                      deny_always, the guard, the privilege tools:
                                                      refused, no card
                                                      policy root_exec: no rule → refused, no card
                                                      envelope type "rootexec" (uid 0) → card
  ◀── {event: card, id}                              the phone recomputes the digest and signs
                                                      fork: setsid, uid/gid 0, no groups, clean env,
                                                      cwd, execve(/proc/self/fd/<pinned>)
  ◀── {event: started, pid}
  ◀── {event: done, exit}                            journal: rootexec, rootexec_exit
```

## What the agent gets and what it does not

- A **request**, never a shell: `argv` as a list, the current directory, `TERM`. No `sh -c` is
  added; if the agent wants a shell, `sh` has to be in the policy and the whole script is on the
  card.
- The command runs with the **agent's descriptors** (stdin, stdout, stderr passed over the socket)
  and its cwd, so `docker logs x | tail` works as the agent expects. It gets a clean environment
  (`PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, `HOME`, `USER`, `LANG`,
  `TZ`, `TERM`, `WARDEND_ROOTEXEC=1`): nothing from the agent's environment, no loader variables.
- The command is **not under the seccomp filter**: it is wardend's child, root, outside the tree,
  and so are its children. The human approved this launch; what it starts is root's business,
  like an approved `docker run` today. It gets its own session (`setsid`) and process group:
  Ctrl-C in the agent's terminal reaches it through wardend, a dead client kills it, and
  `root_exec.timeout` (10 minutes) ends it with SIGTERM, then SIGKILL.
- **Exit codes** of `wardend rootexec`: the command's own; 124 the card expired or the timeout
  hit; 125 refused before a card (policy, mode, guard, socket); 126 denied on the phone.

## What cannot be changed after the card

- The **file**: wardend opens it before the card and executes the open descriptor
  (`/proc/self/fd/3` in the child). A rename, a replaced symlink, a new file at the path after
  the card change nothing; the approved inode runs. Modifying the inode in place needs write
  permission to a root-owned, non-group-writable file, which the agent does not have.
- The **arguments, cwd and environment** are what the card shows: wardend keeps the parsed request
  and does not read the socket again for them.
- What the card **cannot** pin is what the command reads at run time: a compose file in the
  agent's project, a script under `/srv` the agent may edit, a config the command loads. That is
  the operator's policy: allow `docker compose up -d` only where the compose files are not the
  agent's, or accept that approving it means approving what the agent wrote there. The card shows
  `cwd` and the pinned `exe` for exactly this judgement.

## Who may ask

The socket is root:`<agent group>` 0660 (`RuntimeDirectory=wardend` in the unit), and a
connection is served only when all of this holds:

1. `SO_PEERCRED` uid is the `child_user` (in a single-user run: wardend's own uid);
2. the process runs under a seccomp filter deeper than wardend's own (it is under the gate);
3. it descends from the supervised command, or from wardend itself as the subreaper of the
   tree's orphans.

`redteam/hardened-check.sh` runs `wardend rootexec` from outside the tree and expects the refusal.

## What is refused without a card

In order, the first hit answers:

- `mode` is not `ticket`: in `observe` nobody can sign, so nothing runs;
- `argv[0]` not found on the root PATH, not a regular executable file, group- or world-writable,
  owned by neither root nor wardend's user, the agent's own file, or under the agent's home;
- a `deny_always` rule of the policy;
- the built-in guard: the gate binaries (`wardend`, `wardenctl`); privilege and namespace tools
  (`sudo`, `su`, `doas`, `pkexec`, `nsenter`, `unshare`, `chroot`, `setpriv`, `capsh`, `runuser`,
  …) as the program or as a word in the arguments; account and sudoers tools (`usermod`,
  `gpasswd`, `visudo`, `passwd`, `loginctl`, …) the same way; any argument naming wardend's own
  files, unit, sysctl or polkit rule (`/etc/wardend`, `/var/lib/wardend`, `/usr/local/bin/wardend`,
  `wardend.service`, `60-wardend`, `ptrace_scope`, `/etc/sudoers`, `/etc/polkit-1`,
  `/etc/passwd`, `/etc/shadow`, …), and `systemctl … wardend`;
- no `root_exec` rule matches (an empty list refuses everything).

The guard is a stop for the obvious way to switch the guard off with a distracted human, not a
proof: `docker run -v /:/host` is a root shell with extra steps, and only the policy and the
human stand before it. Do not put `docker run`, shells, `mount`, `dd` or editors into
`root_exec` unless you mean it.

## `sudo` for the agent

Agents type `sudo`. With `--root-exec` the installer puts a symlink named `sudo` to the wardend
binary into `/usr/local/libexec/wardend/bin`, and the unit sets that directory first on the
harness PATH, so for the agent `sudo docker restart x` is `wardend rootexec -- docker restart x`:
the same socket, the same policy, the same card. The shim is not setuid and gives nothing of its
own; the real `/usr/bin/sudo` stays as it is for humans (the shim run outside the gate, by a
human whose PATH has it, execs the real sudo unchanged). Its exec under the gate is a service
launch (`rootexec-client`), not a card: the request itself gets the card.

The unit's PATH is not always the one the agent's shell sees: a harness may rebuild PATH for the
processes that run its tools. OpenClaw starts Claude Code with the node directory, `/usr/bin` and
`/bin` ahead of everything else, so `sudo` there is the real `/usr/bin/sudo` again and fails under
`NoNewPrivileges` ("no new privileges flag is set"). Check with `command -v sudo` from the agent's
own shell tool; if it is not the shim, put `/usr/local/libexec/wardend/bin` first where that shell
takes its PATH (for Claude Code: `env.PATH` in `~/.claude/settings.json`). An explicit
`/usr/local/libexec/wardend/bin/sudo …` works regardless of PATH.

What sudo's spelling allows: `-n`, `-H`, `-k`, `-K`, `-S`, `-A`, `-p`, `-u root`, `--`. What is
refused with a message (exit 125) rather than quietly changed: `-i` and `-s` (no shell as root),
`-u <other>` and `-g`, `-E` and `VAR=value` (the environment is never passed), `-D`, `-e`. `-l`
says there are no sudoers rights and how it works; `--help` and `-V` describe the shim.

This is the whole "intercept sudo": the word, not the setuid binary. A real sudoers right for the
agent would make the gate the last thing between the model and root, and no_new_privs on the tree
already makes setuid a no-op; the shim keeps both boundaries and only spares the agent a new word.

The `docker` shim is the same thing for docker's spelling: `docker ps` from the agent is
`wardend rootexec -- docker ps`; the agent user is not in the docker group and never touches the
socket itself.

## Without a card

Two cases run at once, journaled, with the guard and the pinned file as always:

- a rule with `"ticket": false` (the built-in defaults have read-only docker and systemctl): the
  operator's standing approval for a command that would otherwise interrupt the human ten times
  a day; the journal says `policy: no ticket (<rule>)`;
- `mode` other than `ticket`: observe and deny-list run everything they do not refuse and only
  journal `observe: would require ticket (<rule>)`, as for any root launch in those modes. The
  week of watching is a week of watching for root too: before wardend the agent had sudo, and a
  wrapping install must not break its day one.

Refusals stay refusals in every mode: no rule, the guard, a file wardend would not run as root.

## Policy

A fourth rule list, `root_exec`, with the fields of every rule (`argv0`, `argv`, `argv_text`,
`argv_json`, `argv_none`, `path`, `cwd` is not a field: `path` is the pinned realpath). `argv0`
matches `basename(argv[0])` as the agent typed it, strictly; the real file is on the card as
`exe`. Rules are `AND` inside and first-match across the list.

```json
"root_exec": [
  {"id": "docker-restart", "argv0": "^docker$", "argv": ["docker", "restart", "[a-z0-9_-]+"], "note": "restart one container"},
  {"id": "docker-logs",    "argv0": "^docker$", "argv_text": "^docker logs( --since [0-9a-z]+)?( --tail [0-9]+)? [a-z0-9_-]+$"},
  {"id": "compose-up",     "argv0": "^docker$", "argv_text": "^docker compose (up -d|restart)( [a-z0-9_-]+)?$", "note": "compose files under /srv/stack are root-owned"},
  {"id": "journal",        "argv0": "^journalctl$", "argv_none": "^(-f|--follow|--vacuum.*|--rotate|--flush)$"}
]
```

A YubiKey can be required for all of them or some (`require_hardware`, `"class": "rootexec"`,
optionally with `min_score`); the built-in packs never add `root_exec` rules. The built-in
policy (`wardend policy-defaults`) carries four: `docker-read` and `systemctl-read` with
`"ticket": false`, `docker` (a card), `root-any` (anything else: a card). Your own policy file
replaces the list entirely.

## Config

```json
"root_exec": {"enabled": true, "socket": "/run/wardend/rootexec.sock", "group": "", "timeout": "10m"}
```

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Without it no socket exists and `wardend rootexec` fails at connect (125). |
| `socket` | `/run/wardend/rootexec.sock` as root, else `<state_dir>/rootexec.sock` | The state directory is 0700 and unreachable for the agent: a hardened install needs the `/run` path (the unit's `RuntimeDirectory`). |
| `group` | primary group of `child_user`, else wardend's | Group of the socket (0660). |
| `timeout` | `10m` | The approved command is ended (SIGTERM, 5 s, SIGKILL) after this long. |

`install.sh --root-exec` (or `ROOT_EXEC=1` for `deploy/hardened-install.sh`) writes `enabled:
true` into a fresh `/etc/wardend/config.json`; an existing config is never touched. The
`root_exec` rules go into `/etc/wardend/policy.json` by hand: start with `wardend
policy-defaults`, add the list, point `"policy"` in the config at the file, `wardend
config-check`, restart.

## The card and the clients

The envelope has the 14 fields of an exec envelope with `type: "rootexec"`; `uid`/`gid` are the
ids of the launch (0), `exe` the pinned realpath, `ppidChain[0]` the requesting client
([protocol/README.md](../../protocol/README.md), 3a). The type is inside the digest, so a
ticket for an exec card cannot be replayed onto a rootexec card and vice versa. The ticket type
stays `wardenclaw.ticket.exec.v1`.

A client that does not know the type fails closed: its strict parse refuses the
envelope, it can only deny. The app, `wardenctl` and the plugin show it as always
dangerous (hold to allow on the phone, the word `allow` in `wardenctl watch`), the reason first:
"Runs as root: not the agent's launch but wardend's, outside the gate, with root's full access
for this command and everything it starts". The autopilot and the judge never allow it. `meta`
carries `class: "rootexec"`, the rule id, `rootExec: {runAsUid, runAsUser, requesterUid,
requesterPid, timeoutMs, note}` and the usual `hardware` block.

## Journal

`rootexec` for every request that got past the socket: `argv`, `cwd`, `exe` (pinned), `runAsUid`,
`requester: {pid, uid, exe}`, `chain`, `rule`, `decision`, `reason`, the envelope, the ticket, the
second factor, `pid` when started. `rootexec_exit` when the command ends: `exit` (shell style,
128+N after a signal), `signal`, `timedOut`, `clientGone`, `durationMs`. `status` shows
`rootExec: {enabled, socket, clientUid, socketGid, runAsUid, runAsUser, timeoutMs, rules}` and
`metrics.rootexec: {refused, denied, run}`.

## Tests

`daemon/rootexec_test.go` (under a real filter, wardend as the test user): an approved `id -u`
prints the uid through the client's descriptors and exits 0, the journal has the envelope with
`type: rootexec` and the ticket; a deny gives 126, an expired card 124; no rule, observe mode, the
guard (wardend files in arguments, `unshare`, `gpasswd` inside `sh -c`), a missing program and a
group-writable file give 125 without a card; the test process itself, outside the gate, is
refused; the path is swapped between the card and the decision and the approved inode still
runs. `daemon/cmd/wardenctl/rootexec_card_test.go`: the card verifies, is dangerous with root as
the first reason, prints the banner, `y` does not allow it, an unknown type is refused.
`app/scripts/test-core.mjs`: a rootexec envelope parses and verifies, the type changes the
digest, any other type is refused.
