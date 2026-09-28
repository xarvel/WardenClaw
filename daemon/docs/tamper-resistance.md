# wardend tamper resistance

> User-facing version: [`site/src/docs/tamper-resistance.en.md`](../../site/src/docs/tamper-resistance.en.md),
> published under `/docs/`. This file remains the developers' work journal.

Work journal of the audit and hardening. Goal: to justify (truthfully) why a malicious
model that fully controls the harness (OpenClaw or any other agent) and all its
descendants cannot turn off or bypass wardend. Where this cannot be justified, the limitation is
named explicitly.

Audit date: 2026-09-27. Pi kernel: 6.18.50 (seccomp notify, pidfd, addfd: present).

## Threat model

Adversary: the model's code inside the harness. It can make any syscall it is allowed,
from any descendant. It cannot: run execve/execveat bypassing wardend (that is gated), or gain
privileges its uid does not have.

The key question is which uid everything runs under.

### What the live system showed (read-only)

- The harness and wardend run under **one uid** (the agent user, here `agent`, uid 1000). wardend PID 59446:
  `wardend run --mode observe ... -- node ... gateway`.
- The binary `~/.local/bin/wardend`: owner agent, mode 0755 → **the agent can overwrite it**
  (write, no exec).
- `~/.wardend/`: directory 0700 agent; `config.json` 0600 agent; `supervisor.key` 0600 agent;
  `journal.jsonl` 0600 agent; `wardend.sock` 0600 agent. Everything belongs to the agent uid →
  **the agent can read the supervisor key and rewrite the config/journal/key** via open/write.
- The gateway unit is a **user** unit: `~/.config/systemd/user/openclaw-gateway.service` plus the
  drop-in `openclaw-gateway.service.d/wardend.conf`, both writable by agent. wardend
  is hooked in precisely through the drop-in (ExecStart is reset and redefined as `wardend run ... -- node`).
  The agent can rewrite the drop-in, remove wardend and restart the gateway.
- `sudo -n` is unavailable: the process has `no_new_privs` set (we are under the wardend filter), and sudo
  does not elevate under NNP. This does NOT mean there is no passwordless sudo at all, only not from under the gate.
  agent is in the `sudo` group (and `docker`!). The docker group = root equivalent.
- Yama: `/proc/sys/kernel/yama/ptrace_scope` is missing (the Yama LSM is not enabled) → ptrace between
  processes of the same uid is not restricted at all.
- The current mode is **observe**: right now wardend blocks nothing at all, it only writes the journal.

### Main conclusion

With a "single uid" install (the current one) wardend is **defense in depth against unwanted
exec**, NOT protection against tampering with wardend itself. A model under the same uid can turn off
or bypass wardend without a single execve:

- `kill(supervisorPid, SIGKILL)`: not gated (the filter catches only execve/execveat);
- `ptrace`/`process_vm_writev` on wardend: not gated, Yama is off, the uid is the same;
- writing to `~/.local/bin/wardend`, `config.json`, `supervisor.key`, the journal via open/write:
  not gated;
- overwriting `/proc/<supervisorPid>/mem` (open+write): not gated;
- overwriting the unit/drop-in + `daemon-reload`+`restart` via the private systemd D-Bus
  (`/run/user/1000/systemd/private`): **without a single execve**;
- the user's crontab/systemd timer (writing a file + reload): the same way.

The only honest strong guarantee that "the model will not turn off wardend" is achieved by a **hardened
install**: wardend and its files belong to a separate user (or root), and the harness
runs under its own, less privileged uid as a descendant of wardend. Then inter-process
attacks (kill/ptrace/mem) and writes to wardend's files hit the kernel's uid checks, not
seccomp. This is exactly the premise that has to be named explicitly in the article and on the site.

## Vector table: before → after

| Vector | Same-uid (current) | Closed by | Hardened install |
|---|---|---|---|
| execve/execveat bypassing the gate | closed | seccomp USER_NOTIF (seccomp.go) | closed |
| nested seccomp unotify filter (intercepting its own execve) | closed | seccomp(SET_MODE_FILTER, NEW_LISTENER)→EPERM (seccomp.go execFilter) | closed |
| 32-bit/compat exec as a bypass | closed | foreign arch → ENOSYS (seccomp.go) | closed |
| memfd_create+execveat, fexecve, ld.so directly | closed | execveat is gated; the memfd realpath does not resolve → class=missing→deny (procinfo.go/supervisor.go) | closed |
| TOCTOU swap of argv/file after CONTINUE | closed | SIGSTOP post-check `toctou_roots=stop` (toctou.go) | closed |
| kill(SIGKILL) on the wardend pid | **OPEN** (same uid) | - | closed by the kernel (different uid) |
| ptrace / process_vm_writev on wardend | **OPEN** (Yama off, same uid) | - | closed by the kernel (different uid + ptrace_scope) |
| write to the wardend binary/config/key/journal | **OPEN** (owner=agent uid) | the startup permission check (selfcheck.go) catches group/world-writable, but not same-owner | closed (root-owned) |
| write to /proc/<sup>/mem | **OPEN** | - | closed by the kernel (different uid) |
| swapping the unit/drop-in + reload/restart via D-Bus | **OPEN** (user unit writable) | - | closed (system unit, root-owned) |
| the user's crontab/systemd timer | **OPEN** | - (this is not "turn wardend off" but "run around it"), see the note | partly: the timer starts the harness, but still under wardend if the system unit is set up that way |
| approving a ticket for itself over HTTP 127.0.0.1:8787 | closed | needs a trusted device signature; pairing only over the unix socket and not from under the filter (peerSupervised, pairing.go) | closed |
| forging a signed response/decision | same-uid: the key is readable → **OPEN**; otherwise closed | Ed25519, nonce, ts window (envelope) | closed (root-owned key) |
| DoS: overflowing the card queue | closed | max_pending → EAGAIN (queue.go, supervisor.go) | closed |
| DoS: OOM-killing wardend | same-uid: **OPEN** | - | closed (cgroup/oom_score_adj in the system unit) |
| fail-closed when wardend dies | partly | the listener closes → remaining execve→ENOSYS; but processes that are already alive keep running without the gate | the same; see the note |

Note on "run around it" (crontab, a new shell outside the tree): wardend protects only its own
process subtree. Processes that do not start under it are invisible to it by design. This is not
"turning wardend off" but going around its scope; the article honestly states it as a scope limitation.

Note on fail-closed: when wardend exits, the seccomp filter stays on the already running processes,
but the listener is closed, so their future execve calls get ENOSYS (fail-closed for a new exec).
Processes that do not need exec keep running. Full fail-closed (killing the tree when the
supervisor dies) is a separate option, see the "Remaining" section.

## What was done in the code (hardening, without changing the live system)

- [x] `selfcheck.go`: a startup check of the owner and permissions of the binary, config, key and state
      directory. In enforce modes (ticket/deny-list) it refuses on group/world-writable files and
      on a state directory wider than 0700. A warning (not a refusal) on owner==supervisor uid:
      in a same-uid install this is unavoidable and is named as a limitation. The flag `--require-hardened` /
      `"require_hardened": true` → a hard refusal if the binary/config/key are not root-owned.
      The test bypass `WARDEND_SELFCHECK=off` is ignored under require_hardened. Tests in selfcheck_test.go.
- [x] `--child-user` (childuser.go, config `child_user`): wardend under root drops the uid/gid of the
      harness descendant AFTER installing the filter and BEFORE exec (setgroups→setgid→setuid, refuses uid 0).
      This makes the hardened install clean: wardend stays root, the harness runs under a separate uid,
      and the first exec is directly the target (no extra ticket). Tests in childuser_test.go.
- [x] `deploy/wardend.system.service` + `deploy/hardened-install.sh`: a system unit under root,
      the harness under `--child-user`, NoNewPrivileges/ProtectSystem/OOMScoreAdjust; the install script
      (root-owned binary/config, a separate uid, hints about Yama and the docker group). Only
      written and checked with `bash -n`/`DRY_RUN=1`, NOT applied to the live system.
- [x] Reconciling the unit and the script with the install description (2026-09-27): the unit became a template for any
      harness (`@HARNESS_CMD@`, `@AGENT_USER@`, `@AGENT_HOME@`, `@RW_PATHS@`); the mode is taken from the
      config (the first week is observe); the agent's `HOME/USER/LOGNAME` and `WorkingDirectory` (otherwise
      the harness got HOME=/root, hidden by ProtectHome); `ReadWritePaths` now also has the agent's home,
      the work directories and `/etc/wardend` (otherwise ProtectSystem=strict made them read-only and
      `pair approve` could not write the config); `PrivateTmp`; the descendant's oom_score_adj is reset to 0
      (it inherited -500 from the unit, childuser.go `resetOOMScoreAdj`). Script: config 0600 and
      `/etc/wardend` 0700 (they were 0644/0755: the ntfy token and the trusted devices were readable), checks for
      kernel ≥ 5.19, paths outside /home, the agent's groups and sudoers, ptrace_scope in sysctl.d. The new
      `redteam/hardened-check.sh` checks the install from under the agent's uid.
- [x] `redteam/`: reproducible attacks against a SEPARATE temporary wardend instance
      (`redteam/run.sh` via systemd-run on its own port/directory) + Go tests `redteam_test.go`
      (memfd/ld.so interception, an unapproved exec is denied, self-approval is refused). README.md with a
      table and commands for checking the inter-process vectors under a separate uid.

Running the tests: not possible from under the live wardend (the filter forbids a nested unotify listener).
The tests are run by a human from their own terminal outside wardend, or by CI, not by the agent via
`systemd-run --user`: such a run goes outside the gate, and wardend asks about it with a card carrying that
mark. All packages green (2026-09-27).

## What needs the maintainer's action on the live system

See the section at the end (exact commands) and `deploy/hardened-install.sh` + `deploy/wardend.system.service`.
In short: move wardend to a hardened install (a separate uid, root-owned binary and config,
a system unit), enable Yama ptrace_scope, take agent out of the docker group if the harness must not
have a root equivalent.

## Remaining / out of scope

- Gating kill/ptrace/process_vm_* via seccomp: doable for these syscalls (checking the pid argument
  in the notify handler), but it does NOT close writes to /proc/<pid>/mem (that is openat+write, not a separate
  syscall), so same-uid stays leaky anyway. The real fix is different uids. We decided
  not to add an incomplete gate, so as not to create a false sense of protection; instead, a hardened
  install. (Justified in the article.)
- A config signed with the device key (so that a write without a signature is useless): designed, not
  implemented: in same-uid it does not help (the agent forges the signature, the key is right there), in hardened it is not needed
  (root-owned). Little value, postponed.
- Full fail-closed (killing the subtree when the supervisor dies): an option, not implemented.
