---
title: Why the model can't turn wardend off
description: The threat model of an agent that fully controls the harness, which tamper vectors wardend closes and how, which ones need a hardened install, and what stays out of scope. Honest, test-backed.
---

# Why the model can't turn wardend off

The whole point of WardenClaw is that a compromised or malicious model must not be able to disable its own guard. This page states plainly what that guarantee rests on, what is proven by tests in `redteam/`, and where the honest limits are. No marketing.

## The adversary

Assume the worst realistic case: the model fully controls the harness process (OpenClaw or any other agent) and every one of its descendants. It can issue any syscall that its user is allowed to. It cannot gain privileges its user does not have, and it cannot run `execve`/`execveat` around the gate (that is exactly what wardend notifies on).

Everything below turns on one question: does wardend run under the same user as the harness, or a different one?

## The decisive premise: same user vs separate user

wardend gates `execve`/`execveat` through a seccomp user-notification filter. It does not gate `kill`, `ptrace`, `process_vm_writev`, or writes to files and `/proc/<pid>/mem`. Under Linux, whether those cross-process operations are allowed is decided by the kernel from the UID, not by seccomp.

So there are two very different deployments:

- **Same-user install (simple, weaker).** wardend and the harness run as the same user. That user owns the wardend binary, its config, its key and its journal, and may signal and ptrace the wardend process. A malicious model can then disable wardend without a single `execve`: `kill` the supervisor, `ptrace` it, write `/proc/<pid>/mem`, overwrite the binary or config, or rewrite the service unit and restart the gateway without the gate. In this mode wardend is **defense in depth against unwanted exec, not a tamper-proof guard.** This is a limitation, stated openly, not a defect hidden behind a slogan.

- **Hardened install (recommended, strong).** wardend runs as a root system service; the harness runs as a **separate, less-privileged user** as a child of wardend. wardend drops the child's UID itself, after installing the filter and before `exec` (`--child-user`). Now the kernel denies the harness user any signal, ptrace or memory write against wardend, and the root-owned binary, config, key and system unit cannot be rewritten. This is the configuration in which "the model can't turn wardend off" is actually true. Step-by-step setup, data migration and verification: [Install, hardened](../install/#hardened-install-recommended).

## Vector table

| Vector | Same-user | Hardened install |
|---|---|---|
| Run a command around the gate (`execve`/`execveat`) | Closed (seccomp USER_NOTIF) | Closed |
| Nested seccomp notify filter to answer "yes" itself | Closed (filter denies a new listener) | Closed |
| 32-bit / compat exec to dodge the filter | Closed (foreign arch -> ENOSYS) | Closed |
| `memfd_create` + `execveat`, `fexecve`, calling `ld.so` directly | Closed (still gated; unresolved path -> deny) | Closed |
| TOCTOU: swap argv or the file after CONTINUE | Closed (SIGSTOP post-check, default) | Closed |
| Approve its own card over the socket or the relay | Closed (needs a trusted device signature; pairing only off the filter) | Closed |
| Forge or replay a ticket | Closed (Ed25519, nonce, time window) | Closed |
| Flood the card queue (DoS) | Closed (bounded queue -> EAGAIN) | Closed |
| `kill` / `ptrace` / `process_vm_writev` the supervisor | **Open** (same UID) | Closed by the kernel (different UID) |
| Write the binary / config / key / journal | **Open** (owned by the agent's UID) | Closed (root-owned) |
| Write `/proc/<supervisor>/mem` | **Open** | Closed by the kernel |
| Rewrite the service unit and restart without the gate | **Open** (user unit is writable) | Closed (root-owned system unit) |
| OOM-kill the supervisor | **Open** | Reduced (OOMScoreAdjust in the unit) |

Every "Closed" cell above is exercised by a test in `redteam/` or the main suite (exec, memfd, ld.so, nested listener, pairing, forgery, queue). Every "Open" cell is demonstrated succeeding in same-user mode by `redteam/run.sh`, which is the proof that the hardened install is not optional for a real guarantee. The reverse check, `redteam/hardened-check.sh`, runs as the agent user on a hardened install and expects every one of those attacks to be refused ([step 7](../install/#step-6-verify-redteam-as-the-agent)).

## What wardend does at startup

- **Install self-check.** In enforce modes wardend refuses to start if its binary, config, key or state directory is group- or world-writable. With `require_hardened` it also refuses unless the binary, config and key are root-owned. This turns a misconfigured install into a hard failure instead of a silent weakness.
- **UID drop for the child.** With `--child-user`, wardend sets the child's groups, gid and uid (uid last, refuses uid 0) after the filter is in place, so the harness runs unprivileged while wardend keeps its own identity.

## Honest premises and out of scope

- The strong guarantee assumes a **hardened install**: separate UID, root-owned binary and config, a system unit, no passwordless `sudo` and no root-equivalent group (for example `docker`) for the harness user. Turning on Yama `ptrace_scope` is recommended.
- Linux 5.19 or newer is required (`SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`; measured on 6.18).
- wardend guards only its own process subtree. A separate shell, a user cron job or a systemd timer that starts work outside that tree is out of scope; that is bypassing the gate's area, not disabling wardend.
- If wardend dies, future `execve` in the surviving tree fails closed (ENOSYS), but processes that need no exec keep running. Killing the whole tree on supervisor death is an option, not the default.
- Gating `kill`/`ptrace` by argument in seccomp is deliberately not shipped: it cannot cover `/proc/<pid>/mem` writes and would give a false sense of safety in same-user mode. The real answer is a separate UID.
