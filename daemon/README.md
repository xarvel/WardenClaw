# wardend: an execve gate on seccomp user notification, v0.3

*Take back control.* A risky agent command does not run until your phone signs it.

`wardend` runs a process (in production, the OpenClaw gateway) under a seccomp filter and decides
the fate of every `execve`/`execveat` in the whole tree: the kernel stops the call, the supervisor
reads argv/cwd/exe/the ancestor chain from the stopped process and answers `CONTINUE` or an error.
By default (policy mode `tripwire`) every launch is checked against rules: risky ones (remote
execution, delegation, package installation, publishing, secrets …) wait for an **Ed25519
signature of a WardenClaw device** over the canonical envelope, the rest pass and are written to
the journal. The former `root` mode: "root" launches wait for a signature, children of an approved
root pass on their own while its subtree is alive (section 2). No cgo and no libseccomp,
Linux ≥ 5.19 (here Pi 5, 6.18, arm64). The gate itself works without root too, but the recommended
install is the hardened one: wardend as a system service running as root, the harness under a
separate user (section "Installation").

**Does not depend on OpenClaw.** The phone pairs with wardend directly (`wardend pair start` prints
a QR in the terminal, the `wardend pair approve` confirmation happens only on the server) and talks
to wardend's own HTTP endpoint (`127.0.0.1:8787`, exposed as a separate hostname in a Cloudflare
tunnel, [deploy/CLOUDFLARE.md](deploy/CLOUDFLARE.md)). Requests, tickets and responses are signed;
the app pins the server key from the QR. The OpenClaw plugin `wardenclaw-gate` is an optional adapter.

The v0.1 spike (measurements, the `WAIT_KILLABLE_RECV` pitfall, fail-closed on supervisor death) is
in the git history (`085e74e`) and, briefly, below in "Pitfalls".

```
systemd ─ wardend run --mode ticket -- node openclaw gateway
            │  helper: no_new_privs + seccomp(NEW_LISTENER|WAIT_KILLABLE_RECV) → execve(gateway)
            │  listener fd ← SCM_RIGHTS
            ├─ loop: poll → NOTIF_RECV → goroutine per notification:
            │     collect: /proc/<tid>/{mem,status,stat,cwd,exe}, realpath of the target, PPid chain
            │     tripwire policy: deny_always → packs → rules → pair → card | logged
            │     (policy_mode root: deny_always → service_allow → delegating → inherit → root)
            │     card (tripwire, root): envelope v1 → digest → pending queue → ticket (TTL) → verify
            │     NOTIF_ID_VALID → [tgkill SIGSTOP] → NOTIF_SEND(CONTINUE | -EPERM/-EAGAIN/-ENOENT)
            │     stop-verify: the new image stops before its 1st instruction → cmdline/exe == envelope ? SIGCONT : SIGKILL
            │     journal: JSONL, hash chain, signed with the supervisor key
            ├─ ~/.wardend/wardend.sock (0600, SO_PEERCRED uid) JSON-RPC: pending | decide | status | journal.tail | pair.*
            │       ▲  wardend pair start|list|approve (CLI on the server)   ▲ (optional) relay of the wardenclaw-gate plugin
            └─ HTTP 127.0.0.1:8787: /v1/pending | decide | status | pair | pair/status | ping  (responses are signed)
                    ▲
                    └── Cloudflare tunnel (wardend.example.com) ── WardenClaw app (server key pinned from the QR)
```

## 1. Envelope v1 and ticket (`envelope/`)

The normative protocol specification (envelope, canonical JSON, ticket, second factor, signing
strings of the transport and pairing) lives in [protocol/](../protocol/README.md) at the monorepo
root under Apache-2.0; this section describes the implementation.

```
{v:1, type:"exec", argv, cwd, exe, uid, gid, ppidChain:[{pid,exe}], env, envHash,
 requester:{host, supervisorId}, pidfdCookie, ts, nonce}
```

* `exe`: realpath of the file **being launched**; `ppidChain[0]`: the calling process itself (pid = tgid,
  exe = its image before exec), then the parents up to the supervisor (not included); `uid/gid`: effective.
* `env`: variables that change program behavior (the `LD_*` loader, shell startup files and
  functions, interpreter paths and options, `GIT_*`, configs and settings directories, pager, editor,
  proxy; the exact rule is in `protocol/README.md`, section 3): `[{name, value[, cut]}]` in envp order
  with repeats, value up to 1024 code points (`cut`: how much was cut off), secret-looking ones are
  left out. Signed and shown on the card in the "Environment" block. `LD_PRELOAD`, `LD_AUDIT`,
  `LD_LIBRARY_PATH` on a launch outside an approved root that would pass without a card (`logged`,
  `service`) turn it into a card of tripwire category `loader-env`; the app never allows such cards
  on its own.
* `envHash`: sha256 of the whole sorted envp (NUL separators); `requester.supervisorId`:
  sha256 of the supervisor public key; `pidfdCookie`: `pidfs:<inode>` of the caller's pidfd
  (unique within a boot, binds the ticket to the process instance), otherwise
  `start:<pid>:<starttime>`; `ts`: ms (like `Date.now()`), `nonce`: 16 bytes hex.
* **digest = sha256(canonicalJson(envelope))**; the pending record id = `wd-` + the first 32 hex of digest.

**Canonical JSON byte-for-byte with `app/src/core/canonical.ts` and `plugin/src/canonical.js`.**
Those are built on `JSON.stringify`, so the Go encoder (`envelope/canonical.go`) follows the
ECMAScript rules rather than `encoding/json`: keys are sorted by UTF-16 code units (like `Array.sort()`,
which differs from byte sorting on characters outside the BMP), only `"` `\` and control characters
< 0x20 are escaped (`\b\t\n\f\r`, the rest as lowercase `\u00xx`), `< > &`, U+2028/2029, DEL stay as is
(encoding/json escapes U+2028 even with `SetEscapeHTML(false)`), numbers use Number::toString
(`1e+21`, `1e-7`, `0.000001`). Invalid UTF-8 is an error: such an envelope is not built, the exec
gets EPERM (the app could neither show nor recompute it).
**Cross-test**: `protocol/vectors/canonical_vectors.json` is generated by the plugin's `canonical.js`
(a single copy at the monorepo root, no duplicates); Go (`TestCanonicalVectors`), the plugin
(`test/vectors.test.js`) and the app (`npm test` → `scripts/test-core.mjs`, which compiles the
real `canonical.ts`) check the same 7 vectors (Unicode, control characters, U+2028,
UTF-16 sorting, numbers, typed exec envelope) straight from `protocol/vectors/`.

**Ticket**: the plugin's decision format, so that the app signs with the same code (`gate.ts signDecision`):

```json
{"deviceId":"<hex64>","payload":{"type":"wardenclaw.ticket.exec.v1","supervisorId":"<hex64>","id":"wd-…","digest":"<hex64>","decision":"allow|deny","ts":1790000000000,"nonce":"…"},"signature":"<base64url>"}
```

Ed25519 signature over `canonicalJson({type,deviceId,id,digest,decision,ts,nonce,supervisorId[,risk]})`.
The ticket type is under the signature: wardend accepts only `wardenclaw.ticket.exec.v1` with its own
`supervisorId` (otherwise `ticket_type_mismatch` / `supervisor_mismatch`, before the signature check);
a decision on a plugin tool call (`wardenclaw.ticket.tool.v1`) is not a ticket for it (`protocol/README.md`, §4).
Checks (as in the plugin, `envelope.Verify`): type and supervisor → device in `trusted_devices` → key → `|now−ts| ≤ 60 s` → signature →
nonce (taken only after a valid signature) → id is known and digest matches.
**Keys**: trust comes only from the wardend config (`trusted_devices: [{id, pubkey?}]`). A `pubkey` from
the config is pinned; if there is none, it is taken from `~/.openclaw/state/openclaw.sqlite`,
`device_pairing_paired.public_key` (`sqlite3 -readonly -json`, 30 s cache; `gateway_db: off`
turns this off). If both exist and differ, the result is a `pubkey_conflict` refusal, not a silent choice.
Any key (config and DB, both algorithms) is accepted only if `sha256(key) = id`, as in
pairing: the agent uid can write the gateway DB, a foreign key under a trusted id is not accepted
(`gateway_pubkey_mismatch`), and a config entry with such a key keeps wardend from starting.

## 2. Policy (`policy/`): tripwire and "approved root"

Two policy modes, config key `policy_mode` (flag `--policy-mode`); it is orthogonal to `mode`
(`observe | deny-list | ticket` decides whether the decision is enforced):

| `policy_mode` | Who needs a signature | What happens to children of an approved launch |
|---|---|---|
| `tripwire` (default) | only the launch that tripped a rule (remote execution, delegation, package installation, publishing, destruction, protected paths and secrets, agent settings, adb …) | only hits of the same tool family pass without a card (ssh under scp, eas under `npx eas-cli`), and for no longer than 10 minutes; everything else is checked on its own |
| `root` | every "root": a launch not inside an approved tree, and every delegating one | the whole live subtree |

### Tripwire mode

Every exec is checked against rules; no subtree gets blanket trust. Order (`policy/classify.go`,
`ClassifyTripwire`): `deny_always` → harness CLI verbs that change agent settings → harness service
launches (packs, `service_allow`) → custom `tripwire` rules from the policy file →
built-in categories (`policy/tripwire.go`) → `sudo` refusal → inheritance pair → card. Everything
that tripped no rule is allowed and written to the journal with class `logged`.

| class | what | decision |
|---|---|---|
| `logged` | no rule tripped | allow, journal |
| `service` | harness service launch (pack, `service_allow`) | allow, journal, rule `pack:<pack>/<id>` |
| `tripwire` | a rule tripped: `category`/`rule`, `detail` (verb from the dictionary) | ticket |
| `implied` | a hit of the same family under an approved tripwire launch, ≤ 10 min | allow, `rootPid` |
| `refuse` | `sudo`, `su`, `doas`, `pkexec`, `sudoedit`, `newgrp`, `sg`: a setuid binary, while the tree has `no_new_privs` | EPERM at once, reason in the journal, no card |
| `deny_always` | as in root | EPERM |

Categories and rules:

| category | trips | does not trip |
|---|---|---|
| `delegate` | `systemd-run`; `systemctl` except `status/show/cat/is-*/list-*`; `loginctl` except `list-*/show-*` (`enable-linger` is a bypass); `busctl call/set-property`; `dbus-send` except `GetNameOwner/Get*/Introspect`; `tmux/screen/zellij`; `at`; `crontab` except `-l` | reading state |
| `container` | `docker/podman` except `ps/inspect/logs/images/stats/version/info`, `compose` except `ps/logs/config`; `kubectl` except reads; `flatpak-spawn`, `distrobox`, `toolbox` … | |
| `remote` | `ssh`, `scp`, `sftp`, `rsync host:…`, `nc/ncat/socat/telnet` | local `rsync` |
| `privilege` | `nsenter/unshare/chroot/setpriv/capsh`, `apt/dpkg install`; `sudo` and company get `refuse` | |
| `net-write` | `curl/wget` with a body or a write method to a non-loopback address | GET, writes to 127.0.0.1 |
| `pkg-run` | `npm install/ci/exec`, `npx` with `-y/-p/pkg@version`, `pip install`, `uv run`, `pnpm/yarn add/dlx`, `go install/get`, `cargo/gem install` | `npm run`, `npx tsc` |
| `publish` | `git push`, `npm publish`, `gh pr/release/repo/secret` writes, `gh api` with a write, `eas build/submit/update/…` | `gh pr list`, `eas build:view` |
| `destructive` | `rm -r` and `find -delete` outside scratch; `git reset --hard`, `clean -f`, `checkout -- .`, `stash drop`, `branch -D`, `filter-branch`, `reflog expire` in a non-scratch repository | `rm -rf /tmp/…`, `node_modules`, `dist` |
| `protected-write` | write, delete, `chmod` in the `config` zones (dotfiles, `~/.local/bin`, `~/.config/systemd`, `~/.nvm`, `~/.wardend`, `~/.ssh`, `/etc`, `/usr` …, harness settings) and `secret` | |
| `outside-work` | write and delete outside `work_dirs` and scratch (only if `work_dirs` are set) and in top-level directories (`/`, `/home`, `/mnt/<disk>`, the home itself) | |
| `secret-read` | printing tools (`cat`, `head`, `grep`, `jq`, `cp`, `base64`, `openssl -in`, an interpreter with a path) on the `secret` zone (`~/.ssh/id_*`, `~/.config/*token*`, `.env`, `supervisor.key`, harness secrets); `gh auth token` | `*.pub`, `known_hosts` |
| `agent-config` | harness CLI verbs from its pack: `openclaw config set/cron add/secrets/plugins install …`, `claude mcp add/config set …` | `cron list`, `--help` |
| `guard` | CLI of the live wardend/wardenctl: `pair`, `trust`, `devices`, `policy`, `keygen`, `hw` … | test builds in `/tmp` |
| `device` | `adb` except reads (`devices`, `logcat`, `pull`, `exec-out screencap`, `shell dumpsys/getprop/ls/pm list/settings get`); `fastboot` | |
| `cloud` | `aws/gcloud/az/terraform/helm/flyctl/vercel/wrangler` … | |

A rule looks at the **real binary** (basename of the target's realpath) and argv, so
`./ssh.sh 'sudo …'` is an agent script in the journal, but the real `ssh` inside still falls under
the rule. Paths are taken from argv with cwd and `~` resolved: `cat id_rsa` in `~/.ssh` is a secret read.
Path zones (`secret`, `config`, `scratch`, `work`, `top`, `other`) come from the built-in ones (`zones` in
`defaults.json`), from harness packs and from the config: `work_dirs` (working directories), `scratch_dirs`
(extra temporary ones). A policy file without `zones` gets the built-in ones.

**Inheritance pairs.** An approved tripwire launch is registered as a root with its tool family
(`Hit.Family`). Families: `ssh` (ssh, scp, sftp, sshpass, mosh, rsync to a host), `npm` (npm,
npx, pnpm, yarn, bun), `eas` (`npx eas-cli`, eas), `docker` (docker, podman, compose), `systemd`
(systemd-run, systemctl, loginctl, busctl, D-Bus), `adb` (adb, fastboot), `git`, `gh`, `pip`, the
harness CLI (the pack's family); any other tool and a custom `tripwire` rule is a separate
family. A descendant of an approved launch passes without a card (`implied`) only if the rule it
tripped is of the same family (`policy.ImpliedBy`; plus the `ssh` transport under `git push`) and
no more than 10 minutes have passed since the approval: the `ssh` transport under `scp`, `eas` under
`npx eas-cli`, the `docker-compose` plugin under `docker compose`, the OpenClaw CLI restarting
itself. Everything else in the subtree is checked by its own rules: an approved `npm ci` does not
make `curl -d` or `ssh` from a postinstall free. But one more `npm install` or `npx -y` from the same
postinstall passes without a card during those 10 minutes: it is the same family.

**sudo.** The helper sets `no_new_privs` on the tree, setuid under it does not raise privileges, so a
ticket for `sudo` is useless: `refuse`, EPERM at once, the reason in the journal. A `sudo` shim
without the setuid bit gets a regular `privilege` card.

**Harness packs** (`policy/pack.go`, `policy/packs/*.json`, embedded in the binary; to print one:
`wardend policy-defaults --pack claude-cli`). Everything known about a specific harness lives in its
pack: the process model (service launches: `claude` itself, its `rg`, git probes, the environment
snapshot; OpenClaw gateway workers and probes, its OOM launch wrapper), the zones of its settings and
secrets, its CLI verbs for `agent-config`. Paths are given as variables rather than regexes over
`/home`; in a regex `${NAME}` expands to `(?:path1|path2)` of escaped values, so
the install path does not break the regex. The same variables work in the regexes of a custom
policy file, and in `work_dirs` and `scratch_dirs` so does `~`:

| variable | where the value comes from | default |
|---|---|---|
| `${AGENT_HOME}` | `agent_home` from the config, otherwise the home of `child_user`, otherwise wardend's `$HOME` | |
| `${ANY_HOME}` | only in regexes: `${AGENT_HOME}`, `/home/<any>`, `/root` | |
| `${CLAUDE_ROOT}` (claude-cli) | a wardend command like `…/claude/versions/X.Y.Z` (auto-detection), `pack_vars` | `${AGENT_HOME}/.local/share/claude`, `/opt/claude` |
| `${CLAUDE_BIN}` (claude-cli) | `pack_vars` | `${AGENT_HOME}/.local/bin/claude`, `/usr/local/bin/claude` |
| `${OPENCLAW_ROOT}` (openclaw) | a wardend command like `…/openclaw/dist/index.js` (or `entry.js`, `openclaw.mjs`, with realpath), `pack_vars` | `/usr/lib/node_modules/openclaw`, `/usr/local/lib/node_modules/openclaw`, `/opt/openclaw` |
| `${OPENCLAW_HOME}` (openclaw) | `pack_vars` | `${AGENT_HOME}/.openclaw` |

An auto-detected value is added to the defaults; `pack_vars` replaces the whole
list. `AGENT_HOME` and `ANY_HOME` are not set through `pack_vars` (use `agent_home`); an unknown
variable in a rule or pack is a load error (wardend exits with code 2 without starting
anything), not a rule silently matching whatever. Pack selection:

* which are loaded: `packs` in the config (names of built-in ones or file paths; `[]` for none),
  all built-in ones by default;
* which exec it applies to: by the process chain. A pack's rules match only inside its own
  harness (`caller`/`path` by the harness binary, `under`: the harness runtime among the ancestors,
  `chain_all`: all ancestors are gateway processes);
* where the harness lives: the defaults, auto-detection from the command wardend launched
  (`node …/openclaw/dist/index.js gateway` → `${OPENCLAW_ROOT}`), an override with `pack_vars` in the config
  (hardened install: `{"CLAUDE_ROOT": ["/opt/claude"]}`).

Previously 7 of the 20 claude-cli rules were tied to `/home/…` and silently failed to match in a
hardened install (agent home `/var/lib/agent`, harness in `/opt`): `claude` itself became a root,
and one signature covered the whole agent turn. `TestClaudePackHardenedInstall` runs the real
claude-cli log in that layout: all 7 rules match.

**Checking against your own journal:** `wardend replay --journal ~/.wardend/journal.jsonl --config
~/.wardend/config.json` (section "CLI"): the same classifier code, every hit is treated as
approved, only aggregates are printed. On a 25-hour developer journal (98,053 execs) that is
3,162 cards a day in root and 819 in tripwire (74% fewer), peak 34 in 2 minutes; a per-exec
comparison with the review simulator found 0 discrepancies (`docs/tripwire.md`).

**What tripwire honestly does not see** (root does not see it either, it only hides it in one card
for the whole turn):

1. Actions without a new exec: shell redirections (`> ~/.bashrc`, `< ~/.ssh/id_ed25519`),
   builtins (`kill`, `echo >`), harness file tools (Write/Edit), network and
   files from inside long-lived processes, MCP calls.
2. Code inside interpreters: `python3 -c`, `node -e`, an agent script can do anything; only the
   fact of the launch is visible. The same goes for an argv race in a multi-threaded process: a
   checked exec is not verified afterwards (`toctou` only for approved ones).
3. Browser and CDP: `openclaw browser evaluate` and requests to `127.0.0.1:<CDP port>` act in
   logged-in sessions.
4. Execution outside the gate after approval: an approved `systemd-run`, `docker run`, `ssh` is not
   visible beyond that point.
5. Identity by name: a rule is bypassed by a copy of the binary under another name (this needs the
   target's sha256 and an "executing an agent-writable file" flag).
6. The meaning of arguments and what is not in argv: `npm test` and `go test` run code the
   agent writes; `curl -K file` takes the method and body from a file, and `net-write` does not see them.

**Why a box.** Tripwire looks at execs, so it protects against an agent acting with standard
tools (a typical hijacked agent and a typical mistake), but not against an agent that writes its
own code: a `python3 -c` that reads a key and sends it out passes as `logged`.
Against that you need a **box**, that is, restrictions that hold for any code:

* the hardened install (section "Installation"): the harness under a separate user, `ProtectHome=true`
  (your home with SSH keys, tokens and browser profiles does not exist in the agent's file system
  at all, so there is nothing to read there by exec, redirection or interpreter code),
  `ProtectSystem=strict` and writes only to the agent home and the listed `ReadWritePaths`,
  `NoNewPrivileges`;
* outbound network by allowlist: the harness can reach only the model API and named hosts (a proxy
  with a domain allowlist). Without it any code sends anything anywhere. The installer
  **does not do this yet**: the hardened install unit does not restrict the network;
* an MCP proxy for tools that act beyond the host (planned).

Tripwire complements the box rather than replacing it: the box limits what any code can reach at
all, and tripwire asks about risky steps within those limits.

### Root mode

Order (the first match decides):

| class | what | decision |
|---|---|---|
| `supervised_cmd` | the helper's first exec: the operator's command itself (the gateway) | allow, **not** a root |
| `missing` | the target does not exist (execvp PATH search) | ENOENT at once, no CONTINUE |
| `unreadable` | the caller's memory cannot be read, the path is unknown (Yama `ptrace_scope=2` without CAP_SYS_PTRACE) | EPERM, no ticket, the reason in the journal |
| `deny_always` | regex over argv/exe: `rm -r` on `/`, `$HOME`, system directories, `--no-preserve-root`, `dd of=/dev/…`, `mkfs*`/`wipefs`/`fdisk`/`parted`, `shred /dev/…`, `chmod/chown -R /…`; argv0 **or** the real file name (`exec -a innocent rm`) | EPERM without questions, even inside an approved tree |
| `service` | an allow-list of harness service execs by exe + argv template + caller exe | allow, journal, **no inheritance** |
| `delegating` | `setsid`, `systemd-run/systemctl/busctl`, `docker/podman/kubectl/bwrap…`, `tmux/screen/zellij`, `at/crontab`, `sudo/su/pkexec/nsenter/unshare/chroot`, `ssh/scp` | always a new root → ticket |
| `inherit` | the caller is in the live subtree of an approved root | allow |
| `root` | everything else | ticket |

**The claude-cli pack is built from `bench/claude-observe.jsonl`** (claude-cli 2.1.283; it used to be
`service_allow` in `defaults.json`, now it is `policy/packs/claude-cli.json`): `claude` itself, its
built-in `rg` (an exec of itself with argv0 `rg`, without `--pre`), git probes (only known `-c`,
only reading subcommands), `sh -c "ps -o command= -p N"`, `sh -c "uname …"`, `bash -c env`,
the snapshot script `bash -c -l SNAPSHOT_FILE=…` (the whole text is a literal; only the snapshot
path, `$HOME`, the PATH line inside the heredoc and its delimiter vary; injections anywhere in the
script are rejected, `TestSnapshotRuleRejectsInjection`) and its children with exact argv (`id -u`,
`locale`, `run-parts --list …`, `grep`/`sed`/`awk`/`head`/`cut`/`cat` from the script, only with the
calling bash). The generator is `bench/gen_defaults.py`; after a claude-cli update the snapshot
script may change → it falls into "root" (fail-closed) → regenerate. Custom rules:
`test -e ~/.wardend/policy.json || wardend policy-defaults > ~/.wardend/policy.json` (the existence
check keeps a rerun from overwriting your additions), add your rules, `"policy": "…"` in the config.
`TestClaudeObserveLog` runs the whole real log: 34 service, 1 root (the user's command itself
`bash -c "source snapshot … eval 'ls -la /tmp'"`), 1 inherit (`ls`).

**Subtree** (`policy/tracker.go`): a root is registered before `CONTINUE`; every process whose exec
passed as a descendant enters the lineage (pid + starttime from `/proc/<pid>/stat`, protection against
pid reuse). Inheritance walks up the caller's PPid chain to a live lineage member, so "the subtree
is alive" while at least one of its ancestor processes is alive, not only the root.
Cleanup every 2 s; the end of a subtree is a `root_exit` record in the journal.

### Delegating spawn and detaching from the tree: what happens (pinned by tests)

* `bash -c 'ls; (sleep 0.2; ls) & wait; python3 -c "import os; os.system(\"true\")"'`: **one
  ticket** for `bash`; `ls`, `sleep`, `ls`, `python3`, `sh -c true` are inherit
  (`TestTicketOneRootChildrenInherit`, demo step 1).
* `bash -c 'setsid nohup ls &'`: `setsid` inside an approved root = a new root, **a second
  ticket** (`meta.delegating` on the card). Not approved → `setsid: Operation not permitted`. Approved →
  `nohup` and `ls` (the same pid) inherit from it (`TestSetsidIsNewRoot`).
* Double-fork / daemonization: a process orphaned **before its first exec** (the root parent has
  already exited, the kernel re-parented it to wardend, the tree's subreaper) is a new root for wardend: we do not
  see fork, and the link to the root through the chain is lost. `bash -c '(read -t 0.3; ls) & exit 0'` → `ls` asks for a ticket;
  with `wait` instead of `exit` it inherits (`TestOrphanBeforeExecIsNewRoot`). This is fail-closed, but can
  cause extra requests for scripts that start a background job and exit right away.
  wardend is a child subreaper (`PR_SET_CHILD_SUBREAPER`), so an orphan stays its descendant: Yama
  `ptrace_scope=1` (the Ubuntu default) still lets wardend read the orphan's memory, and the sweep reaps
  the orphans when they exit (only processes under the tree's filter; a process wardend started itself
  keeps its exit status for its waiter).
* `systemd-run`, `docker`, `tmux`, `ssh`, `at`: the client itself is a root with a ticket, but **execution
  goes to a daemon outside the wardend tree** (systemd, dockerd, an already running tmux server, another
  host), and wardend does not see it beyond that. By approving such a ticket, a person approves "anything over there".
  If a tmux server starts from our tree, it daemonizes → its children are orphans → every
  launch in it asks for a ticket again.
* **Nested supervisor**: the wardend filter answers EPERM to `seccomp(SET_MODE_FILTER)` with the flag
  `NEW_LISTENER`. Otherwise a process under wardend could install its own unotify filter: with equal actions
  the kernel hands the notification to the newest filter, and it would answer `CONTINUE` past us. Regular
  filters (chromium, systemd services) are allowed: they can only tighten things, `USER_NOTIF`
  takes precedence over `ALLOW/TRACE/LOG` (`TestNestedListenerBlocked`; the idea comes from grith, no code borrowed).

## 3. TOCTOU: post-check

argv/filename are read from the caller's memory **before** the answer, while the kernel copies them **after**
`CONTINUE`; other threads of the process, a vfork parent or `process_vm_writev` can swap the buffer
between these moments. The kernel cannot pin execve arguments. Modes (`toctou_roots`,
`toctou_service`):

* **`stop`** (default for roots): before `CONTINUE`, `tgkill(SIGSTOP)` to exactly the calling
  thread. While it is in the kernel, the signal stays pending; the first return to user space after a successful execve is already in
  the new image, and the process stops **before the first instruction of the new program**. We compare
  `/proc/<pid>/exe` (+ dev/ino of the file resolved during the check, which catches a file swapped at the path) and
  `/proc/<pid>/cmdline` (for `#!` scripts the expected value is `[interp, (arg), path, argv[1:]…]`) with the
  envelope: match → `SIGCONT`, mismatch → `SIGKILL` via pidfd + `toctou_kill` in the journal.
  If execve returned an error, the old image stops too, is recognized by matching the
  pre-exec snapshot, `SIGCONT`.
* `poll`: no stop, polling `/proc` until the image changes (≤ 50 ms), `SIGKILL` on mismatch.
* `off`.

**Test with an "evil" process** (a single run; `bench/evil_argv.c`: a second thread keeps rewriting argv[1]
between `SAFE-ARG` and `EVIL-ARG` in a loop, the main one does execve `/bin/echo`; the device approves only
envelopes with `SAFE-ARG`), 40 launches per mode, `TestToctouEvil*`:

| mode | approved | echo printed something other than `SAFE-ARG` (leak) | killed by the post-check |
|---|---|---|---|
| off | 5 | **4** (`EVIL-ARG`, `SVIL-ARG`, `SAFL-ARG`…) | n/a |
| poll | 7 | **3**: echo manages to print before SIGKILL, the window exists | 7 |
| stop | 8 | **0** | 6 (2 honest SAFE passed) |

So the race is real (off), poll catches it but too late, **stop closes the window completely**: the swapped
program does not execute a single instruction. The cost of stop is that the parent sees `CLD_STOPPED/CLD_CONTINUED`
(for `waitpid(WUNTRACED|WCONTINUED)` and `SIGCHLD` without `SA_NOCLDSTOP`); verified that dash, bash,
python `subprocess` (vfork/posix_spawn) and node `child_process` (libuv fork) work as usual:
the same output and exit codes (`TestStopVerifyParents`); the check itself takes ~1–1.5 ms per root.
For service the default is `off`: their callers are trusted harness code (claude/git), and TOCTOU
requires a malicious caller; enable it with `toctou_service: stop`. There is no post-check for `inherit`:
the subtree is already approved as a whole (and `deny_always` inside it is a safety net,
not a boundary; an evil approved process can bypass it with a race).

## 4. Transport and pairing

**The main path is wardend's own HTTP endpoint** (`httpapi.go`, `http_listen`, default
`127.0.0.1:8787`; if it fails to come up, wardend keeps running, the reason is in `status.http.error`):

* `GET /v1/pending?since&wait` (long-poll ≤ 25 s), `GET /v1/status`: headers
  `X-Wardenclaw-Device/-Ts/-Nonce/-Signature`, a device-key signature over
  `canonicalJson({type:"wardenclaw.req.v1", supervisorId, action, deviceId, ts, nonce})` with the supervisorId
  of this wardend (a request for another wardend or in the plugin format does not pass), window `ts_window`,
  single-use nonce;
* `POST /v1/decide`: a ticket (signed itself, the same check as over the socket);
* `POST /v1/pair`, `GET /v1/pair/status`: pairing; `GET /v1/ping`: no authentication;
* **every response is signed with the supervisor key** (the same `supervisor.key` that signs the journal):
  `X-Wardend-Signature` over a string bound to the request: `canonicalJson({type:"wardenclaw.resp.v1",
  action, deviceId, nonce, status, bodySha256[, id, digest]})` for an authenticated request (for decide, the
  ticket's id and digest), `wardenclaw.ping.v1` with `?nonce` for ping, `wardenclaw.resp.unauth.v1` with only
  action for a refusal before the request signature is checked. The app, the watch and `wardenctl` accept only a response
  to their own request signed with the key from the QR: the tunnel can neither slip in a card, nor replay
  an old response, nor pass off a ping or a response to another request as a response to decide.

**Pairing** (`pairing.go`, `paircmd.go`): `wardend pair start` → a one-time code (5 min) and a QR with
the link `wardenclaw://pair?code&host&key=<supervisor key>&url=<public_url>&v=1` (our own QR, `qr/`,
byte mode, level M; verified with the zxing decoder on all versions and masks). The app sends
its public key, signed together with the code and `supervisorId` (`wardenclaw.pair.v1`); the code
burns on the first valid request, 10 wrong ones in a row kill all codes. `wardend pair list`
shows the fingerprint (the first 16 hex of deviceId, in groups of 4), the same one as on the phone screen;
`wardend pair approve <id>` appends `{id, pubkey, name, added_at}` to `trusted_devices` in the config
(atomically, other fields are left untouched) and immediately trusts the device in the running supervisor.
**Approval works only over the socket and not from under this wardend's filter**: the socket client
(`SO_PEERCRED` pid) must not have more seccomp filters than the supervisor and must not be a
descendant of the supervisor's child, so an agent under the gateway cannot pair a device for itself. Signing strings,
signatures and the link format are pinned by the cross-fixture `protocol/vectors/transport_vectors.json`
(Go ↔ app). `gateway_db` (keys from the OpenClaw gateway DB) is now `off` by default.

**wardenctl** (`cmd/wardenctl`, a separate binary in the same module, no cgo, builds for
darwin/linux arm64/amd64) is a terminal counterpart of the app for your laptop: pairing via the same
link, `pending/show/approve/deny/watch`, YubiKey over USB via the libfido2 utilities (not in the
first release: only a build with `-tags hwkey`, [docs/hwkey.md](docs/hwkey.md); in the release `approve` and
`watch` sign only with the device key), the device key in the macOS Keychain. Next to the agent
(under the wardend filter or as the same user on the server)
it refuses to work. Details: `cmd/wardenctl/README.md`.

**ntfy** (optional, `ntfy_url`): on a new card wardend POSTs "New request to approve"
to the topic, without the command or host, at most once per 10 s. Anyone who knows the topic name sees when
cards appear and can send pushes to that topic: use a long random name or your own ntfy server with `ntfy_token`.

**Apple Watch and APNs** (optional, `apns` in the config; `apns.go`, `push.go`,
`envelope/devicekey.go`). The watch pairs as a separate device with a P-256 key from the Secure
Enclave (`alg: "es256"` in pairing and in `trusted_devices`, a signature over the same bytes, raw r||s or
DER). Devices register APNs tokens (`POST /v1/push/register`, signed with headers over the
body); on a new card wardend sends a push over HTTP/2 with an ES256 JWT from the `.p8`; the payload carries only
`cardId`. A 410 from APNs deletes the token, `wardend pair revoke` deletes the device's tokens,
`wardend push list|test` is for debugging. The watch does not approve cards with `meta.hardware.required`
(`hardware_required`). Specification: `protocol/README.md`, sections 7 and 8; work log:
`docs/watch-apns.md`.

Unix socket `~/.wardend/wardend.sock` (0600, directory 0700, plus `SO_PEERCRED`: only the supervisor
uid), JSON-RPC 2.0, one line per message, requests within a connection are served in parallel:

* `pending {since, wait≤25000}`: long-poll: `{seq, mode, supervisorId, host, pending:[{id, kind:"exec", digest, envelope, meta:{class, rule, path, syscall, callerExe, delegating?, insideRoot?}, createdAt, expiresAt}], now}`
* `decide <ticket>` → `{ok:true, id, decision}` | `{ok:false, reason}` (`type_invalid`, `supervisor_id_invalid`, `ticket_type_mismatch`, `supervisor_mismatch`, `untrusted_device`, `bad_signature`, `digest_mismatch`, `stale_timestamp`, `nonce_reused`, `unknown_pending`, `already_decided`, `pubkey_conflict` …)
* `status`: mode, queue, tracker, trusted devices, journal key, metrics (below)
* `journal.tail {n}`
* `pair.start {ttl?, url?}`, `pair.list`, `pair.approve {id}`, `pair.reject {id}`, `pair.revoke {device}`
* `push.list`, `push.test {device?}` (test: not from under the wardend filter, like pair.*)

**Relay in the plugin** (the optional OpenClaw adapter) (`plugin/src/relay.js`): if the socket exists, the plugin holds a
long-poll to it and adds exec records (`id` `wd-…`, `kind:"exec"`, `envelope`, `meta`) to the response of its
`/wardenclaw/pending` (and WS `wardenclaw.pending`), bumping the store seq, so the app wakes up as if
for its own record. A `decide` with `wd-…` is forwarded to wardend as is. **The signature check happens in
wardend**; the plugin additionally pre-checks with the same `verifyDecision` (separate nonce accounting,
`relayPreverify`), which is only an early refusal. Tests: a fake wardend + **e2e with the real
binary** (a device on `@noble/ed25519` signs via the plugin's HTTP routes →
relay → wardend → execve runs).

**App** (`app/src/core/wardendClient.ts`, `wardendProto.ts`, `execEnvelope.ts`, `approvals.ts`, `FeedScreen`,
the Connect tab; by default directly to wardend, the OpenClaw adapter is off):
pending records `kind:"exec"` → an "EXEC · OS (wardend)" card: the command (for the claude-cli wrapper
the `eval '…'` is extracted), exe/uid/host, argv element by element, cwd, the process chain, the policy class,
a warning about a delegating launch. Before signing, the app **recomputes the digest itself**
from the envelope (strict parsing: exactly the 13 fields of v1) and compares it with the record's digest and id, and with a direct
connection also `requester.supervisorId` with the one pinned from the QR; on a mismatch only a denial
can be signed. Signing uses the same device key and the same `signDecision`.

## 5. Journal

`~/.wardend/journal.jsonl`, 0600, append-only. The plugin's journal format:
`hash = sha256(prevHash + canonicalJson({seq, ts, kind, data, prevHash}))`,
`sig = Ed25519(supervisor key ~/.wardend/supervisor.key, "wardenclaw.journal.v1\n" + hash)` (the prefix separates the journal signature from HTTP API responses, which the same key signs; journals written before the prefix are rejected by `verify-journal` with `bad_signature`). Both
`wardend verify-journal --pubkey <b64url> file` and the plugin's `verifyJournalFile` check it (verified).
Records: `start` (mode, command, journal key, trusted devices), `exec` for **every** exec
(pid/tgid/ppid, syscall, path, exe, callerExe, argv, cwd, envHash, uid, chain, class, rule,
rootPid, decision, errno, reason, digest + envelope + signed ticket for roots, TOCTOU
result, latency and ticket wait), `decide_reject`, `toctou_kill`, `root_exit`, `signal`, `stop`
(metrics). ~760 bytes per exec, which on the gateway is tens of MB a day; no rotation yet.

## 6. Reliability

* The queue of execs waiting for a ticket is bounded (`max_pending`, 64: the replay peak in tripwire is 34 cards in
  2 minutes, that is, within the TTL): on overflow the exec gets **EAGAIN** at once (`TestQueueLimitEAGAIN`).
  The limit remains a flow limiter; ntfy notifications are still at most once per 10 s.
* **Denial cache** of 10 s by (process, realpath, argv): dash/execvp continue the PATH search after EPERM
  (`/usr/bin/bash` → `/bin/bash`, the same file); without the cache a person would get a second request.
* SIGTERM/SIGINT/SIGHUP/SIGQUIT/SIGUSR1/SIGUSR2 → the child; the exit code is the child's code, death by
  signal is 128+N (SIGTERM = 143, as in the unit's `SuccessExitStatus`) (`TestSignalForwarding`).
* The child exited → wardend serves the rest of the tree until the listener's `POLLHUP` (the kernel: nobody is
  left under the filter) or `linger` (2 s), those waiting for a ticket get a denial, then it exits. Remaining
  processes get ENOSYS on exec (fail-closed); under systemd `KillMode=mixed` finishes them off.
* Death of wardend itself → all execs of the tree get ENOSYS (fail-closed); the unit restarts
  as a whole with `Restart=always`.
* `status.metrics`: `execs/allowed/denied`, `byClass`, tickets (allowed/denied/expired/queueFull),
  `toctouKills`, `decideRejects`, `latencyUs` and `ticketWaitUs` as count/p50/p95/max.

**Measurements** (Pi 5): `bash -c 'for i in $(seq 1000); do /bin/true; done'` takes 0.51 s without wardend,
1.06 s in observe (**+0.55 ms per exec**; the spike had +0.35, since then the chain with exe,
the target's realpath and the caller's cmdline were added). Inside the supervisor RECV→SEND p50 310 µs, p95 510 µs
(the journal is written after answering the kernel). stop-verify of a root +1–1.5 ms. For claude-cli (~36 execs per turn)
that is ~20 ms per turn.

## CLI

```
go build -o wardend .
wardend run [--config ~/.wardend/config.json] [--mode observe|deny-list|ticket] [--policy-mode tripwire|root]
            [--state-dir ~/.wardend] [--socket …] [--journal …] [--policy rules.json] [--ttl 120s] [--max-pending 64]
            [--trust <deviceId>[:<pubkey>]]… [--gateway-db off|auto|path]
            [--toctou-roots stop|poll|off] [--toctou-service off|poll|stop]
            [--http-listen 127.0.0.1:8787|off] [--public-url https://…] [--ntfy-url …] [--linger 2s] [--quiet] -- <cmd…>
wardend config-check [--config f] [--state-dir d] [--policy rules.json]   # config and policy as run reads them; 0 = starts
wardend pair start [--url https://…] [--ttl 5m] [--qr ansi|utf8|invert|none] [--no-wait]   # QR for the app
wardend pair list | approve <id> | reject <id> | revoke <deviceId|prefix>                 # on the server only
wardend keygen                         # test device: seed, pubkey (b64url), deviceId
wardend approve --key-file <file\|-> [--match regex] [--deny] [--count N] [--timeout 30s] [--socket …]
wardend status | journal [-n 20]       # over the socket
wardend verify-journal [--pubkey b64url] <journal.jsonl>
wardend policy-defaults [--pack name]  # built-in rules or a harness pack (claude-cli, openclaw)
wardend replay --journal <file> [--config f] [--policy-mode tripwire|root] [--from t] [--until t] [--json]
                                       # the journal through the classifier: cards per day, peaks, categories
```

Config: `deploy/config.example.json` (JSON; flags override it). Modes: `observe` allows
everything and writes the "what would have happened" class to the journal, roots and hits are "approved" automatically
(to see the real number of tickets); `deny-list` applies only `deny_always`; `ticket` is the enforcing mode. Policy
mode (`policy_mode`, section 2): `tripwire` by default, or `root`. Install keys for
tripwire and packs: `agent_home`, `work_dirs`, `scratch_dirs`, `packs`, `pack_vars`.

**Demo**: `bench/demo_ticket.sh` (≈15 s): a root waits for a ticket (`status: pending 1`), `wardend approve`
signs with a test key, children pass; `rm -rf /` and `dd of=/dev/null` are cut; `setsid` is
a second ticket; the TOCTOU villain under stop-verify (approved swapped images are killed); the journal
verifies, tampering with a single line is caught (`hash_mismatch`).

## Tests

`go test -p 1 ./...` (≈20 s): `envelope`: canonical vectors, tickets (forgery,
foreign key, replay, expiry, digest, config/DB key conflict); `policy`: the real
claude-cli log, snapshot injections, deny_always (including `exec -a`), delegating, git/rg,
tracker (subtree after the root dies, orphan, reused pid), tripwire: every
category and the neighboring cases that are only journaled, zones and cwd, sudo refusal, inheritance pairs and their
expiry, custom rules, the claude-cli pack in the hardened install layout, the OpenClaw pack (root
by command, gh and CA only from the gateway, the OOM wrapper as a literal), the `adb shell` tokenizer against
Python shlex; **tripwire under seccomp** (`tripwire_e2e_test.go`): `ls` without a card, `ssh` with
a card and a TTL denial, `ssh` under an approved `scp` without a card while a neighboring
`ssh` gets a card, `sudo` refused at once, `/proc/self/exe` and `/dev/fd/0` via the caller; `wardend replay`
on a synthetic journal; the root mode integration tests run with `policy_mode: root`; `journal`: chain,
forgery, line deletion, foreign key; integration: observe, one ticket per root,
deny_always inside a root, forgeries → TTL, device denial + PATH retry cache, EAGAIN, setsid,
orphan, nested listener, status/journal over RPC, SIGTERM forwarding, TOCTOU off/poll/stop,
python/node parents under stop; transport and pairing (`httpapi_test.go`): signed requests
(foreign device, other action, expiry, nonce replay), the response signature is bound to the nonce,
long-poll wakes up on a card, a ticket over HTTP releases the exec; pairing: no code, foreign
supervisor, spoofed name, wrong code, single-use code, status before/after approve, revoke,
preserving other config fields and 0600 permissions, 10 wrong codes kill the codes, `pair.*` refused
to a process under an extra seccomp filter and to a descendant of the child; ntfy coalesces and carries no details;
**e2e under seccomp** (`e2e_http_test.go`): QR link → `/v1/pair` → `pair approve` → card
over HTTP with the signature checked against the pinned key → ticket → execve; `qr/`: structure and (with
`WARDEND_QR_DECODER=<python with zxing-cpp>`) decoding of all versions and masks. Integration
tests install their own seccomp filter, and inside a wardend tree the kernel does not allow that: there they fail or
are skipped. A person runs them from their own terminal outside wardend (not from an agent session), or CI does.
Do not ask an agent to wrap them in `systemd-run --user` and the like: that is running code outside the gate, and
wardend will ask about it with a card marked accordingly.
The app against the real binary: `WARDEND_BIN=… node scripts/e2e-wardend.mjs` in `app/`. Plugin: `npm test` (41, including relay and e2e with `../daemon/wardend`).
App: `npm test` (vectors, envelope, `checkExecPending`) and `npx tsc --noEmit`.

## Installation

```shell
curl -fsSL https://wardenclaw.dev/install.sh | sudo sh
```

By default this is a **hardened install in observe mode**: wardend as a system
service running as root, the agent harness under a separate user without sudo. The script asks for the
agent user and the harness command (or flags: `sudo sh -s -- --agent-user agent
--harness-cmd '/usr/bin/node /opt/…' --rw-paths /srv/projects --yes`), verifies the release signature,
installs the files and prints the next steps: pairing the phone via QR, a week of observe, `ticket`
mode, the `redteam/hardened-check.sh` check. It does not start wardend itself. More flags:
`--version`, `--dry-run`, `--uninstall` (the journal and a copy of the config stay; `--purge` removes them too),
`--single-user` (only for a trial), `--help`. What each step does: section "Hardened
install" below; removal: [site/src/docs/uninstall.en.md](../site/src/docs/uninstall.en.md).

### Before you pipe into sudo

This is a security project, so here is the manual check. `install.sh` on the site is a copy of the file from
the latest signed release, its sha256 is in the signed `checksums.txt`. The check is worth
as much as the key in it: this README, the site and the release notes can all be swapped with a single
GitHub access, so compare the key against the domain's DNS as well (`dig +short TXT _release-key.wardenclaw.dev`), and if they
differ, do not install. Each step runs only if the previous one passed:

```shell
U=https://github.com/xarvel/WardenClaw/releases/latest/download
curl --proto '=https' --tlsv1.2 -fsSLO https://wardenclaw.dev/install.sh &&
  curl --proto '=https' --tlsv1.2 -fsSL --remote-name-all $U/checksums.txt $U/checksums.txt.minisig &&
  minisign -Vm checksums.txt -P RWRP9RFOUaTjromMP2NoZJz+e9Mk6pNHqu+6IK3TL7jQkLabwOIk30mE &&
  sha256sum --ignore-missing -c checksums.txt &&
  less install.sh &&
  sudo sh install.sh
```

`minisign` prints `Trusted comment: wardend vX.Y.Z checksums.txt YYYY-MM-DD`: the signed
version and the signing day. For a few minutes after a release the site may still serve the previous `install.sh`;
then `sha256sum` prints `FAILED`: retry later. A specific version: `U=…/releases/download/daemon%2FvX.Y.Z`,
`install.sh` comes from the same place (`$U/install.sh` instead of the site address), run
`sudo sh install.sh --version vX.Y.Z`. The installer itself repeats the same check for the archive with
the binaries and installs nothing without it; an installer with a test key installs nothing.

The first hardened install pins the key in `/etc/wardend/release.pub`. Upgrade with the installed
copy, without the site: `sudo /usr/local/share/wardend/install.sh`. It installs only a release signed with
the pinned key (a new key only on a statement signed by the old one), and does not install a release older than
the installed one without `--allow-downgrade`. How releases, signing, pinning and serving
`install.sh` from the site work: [docs/release.md](docs/release.md).

<details>
<summary>Building from source</summary>

Go 1.26, no cgo:

```shell
git clone https://github.com/xarvel/WardenClaw && cd WardenClaw/daemon
go build -o wardend .
# dry run, changes nothing; use your own values: HARNESS_CMD with absolute paths outside /home
DRY_RUN=1 AGENT_USER=agent RW_PATHS="/srv/projects" HARNESS_CMD="/usr/bin/node /opt/openclaw/dist/index.js gateway --port 18789" \
  deploy/hardened-install.sh ./wardend
```

If the output looks right, the same command with `sudo` and without `DRY_RUN=1` does the real install.

Release (reproducible) build: `scripts/release.sh --snapshot`, then
`sh install.sh --dry-run --from-dir dist` ([docs/release.md](docs/release.md)).
</details>

### Two variants

The difference is which uid the harness runs under: wardend gates only
`execve`/`execveat`, while signals, ptrace, `/proc/<pid>/mem` and file writes are decided by the kernel by uid.

| | **Hardened (recommended)** | Single-user (dev, trial) |
|---|---|---|
| wardend | root, system unit `/etc/systemd/system/wardend.service` | your user, a drop-in for a user unit |
| harness | a separate user without sudo/wheel/docker/lxd, a child of wardend (`--child-user`) | your user |
| binary, config, key, journal | root (`/usr/local/bin`, `/etc/wardend` 0700, `/var/lib/wardend` 0700) | your user (`~/.local/bin`, `~/.wardend`) |
| the model can turn wardend off | no, the kernel refuses by uid | yes, without a single execve |

The full step-by-step description (moving harness data, groups and ACLs, rollback, troubleshooting) is on
the site: `/docs/install/`; the vector analysis: `/docs/tamper-resistance/` and [docs/tamper-resistance.md](docs/tamper-resistance.md).

### Hardened install (recommended)

What provides the boundary: `--child-user` (wardend running as root installs the filter, resets the child's
`oom_score_adj` to 0, then setgroups → setgid → setuid and exec of the harness), `--require-hardened`
(refuses to start if the binary, config or key is not root-owned; cannot be turned off with an environment
variable), the systemd sandbox (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
`PrivateTmp`, `ReadWritePaths` only for `/var/lib/wardend`, `/etc/wardend`, the agent home and
`RW_PATHS`), `OOMScoreAdjust=-500`, `kernel.yama.ptrace_scope=2` (if the kernel has Yama).
The sandbox options apply to the harness too: it can write only to its home and `RW_PATHS`, and
nothing it needs may live in `/home` or `/root`.

1. **Prerequisites**: kernel ≥ 5.19 (`WAIT_KILLABLE_RECV`), systemd, root. `ls /proc/sys/kernel/yama` shows whether Yama is present.
2. **Agent user** (the script creates it): `useradd --system --user-group --create-home --home-dir /var/lib/agent --shell /usr/sbin/nologin agent`. No `sudo`, `wheel`, `admin`, `docker`, `lxd`, `incus`, `libvirt`, `disk` groups and no sudoers rights (the script checks and stops).
3. **Moving the harness (manual)**: stop and disable the old harness service; install the harness itself system-wide (`/opt`, `/usr/local`, owned by root); copy its state to the agent home (`rsync -a ~/.<harness>/ /var/lib/agent/.<harness>/ && chown -R agent: /var/lib/agent`, fix absolute paths); share common working directories via a group (`chgrp -R`, `g+rwX`, setgid on directories) or ACLs (`setfacl -R -m u:agent:rwX -m d:u:agent:rwX`) and list them in `RW_PATHS`. No agent write access to anything that runs as you or root (home, dotfiles, `~/.local/bin`, `PATH` directories, user units, crontab, git hooks).
4. **Install.** `install.sh` (the one command above) verifies the signature and calls
   `deploy/hardened-install.sh` from the signed archive; a copy of `deploy/` and `redteam/` stays in
   `/usr/local/share/wardend/`. From source, the same by hand: first a dry run, which prints
   the ready config and unit and changes nothing, then the real one:

   ```bash
   DRY_RUN=1 AGENT_USER=agent RW_PATHS="/srv/projects" \
     HARNESS_CMD="/usr/bin/node /opt/openclaw/dist/index.js gateway --port 18789" \
     deploy/hardened-install.sh ./wardend
   ```

   If the output looks right, the same with `sudo` and without `DRY_RUN=1` (as a separate step, not together with the dry run):

   ```bash
   sudo AGENT_USER=agent RW_PATHS="/srv/projects" \
     HARNESS_CMD="/usr/bin/node /opt/openclaw/dist/index.js gateway --port 18789" \
     deploy/hardened-install.sh ./wardend
   ```

   The script: the user and the groups/sudoers check, a root-owned binary, `/etc/wardend` and
   `/var/lib/wardend` (0700), `config.json` (0600, `mode: observe`, `require_hardened`,
   `child_user`), the unit from the `deploy/wardend.system.service` template, the ptrace_scope sysctl,
   `daemon-reload`. It does not move data, does not stop the old service, does not start wardend.
5. **Start and pairing**: `sudo systemctl enable --now wardend`; `ps -o user,pid,args --ppid "$(systemctl show -p MainPID --value wardend)"` shows the harness running as agent. Client commands as root with an explicit socket: `sudo wardend pair start --socket /var/lib/wardend/wardend.sock`. The plugin relay inside the harness cannot reach the root socket (by design), the app talks to the HTTP endpoint.
6. **A week of observe, then ticket**: review with `sudo jq … /var/lib/wardend/journal.jsonl`, service launches into `/etc/wardend/policy.json` (root 0600), then `"policy"` and `"mode": "ticket"` in `/etc/wardend/config.json`, `sudo wardend config-check --config /etc/wardend/config.json` (JSON errors with line and column, unknown keys, values wardend will not start with) and `sudo systemctl restart wardend`.
7. **Check**: `sudo -u agent bash -s < /usr/local/share/wardend/redteam/hardened-check.sh` (from source: `redteam/hardened-check.sh`) (and the same from inside the harness). Every attack must be refused: `FAIL=0` ([redteam/README.md](redteam/README.md)).
8. **Rollback**: `curl -fsSL https://wardenclaw.dev/install.sh | sudo sh -s -- --uninstall` (offline: `sudo sh /usr/local/share/wardend/install.sh --uninstall`). Stops wardend and the harness, removes everything the installer put in place, restores the previous `ptrace_scope`; the journal (renamed, with the public key next to it) and a copy of the config stay in `/var/lib/wardend`, `--purge` removes them too. It does not touch the agent user, its data or working directories; `--remove-agent-user` removes the user created by the installer once the directories are freed. The filter cannot be removed from a live tree, rollback is only by restart. The full scenario (returning the harness, devices, YubiKey, APNs, tunnel, checks, a light rollback to observe): [site/src/docs/uninstall.en.md](../site/src/docs/uninstall.en.md).

### Single-user install (dev, trial; the OpenClaw gateway as an example)

Only for trying it out: a model with the same user's rights can kill wardend,
ptrace, rewrite the binary, config, key or drop-in and restart the harness without the gate, without
executing a single execve. This is defense in depth against unwanted exec, not a guard that
cannot be removed. Do not enable `ptrace_scope=2` here: a wardend not running as root would lose access to
its descendants' `/proc/<pid>/mem`.

With the installer, without sudo: `curl -fsSL https://wardenclaw.dev/install.sh | sh -s -- --single-user` (installs to
`~/.local/bin`, config in `~/.wardend`, then as below from the observe stage). By hand:


The gateway is the user unit `~/.config/systemd/user/openclaw-gateway.service` (already `KillMode=mixed`,
`Restart=always`). A gateway restart breaks current sessions, so do not run it from a chat with the agent.

**Stage 1, observe:**

```bash
cd daemon && go build -o wardend . && install -D -m 0755 wardend ~/.local/bin/wardend
mkdir -p ~/.wardend && chmod 700 ~/.wardend
# a new config from the example, only if there is none yet: the existing one holds paired devices;
# fill in "public_url" in it yourself (deploy/CLOUDFLARE.md)
test -e ~/.wardend/config.json || install -m 600 deploy/config.example.json ~/.wardend/config.json
# @GATEWAY_CMD@ in the template: the command from ExecStart of the main unit (systemctl --user cat openclaw-gateway),
# absolute paths and the same node flags; a plain cp of the template leaves the placeholder, and the gateway will not start
GW="$(command -v node) $(npm root -g)/openclaw/dist/index.js gateway --port 18789"
mkdir -p ~/.config/systemd/user/openclaw-gateway.service.d
sed "s#@GATEWAY_CMD@#$GW#" deploy/wardend-observe.conf > ~/.config/systemd/user/openclaw-gateway.service.d/wardend.conf
grep '^ExecStart=.' ~/.config/systemd/user/openclaw-gateway.service.d/wardend.conf   # both paths after -- are absolute
```

If the `ExecStart` line is right and `~/.local/bin/wardend` is in place, restart:

```bash
systemctl --user daemon-reload && systemctl --user restart openclaw-gateway
systemctl --user status openclaw-gateway     # Main PID = wardend, node as its child
wardend status                               # over ~/.wardend/wardend.sock
```

A few days of observation, then a review of what would have needed a signature. The flow without printing argv:
`wardend replay --journal ~/.wardend/journal.jsonl --config ~/.wardend/config.json` (cards per
day, peaks, categories; `--policy-mode root` for comparison). The commands themselves:
`jq -r 'select(.kind=="exec" and (.data.class=="tripwire" or .data.class=="root" or .data.class=="delegating")) | .data.argv|join(" ")' ~/.wardend/journal.jsonl | sort | uniq -c | sort -rn | head -50`.
In tripwire, service launches rarely need a card; if a rule trips on a service launch (crons,
the browser, `openclaw …` subcommands, MCP servers, plugins), you can add it to `service_allow`
in `~/.wardend/policy.json` (with `wardend policy-defaults` as a base) and set `"policy"` in the
config. In `policy_mode: root` all service launches go there too, otherwise each becomes a root.

**Pairing the phone** (after the restart, from your own terminal, not from a chat with the agent):
`wardend pair start` → "Scan QR" on the Connect tab → compare the fingerprint in
`wardend pair list` with the phone screen → `wardend pair approve <id>`. An old
`trusted_devices` entry with a placeholder instead of a deviceId is ignored (`pair list` marks it), it can be deleted.

**Stage 2, ticket:** first `wardend pair list`: the phone must be among the trusted devices
and online, otherwise every command that trips a rule (in `policy_mode: root`, every
new root) waits for the TTL and gets denied. Then the mode is changed right
in the drop-in, the gateway command from stage 1 stays as it is (repeating the `sed` from the template in a new shell
would substitute an empty `$GW`, and the gateway would not start):

```bash
chmod 600 ~/.wardend/config.json    # a group-writable config stops wardend in ticket mode
sed -i 's/--mode observe/--mode ticket/' ~/.config/systemd/user/openclaw-gateway.service.d/wardend.conf
wardend config-check                # the same config and policy that run will read; exit code 1 = will not start
systemctl --user daemon-reload && systemctl --user restart openclaw-gateway
```

Back to observe: the same `sed` with the modes swapped, and a restart. The relay of the `wardenclaw-gate` plugin is needed
only if the OpenClaw adapter is enabled in the app (`relay: false` in the plugin config turns it off).

**Rollback** (any stage): `rm ~/.config/systemd/user/openclaw-gateway.service.d/wardend.conf && systemctl --user daemon-reload && systemctl --user restart openclaw-gateway`. To remove the trial install completely: `curl -fsSL https://wardenclaw.dev/install.sh | sh -s -- --single-user --uninstall` ([site/src/docs/uninstall.en.md](../site/src/docs/uninstall.en.md)).
There is no emergency path without a restart: the filter cannot be removed from a live tree; `kill` of wardend = ENOSYS for
all gateway execs until the unit restarts (which `Restart=always` does).

## What is proven by tests, and what only on a live gateway

Proven on test processes: interception and classification of the whole tree; one ticket per root and
inheritance (background jobs, python/os.system, node child_process); deny_always inside a root; all kinds of
forged tickets are rejected, without a ticket EPERM after the TTL; queue → EAGAIN; delegating spawn and
orphans are a new root; a nested unotify listener is forbidden; TOCTOU is closed by stop-verify; the journal
is verifiable; the envelope is identical in Go/JS/TS and goes the path app → plugin → relay → wardend →
execve (e2e on the real binary). Classify on the real claude-cli log.

Only on a live gateway:
1. **What the gateway's real exec flow is**: crons on claude-cli, `openclaw browser`/Brave
   (chromium installs seccomp filters itself and runs under `no_new_privs`, so the setuid sandbox is impossible,
   the userns sandbox is needed; check that Brave starts), MCP servers, plugins, `openclaw` subcommands,
   git/ssh for deploys, tmux. Without observe and an extended policy, all of this stalls in ticket mode.
2. The real arguments the gateway launches `claude` with (in the bench, wardend launched claude itself).
3. Behavior on `openclaw update` / a gateway restart from inside (`update.run`): a unit restart
   restarts wardend too; check that the gateway does not try to restart itself with an exec.
4. Double approval: a Bash command from claude-cli goes both through the plugin's `before_tool_call` (if the hook
   sees it) and through wardend (root): two cards for one action. Linking them (the plugin
   puts its digest into the environment/meta, wardend a reference) is the next step.
5. Latency under the gateway's real load and journal growth (no rotation).
6. Relay inside the gateway: the plugin in the node process under the filter talks to the wardend socket (not an exec,
   so the filter does not interfere), but `wardendSocket` defaults to `~/.wardend/wardend.sock`; check the path
   in the unit's environment.

## Limitations and what is left

* Only `execve/execveat` are intercepted. Interpreters (`python -c`, `node -e`, `bash -c`
  inside an approved root), `LD_PRELOAD`, file writes, network are not gated; an approved root
  can do anything within its uid. The root itself is approved with the environment on the card (the `env` list), but
  only the variables of that list are visible, the rest is signed as a single `envHash`. In tripwire everything that tripped no rule goes through without a signature: the full
  list of blind spots is in section 2, "What tripwire honestly does not see". The next layers from the notes:
  Landlock, eBPF LSM `bprm_check_security`, the box (allowlisted network, MCP proxy).
* Tripwire and pack rules recognize a tool by the real file's name, not by sha256: a copy
  of the binary under another name bypasses the rule. The packs are written by hand from the journal (claude-cli
  2.1.283, OpenClaw 2026.9.6); automatic building for a harness version (`pack learn`) is the next step.
* realpath is resolved in the supervisor's mount ns (wrong for processes in another ns/chroot; they
  are launched via the delegating `unshare/nsenter/chroot` → ticket).
* Swapping file contents **on the same inode** between the check and the exec is not caught (path/inode
  are compared); the binary's hash is not part of the envelope.
* Nested shebangs and `binfmt_misc` are not modeled in stop-verify → mismatch → SIGKILL (fail-closed).
* An orphan before its first exec loses inheritance (see above); `KillMode=mixed` finishes off the rest of the tree.
* No journal rotation, no approval cache for "the same thing again", no link to the plugin's digest.
* Pairing is protected from the agent by the "socket client is not under the wardend filter" check, but in
  a single-user install the config (`trusted_devices`) is a regular file of the same uid
  (in the hardened one it is root 0600 in a 0700 directory): a process that writes files can add
  a device there, and it will work after a wardend restart (file writes are not gated, see above).
* The HTTP endpoint has no TLS: the tunnel provides HTTPS; integrity and authenticity come from signatures, but the contents
  of cards (argv, cwd) are visible to whoever terminates TLS (Cloudflare).
* The YubiKey second factor (`require_hardware`, [protocol/HARDWARE.md](../protocol/HARDWARE.md)) is verified
  with a software authenticator in tests; the attestation chain up to the Yubico root is not checked.
  Not in the first release: built only with a tag (`go build -tags hwkey`, [docs/hwkey.md](docs/hwkey.md)).
  The release build hides `wardend hw-register` and `hw-keys` (code 2), does not start (code 2) with non-empty
  `hardware_keys` in the config or `require_hardware` in the policy, and rejects a decision with `hw` with the reason
  `hardware_not_configured`.
* 32-bit compat syscalls get ENOSYS (a bypass via a 32-bit exec is impossible).

## Pitfalls (from the spike, still valid)

* `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` is required (kernel ≥ 5.19): without it any signal to the target
  (SIGURG of the Go runtime) cancels the notification and restarts execve; in the spike, 662 duplicates of a single
  exec in 40 s.
* The filter is installed on the thread from which the helper does execve (`LockOSThread`).
* `encoding/json` re-escapes `& < >` even in `RawMessage` (and U+2028 always), hence our own
  canonical encoder; the envelope is passed in RPC as an object, and only the recomputed digest is trusted.
* Reading `/proc/<pid>/mem` of a descendant with the same uid works without privileges. With Yama
  `ptrace_scope=1` (the Ubuntu default; Raspberry Pi OS has no Yama) the reader must be an ancestor of the
  target, which is why wardend is a child subreaper: an orphan of the tree (a background job whose parent
  exited) is re-parented to wardend instead of init and stays readable; before that, its exec was denied
  as unreadable on Ubuntu and passed on the Pi. `ptrace_scope=2` only for wardend running as root
  (CAP_SYS_PTRACE), that is, for the hardened install: without the capability every exec is `unreadable`.

## Files

* `main.go`: CLI; `supervisor.go`: launch, notification loop, decision, signals, exit;
  `httpapi.go`: the app's HTTP endpoint; `pairing.go` / `paircmd.go`: pairing and `wardend pair`;
  `ntfy.go`: notifications; `push.go` / `apns.go` / `pushcmd.go`: push tokens, APNs, `wardend push`;
  `procinfo.go`: collection from `/proc` and memory; `toctou.go`: stop/poll check; `queue.go`:
  pending queue; `rpc.go`: unix-socket JSON-RPC (server and client); `metrics.go`; `config.go`;
  `seccomp.go`: kernel structures, BPF (execve/execveat → notify, NEW_LISTENER → EPERM).
* `envelope/`: canonical JSON, envelope v1, tickets, trusted devices, transport signing strings
  and the QR link (`transport.go`), vectors.
* `../protocol/` (monorepo root): the protocol and second-factor specification and vectors (Apache-2.0).
* `qr/`: QR encoder and terminal printing.
* `cmd/wardenctl/`: terminal approver (pairing, cards, watch, YubiKey via libfido2 only with `-tags hwkey`), with its own README.
* `policy/`: rules (`defaults.json` and harness packs `packs/*.json` from `bench/gen_defaults.py`),
  classification (root and tripwire), path zones, install variables, subtree tracker.
* `replay.go`: `wardend replay`, the journal through the same classifier; the tripwire work log
  is in `docs/tripwire.md`.
* `journal/`: the journal with a hash chain and signature.
* `install.sh`: the `curl … | sudo sh` installer (signature check, hardened install, upgrade,
  removal); `scripts/release.sh`, `scripts/sign-release.sh`, `../.github/workflows/release-daemon.yml` (tag `daemon/vX.Y.Z`):
  reproducible build and offline release signing ([docs/release.md](docs/release.md)).
* `deploy/`: `hardened-install.sh` and the `wardend.system.service` template (hardened install),
  observe/ticket drop-ins (single-user), an example config, `CLOUDFLARE.md` (exposing the endpoint).
* `redteam/`: `run.sh` (vectors open in same-uid), `hardened-check.sh` (checking the hardened
  install as the agent uid).
* `bench/`: `demo_ticket.sh`, `evil_argv.c`, `claude-observe.jsonl`, `gen_defaults.py`,
  spike measurements (`bench.sh`, `sigtest.py`).

## License

Copyright (C) 2026 The WardenClaw Authors (see [AUTHORS](../AUTHORS)).

wardend and `wardenctl` are free software: you can redistribute them and/or modify them under
the terms of the **GNU Affero General Public License, version 3 or (at your option) any later
version** ([LICENSE](LICENSE), SPDX `AGPL-3.0-or-later`). Running wardend on your own machine
creates no obligations; if you run a modified wardend for other people over a network, the AGPL
asks you to offer them its source.

The protocol specification and its test vectors live outside this directory, in
[`protocol/`](../protocol/) at the repository root, under the **Apache License 2.0** so that
anyone can implement the protocol. The license map of the whole repository is in the root
[LICENSE](../LICENSE).

Source files carry `SPDX-License-Identifier` lines. Third-party components and their licenses
are listed in [NOTICE](NOTICE). "WardenClaw" and the logo are trademarks, see
[TRADEMARKS.md](../TRADEMARKS.md). Contributions: [CONTRIBUTING.md](../CONTRIBUTING.md) (DCO
sign-off); vulnerabilities: [SECURITY.md](../SECURITY.md).
