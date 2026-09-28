# Tripwire and harness packs: work journal

Work journal of the `tripwire` policy mode in wardend together with harness packs, small fixes
from the replay, and a Go replay of the journal. Mandates, a separate judge key and the privileged
helper are out of scope here.

## 2026-09-28

- Read: the replay simulator (`rules.py`, `pathx.py`, `replay.py`), `policy/` (classify, rules, tracker, defaults.json),
  `supervisor.go`, `procinfo.go`, `config.go`, `queue.go`, `main.go`, `protocol/README.md`,
  the integration and redteam tests.
- Plan:
  1. `policy/`: the tripwire classifier (a port of `rules.py: tripwire` and `pathx.py`), path zones with
     variables, inheritance pairs, refusal for `sudo` and company; harness packs
     (`policy/packs/*.json`, embedded in the binary) with the `${AGENT_HOME}` variables and the harness root.
  2. `supervisor.go`: the config key `policy_mode: tripwire | root` (default `tripwire`),
     `max_pending` 64, the target path via `/proc/<pid>` of the caller.
  3. `wardend replay --journal <path>`: the same classifier code over the journal, metrics as in the
     simulator; a cross-check with the simulator on the same records.
  4. Tests: unit tests for each class and for the inheritance pairs, e2e under seccomp (ls without a card, ssh with
     a card, sudo refused).
  5. Documentation: README, `site/src/docs/cli.en.md`.
- Done (step 1, `policy/`): `vars.go` (the variables `${AGENT_HOME}`, `${ANY_HOME}`, pack
  variables; values are escaped with QuoteMeta), `zones.go` (path zones, a port of `pathx.py`),
  `shlex.go` (a port of Python shlex for `adb shell`), `tripwire.go` (a port of `rules.py: tripwire`,
  categories and families), `pack.go` + `packs/claude-cli.json`, `packs/openclaw.json` (the pack
  format, selection, root autodetection from the wardend command), `classify.go` (`ClassifyTripwire`,
  the classes `tripwire | implied | refuse | logged`, sudo refusal via `SysInfo`), `tracker.go`
  (`Root.Family`). `bench/gen_defaults.py` now writes `defaults.json` (without the claude-cli rules,
  with zones and `guard`) and both packs. The `policy` tests are green.
- Decisions that differ from the simulator:
  - agent-config (the harness CLI verbs) is checked before the pack's service rules: otherwise
    `claude mcp add` would pass as "claude itself" (in the simulator the service rules of `defaults.json`
    were not applied in tripwire at all).
  - `cat id_rsa` in `~/.ssh`: for file-printing commands (`cat`, `head`, `grep` …) positional arguments
    count as paths even without `/` (the simulator took only path-like ones), so a read relative to cwd is visible.
  - The OpenClaw CLI started as `node …/openclaw/dist/index.js cron add` is agent-config too.
  - Harness rules in packs have no subtree inheritance (in the simulator the workers and the launcher were
    "tree"): the OpenClaw launcher (`sh -c 'echo 1000 > /proc/self/oom_score_adj …; exec "$0" "$@"'`)
    starts both claude and shells, and inheriting from it in root mode would give the whole agent turn without
    cards. The `inherit` field exists in the format, the built-in packs do not use it.
  - Refusal without a card only for a setuid binary from the list (sudo, su, doas, pkexec, sudoedit,
    newgrp, sg) under `no_new_privs`; a `sudo` shim without setuid is a normal card.
- Next: `supervisor.go` (done in draft), `wardend replay`, the cross-check with the simulator.
- Done (step 2): `supervisor.go` (`classifyExec` shared with the replay; tripwire classes in the journal with
  `category` and `detail`; card: `meta.category`, `meta.detail`, `meta.delegating` for
  delegate/container/remote; an approved tripwire launch is registered as a root with `Family`;
  `refuse` is EPERM without the queue), `config.go` (`policy_mode` defaults to `tripwire`,
  `agent_home`, `work_dirs`, `scratch_dirs`, `packs`, `pack_vars`, `max_pending` 64),
  `procinfo.go` (`evalSymlinksAs`: `/proc/self`, `/proc/thread-self` and everything that links to them
  go through the caller's process), `main.go` (`run --policy-mode`, `policy-defaults --pack`,
  `replay`), `replay.go`.
- Replay (a copy of the 01:34 journal in `/srv/scratch/tripwire/`, 0600; only aggregates are printed):
  - the design window (Sep 26 22:01 to Sep 27 23:11, 98,053 exec records, 62,400 without missing):
    Go tripwire **859 cards, 819 per day**, a peak of 34 in 2 min and 158 in an hour, 225 at night
    (26.2%), by category pkg-run 341, device 240, delegate 115, remote 104, protected-write 15,
    agent-config 14, secret-read 11, destructive 10, container 6, publish 2, outside-work 1;
    implied 74, sudo refusals 4. Simulator P2: the same down to one; the per-exec cross-check (`--dump` against
    `sim_dump.py`): 0 mismatches on 62,400 execs.
  - the only mismatch before the cross-check: 36 `dbus-send` calls from the browser (`GetNameOwner`): the simulator
    dropped them with the `brave:dbus-probe` pack, Go drops them by parsing the method correctly (the second
    positional argument of dbus-send), without a pack.
  - root mode with the old rules and without packs: Go 3,312 cards against 3,315 recorded by wardend,
    class agreement with the journal 99.995% (the simulator has 3,270 and 99.93%: Go resets the
    tracker on every wardend start, like the live one).
  - root mode with packs: 3,114 (minus 198 over the window, about 189 per day: internal workers and
    OpenClaw probes); the claude-cli pack alone gives exactly the previous 3,312 (the rules were moved 1:1).
  - the whole journal up to Sep 28 01:34 (27.55 h): tripwire 1,092 (951 per day) against 4,031 (3,511) in
    root, minus 73%.
- Tests: `policy` (categories, zones and cwd, sudo refusal, inheritance pairs and TTL, custom rules,
  the claude-cli pack in the protected install layout, the OpenClaw pack, pack selection, variables,
  shlex against Python), e2e under seccomp (`tripwire_e2e_test.go`: ls without a card, ssh with
  a card and a refusal by TTL, ssh under an approved scp as implied with a card for the neighbouring ssh,
  sudo refused without waiting, observe, `/proc/self/exe` and `/dev/fd/0` via the caller).
  The earlier integration tests run in `policy_mode: root`. All green: `wardend` 16 s,
  the libraries under a second; `go vet` on amd64 and arm64 is clean.

## 2026-09-28, continued (second executor)

The first executor broke off after commit `06f491d`; its edits were left in the tree, here is their review:

- `policy/rules.go`, `Parse`: a policy file without the `zones` and `guard` keys (taken with
  `wardend policy-defaults` before tripwire) gets the built-in ones. Without this an old `policy.json`
  silently turned off the secret and protected-path zones, that is `secret-read` and `protected-write`.
  The fix is correct and kept; test `TestPackFileUnderRuntimeAndLegacyPolicy` (it also checks
  `under: "runtime"` for a pack from a file and the refusal if the pack has no `runtime`). `policy` is green.
- `replay.go`: on a window shorter than an hour the rate per hour and per day is not printed (it was "2457/h, 58976/day"
  on a seven-second demo journal). Correct, kept.
- `bench/demo_ticket.sh`: the demo shows the root model, hence an explicit `--policy-mode root`.
  Correct, kept.
- README and `site/src/docs/cli.en.md`: the policy modes section is almost done, the outputs in the
  examples were taken from a real `wardend-dev` (`/srv/scratch/tripwire/demo*.sh`, `demo.out`) and
  match them. Found while checking against the code:
  - "pairs" are described more narrowly than in the code: `ImpliedBy` lets through any trigger of the same family
    (the simulator counted it the same way), including `npm install` from postinstall under an approved `npm ci`.
    The documentation must say this directly, with the list of families;
  - the box gets one line, and there is no allowlisted network in the install at all (the protected
    install unit: `ProtectHome`, `ProtectSystem=strict`, `ReadWritePaths`, no `IPAddressAllow` and no
    proxy); what exists has to be honestly separated from what is planned;
  - there is no table of pack variables (`CLAUDE_ROOT`, `CLAUDE_BIN`, `OPENCLAW_ROOT`,
    `OPENCLAW_HOME`, their default values and autodetection);
  - `deploy/config.example.json` still sets `max_pending: 16` and overrides the new default of 64
    (the single-user install copies it to `~/.wardend/config.json`); the comments of the drop-ins
    `wardend-observe.conf` and `wardend-ticket.conf` describe only the root model.
- Done on the findings:
  - README, section 2: pairs are described as "the same family" with the list of families and an honest caveat
    about `npm install` from postinstall under an approved `npm ci`; a table of pack variables
    (where the value comes from, the default; autodetection adds, `pack_vars` replaces;
    an unknown variable stops the start with code 2); "Why the box": what the protected
    install gives (`ProtectHome`, `ProtectSystem=strict`, `ReadWritePaths`,
    `NoNewPrivileges`), and that the install has no allowlisted network and no MCP proxy yet; `curl -K file` was added
    to the blind spots. The observe and ticket stages of the single-user install were rewritten for tripwire
    (`wardend replay`, jq with the `tripwire` class). Long dashes in the added text were removed.
  - `site/src/docs/cli.en.md`: the same; the config example is now literally
    `deploy/config.example.json`, `http_listen`, `public_url`,
    `pair_code_ttl`, `ntfy_url` were added to the config table. Along the way the default of `gateway_db` and `--gateway-db` was fixed: in the code it is
    `off` since `9af82a6`, the site said `auto`; the "Keys" paragraph takes this into account.
  - `deploy/config.example.json`: `policy_mode: tripwire`, `max_pending: 64`. The drop-in comments
    describe both policy modes. `docs/CLI.md` (the dev copy) got a note that it
    describes only root mode.
- A regression from the tripwire default outside the `wardend` package: the e2e tests of `cmd/wardenctl` (`TestE2E*`: three tests
  expected a root card on `bash -c "echo …"`, in tripwire there is none, they failed on the expectation) and the plugin e2e
  (`plugin/test/relay.test.js`). Fixed with an explicit `--policy-mode root` when starting
  wardend; the original plugin e2e fails on the new binary (checked), with the fix the plugin passes 43 of 43.
  `app/scripts/e2e-wardend.mjs` works the same way (ticket, `bash -c 'echo root-ran'`) and will fail
  the same way, but `app/` is being worked on by another executor: not touched, handed over in the report.
- Checks (outside the filter of the live wardend; back then via `systemd-run --user`, that is outside the gate;
  now such runs are done by a human or CI, see `CONTRIBUTING.md`): `go test -p 1 -count=1` per package: `policy`, `envelope`, `journal`, `hwkey`,
  `qr` under a second, `wardend` 16.9 s, `cmd/wardenctl` 16.2 s; `go vet ./...` with GOARCH=arm64 and
  amd64 is clean; `bench/demo_ticket.sh` from a copy in `/srv/scratch/tripwire/demo-copy` (so as not
  to put an 11 MB binary into the share) ran through in `policy=root`; site: a copy of `site/` in
  `/srv/scratch/tripwire/site-copy`, `npm ci` and `npm run build` via `nohup`, 14 pages,
  all internal anchors on `/docs/` exist (`#policy-modes`, `#wardend-replay`).
- Commits: `02d8c9b` (code, tests, config example, drop-ins), `bbde47f` (documentation and this
  part of the journal).
- A control replay after the fixes (a binary from the `02d8c9b` tree, the design window): 859 cards,
  819 per day, a peak of 34 in 2 minutes, the categories and `implied` 74, 4 refusals, all as in the first part.
  Compared with the 01:52 run before commit `06f491d`, 270 execs moved from `logged` to `service`; both branches
  pass without a signature, this does not affect cards.
- The copy of the live journal `/srv/scratch/tripwire/journal.jsonl` was destroyed with `shred -u` on Sep 28
  around 02:31, together with the demo journals (`demo-state*`) and the demo outputs. What is left in the directory:
  scripts, replay aggregates (`replay-*.txt`) and `seq, class, rule` dumps without argv; a
  `grep` for `"argv"`, `"kind":"exec"`, `argv=[` and traces of secrets finds only code and documentation
  text. There are no other copies of the journal in `/srv/scratch`.

## 2026-09-28, core security review: net-write, mount-ns, self-built exe

Closing the high-severity core findings (net-write bypass, a foreign mount namespace, a self-built executable). For each finding: a fix, a test (fails on the old code, passes on the new one), this entry.

- **[high] net-write was bypassed with the real curl/wget**:
  a leading loopback URL masked an external address (`urlHost` took the first one), and `-G/--get` with `-d`
  zeroed `curlWrite`. Fix in `policy/tripwire.go`: `urlHost` was replaced with `anyRemoteHost`:
  we trigger if AT LEAST ONE of the given addresses is not loopback (curl/wget send the body to every
  URL); the `-G/--get` branch was removed from `curlWrite` (the data still goes out in the query). The body and the address
  are checked independently of the method. Test `TestTripwireNetWriteBypass` (both vectors plus
  non-bypasses: loopback only, `-G` without data stay `logged`).
- **[high] path resolution bypass via a foreign mount namespace**:
  `resolveTarget` resolves the realpath in the supervisor's mount ns, while the file is executed in the child's ns;
  `unshare(2)` as a syscall (without a delegating `unshare`/`nsenter` binary) moved the launch to `logged`
  without a card. Fix: `collect` reads `/proc/<pid>/ns/mnt` of the caller (`procinfo.go`),
  the supervisor remembers its own (`supMntNs`), and in `decide1` on a mismatch any non-ticket class
  (logged/implied/inherit/service) is escalated to a card of category `mount-ns` (deny/refuse block
  anyway). Empty on either side is not escalated (a transient read error does not break work).
  Test `TestTripwireForeignMountNs` via the helper `bench/nsexec.c` (unshare user+mount ns → execve):
  before, `/bin/true` went `logged`+`allow`, now a `mount-ns` card + `deny` by TTL.
- **[next-steps item 1] the "self-built executable" class**: a target file that the agent owns or
  that it can write to (`agentWritable`: owner == the caller's uid, or writable by the
  group/others) is escalated in tripwire mode from `logged`/`implied` to a card of category
  `self-built`: the name does not prove what it is (a renamed curl, a copy of busybox, a custom ELF).
  Service launches of the harness (`service`, from packs) and the first exec of the command (`supervised_cmd`) are not
  escalated. The new `provenance.go` computes provenance only on the card path (rare, not
  on every exec): the file's sha256 (for a mandate and recognition), for a script the interpreter and the start of
  the text (without control bytes, `sanitizeHead`), for an ELF static/dynamic,
  the NEEDED libraries and whether there are network imports. The facts go into the card's `meta.provenance` and into
  the journal record (`provenance`). Tests: `TestAgentWritable`, `TestSanitizeHead`,
  `TestProvenanceScriptAndOther`, `TestProvenanceELF` (dynamic with network, static),
  e2e `TestTripwireSelfBuiltExe` (the agent's binary `notcurl` as a child of sh: before, `logged`+`allow`
  rc=0, now `self-built`+`deny`, rc=126).
- Checks: `go vet ./...` with GOARCH=arm64 and amd64 is clean; `go test -p 1 -count=1` for `policy`,
  `wardend` (19.5 s) and `cmd/wardenctl` (16.9 s) is green (outside the filter of the live wardend, as in the
  entry above). Each new test was checked to fail on the old code.
- Remaining limitations (honestly): `self-built` catches what the agent created by the file's owner and
  mode; a hard link to a system binary under another name keeps the root owner and mode
  0755 and stays under the acknowledged "identity by name" zone: only the target's sha256 closes it
  (the next step, below). The criterion "a file in a directory writable by the agent" from `next-steps`
  was not added to the hot path because of the cost (an extra stat on every exec); if desired, it can be
  computed on the card path. The medium-severity leftovers (3 `logged`+`toctouOff`,
  4 classifier misses hexdump/busybox, 5 DoS by a flood of cards) and wardenctl (M6, W2-W4 from
  `security-mobile.md`) were not in the mandatory scope and were not touched.

## Summary of the first P1 step and what comes next

Done: the `tripwire` policy mode by default (`policy_mode`, `root` kept): trigger categories
by the real binary and argv with path zones, inheritance pairs by family for no longer than
10 minutes, a `sudo` refusal with a reason and without a card, the harness packs `claude-cli` and `openclaw` with
path variables and autodetection, `wardend replay`, `/proc/self` and `/dev/fd` via the
caller, `max_pending` 64. On the developer's journal 819 cards per day against 3,162 (minus
74%), per-exec agreement with the simulator. Documentation of the modes on the site (en, ru) and in the README,
including an honest list of blind spots and the role of the box.

Next step:

1. **Mandates v1** (sections 3 and 7.2): a device-signed scope (the target's sha256, per-element
   argv matchers, cwd, harness role), a lifetime and limits, issuing from a card with biometrics, an
   "Active mandates" screen with revocation, `decidedBy` in the journal and `by` in the v2 ticket. By design a mandate
   is checked after the pair and before the card: in `ClassifyTripwire` that is the spot before the last
   `return` with the `tripwire` class. Before mandates, for
   `device`, `remote` and `eas`, close the "agent controls the approver phone" channel (section 2.4).
2. **`wardend pack learn`** (section 6): building a pack for a harness version in `observe` from a
   scenario, generalizing literals, signing with the release key, a single "the harness was updated, there is no
   pack" card. For now the packs are manual: claude-cli 2.1.283, OpenClaw 2026.9.6.
3. **Judge key** (section 3.6): a second app key with `role` and `caps` in `TrustedDevice`,
   checked in `decide`; the human's key under biometrics for every signature. For now the judge's signature
   is indistinguishable from the human's.
4. **Root by signature** (section 5): a privileged helper `priv.exec` over a separate
   agent socket, an envelope with hashes of the binary and files, YubiKey, execution outside the agent's tree.
   For now `sudo` under the gate gets a refusal with a reason.
5. Along the way:
   - `app/scripts/e2e-wardend.mjs` starts wardend in `ticket` without `--policy-mode root` and expects
     a card on `bash -c 'echo root-ran'`: on the new default it will fail just as the e2e tests of
     `wardenctl` and the plugin failed (the same one-line fix);
   - identity by the target's sha256 and an "executes a file writable by the agent" flag (section 4.5,
     item 5); for now the rules recognize a tool by the file name;
   - an allowlisted network and an MCP proxy in the protected install (the box);
   - deferred execution for night crons instead of EPERM by TTL (section 4.6);
   - the `npm` family is broad: under an approved `npm ci` its postinstall installs packages for 10 minutes without
     a card; it is worth deciding whether to narrow the pairs to a list from the pack, as in the design (section 4.4).
     Done 2026-09-30: package-manager families never imply their children (section below);
   - the step 4 hint in `install.sh` ("add housekeeping to a policy") is written for root mode;
     the file is currently being edited by the executor of the uninstall split.

## 2026-09-28, crypto review, finding 4: the environment and the `loader-env` category

- `env` goes into the envelope and under the digest: the variables that change program behavior (the selection rule in
  `protocol/README.md`, section 3); the card shows them in the "Environment" block.
- `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH` with a non-empty value on a launch outside an approved root
  that would pass without a card (`logged`, `service`) give a card of category `loader-env`
  (rule = the variable name, `loader-env/ld_preload`). Before, `LD_PRELOAD=/tmp/x.so uptime` went
  `logged`+`allow`, now it is a card. For what is a card anyway (`remote/ssh` and so on) the category
  stays the same: an added variable does not take the launch out from under the key rule of its category, and the
  rule for `loader-env` is checked in addition. Inside an approved root (`inherit`,
  `implied`, `logged` in the live chain of the root) it is not gated, as before.
- Why a card and not a refusal: `LD_LIBRARY_PATH` is legitimately set in conda/CUDA/nix environments; a refusal by
  default (EPERM without a card) would silently break all agent launches if the variable is set on the
  gateway itself. The cost: with a gateway that has a global `LD_LIBRARY_PATH`, every agent command in tripwire mode
  becomes a card; the fix is the gateway's environment.

## 2026-09-30, product-logic review, finding 1: package families do not imply their children

- Before: `ImpliedBy` let any trigger of the same family through under an approved root for 10 minutes,
  and the package-manager families are wide: an approved `npm ci` covered `npm install -g <anything>` and
  `npx -y <anything>` from a postinstall, an approved `pip install` covered every nested `pip install`.
  On the developer's journal `pkg-run` is the largest category (341 cards a day), so this was the widest
  path around the judge: the model never saw the nested install.
- Now the package-manager families (`npm`, which also covers npx, pnpm, yarn and bun; `pip`, which also
  covers pipx, uv and uvx; `go`; `cargo`; `gem`; `brew`) never imply their children, in either role: a
  nested install under an approved install is a card of its own, and an approved install does not
  inherit from anything either. The mechanical pairs stay: `ssh` under `scp`, `sftp`, `rsync` and `git`;
  the `docker-compose` plugin under `docker compose`; `eas` under `npx eas-cli`; a harness CLI
  restarting itself; every other family of the same name. `policy.ImpliedBy` and
  `TestTripwireImplied` cover both directions.
- The cost is one more card per nested install inside an approved one. A repeated identical argv is a
  matter for a verdict cache by digest (product-logic review, finding 1), not for the family table.
