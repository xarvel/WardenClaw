# wardend on macOS: the Endpoint Security gate

Status (2026-10-10): the code builds, vets and passes its suite on a Mac (`mac2.metal`, M1, macOS
27.0), the pure-Go parts (the deadline-capped ticket wait, the tree, the policy names, the
installer) are tested on Linux too; **the Endpoint Security path itself has still not run**. The
stand got as far as a build and was then lost setting the boot-args of step 2 (runbook below):
after `nvram boot-args="amfi_get_out_of_my_way=1"` and a reboot the instance never answered
again, for a reason not established (step 2 has what is known). So the development-mode recipe
("SIP off and `amfi_get_out_of_my_way=1`") is **unproven on EC2**, and the open question is
whether SIP off alone is enough for `es_new_client`. Also found that day, without the Mac: until
the fix of 2026-10-10 the gate could not select the fail-closed deadline mode on any SDK ("Fail-closed
deadline" below), so only a build from that fix on can answer the fail-closed part of step 7.
Until Arthur's Team ID holds the Endpoint Security entitlement there is nothing else to run it on;
read "The entitlement" below before you put an agent you do not trust on such a machine.

## How it works

On Linux wardend puts a seccomp filter on the harness and the kernel parks every `execve` until
wardend answers. macOS has no seccomp; the host mechanism that sees `execve`/`posix_spawn` before
the new image runs and can refuse it is **Endpoint Security** (ES), event `AUTH_EXEC`. wardend is
the ES client itself (`esgate_darwin.go`, cgo, `-lEndpointSecurity -lbsm`: the headers live in `usr/include/EndpointSecurity`, the library is `libEndpointSecurity.tbd`, there is no framework): no separate
system extension, no XPC, no Linux guest. The agent stays on the host, in its own home, with its
own binaries, as Arthur's product rule asks (wrap in place, one command, do not break the habitual
setup).

- **Descendants client.** macOS 27 added `es_new_descendants_client`: a client that receives only
  the events of the calling process's descendants. That is exactly wardend's tree: no system-wide
  event stream, no fork-tracking race, nothing to mute. Without it (macOS 26, or the symbol
  missing) wardend falls back to `es_new_client` plus `NOTIFY_FORK`/`NOTIFY_EXIT` tree tracking
  (`gatetree.go`) and answers ALLOW at once, unjournaled, for processes outside the tree. Config:
  `"gate": {"scope": "auto|descendants|global"}`, default `auto`.
- **The snapshot is the kernel's.** ES hands over argv, env, cwd, the target and the caller as the
  kernel copied them: no `/proc/<pid>/mem`, no re-read of user memory, no TOCTOU post-check. The
  envelope is the same v1 as on Linux; the card on the phone looks the same.
- **"The command waits for the ticket."** As on Linux, in the kernel: the `AUTH_EXEC` message is
  not answered until the ticket is decided, and the caller sits inside `execve` until then. An ES
  message has a deadline of the kernel's own (not extendable), so the ticket wait of one exec is
  capped at what is left of that deadline minus one second (`execEvent.ttl`, `decide1`; the card's
  expiry says the same), and a watchdog answers DENY at that point should the decision be late for
  any other reason. Under two seconds of budget there is no card at all: DENY. The journal record
  carries `deadline`: `{"leftMs": …, "budgetMs": …, "missed": true, "tooShort": true}` (the last two
  only when they happened). With a descendants client the gate first raises the floor of that
  deadline to `ticket_ttl + 2s` (`es_set_deadline_min_milliseconds`; the 27 SDK header: "not capped
  by the system default ... will effectively extend deadlines beyond the system default"), and the
  `start` record reports what the kernel confirmed as `gate.deadlineFloorMs`. So on macOS 27 a card
  has the whole TTL; the cap `min(ticket_ttl, deadline - 1s)` is what the global client (26) gets.
  A `SIGSTOP` of the caller before an early ALLOW was considered and rejected: the agent owns the
  stopped process and could `SIGCONT` it before the decision.
- **Fail-closed deadline.** macOS 27 added `es_set_deadline_miss_mode(client,
  ES_DEADLINE_MISS_MODE_FAIL_CLOSED)`: a missed deadline denies the exec instead of allowing it and
  killing the client. wardend sets it when the symbol resolves (`dlsym`, so the binary builds
  against older SDKs) **and** the binary was built against the 27 SDK: the mode's value comes from
  the header, and the build tests the SDK version (`__MAC_OS_X_VERSION_MAX_ALLOWED >= 270000`).
  Not `#ifdef ES_DEADLINE_MISS_MODE_FAIL_CLOSED`: that name is an enumerator of a typedef enum
  (`c:@EA@es_deadline_miss_mode_t` in Apple's documentation), invisible to the preprocessor. The
  first version tested `#ifdef` and so never had the mode, on any SDK: observe and deny-list fell
  back to `kill` with a log line, ticket mode refused to start. On a 27 host with a 27 SDK build the
  `start` record of the default config says `"deadlineMiss": "fail-closed"`; `"kill"` there means
  the binary has no deadline mode. On macOS 26 the only mode is the old one, ALLOW and kill the client: wardend
  **refuses to start in ticket mode** there unless the config says
  `"gate": {"deadline_miss": "kill"}`, the operator's acknowledgement that a slow decision opens
  the gate and restarts wardend (launchd `KeepAlive` brings it back). Default `fail-closed`.
- **A message with less than 500 ms left** when it arrives is logged once and counted in the
  metrics; the flow does not change.
- **No helper child.** wardend runs as root (ES requires it), starts the harness with
  `exec.Command` under the agent's uid/gid/groups (`child_user`, with that user's HOME, USER,
  LOGNAME), and starts the ES client *before* the child so the child's first exec is seen. If the
  client cannot start, the command is not started.
- **Linux is unchanged.** Everything macOS-specific is behind `//go:build darwin` or is pure Go
  with tests that run on Linux.

## Requirements

| | |
|---|---|
| macOS 27 ("Golden Gate", Sept 2026) | fail-closed deadline and the descendants client: the configuration the gate is designed for. |
| macOS 26 | works only with `"gate": {"deadline_miss": "kill"}` and the global client; a missed deadline lets the exec through and restarts wardend. Not for an agent you do not trust. |
| root | the ES client needs it; `sudo wardend wrap -- …` runs the command as you (`SUDO_USER` becomes `child_user`). |
| Full Disk Access | for the bundle (System Settings > Privacy & Security > Full Disk Access); without it the client gets no events. On a development machine with SIP off it can be granted with a row in the system TCC database. |
| the entitlement | `com.apple.developer.endpoint-security.client`, see below; without it, development mode only. |
| build | Go 1.26 with cgo: Xcode Command Line Tools (`xcode-select --install`) are enough. `CGO_ENABLED=0` builds a wardend that refuses to start on macOS ("built without cgo: no Endpoint Security client, nothing can be gated"). |

## The entitlement

`es_new_client` returns `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED` unless the calling binary is
signed with `com.apple.developer.endpoint-security.client`. Apple grants that entitlement per
Team ID through the System Extensions / Endpoint Security request form; it takes weeks and comes
first for development, then separately for distribution. It is honoured only in an **app bundle**
(`/Library/Application Support/WardenClaw/wardend.app`, `Contents/Info.plist` with
`CFBundleIdentifier dev.wardenclaw.wardend`) signed with a **Developer ID** certificate, hardened
runtime, with the matching **provisioning profile** embedded as `Contents/embedded.provisionprofile`,
and notarized. `deploy/wardend.entitlements` is the entitlements file; the release will ship the
profile as `deploy/embedded.provisionprofile` once it exists and the installer copies it into the
bundle.

Until then: **development mode**. On a machine with SIP off and `amfi_get_out_of_my_way=1` in the
boot-args, `es_new_client` is said not to check the entitlement (root and Full Disk Access are
still required). Two caveats, both from the 2026-10-10 stand: that was never verified, and the
one attempt to set the boot-arg on an EC2 Mac lost the machine (runbook, step 2). On Apple
silicon whether the kernel gets a boot-arg at all is a LocalPolicy bit (`sip3`) that only 1TR can
change, and a rented headless Mac has no 1TR; whether AWS's SIP task sets that bit is not
documented. Whether SIP off **alone** is enough is the one measurement that decides
whether a dev-mode stand exists; it has not been made. The installer prints this warning when
`codesign -d --entitlements -` on the binary lacks the key. A machine in that state has no
platform integrity: it is a test stand, not a place for an agent you do not trust. Arthur's
request to Apple is independent of the stand work and should go first.

## What is not there yet

- **rootexec on macOS**: the daemon has the socket path (`/var/run/wardend/rootexec.sock`) and
  the pinned exec path (`/dev/fd/3`), but the installer does not enable it and installs **no
  `sudo`/`docker` shims**. The agent keeps its own `sudo`, which asks for its password; wardend
  sees the `sudo` exec and the tripwire classifies it, but nothing routes it to a card.
- **No privilege strip**: the agent user keeps its groups (`admin`, `staff`). On Linux the
  install takes the user out of `sudo`/`docker` and gives root to a human account; on macOS that
  is left to you.
- **No equivalent of the polkit/linger guard**: a user LaunchAgent of the agent user runs
  outside wardend's tree and outside the gate. The install boots out and disables the one
  LaunchAgent it wraps; look at `~/Library/LaunchAgents` of the agent user for others.
- **Policy names**: `launchctl` (bootstrap/bootout/load/submit/kickstart/… are delegating, the
  read-only verbs are logged), `osascript` (always delegating: `do shell script` starts a shell
  outside the argv you see), `open` (LaunchServices starts the app outside the tree), `shortcuts
  run`, `automator`; privileged paths `/Library/LaunchDaemons`, `/Library/LaunchAgents`,
  `/Library/PrivilegedHelperTools`, `~/Library/LaunchAgents`. Everything the Linux tripwire does
  not see ([README, section 2](../README.md)) it does not see here either.
- **The ES cache is never used** (`cache=false` on every answer): the cache is keyed by file, not
  argv, and one ALLOW on `/usr/bin/ssh` would let the next `ssh` with another argv through.
- **The ticket wait is the kernel's deadline, not two minutes**: if the `AUTH_EXEC` deadline on
  macOS turns out short (tens of seconds), a card has that long to be answered. Measured on the
  stand first (runbook, step 7); if it is too short for a human, the answer is a design change
  (DENY and let the harness retry after the approval), not a signal trick.

## Wrapping the OpenClaw gateway

`curl -fsSL https://wardenclaw.dev/install.sh | sudo sh` on a Mac, from the account that runs
OpenClaw. The installer (`deploy/macos-install.sh`, sourced by `install.sh`) reads
`~/Library/LaunchAgents/ai.openclaw.gateway.plist` (or the profile's `ai.openclaw.<profile>`,
`OPENCLAW_LABEL=`) with `PlistBuddy`, shows the plan, and after a `y`:

1. `launchctl bootout gui/<uid>/ai.openclaw.gateway` and `launchctl disable` it: the gateway stops
   and does not start at the next login.
2. Installs the bundle, `/etc/wardend/config.json` (mode `observe`, `child_user`, `agent_home`,
   `root_exec` off, the `gate` defaults), `/var/db/wardend` (root 0700).
3. Writes `/Library/LaunchDaemons/ai.openclaw.gateway.plist` from
   `deploy/wardend.launchd.plist`: **the same label as the gateway's LaunchAgent**. OpenClaw's own
   tooling checks `launchctl print system/<label>` and `/Library/LaunchDaemons` and refuses to
   write, start, restart or repair a user LaunchAgent next to a same-label system LaunchDaemon
   (its docs, "Existing system LaunchDaemons"); `openclaw gateway status` reports it. Run `openclaw
   doctor` with `OPENCLAW_SERVICE_REPAIR_POLICY=external`: it stays diagnostic for the service
   lifecycle. Restarts are `sudo launchctl kickstart -k system/ai.openclaw.gateway`.
4. `launchctl bootstrap system /Library/LaunchDaemons/ai.openclaw.gateway.plist`.

The harness command and its environment come from the LaunchAgent verbatim (its `PATH` replaces
the template's default). Logs: `/var/log/wardend.log`. Uninstall
(`sudo /usr/local/share/wardend/uninstall.sh`) boots the daemon out, keeps the journal and a config
copy in `/var/db/wardend`, removes the rest, and enables and bootstraps the gateway's own
LaunchAgent again when its plist is still there.

Without an OpenClaw LaunchAgent: `--harness-cmd '/usr/local/bin/node /opt/x/index.js …'`, label
`dev.wardenclaw.wardend`. Not on macOS: `--single-user` (the ES client needs root; use `sudo
wardend wrap`), `--root-exec`, `--rw-paths`, `--admin-user`, `--ptrace-scope`.

`--dry-run` works on any OS with `WARDEND_UNAME=Darwin` and a `PLISTBUDDY=` stand-in; that is how
`deploy_macos_test.go` tests the installer on the Linux CI.

## The stand (EC2 mac2-m2), runbook

The host is allocated with `/mnt/ssd/tmp/wc-mac/s3_allocate_host.py`, the instance started with
`s4_run_instance.py`, first setup `mac_setup.sh` (not in the repository). Then, in order:

1. **SIP off**: AWS does it by API, `CreateMacSystemIntegrityProtectionModificationTask` with
   `MacSystemIntegrityProtectionStatus=disabled` (the instance is stopped and started by the task;
   ~an hour). Check: `csrutil status` → `disabled`.
2. **boot-args: do not set them on an EC2 Mac.** ⚠️ `sudo nvram
   boot-args="amfi_get_out_of_my_way=1"` **bricked the stand** on 2026-10-10: the write succeeded
   (`nvram boot-args` read the value back), and after the reboot (15:09 UTC) the instance never
   came back: port 22 stayed closed on every probe until the last one at 16:40 UTC, with SIP
   already off and the security group unchanged.

   Why is **not established**: nothing on an EC2 Mac shows its screen. What is known: on Apple
   silicon the boot-args pass a LocalPolicy bit, `sip3`: "If sip3 is present and true, iBoot won't
   enforce its built-in allow list for the boot-args NVRAM variable, which would otherwise filter
   the options passed to the kernel. Users can change this field using csrutil or bputil from 1TR"
   (Apple Platform Security, "Contents of a LocalPolicy file for a Mac with Apple silicon"). An
   EC2 Mac has no 1TR: no power button, no screen. Read literally, without `sip3` the arg is
   filtered out and the Mac boots as before, so a dead instance points the other way: AWS's SIP
   task (its own authenticated path into the LocalPolicy, documented only as the SIP flags) may
   set `sip3` along with SIP, as `csrutil` can, the kernel got `amfi_get_out_of_my_way=1`, and
   something on the boot or network path of the EC2 Mac does not survive AMFI off. That is a
   hypothesis; either way it is not a step to take on an EC2 stand.

   Recovery is a **stop/start of the instance**, not a reboot: "EFI NVRAM variables will be reset
   if the instance is stopped or terminated" (the EC2 Mac FAQ), which is exactly what clears
   boot-args. A reboot keeps them ("will persist across reboots"), so a wedged instance stays
   wedged. SIP on Apple silicon is "applied at the volume level" (AWS, "Configure SIP"), so it
   should survive the stop/start: check `csrutil status` and `nvram boot-args` first.

   **Budget the stop/start as 30–60 minutes and get a fresh AWS token before it, not during.**
   Measured on 2026-10-10: `StopInstances` at 16:46 UTC, `stopped` at 16:57:47 UTC (~11 minutes,
   a Mac instance is not a Linux one), and the dedicated host was still `pending` — being
   scrubbed — 24 minutes later at 17:21 UTC; `StartInstances` cannot land until the host is
   `available` again (AWS documents up to ~50 minutes). The `aws` MCP token lives about an hour
   and expired inside that wait: the endpoint answered `HTTP 401`, and `openclaw mcp probe aws`
   (what `scripts/aws-mcp.py` falls back to) replied `requires OAuth authorization`, which only
   `openclaw mcp login aws` by hand fixes. There is no other route to EC2 from the Pi: no
   `~/.aws`, no `boto3`, and `AWS_BEARER_TOKEN_BEDROCK` is a Bedrock key, not SigV4. Losing the
   token mid-wait leaves the stand stopped with nobody able to start it. The stop also
   **releases the public IP** (no Elastic IP attached), so re-read it from `DescribeInstances`
   after the start instead of reusing the old address. Poller for all of this:
   `/mnt/ssd/tmp/wc-mac-20261010/stand/revive.py`.

   So the first question on the stand is whether the boot-arg is needed at all. Try step 4 (Full
   Disk Access) and step 6 **without** it: with SIP disabled, `es_new_client` may already skip the
   entitlement check. If it returns `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`, the dev-mode stand on
   EC2 is a dead end and the gate has to wait for the real entitlement (or run on a Mac somebody
   can hold a power button on). Until that is measured, the "SIP off and
   `amfi_get_out_of_my_way=1`" recipe in this document and in `spikes/macos-gate.md` is
   **unproven** for EC2: the second half of it is unreachable there.
3. **Xcode CLT**: present on the EC2 macOS 27 image (`/Library/Developer/CommandLineTools`, clang
   21, `MacOSX27.sdk` with the ES symbols). Go 1.26: the darwin-arm64 tarball unpacked into `~/go`
   (set `GOPATH` elsewhere, `~/gopath`, or go complains that it equals `GOROOT`). No Homebrew.
4. **Build with cgo**: `cd daemon && CGO_ENABLED=1 go build -o wardend .`, `go vet ./...`,
   `go test -p 1 ./...` (as a plain user the gate tests skip; as root with `WARDEND_ES_TESTS=1
   WARDEND_TEST_CHILD_USER=ec2-user` after step 5 they run for real). Done 2026-10-10 on
   `mac2.metal` (M1), macOS 27.0: build, vet and the suite green.
   SIP prerequisite on Apple silicon: `sudo dscl . -passwd /Users/ec2-user <pw>` and
   `sysadminctl -oldPassword <pw> -newPassword <pw>` (secure token; 4–16 characters), then the
   API task `CreateMacSystemIntegrityProtectionModificationTask` with
   `{"internalDiskPassword": "", "rootVolumeUsername": "ec2-user", "rootVolumePassword": …}`
   as the `MacCredentials` JSON string.
5. **Full Disk Access** for the binary. With SIP off a row in the system TCC database works:
   `sudo sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db"`, insert an `access` row with
   service `kTCCServiceSystemPolicyAllFiles`, client the binary's path, `client_type 1`,
   `auth_value 2`, `csreq NULL`, then `sudo killall tccd`. Or the GUI through VNC.
6. **Run**: `sudo ./wardend wrap -- /bin/sh -c 'curl https://example.org'`. Expected: the pairing
   QR on the first run; then the `sh` exec passes (logged), the `curl` exec trips the tripwire
   (remote fetch), the card arrives on the phone, the process sits in the kernel (`ps` shows it in
   `U`, uninterruptible) while the card waits, the curl output after approve, or `Operation not
   permitted` from the shell after deny. The journal: a `start` record with
   `"gate": "endpoint-security"`, `"scope": "descendants"` (or `"global"` on 26) and
   `"deadlineMiss"`, one `exec` record per exec with `deadline.leftMs`/`budgetMs` and
   `ticketWaitUs` around the wait.

   `wardend journal` is a call on the socket of a **running** wardend (`journal.tail`), so it
   shows nothing once a one-shot `wrap` has exited: read the file instead, `sudo cat
   <state-dir>/journal.jsonl`. On macOS `wrap` puts its state under root, `/var/db/wardend/wrap`
   by default (`--state-dir` moves it); the config of that run is `<state-dir>/config.json`, which
   is the only way to set `gate.scope` and `gate.deadline_miss` (no flags for them).

   Lay that state down with the modes selfcheck insists on, or wardend refuses to start in the
   enforce mode (`selfcheck.go`): the state directory no wider than 0700 and the config not
   group- or world-writable. `sudo mkdir -p` and `… | sudo tee` give 0755 and 0644, which both
   fail; use `sudo install -d -m 700 <state-dir>` and `… | sudo install -m 600 /dev/stdin
   <state-dir>/config.json`.

   Without a phone, run the same thing in observe: `--mode observe --relay-url off` asks nothing
   and reaches no relay, and the journal still carries every `deadline`/gate field. `--relay-url
   off` matters: observe does not need the relay, but wardend would otherwise still dial it.
7. **Measure** what the 30.09 spike could not: the `deadline_ms` of an `AUTH_EXEC` message on this
   build (`deadline.leftMs` in every record; the 500 ms guard logs the low ones), whether a card
   left unanswered ends exactly at `budgetMs` with `ttl expired` and the exec denied, and what a
   missed deadline does on this version with and without `fail-closed` (a build against the 27 SDK
   is needed for fail-closed: the mode's value comes from the header).

   All three are measurable **without a phone and without the relay**, with a binary built from
   the deadline-mode fix of 2026-10-10 or later against the 27 SDK. Check the SDK before the
   runs: `xcrun --show-sdk-version` (27.x) and `grep -rn DEADLINE_MISS "$(xcrun
   --show-sdk-path)/usr/include/EndpointSecurity/"`; then the `start` record of the first observe
   run, `gate.deadline_miss` left at its default, must say `"deadlineMiss": "fail-closed"`. `"kill"` there means the
   binary has no deadline mode and the third measurement would compare `kill` with itself.

   - *The deadline.* Two observe runs, `"gate": {"scope": "descendants"}` and `{"scope":
     "global"}`. The descendants run reports what `es_set_deadline_min_milliseconds` achieved
     (`start`, `gate.deadlineFloorMs`, asked for `ticket_ttl + 2s`); the global run never raises
     the floor, so its `deadline.leftMs` is this macOS's own AUTH_EXEC deadline. That second
     number is the one the design depends on.
   - *A card nobody answers.* Ticket mode, `"relay_url": "off"` and one `trusted_devices` entry
     with an `id` and **no** `pubkey`: such an entry loads, so `wrapPrepare` sees a paired device
     and starts the command, but `Devices.Key` refuses it as `unknown_device`, so no decision can
     ever be signed. The card waits out `min(ticket_ttl, deadline budget)` and the journal says
     `ttl expired` with `EPERM`; with `ticket_ttl` above the budget the wait shows the budget, not
     the TTL. Nothing leaves the machine.
   - *A missed deadline.* wardend's own watchdog answers DENY at `budgetMs`, so a real miss needs
     a throwaway build that sleeps past the deadline before responding (one patch in `handle`,
     never committed). Run it twice, with the default `fail-closed` and with `"gate":
     {"deadline_miss": "kill"}`, and compare: whether the exec was denied or allowed, and whether
     wardend survived.
8. **Install path**: `sudo sh install.sh --from-dir <release dir> --harness-cmd …` with a release
   directory built by hand (`wardend_darwin_arm64.tar.gz` and `checksums.txt`: scripts/release.sh
   does not build it yet).

Write the three numbers of step 7 into `spikes/macos-gate.md` next to the decision.
