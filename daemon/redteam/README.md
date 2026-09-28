# wardend redteam

Reproducible attacks against wardend from the position of a malicious harness child.
These verify that the protections described in the article and on the site are real, not marketing.

## What is tested where

| Vector | Where | Expected outcome |
|---|---|---|
| execve/execveat bypassing the gate | `go test -run TestTicket` | deny/ticket |
| memfd_create + execveat (AT_EMPTY_PATH) | `TestRedteamMemfdIntercepted`, `TestRedteamMemfdDeniedUnapproved` | intercepted; unapproved -- deny |
| direct launch via ld.so | `TestRedteamLdSoIntercepted` | intercepted |
| nested unotify filter | `TestNestedListenerBlocked` | EPERM |
| 32-bit/compat exec | filter (seccomp.go) -> ENOSYS | -- |
| self-approval over HTTP without a key | `run.sh` #1, `TestRedteamSupervisedCannotSelfApprove` | refused |
| pairing from under the filter | `httpapi_test.go` (peerSupervised) | refused |
| ticket forgery (wrong key/digest/ts) | `TestTicketRejectsForgeriesThenTTL` | refused |
| card queue overflow | `TestQueueLimitEAGAIN` | EAGAIN |
| **kill/ptrace/write wardend files** | `run.sh` #4/#5 | **succeeds in same-uid** (requires hardened) |
| same vectors in a hardened install | `hardened-check.sh` run as the agent uid | kernel refusal, `FAIL=0` |

## Running

The Go tests only work outside the wardend filter: inside its tree the kernel does not allow
setting up a nested seccomp-notify listener. A human runs them from their own terminal, which
is not under wardend, not the agent from its session:

```sh
cd daemon && go test -p 1 ./...
```

Do not ask the agent to wrap the tests in `systemd-run --user` or similar: that launches code
outside the gate, and wardend will show a card for it with that note. Approving such a card to
run tests trains you to approve arbitrary code that bypasses the gate.

Live scenario against a separate instance (its own port, own directory, test keys). A human runs
this too: the script starts a temporary wardend via `systemd-run --user`, that is, outside the gate.

```sh
wardend/redteam/run.sh
```

`FAIL` in the "OPEN IN SAME-UID" block is NOT a bug; it is a demonstration: under the same uid
the agent can send signals to the supervisor and overwrite its files. This is only closed by a
hardened install.

## Checking a hardened install from the agent uid

`run.sh` shows that kill and file writes succeed in same-uid. `hardened-check.sh` verifies the
opposite on an installed hardened system (`deploy/hardened-install.sh`): it is run **as the agent
user** and tries every inter-process and file vector. It causes no damage: it sends signal 0 and
SIGCONT to the main process instead of SIGKILL, opens files for append without writing and only
if they already exist, and reads without printing content.

```sh
sudo -u agent bash -s < wardend/redteam/hardened-check.sh
# or from inside the harness: ask the agent to run this script
```

| Check | Expected |
|---|---|
| wardend uid != agent uid | PASS |
| agent not in `sudo`/`wheel`/`admin`/`docker`/`lxd`/`incus`/`libvirt`/`disk`, `sudo -n` refused | PASS |
| `kill -0 <MainPID>`, `systemctl kill` without authorization | Operation not permitted / Interactive authentication required |
| open `/proc/<MainPID>/mem` for read and write, `environ`, `fd` | kernel refusal |
| append to binary, unit, config, key, journal; read config and key | Permission denied (root, 0600, directories 0700) |
| agent linger off, no own `systemd --user`, `loginctl enable-linger` for self refused (installer polkit rule); if it passed, the script disables it immediately | PASS |
| write to binary, config, state, `/etc/systemd/system` directories (replacement via rename) | not writable |
| socket `/var/lib/wardend/wardend.sock` | not accessible |
| `POST /v1/decide` without a device signature | `"ok":false` |
| `/etc/crontab`, `/etc/cron.d`, `/etc/sudoers.d`, `/etc/sysctl.d` | not writable |

`FAIL=0` means every vector from the tamper-resistance table that is open in same-uid is
closed by kernel uid and permission checks. Any `FAIL` names the item where the install is not
hardened. Paths can be overridden with `UNIT`, `BIN`, `CONF_DIR`, `STATE_DIR`, `HTTP`.
