# Live run of a hardened install in AWS (Sep 28, 2026)

Temporary EC2 instances to verify `install.sh` + hardened mode on amd64 and arm64.
All resources tagged `Project=wardenclaw-test`, `Owner=<name>`, `Expire=2026-09-27`, region eu-north-1.
Access: local AWS MCP client (`aws___run_script`), IAM user `<test-user>`.

## Created resources (delete all!)

| Resource | id | status |
|---|---|---|
| key pair `wardenclaw-test-20260927` | key-0376444c628e2313c | deleted 16:16 |
| security group `wardenclaw-test-20260927` | sg-06f0c37ab202c43ed | deleted 16:16 |
| EC2 t3.small amd64 | i-00dcb7f893499d123 | terminated 16:15, volume deleted |
| EC2 t4g.small arm64 | i-02a8c1b85ac7720eb | terminated 16:15, volume deleted |

## Log

- 15:35 AWS MCP token expired (refresh expired), the maintainer re-logged in.
- 15:36 snapshot built: `DIST=/tmp/wc-aws/dist scripts/release.sh --snapshot`. SSH key `/tmp/wc-aws/id_ed25519`.
- 15:40 resources from the table created (AMI ubuntu-noble-24.04 20260923: amd64 ami-0769f265f707fecc8, arm64 ami-0fa156f9d99979afc).

Teardown: TerminateInstances for both ids, then DeleteSecurityGroup sg-06f0c37ab202c43ed, DeleteKeyPair key-0376444c628e2313c.
- 15:45 install succeeded on both (signature via OpenSSL; minisign is not available on Ubuntu), but `systemctl enable --now wardend` crashed in a loop: `__child: drop privileges: setuid 999: operation not permitted`.
  Cause: `User=root` + `NoNewPrivileges=true` in the unit; systemd 255 drops CAP_SETUID (CapPrm 0x1fffffeff7f, bit 7). Confirmed by bisecting unit file copies and a Go reproducer; without `User=` or without NNP everything works. Not caught earlier because no live run had been done on the Pi.
  Fix: remove `User=root`/`Group=root` from `deploy/wardend.system.service`, add test `TestSystemUnitKeepsSetuid`, add a hint to the `dropPrivileges` error.
- 15:50 after fix 098ad36 the service starts on both; observe (ls/curl/rm), pairing wardenctl under `ubuntu`, ticket: wait, approve, deny (rc=126 EPERM), expiry exactly after 120 s. hardened-check 27/27. Fail-closed: SIGSTOP (exec hangs), SIGKILL and stop (harness tree killed, command not executed).
- 15:53 **gate bypass**: `loginctl enable-linger agent` from the agent passes (polkit default), user@999 starts, `systemd-run --user` gives Seccomp: 0. Fix e169825: polkit rule in hardened-install.sh, check in hardened-check.sh, docs. Linger disabled manually on the machines.
- 16:05 upgrade without `--harness-cmd` did not add the polkit rule for existing installs: fix 83ff8dd (agent_guard, ONLY_AGENT_GUARD=1). Verified: amd64 binary-only upgrade, arm64 full repeat; hardened-check 30/30 FAIL=0, `busctl SetUserLinger` from the agent: Access denied. Pairing and ticket survived the upgrade.
- 16:10 repeated install printed `mode: observe` with a ticket config: fix 073321e.
- 16:12 `--uninstall` on both: service, binaries, unit, /etc/wardend, sysctl and polkit rule removed; journal and config-backup in /var/lib/wardend kept; no agent processes.
- 16:16 teardown: instances terminated, volumes deleted with them, SG and key pair deleted. DescribeInstances/Volumes/SecurityGroups/KeyPairs with tag Project=wardenclaw-test is empty (except terminated instances, which AWS shows for about an hour). Lightsail censorpulse-cp not touched.
- Cost: about 40 min t3.small ($0.0216/h) + t4g.small ($0.0172/h) + 2 public IPv4 ($0.005/h) + 2x10 GB gp3, total about $0.04, covered by credits.

## Results

| Check | amd64 (t3.small) | arm64 (t4g.small) |
|---|---|---|
| install.sh --from-dir, OpenSSL signature, sha256 | ok | ok (also with explicit --pubkey) |
| service start per docs | failed (User=root + NNP), ok after fix | same |
| harness under agent, Seccomp 2, CapEff 0 | ok | ok |
| observe: ls, curl, rm | ok | ok |
| pairing wardenctl under ubuntu | ok | ok |
| ticket: waits, approve runs, deny rc=126, TTL 120 s rc=126 | ok | ok |
| fail-closed: SIGSTOP, SIGKILL, stop | ok | ok |
| hardened-check from agent | 27/27, 30/30 after fix | same |
| manual attacks from agent | all denied except enable-linger (fixed) | same |
| upgrade, repeat, --uninstall | ok | ok |
