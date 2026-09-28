# Moving uninstall out of install.sh into uninstall.sh (work notes, 2026-09-28)

Task: make `install.sh` short again (1179 lines after `e08088e`, 610 before it), uninstall lives
in `daemon/uninstall.sh` and ships in the signed archive, `install.sh --uninstall` stays a
thin wrapper. Working directory for the checks: `/srv/scratch/wc-split/`.

## What was done

- `daemon/uninstall.sh` (736 lines): all the uninstall logic from `install.sh` with no change in
  behavior, its own flag parsing (`--purge`, `--remove-agent-user`, `--agent-user`,
  `--single-user`, `--dry-run`, `--yes`; `--uninstall` is accepted and means nothing),
  the whole body in functions, `main "$@"` as the last line. Its own "Project identity" block.
- `daemon/install.sh`: 1179 → 619 lines. The wrapper `uninstall()` with `root_only` (36 lines including
  the comment), `check_arch` split out of `check_platform`, creating `$WORK` moved to
  `verify_release`, the `SHARE_FILES` list with `uninstall.sh` for both install variants,
  `uninstall.sh` in the list of required archive files, the final hints point to the installed
  copy, a failed check says "Nothing was changed" (true for both install and uninstall).
- `daemon/scripts/release.sh`: `uninstall.sh` goes into the archive (0755), the "Project identity" blocks
  of the two scripts are compared, and on a mismatch the release is not built.
- `daemon/deploy/hardened-install.sh`: comments and manual steps refer to `uninstall.sh`.
- Documentation: `daemon/docs/release.md` (section "Removal: uninstall.sh"),
  `site/src/docs/uninstall.en.md`, `site/src/docs/install.en.md`.

## How uninstall is delivered and run

1. `uninstall.sh` is in `wardend_linux_<arch>.tar.gz` under the signed checksums.
2. The install puts it into `/usr/local/share/wardend/uninstall.sh` (root, a directory not writable by the
   group and others) or into `~/.local/share/wardend/`.
3. The main path: `sudo /usr/local/share/wardend/uninstall.sh`, no network needed. The copy deletes
   itself together with the directory: dash, bash and busybox sh calmly run to the end of a script whose
   file has been deleted (checked on a script larger than the read buffer).
4. `install.sh --uninstall`: the copy, if it is root-only; otherwise, and also with `--version` or
   `--from-dir`, the release via `verify_release` and `uninstall.sh` from the verified archive.
   `--single-user` under root refuses before running anything.

## Checks (2026-09-28, Pi)

- 02:33 `sh -n`, `dash -n`, `bash -n`, `busybox sh -n` for `install.sh`, `uninstall.sh`;
  shellcheck 0.11.0 (`-s sh`) for them, `release.sh`, `hardened-install.sh`: clean.
- 02:33 the test bench `/srv/scratch/wc-split/test/all.sh`, a fake root in a user+mount namespace and
  a fake HOME, `--dry-run` only. Direct mode (`uninstall.sh`): 24/24. The logs were compared with the
  old `install.sh --uninstall` logs from `/srv/scratch/wc-uninstall/logs-repo`: after replacing
  the times, all 18 scenarios matched, except for two intentional wordings ("the installer" instead of
  "this installer", "the installer did not put it there" about `wardenctl`).
- 02:35 snapshot `v0.0.0-snapshot.f073a5c19a6a` (`release.sh --snapshot` in a clone of HEAD with my
  files): `uninstall.sh` in both linux archives, 0755, byte for byte identical to the repository. Signed
  with a one-time key (OpenSSL in minisign format), a second key with the same key id for checking
  a foreign signature.
- 02:37 wrapper mode (`install.sh --uninstall`). The first run failed on 9 scenarios, and that is
  correct: in the fake root the directory `/usr/local/share/wardend` was 0775 (umask 002),
  `root_only` rejected the copy and went on to download. The bench now does `chmod -R go-w`, like
  `install_share`. One more error was in the bench itself (the archives were repacked without `--owner=0`).
  After fixing the bench, wrapper 29/29: the copy runs; a copy that a non-root user can write
  does not run; a user's copy does not run under root; a tampered archive, a foreign signature
  and a release without `uninstall.sh` give a refusal, and the uninstall code is never reached.
- 02:39 release mode (always `--from-dir` of the snapshot): 23/23. Repeating direct and wrapper under bash and
  busybox sh: 24/24 and 29/29.
- 02:41 site: a copy of `site/` in `/srv/scratch/wc-split/site`, `npm ci`, `npm run build`: 14 pages,
  internal links and anchors in the built HTML: 483 checked, 0 broken.
