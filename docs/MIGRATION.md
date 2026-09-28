# Monorepo migration (log, Sep 27, 2026)

The working directory name `mono/` was temporary. The published repository is `xarvel/WardenClaw`.

## Steps

1. [x] History: clones with `git clone --no-local` into `/tmp/mono-build`, `git filter-branch --index-filter`
   moves each repository into a subdirectory across all commits (git-filter-repo is not on the
   machine; subtree would have left old commits with files at the root). Then `merge --allow-unrelated-histories`:
   `daemon/` (wardend, 34 commits) + `app/` (wardenclaw, 48) + `plugin/` (wardenclaw-gate, 11) +
   `site/` (wardenclaw-site, 9) + 3 merge commits = 105. HEAD trees verified by blob hashes.
   Old repositories untouched.
2. [x] `protocol/`: specification (`README.md`, `HARDWARE.md`, `LICENSE` from `wardend/docs/protocol/`) and
   vectors in `protocol/vectors/` (`canonical_vectors.json`, `hw_vectors.json`,
   `transport_vectors.json`, generator `gen_vectors.mjs` from `wardend/envelope/testdata/`). Copies in
   `app/src/core/__fixtures__/protocol/` and `plugin/test/fixtures/` removed from the tree (were
   byte-for-byte equal, verified with `cmp`), `bench/sync_vectors.sh` removed. Tests read `protocol/vectors/`:
   Go `envelope` (`vectorsDir`), `cmd/wardenctl/proto_test.go`, `app/scripts/test-core.mjs`,
   `plugin/test/{vectors,hardware}.test.js`. Tests that compared copies (`TestVectorCopiesInSync`,
   `TestVectorsIdenticalInApp`) removed: there are no more copies. In `hw_vectors.json` and
   `transport_vectors.json` only the `note` field changed (regenerated with `-update-*`).
3. [x] Shared files at the root: `AUTHORS`, `SECURITY.md`, `CONTRIBUTING.md` (DCO, license map,
   tests for all parts) instead of four copies per component; `LICENSE` (map by path), `NOTICE`
   (links to component NOTICEs, which stay: they go into release archives and APKs), `TRADEMARKS.md`,
   `README.md`, `.gitignore`, `.editorconfig`, `.easignore` (moved from `app/`, see EAS).
   Component LICENSEs untouched. Links in component README/NOTICE files point to the root files.
4. [x] CI: `.github/workflows/{daemon,app,plugin,site,protocol}.yml` with path filters,
   `release-daemon.yml` (tag `daemon/v*`), actions pinned by SHA (checkout v7.0.1, setup-go v7.0.0,
   setup-node v7.0.0, attest-build-provenance v4.2.2; SHAs verified with `git ls-remote`).
5. [x] `install.sh` (`TAG_PREFIX="daemon/"`, `%2F` in URL for `--version`), `scripts/release.sh`
   and `sign-release.sh` (accept `daemon/vX.Y.Z`, AUTHORS from root), `docs/release.md`.
6. [x] Paths in documentation and comments: `wardend/...` -> `daemon/...`, `wardenclaw/src` -> `app/src`,
   `wardenclaw-gate/...` -> `plugin/...`, `cd wardenclaw/wardend` -> `cd wardenclaw/daemon` on the site,
   `site/src/config.ts` (`tree/main/daemon`, `tree/main/plugin`). The plugin identifier
   `wardenclaw-gate` and the Go module `wardend` were not changed (those are names, not paths).
7. [x] Checks (Sep 27, 2026, clean monorepo clone at `/tmp/mono-check`, `npm ci` there so that
   `node_modules` do not go into the synced folder; for the app `npm ci --ignore-scripts`, as in CI):
   - daemon: `go vet ./...`, `GOARCH=amd64 go vet ./...`, `go test -p 1 ./...` via
     `systemd-run --user`: all packages ok;
   - app: `npx tsc --noEmit` no errors, `npm test` 12/12;
   - plugin: `npm test` 43/43, including e2e with `daemon/wardend` from the same clone (via
     `systemd-run --user`; binary built with umask 002 and wardend selfcheck refused due to 0775,
     green after `chmod 755`; in CI umask 022);
   - site: `npm run build` 8 pages;
   - protocol: generator and `-update-hw -update-transport` reproduce the files byte-for-byte,
     Go, TS and JS vector tests green.
8. [x] EAS: `.easignore` must live at the git root (eas-cli 24.8: `Ignore(rootDir)`, rootDir = repo root;
   `app/.easignore` in the monorepo would be ignored, and without it EAS would fall back to
   `.gitignore`, losing `app/.env`). The root `.easignore` keeps only `app/`: archive 1.4 MB.
   Build `66c435b0-8d87-4259-a8d4-bb1f4306028e` (bench profile, commit `265d5fb`) launched
   with `app/scripts/eas_build.sh` from a clean clone `/tmp/mono-check` using `npm ci --ignore-scripts`
   and a copy of `app/.env` (no `node_modules` installed in the synced folder itself). Wait script:
   `/tmp/mono-eas-wait.sh`, log `/tmp/mono-eas-wait.log`, APK at `/tmp/mono-eas-<id>.apk`.
   Result: FINISHED at 14:53, APK 93.5 MB; the bundle contains the gateway and model addresses
   from the local `app/.env` (so `.env` reached EAS via the root `.easignore`). Pixel (`adb -s <serial>`):
   launch from launcher (task reset) -> `adb install -r` Success (lastUpdateTime 14:54:08) ->
   launch: feed, status "Connected", meaning pairing and settings were preserved; logcat without
   FATAL/Fatal signal and without app process errors.
9. [x] `mono/` is the single source of truth for further development: the app, `wardend`,
   `wardenctl`, the installer, the protocol, the plugin, the site and user documentation are
   changed and released from here only. The old repository directories are kept as a backup for
   now but no new commits are made to them; they can be deleted or archived after publication.
10. [x] Final check from a clean clone: app 12/12, plugin 43/43, site 8 pages, `go vet`
    for arm64/amd64 and all Go packages green. Also fixed an old hang in
    `TestOrphanBeforeExecIsNewRoot`: `bash read -t` on an unclosed pipe replaced with a delay
    using only bash built-ins; the scenario ran three times and then in the full suite.

11. [x] App identifier `com.wardenclaw.app` (maintainer's decision, Sep 27, 2026, commit `ac1bca4`):
    `android.package` and `ios.bundleIdentifier` in `app/app.json`; Kotlin packages and `namespace`
    of native modules `expo.modules.*` -> `com.wardenclaw.modules.{benchprobe,wardenwatch,yubikey}`
    (plus `expo-module.config.json` and the service name in `withWardenWatch.js`), `group` in
    `build.gradle` -> `com.wardenclaw.modules`, `PKG` in `scripts/bench_device.py`. The scheme
    `wardenclaw://`, SecureStore keys (`wc.*`), notification channels, `rpId` `wardenclaw` and
    `origin` `wardenclaw:app` do not depend on the package identifier and were not changed; wardend
    and the plugin have no bindings to the package id.
    For Android this is a new app: its own SecureStore, its own device key, pairing again; the
    YubiKey (credential is not resident, stored only in SecureStore) is re-bound through the master
    and `wardend hw-register`. EAS in `--non-interactive` created a new keystore in the cloud
    automatically (`Using remote Android credentials`, `Generating keystore in the cloud`), nothing
    needed manually. Build `62e7cfa6-fc7d-49a6-b991-2f658814d8e6` (bench, clean clone `/tmp/mono-bid`),
    APK 93.5 MB `/tmp/mono-eas-62e7cfa6-fc7d-49a6-b991-2f658814d8e6.apk`. Pixel (`adb -s <serial>`):
    `adb install` Success alongside the old one, `pm list packages` shows both, the new one starts
    on the feed "Not connected", logcat without FATAL. Checks in the clone: tsc clean, app 12/12,
    plugin 42/43 (1 skipped), site 8 pages. Go not touched.

12. [x] Local build on the Mac instead of cloud EAS (Sep 27, 2026; EAS credits nearly exhausted
    for the cycle: 4400 out of 4500 cents, iOS medium costs 200, so no cloud simulator build
    for iOS verification was started). `app/scripts/local/`: `doctor.sh` (Xcode, CocoaPods,
    fastlane, Node per `.nvmrc`, JDK 17, SDK 36, build-tools 36.0.0, NDK 27.1.12297006, CMake 3.22.1),
    `ios.sh` (`eas build --local` production, `sim`, `sim-xcode` and `xcode` without EAS, `submit`
    via `eas submit` or `xcrun altool` with an App Store Connect key), `android.sh` (`eas` with a
    profile, `gradle apk|aab` with a local upload keystore, `keystore`, `install`). Scripts build
    not in the synced folder but in a copy at `~/.cache/wardenclaw/stage` (rsync without
    node_modules, ios/, android/), artifacts in `~/WardenClaw-builds`. `eas.json`:
    `appVersionSource: remote`, autoIncrement; production = AAB + store, `preview`/`bench` = APK,
    `simulator` for iOS.
    `app/ios/` and `app/android/` added to `app/.gitignore` and the root `.easignore` (otherwise
    EAS after a local prebuild would treat the project as bare). iOS by code: Kotlin-only modules
    (`platforms: ["android"]`), wrappers on `requireOptionalNativeModule`, no Swift stubs needed;
    YubiKey on iOS "not yet supported"; background notifications shown as disabled with a note
    about APNs; the judge bench entry hidden. `app.json`: `ios.deploymentTarget` 16.4,
    `NFCReaderUsageDescription`, entitlement increased-memory-limit, privacy manifest. `expo
    prebuild` for ios and android in a clean clone without errors, tsc clean, app 12/12. Docs:
    `app/docs/BUILD.md`.
13. [x] Go module path `github.com/xarvel/WardenClaw/daemon` (Sep 30, 2026, before the first
    `daemon/v*` tag): `go mod edit -module`, every `wardend/...` import rewritten, the wardenctl
    e2e test builds both binaries by the new package path, `go.sum` unchanged (same dependencies).
    With this path the `daemon/v*` tags are module versions, so
    `go install github.com/xarvel/WardenClaw/daemon/cmd/wardenctl@latest` works from the first
    tag on. The binary name `wardend` and the daemon directory did not change.

## What remains

- User documentation is in one place (`site/src/docs/`), but `daemon/docs/CLI.md` is longer than
  the site: the HTTP API, `wardenctl` and socket protocol detail sections should move to the site,
  leaving only developer notes in `daemon/docs/`. A note has been added to the file.
- Full trademark policy is in the private `wardenclaw-brand`: publish a `/trademarks` page on the
  site, add a link in `TRADEMARKS.md`.
- `gofmt -l` reports `daemon/supervisor.go` (was there before the migration, not touched).
- The plugin identifier `wardenclaw-gate` and the binary name `wardend` were not changed: that is
  a separate decision together with the project name. The app package was changed to
  `com.wardenclaw.app` (step 11).
- Delete the old app (previous applicationId) from the Pixel when the maintainer pairs the new one
  and decides it is no longer needed; revoke its device in wardend `trusted_devices` at the same
  time (`wardend pair revoke <device id>`).
