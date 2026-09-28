# Go version and govulncheck in the release: work log

Task: close finding V2 of the supply-chain audit (2026-09-28). The release was pinned to Go 1.26.0,
and `govulncheck` found 18 reachable standard library vulnerabilities in it, including in the HTTP
server that listens for the phone. The rules for the maintainer are in `release.md` (sections
"Go version" and "Go vulnerabilities: govulncheck"); this file has the timeline, commands and
results. Working directory for the checks: `/srv/scratch/wc-gohard/`.

## 2026-09-28

### Choosing the version

- The latest version in the 1.26 branch is 1.26.8 (go.dev/dl). There is also 1.27.1, but closing the
  vulnerabilities doesn't need a move to a new minor version, and such a move brings behavior
  changes. 1.26.8 was chosen; the move to 1.27 is left as a separate decision.
- `go.mod`: the line `go 1.26.0` is unchanged, it is the minimum for `golang.org/x/sys v0.48.0`
  (which itself has `go 1.26.0`). Added `toolchain go1.26.8` (`go mod edit -toolchain=go1.26.8`).
- `go mod tidy` on Go 1.26.8 (`-mod=mod`, `GOPROXY=off`) changes neither `go.mod` nor `go.sum`:
  third-party dependencies were not updated.

### Where CI gets the version

- All workflows install Go with `actions/setup-go` and `go-version-file: daemon/go.mod`
  (`release-daemon`, `daemon`, `protocol`, `plugin`). There is no hard-coded Go version anywhere in
  the repository except `go.mod`.
- setup-go v7.0.0 at the pinned SHA `b7ad1dad…`, `src/installer.ts`, `parseGoVersionFile`: if
  `GOTOOLCHAIN` in the environment is not `local`, the version comes from the `toolchain` line,
  otherwise from the `go` line. After installing, setup-go itself exports `GOTOOLCHAIN=local`, and
  `go` no longer switches toolchains. So all four workflows now install 1.26.8 without changes.
- The fallback to the `go` line when `GOTOOLCHAIN=local` is set in the workflow environment is
  silent, so `release-daemon.yml` got an explicit check of `go env GOVERSION` against the
  `toolchain` line.

### Checks on the Pi (linux/arm64)

A clean `git archive HEAD` snapshot (`d356a20`, the `daemon/` and `protocol/` directories) with the
new `go.mod`: someone else's edits to the Go code were in progress in the working tree at the same
time, and the check was not supposed to touch them. Go 1.26.8 from the module cache,
`GOTOOLCHAIN=local`, `GOPROXY=off`, `GOFLAGS=-mod=readonly`.

- `go build ./...` and `go vet ./...` for linux/amd64 and linux/arm64: clean.
- `go build` and `go vet` for `./cmd/wardenctl` under darwin/arm64 and darwin/amd64: clean.
- `go test -p 1 -count=1` per package, outside the live wardend filter: all packages `ok` (`wardend`
  16.3 s, `cmd/wardenctl` 17.9 s, the rest under a second). Back then the tests ran through
  `systemd-run --user`, that is, outside the gate; the project rule is different now: such runs are
  done by a human from their own terminal or by CI (`CONTRIBUTING.md`). Only `TestDecodeWithZXing`
  was skipped: it needs the external decoder `WARDEND_QR_DECODER`, as before the version change.

`govulncheck` v1.8.0 (the latest version, module hash checked against sum.golang.org), symbol mode,
the vuln.go.dev database. The same snapshot, only Go changes:

- linux/amd64 `./...`: 1.26.0 gives 18 reachable (exit code 3), 1.26.8 none (exit code 0).
- linux/arm64 `./...`: 18 and 0.
- darwin/arm64 `./cmd/wardenctl`: 16 and 0.
- darwin/amd64 `./cmd/wardenctl`: 16 and 0.

Findings on 1.26.0 (linux): GO-2026-4599, 4600, 4601, 4602, 4866, 4870, 4918, 4946, 4947, 4971,
5026, 5037, 5039, 5856, 5972, 6089, 6090, 6218. Packages `crypto/tls`, `crypto/x509`,
`encoding/asn1`, `net`, `net/http`, `net/textproto`, `net/url`, `os`; fixed in 1.26.1–1.26.6.
Under darwin, GO-2026-4602 and GO-2026-6089 are absent. On 1.26.8 the informational part (packages
imported but not called) is empty too.

### CI: `release-daemon.yml`

- A new first job, `vulncheck`, with only `contents: read`: checkout, setup-go, the Go check against
  the `toolchain` line, `go install golang.org/x/vuln/cmd/govulncheck@v1.8.0` and four runs, the
  same targets as above. A separate job because the tool is downloaded at release time and must not
  see the write token and the OIDC token of the `release` job.
- `release` got `needs: vulncheck`: without a green govulncheck, the tests, the build, the
  attestation and the draft don't run.
- In `release`, the same check of `go env GOVERSION` against the `toolchain` line before the tests.
- No new actions. The SHAs of the existing ones were checked with `git ls-remote`: checkout v7.0.1
  `3d3c42e5…`, setup-go v7.0.0 `b7ad1dad…`, attest-build-provenance v4.2.2 `4d101475…` (all tags
  are lightweight, the SHAs are commits).
- Checked locally: the version check passes on 1.26.8, fails on 1.26.0 and with a `go.mod` without
  the `toolchain` line; the YAML parses (`yaml.safe_load`).

### Not part of this change

- `scripts/release.sh`: take `GOTOOLCHAIN` from the `toolchain` line and refuse if `go version`
  differs; write the Go version into the archive. For now the maintainer sets the version (step 3 of
  the release process in `release.md`), and CI checks it on its own.
- Done since (2026-09-30): `daemon.yml` runs the same govulncheck on every push and pull request
  (job `vulncheck`), so a vulnerability shows up before the tag and not on release day; and
  `.github/dependabot.yml` watches `gomod` in `daemon/`, the npm packages and the actions, so the
  `toolchain` line and the action SHAs keep up with patch releases.
