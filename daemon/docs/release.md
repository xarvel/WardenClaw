# Releases and the `curl … | sudo sh` installer

How a wardend release is built, signed and distributed, and how
`curl -fsSL https://wardenclaw.dev/install.sh | sudo sh` works. The site is on GitHub Pages, `install.sh` sits
in its root as a copy from the latest signed release, archives and checksums stay in GitHub Releases.
The workflows and scripts are ready, but nothing is published: there is no GitHub repository, Pages is not
enabled, the signing key is a test key (what is left: at the end of the section
["GitHub Pages site"](#github-pages-site-and-installsh-from-the-site)).

## Where the name and domain live

The project name and domain change by a replacement in one place per artifact:

| where | what |
|---|---|
| `install.sh`, the "Project identity" block at the top | `PROJECT`, `DOMAIN` (it gives `INSTALL_URL` = `https://<domain>/install.sh`, `DOCS_URL`, `UNINSTALL_DOCS_URL`), `GITHUB_REPO` (it gives `RELEASES_URL`, where the archives and checksums are downloaded from), `TAG_PREFIX`, `DAEMON`, `CTL`, `MINISIGN_PUBKEY`, `REFUSED_PUBKEYS` (test and revoked keys) |
| `uninstall.sh`, the same block | `DOMAIN` (it gives `INSTALL_URL`, `UNINSTALL_DOCS_URL`), `DAEMON`, `CTL`: the same values as in `install.sh`. `scripts/release.sh` compares them and does not build a release if they differ |
| site, `src/config.ts` | `PROJECT_NAME`, `DOMAIN` (it gives `SITE_URL`, which is also `site` in `astro.config.mjs`, and `INSTALL_URL` = `SITE_URL/install.sh`), `RELEASES_URL`, `MINISIGN_PUBKEY`; the documentation markdown takes them through placeholders `%INSTALL_URL%` etc. |
| site, `public/CNAME` | the domain once more, for Pages. `astro.config.mjs` does not build the site if it differs from `DOMAIN` in `src/config.ts` |
| `site/scripts/fetch-install-sh.sh` (site deploy) | nothing of its own: it reads the domain and key from `src/config.ts`, the repository from the workflow context, and checks the "Project identity" block in the release's `install.sh` against them |
| `scripts/sign-release.sh` | `DAEMON` (the first word of the signed comment) |

The README and `docs/` of the repository write the address as text: when renaming, `git grep -n wardenclaw.dev/install.sh`.
The names `wardend`, `/etc/wardend`, `/var/lib/wardend` are also hardcoded in `deploy/` and the code; renaming
the binary is a separate task.

## What is in a release

| file | what |
|---|---|
| `wardend_linux_amd64.tar.gz`, `wardend_linux_arm64.tar.gz` | `wardend`, `wardenctl`, `deploy/`, `redteam/`, `install.sh`, `uninstall.sh`, `LICENSE`, `NOTICE`, `AUTHORS` (from the monorepo root), `README.md`, `VERSION` in the directory `wardend_linux_<arch>/` |
| `wardenctl_darwin_arm64.tar.gz`, `wardenctl_darwin_amd64.tar.gz` | the approver for the Mac (`wardenctl`, licenses, README) |
| `install.sh` | the same installer as a separate file (the site serves its copy, `https://<domain>/install.sh`) |
| `release-key.txt`, `release-key.txt.minisig` | only after a key rotation: the new key and a statement signed by the old one (section "Key Rotation") |
| `checksums.txt` | sha256 of all the files above |
| `checksums.txt.minisig` | minisign signature over `checksums.txt`, trusted comment `wardend <version> checksums.txt <signing date>` (version `vX.Y.Z` without the tag prefix, date `YYYY-MM-DD`) |

The names carry no version so that `releases/latest/download/<file>` works without the GitHub API (the API allows 60
requests per hour without a token). The installer takes the version from the signed comment and from `VERSION`
in the archive, and they must match.

armv7 is not built: the seccomp filter knows only `AUDIT_ARCH_AARCH64` and `AUDIT_ARCH_X86_64`
(`seccomp_arch_*.go`); 32-bit ARM needs separate handling and a test on hardware. The installer
refuses on armv7 with an explanation. x86_64 is checked by the filter test (`seccomp_filter_test.go`,
a BPF interpreter) and `go vet` under `GOARCH=amd64`; the live run on x86_64 is done by CI
(`go test` in `release-daemon.yml` and `daemon.yml` runs on ubuntu x86_64).

## Removal: `uninstall.sh`

Removal lives in a separate `uninstall.sh`, so that `install.sh`, which is run via
`curl … | sudo sh`, stays short and can be read in full.

- `uninstall.sh` is in the `wardend_linux_<arch>.tar.gz` archive, under the same signed checksums
  as the binaries. It is not a separate release file; there is no reason to pipe it into sudo. The installer
  requires it in the archive, like `deploy/hardened-install.sh`.
- The installer copies it to `/usr/local/share/wardend/uninstall.sh` (root, 0755, a directory not
  writable by group and others), the single-user variant to `~/.local/share/wardend/`.
  The main removal command: `sudo /usr/local/share/wardend/uninstall.sh`, no network needed.
- `install.sh --uninstall` stays for compatibility and for machines without the copy. It runs the
  installed copy only if the copy and its directory are owned by root and nobody else can
  write to them. Otherwise, and also with `--version` or `--from-dir`, it downloads the release, checks
  the signature and checksums with the same `verify_release` as the install, and runs `uninstall.sh` from
  the verified archive. With `--single-user` under root it refuses before running anything: a file in the
  user's home can be rewritten by the model.
- The copy deletes itself together with `/usr/local/share/wardend`: by then the shell has already read
  the script (the whole body is in functions, `main "$@"` is the last line). So the steps after the first
  removal (`--purge`, `--remove-agent-user`) go through `curl … | sudo sh -s -- --uninstall …`,
  and the script says so.
- The pinned release key (`/etc/wardend/release.pub`) goes away with `/etc/wardend`; its copy
  stays in the config backup. An install after removal pins the key again, like the first one.

## Tags in the monorepo

The daemon lives in `daemon/` of the monorepo, and releases are tagged **`daemon/vX.Y.Z`**, not `vX.Y.Z`:

- this is the Go convention for a module in a subdirectory: the module path in `go.mod` is
  `github.com/xarvel/WardenClaw/daemon`, so the module proxy sees versions only from `daemon/v…` tags,
  and `go install github.com/xarvel/WardenClaw/daemon/cmd/wardenctl@latest` resolves the newest one.
  The path is fixed with the first tag: changing it afterwards breaks importers and the checksum database;
- a bare `v*` stays free; the app and the plugin will have their own `app/v*`, `plugin/v*`,
  and one component's tag does not start another component's release;
- GitHub has one "latest" per repository, the installer downloads `releases/latest/download/<file>`,
  and the site takes `install.sh` from exactly that release. So "latest" is set only on
  daemon releases (step 5 below); releases of other components are created with `--latest=false`. CI
  creates the draft with `--latest=false` anyway. If "latest" turns out not to be a daemon release, the site
  deploy fails with an explanation instead of publishing someone else's file.

The version inside a release has no prefix: `VERSION`, `main.version` and the signed comment contain
`vX.Y.Z`. `scripts/release.sh`, `scripts/sign-release.sh` and `install.sh --version` accept both
forms. For `--version` the installer builds the URL `releases/download/daemon%2FvX.Y.Z/<file>` (the slash in
the tag is encoded; kustomize releases with `kustomize/v…` tags are downloaded the same way).

## Build: `scripts/release.sh`

A simple script instead of goreleaser: one dependency (Go), all the logic in plain sight.

```sh
scripts/release.sh daemon/v0.4.0   # dist/ for the tag (from a clean checkout of the tag, run from daemon/)
scripts/release.sh --snapshot   # v0.0.0-snapshot.<commit>, for checking, publishes nothing
```

A release is built only from a verified tag. Before the build `release.sh` checks (the common checks are in
`scripts/release-checks.sh`, and `sign-release.sh` repeats them):

- `install.sh` has no test key: not from `REFUSED_PUBKEYS` and without the `TEST KEY` marker, and the same key
  is in `site/src/config.ts`. To run the release path on a test bench there is `--allow-test-key`; CI does not
  use it;
- the tag is annotated and signed with an SSH key from `allowed_signers` (section "Signed Tags");
- `HEAD` is the tag's commit, `git status --porcelain` is empty, untracked files included: Go sets
  `vcs.modified=true` from the full status;
- if the release key differs from the one in the release before this tag, `daemon/` holds the old key's
  statement (`release-key.txt`, section "Key Rotation"), and it goes into the release.

A snapshot skips these checks: it checks the build, it is not a release.

Reproducibility: `CGO_ENABLED=0`, `-trimpath`, `-ldflags "-s -w -buildid= -X main.version=<tag>"`,
`GOAMD64=v1`/`GOARM64=v8.0`, `SOURCE_DATE_EPOCH` = the tag commit time; archives via GNU tar with
`--sort=name --owner=0 --group=0 --numeric-owner --mtime=@$SOURCE_DATE_EPOCH`, normalized permissions,
`gzip -n`. Go writes `vcs.revision` and `vcs.modified` into the binary, so only builds
from a clean checkout of the same tag can be compared.

Checked 2026-09-27 on the Pi: two snapshots in a row gave the same `checksums.txt`.

**Go version.** The binaries match only with the same Go version, and the stdlib vulnerabilities
in the release depend on it too. `go.mod` has two lines:

- `go 1.26.0`: the minimum language version. It can't go lower: `golang.org/x/sys` requires it.
- `toolchain go1.26.8`: the Go the release is built with. On 1.26.0 `govulncheck` found 18
  reachable stdlib vulnerabilities (the HTTP server for the phone, the ntfy and APNs TLS client, `crypto/x509`,
  `encoding/asn1`), on 1.26.8 none (work log in `go-hardening.md`).

setup-go in CI installs the version from the `toolchain` line (from the `go` line only if the workflow
environment sets `GOTOOLCHAIN=local`) and then works with `GOTOOLCHAIN=local`. Both jobs in `release-daemon.yml`
compare `go env GOVERSION` with the `toolchain` line and fail on a mismatch. Locally
`GOTOOLCHAIN=auto` raises an older Go to 1.26.8 but does not lower a newer one: with Go 1.27 in `PATH`
the binaries come out different, and `sign-release.sh` refuses to sign. So for a comparison with CI the version
is set explicitly (step 3 of the release process), and the first line of the `release.sh` output shows which Go
the build used.

`toolchain` is raised with every Go patch release that has security fixes:
`go mod edit -toolchain=go1.26.N`, then the tests and `govulncheck`. Moving to a new minor version
(1.27) is a separate decision; raise the `go` line only if the code or dependencies require it.

## Go vulnerabilities: `govulncheck`

A release starts with the `vulncheck` job in `release-daemon.yml`: `govulncheck` v1.8.0 over `./...` for
linux/amd64 and linux/arm64 and over `./cmd/wardenctl` for darwin/arm64 and darwin/amd64. A reachable
vulnerability (exit code 3) stops the release before the tests and the build. The usual fix: a new
`toolchain` line (see "Go version") or a new dependency version.

The job is separate, with only `contents: read`, no write permission and no OIDC token: the tool
is downloaded at release time (the go command checks the modules against sum.golang.org), and it has no reason to see
the token that creates the draft and signs the attestation. The vulnerability database comes from vuln.go.dev; if
it is unavailable, the release stops, and this is deliberate: no release goes out without the check.

Before tagging, run the same locally with the same Go as in CI (the `govulncheck` version here and in the workflow
changes together):

```sh
cd daemon
export GOTOOLCHAIN=$(sed -n 's/^toolchain //p' go.mod)
GOBIN=/tmp/gvc go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
/tmp/gvc/govulncheck ./...
GOOS=darwin /tmp/gvc/govulncheck ./cmd/wardenctl
```

## Signing: minisign, offline key

**Choice: minisign.** Why not cosign keyless:

- **Verification without new dependencies.** Users almost never have cosign (and it is tens of MB
  that would have to be downloaded and trusted somehow before the check). minisign is Ed25519, and
  `install.sh` verifies the signature either with `minisign`, if present, or with OpenSSL 3 (`pkeyutl -rawin`,
  BLAKE2b-512 for the prehash): OpenSSL is installed almost everywhere. The public key is one line in the script.
- **The key is not the GitHub account.** A keyless signature certifies "this was built by this repository's
  workflow". Whoever gets tag push access to the repository (a hijacked account, a token, a malicious PR to the
  workflow) also gets a valid keyless signature. Such an attack does not get the maintainer's offline key: a GitHub
  takeover lets an attacker replace the archives, but not sign them.
- **No external infrastructure at install time**: no Fulcio, no Rekor, no network to reach them.

Keyless is not dropped entirely: CI runs `actions/attest-build-provenance` (Sigstore) over the same
files. This is a second, independent trace "built in CI from such-and-such commit"; it can be checked with
`gh attestation verify <file> --repo <owner>/<repo>`, but the installer does not rely on it.

### Keys

- Since 2026-09-28 `install.sh` and the site's `src/config.ts` hold the **production** key
  `RWRP9RFOUaTjromMP2NoZJz+e9Mk6pNHqu+6IK3TL7jQkLabwOIk30mE` (key id `AEE3A4514E11F54F`): the maintainer
  created it offline on a separate machine; the secret half is password-protected and has never been on the Pi.
- The snapshot test key `RWRtZZCNqXGxFzK4Bx/67mlyraSSBoW2evVgCLiCgulBoLMmnrUanfsi` (key id
  `17B171A98D90656D`) lives on the development machine and installs nothing: it is in the installer's
  `REFUSED_PUBKEYS`, and a download with it is rejected before the first network request; a local build with it
  installs only with `--from-dir --allow-test-key` and is not pinned. `release.sh`,
  `sign-release.sh` and `release-daemon.yml` do not release if `install.sh` has the test key
  or the `TEST KEY` marker; the site deploy checks `src/config.ts` the same way.
- Every key whose secret was on the development machine or could have leaked goes into `REFUSED_PUBKEYS`:
  test and revoked keys. Keys for test benches are better created inside the bench and wiped after the run.
- **The production key is created by the maintainer offline**: not on the Pi, not in CI, not in a synced folder and
  not in a user account on a machine the agent logs into.

  ```sh
  minisign -G -p wardenclaw.pub -s ~/.minisign/wardenclaw.key   # with a password
  ```

  A backup of the secret key goes on a separate medium. Write the public key in one commit into
  `install.sh` (`MINISIGN_PUBKEY`) and the site's `src/config.ts`, remove the `TEST KEY` markers; then into the
  README, `SECURITY.md` and the description of every release. A single GitHub access can replace all of this,
  so the key is also published **outside GitHub**: a TXT record `_release-key.<domain>` with the key string
  (`dig +short TXT _release-key.wardenclaw.dev`; the manual check in the install documentation refers to it)
  and the maintainer's profile.

### Key pinning on installed systems

- The first hardened install writes the key it verified the release with to
  `/etc/wardend/release.pub` (root, 0644, minisign `.pub` format: `minisign -Vm checksums.txt -p
  /etc/wardend/release.pub` works with it). The single-user install does not pin: there the model
  can rewrite any file.
- From then on `install.sh` verifies the release with the pinned key, not its own. An update as documented
  goes through the installed copy, `sudo /usr/local/share/wardend/install.sh`, which does not depend on the site.
  A repeated `curl … | sudo sh` also checks the pinned key, but a tampered script checks
  only itself.
- A script whose key differs from the pinned one installs a release only if the release contains a
  statement by the pinned key naming the script's key. An old copy that meets a release signed with the
  new key accepts it by the statement the same way. After the install `release.pub` is rewritten to the
  new key.
- The test key, a key from `--pubkey` and keys from `REFUSED_PUBKEYS` are not pinned. If a new
  installer has declared the pinned key revoked, the install stops and asks you to verify the new
  key outside GitHub and delete `release.pub` by hand.
- Downgrade: a release older than the installed one (`/usr/local/share/wardend/VERSION`, semver order,
  a pre-release before the release) is rejected without `--allow-downgrade`, both for `latest` and for `--version`.
  The installer prints the signing date from the trusted comment; if `latest` was signed more than 180
  days ago, it warns: that is also what a mirror serving a frozen "latest" looks like.
  A comment without a date (three words, as before this change) is also accepted.

### Key Rotation

Planned, the old key is intact. On the offline machine:

```sh
cd daemon
scripts/rotate-release-key.sh ~/.minisign/wardenclaw.key ~/.minisign/wardenclaw-new.pub
```

The script writes `daemon/release-key.txt` (the new key as one line) and `release-key.txt.minisig`
(a signature by the old key, trusted comment `wardend release-key <new key> <date>`) and
verifies the signature with the key currently in `install.sh`. In the same commit: the new `MINISIGN_PUBKEY`
in `install.sh` and `src/config.ts`, README, `SECURITY.md`, the TXT record. Do not add the old key to
`REFUSED_PUBKEYS`: otherwise the installs pinned to it will not accept the statement.
`release.sh` will not build a release with a rotated key without the statement, and `sign-release.sh` checks the
statement with the previous release's key. The statement stays in later releases too: an install that skipped
several releases still finds it.

Leak: a statement signed with a leaked key proves nothing. The old key goes into
`REFUSED_PUBKEYS`, the new one is published in `SECURITY.md`, on the site and in DNS. Pinned installs
stop with an explanation; a person verifies the new key outside GitHub, deletes
`/etc/wardend/release.pub` and runs the installer again. Loss without a leak: the same, but without the entry
in `REFUSED_PUBKEYS`.

An install pinned to A will not get through two rotations in a row (A, then B, then C): the release has one
statement, B → C. It stops with an explanation; from there, as with a leak.

### Signed Tags

- Release tags (`daemon/v*`, `app/v*`, `plugin/v*`) are signed by a person with an SSH key on a YubiKey
  (a touch for every signature):

  ```sh
  ssh-keygen -t ed25519-sk -O resident -O verify-required -C wardenclaw-release-tags
  git config gpg.format ssh && git config user.signingkey ~/.ssh/id_ed25519_sk.pub
  git tag -s daemon/v0.4.0 -m "wardend v0.4.0"
  ```

- `allowed_signers` in the repository root (ssh-keygen format: `<principal> namespaces="git" <key>`)
  is under `CODEOWNERS`. While it lists nobody, no release is built.
- `release.sh` and `sign-release.sh` check the tag with `git verify-tag` against `allowed_signers` **from the
  previous release tag**: a signer added by a commit becomes trusted only from the
  release after the one that shipped that commit. This way the tag and the commit it
  points to do not vouch for themselves. For the first release the file is taken from the tag itself, and the script
  asks you to check who is in it. `ALLOWED_SIGNERS=<file>` sets your own copy of the file (for example, after
  losing the YubiKey).
- Only an SSH signature is accepted: git would check a GPG signature against the machine's keyring, not against
  `allowed_signers`.
- In CI `release.sh` does the same in the `build` job; checkout with `fetch-depth: 0` brings all the tags and
  the annotated tag object (checkout v7.0.1 fetches the tag via `+refs/tags/X:refs/tags/X`).

## Release process

1. `git tag -s daemon/v0.4.0 -m "wardend v0.4.0" && git push origin daemon/v0.4.0`: signed
   with the SSH key on a YubiKey (section "Signed Tags").
2. `.github/workflows/release-daemon.yml`, four jobs:
   - `vulncheck` (`contents: read`): `govulncheck`, blocks the release;
   - `build` (`contents: read`, no OIDC): a check that `install.sh` and `src/config.ts` have no
     test key (before any code of the commit runs), Go compared with the `toolchain` line, `go vet`,
     `go test -p 1 ./...`, `scripts/release.sh` with the tag checks, the `dist` artifact;
   - `attest` (`id-token`, `attestations`): a provenance attestation over `checksums.txt` from the artifact,
     without checkout and without project code;
   - `draft` (`contents: write`, environment `release`): waits for reviewer approval, without checkout and
     without project code; uploads exactly the files from `checksums.txt` as a **draft** with `--latest=false`.
   The code of the tagged commit (tests, `release.sh`) runs only with a read token: a malicious
   test can't get a write token from the runner's memory. A draft without `.minisig` does not install.
3. On your machine, from a clean checkout of the tag:

   ```sh
   git fetch origin tag daemon/v0.4.0 && git checkout daemon/v0.4.0
   cd daemon
   export GOTOOLCHAIN=$(sed -n 's/^toolchain //p' go.mod)   # the same Go as in CI
   scripts/release.sh daemon/v0.4.0
   gh release download daemon/v0.4.0 -p checksums.txt -D /tmp/ci
   scripts/sign-release.sh daemon/v0.4.0 /tmp/ci/checksums.txt   # checks, comparison with CI, signing
   ```

   Before signing, `sign-release.sh` repeats the `release.sh` checks (key, tag, clean tree),
   checks that the binaries in `dist/` are built from the tag commit without changes (`go version -m`:
   `vcs.revision`, `vcs.modified=false`), compares the checksums with CI (without the CI file only with an explicit
   `--no-ci-compare`), after a key rotation checks the old key's statement, and prints the `git log` and
   diffstat since the previous release: read them before you enter the key password. The signature
   goes to a temporary file, and only a signature by the key from `install.sh` gets into `dist/`.
   The trusted comment gets the signing date.
4. A check with the installer on your own build, without root and network:

   ```sh
   sh install.sh --dry-run --from-dir dist --harness-cmd '/usr/bin/true' --rw-paths '' --public-url '' --yes
   sh install.sh --uninstall --dry-run --from-dir dist   # uninstall.sh from the same verified build
   ```

5. On `main`, set `DAEMON_RELEASED` to `true` in `site/src/config.ts` (the site is built from `main`,
   not from the tag) and push it. Then
   `gh release upload daemon/v0.4.0 dist/checksums.txt.minisig && gh release edit daemon/v0.4.0 --draft=false --latest`.
   Publishing (the `release: released` event) starts the site deploy: `site-pages.yml` takes the new release's
   `install.sh`, checks it and publishes it at `https://<domain>/install.sh` (section
   ["GitHub Pages site"](#github-pages-site-and-installsh-from-the-site)). The try page stops saying
   there is no installer only after `DAEMON_RELEASED` is on `main`.
6. A few minutes later: `curl -fsSL https://wardenclaw.dev/install.sh | sha256sum` matches the
   `install.sh` line in `dist/checksums.txt`, and the `site-pages` run summary has the line
   `install.sh of daemon/v0.4.0, signed and checked (sha256 …)`.

Actions in `release-daemon.yml` are pinned by commit SHA (checkout v7.0.1, setup-go v7.0.0,
attest-build-provenance v4.2.2, upload-artifact v7.0.1 `043fb46d`, download-artifact v8.0.1
`3e5f45b2`; the SHAs were checked against the upstream tags with `git ls-remote` on 2026-09-28, the tags are
lightweight), default permissions are `{}`, each job has its own, `persist-credentials: false`, the branch and tag
get into commands only through environment variables. actionlint 1.7.7 reports nothing.

### GitHub Settings

The workflows and `CODEOWNERS` are in the repository, but they protect only together with the settings
the maintainer sets (the agent needs no rights to them):

1. **The `release` environment** (Settings → Environments), created **before the first tag**: if a job
   refers to a nonexistent environment, GitHub creates it itself, without rules. Required reviewers:
   the human maintainer; Deployment branches and tags: only `daemon/v*` tags. It holds no secrets.
2. **A tag ruleset** for `daemon/v*`, `app/v*`, `plugin/v*`: only the maintainer can create, change and delete
   them (bypass list), with no exceptions for apps and bots.
3. **A ruleset on `main`**: only via PR, required review by a code owner from `CODEOWNERS`, required
   status checks, no force-push and no deletion. The code owner in `CODEOWNERS` (`@xarvel`) must have write
   access to the repository, otherwise the rule silently requires no one; when moving to an organization,
   replace it with the maintainer's account or team. Required status checks are picked by job name.
   Require `dco` (`.github/workflows/dco.yml`, the sign-off check): it runs on every pull request. The
   component jobs (`test` in `daemon.yml`, `app.yml` and `plugin.yml`, `vulncheck` in `daemon.yml`,
   `vectors` in `protocol.yml`, `build` in `site.yml`) run only when their paths change, and three of them
   share the name `test`; a required check that never reports leaves the pull request unmergeable, so
   require them only after the jobs get unique names and a run on every pull request (a change to the
   workflows, not to the settings).
4. **Immutable releases**: after publishing, the release assets and tag do not change.
5. Actions → General → Workflow permissions: "Read repository contents and packages permissions", without
   "Allow GitHub Actions to create and approve pull requests".
6. **Private vulnerability reporting** (Settings → Code security): turn it on, then in one change set
   `PRIVATE_REPORTING = true` in `site/src/config.ts` and put the GitHub paragraph back into `SECURITY.md`
   (its text sits in the HTML comment there). Until then `SECURITY.md`, `/security/` and `security.txt` give
   the email only. On the same page: Dependabot alerts on; version updates come from `.github/dependabot.yml`
   once it is on `main` (weekly, grouped minor and patch, at most three open pull requests per ecosystem).
7. The agent's token (if it has one in this repository at all): fine-grained, without Workflows,
   Administration, Environments, Secrets and without rights to releases and tags.

## GitHub Pages site and `install.sh` from the site

The maintainer's choice (2026-09-28): the documentation site on GitHub Pages under its own domain, with the installer
served from the site itself:

```
curl -fsSL https://wardenclaw.dev/install.sh | sudo sh
```

There is no `get.` subdomain and no redirect: one domain, one distribution point, and neither a redirect rule nor
a Cloudflare Worker that would have to be kept outside the repository.

### How the deploy works

`.github/workflows/site-pages.yml`:

| event | what happens |
|---|---|
| push to `main` touching `site/**` or the workflow itself | build and deploy |
| a daemon release is published, unpublished or deleted (`release`: `released`, `unpublished`, `deleted`, tag `daemon/v*`) | job `on-release` reruns the workflow on the default branch (`gh workflow run`), then as on push |
| `workflow_dispatch` | the same, by hand |

Why a release does not deploy by itself. The `release` event runs the workflow as of the tag and with
the tag's `GITHUB_REF`, while the `github-pages` environment by default accepts deploys only from the default
branch. Besides, the site must be built from `main`, not from a snapshot as of the tag.
`workflow_dispatch` is one of the two events (the other is `repository_dispatch`) that `GITHUB_TOKEN`
can trigger, so `on-release`, with the single permission `actions: write`, only reruns the
workflow on `main`.

Job `build`, permissions `contents: read`:

1. checkout without persisting the token;
2. refusal if `site/src/config.ts` has the test minisign key (the `TEST KEY` marker or the key itself):
   a public site with the test key does not go out;
3. `minisign` from the Ubuntu packages;
4. `site/scripts/fetch-install-sh.sh`: `install.sh`, `checksums.txt` and `checksums.txt.minisig`
   of the release GitHub marks "latest", and the checks (below);
5. `npm ci`, `npm run build` (the same Astro build as in `site.yml`);
6. no `%KEY_NAME%` placeholders left in the HTML;
7. the checked `install.sh` is copied to `site/dist/install.sh`, its sha256 goes to the log;
8. the job fails if `site/dist/.well-known/security.txt` is missing;
9. `actions/upload-pages-artifact` with `include-hidden-files: true`. Without that flag the action
   drops every name starting with a dot, so `security.txt` never reached Pages. `.git` and `.github`
   stay excluded either way.

Job `deploy`, permissions `pages: write` and `id-token: write`, environment `github-pages`:
`actions/deploy-pages`. `concurrency: pages` without cancelling a run in progress: deploys go one at a time and
in order, and only the newest stays in the queue (it builds the same `main` and the same "latest", only
fresher). Runs on a release event do not join this queue, each has its own group: otherwise a release
of another component, with all its jobs skipped, would push a waiting deploy out of the queue.

Actions are pinned by commit SHA; the SHAs were checked against the upstream tags with `git ls-remote`
on 2026-09-28 (the tags are lightweight, so the tag SHA is the commit SHA): checkout v7.0.1 `3d3c42e5`, setup-node
v7.0.0 `82076278`, upload-pages-artifact v5.0.0 `fc324d35`, deploy-pages v5.0.1 `368f8252`.
Default permissions are `{}`, each job has its own.

### What `fetch-install-sh.sh` checks

`install.sh` reaches the site only if:

- `checksums.txt.minisig` verifies against `MINISIGN_PUBKEY` from `site/src/config.ts`, that is, the key
  the site shows in "Before you pipe into sudo". The key is taken from the repository, not from the
  release: a key from the same release would "confirm" anything;
- the signed comment is exactly `wardend <version from the tag> checksums.txt`;
- the sha256 of `install.sh` equals its line (exactly one) in the signed `checksums.txt`;
- the "Project identity" block of the downloaded script (read as text, not executed) matches the
  site: the same `MINISIGN_PUBKEY` and `DOMAIN`, `INSTALL_URL` expands to
  `https://<domain>/install.sh`, `GITHUB_REPO` is the repository the workflow runs in, and
  `RELEASES_URL` expands to `https://github.com/<this repository>/releases`. Otherwise the
  installer from the site would expect another key or download from another repository, and the docs
  would name the wrong key;
- "latest" is a daemon release (`daemon/vX.Y.Z`): the installer downloads the archives from
  `releases/latest` specifically, and a "latest" of another component breaks installs for everyone.

Before it even gets to the release, the script checks `GITHUB_REPO` from `src/config.ts` against the
workflow's repository: otherwise the site's links to the releases and the repository, including in the manual check, would point elsewhere.

No published release (`releases/latest` answers 404): the site is built and goes out without
`install.sh`, the run writes a warning to an annotation and to the summary, `https://<domain>/install.sh`
answers 404. Any other error (missing asset, signature, checksum, version, identity, API failure) fails
`build`, `deploy` does not run, and the previous site with the previous `install.sh` stays online.

### Why `install.sh` on the site is a copy of the release, not separate code

- The file is not built from the tree: the workflow does not take `daemon/install.sh` from `main`. What reaches the site
  is the published release's asset, byte for byte, and only after its offline-key signature is verified.
  A change to the installer in `main` does not reach users until it is released and signed.
- The copy's checksum is in the release's signed `checksums.txt`, so anyone can check that the site
  serves the signed file. That is what the "Before you pipe into sudo" block does: the script from the site, the checksums and
  the signature from GitHub, two different sources.
- There is one source of truth, the release. The site mirrors it and replaces the copy on every publication;
  the copy has no edits of its own and can differ from the release only while a deploy is in progress.
- The command leads to the same version as `releases/latest/download/install.sh`: the site takes
  "latest", the installer downloads the archives from "latest".
- Substituting just the `install.sh` asset in a release (a token with rights to releases but not to change `main`)
  does not reach the site: the checksum will not match the signed one. With a redirect to the asset, as planned
  earlier for `get.<domain>`, such a substitution would go straight to everyone who pipes.

Delay. After a release is published, the site updates within a few minutes (build, deploy, up to 10
minutes of Pages cache). In this window the site serves the previous release's `install.sh`, which installs the new release:
it downloads "latest" and checks it the same way. A manual check in this window shows `FAILED` from `sha256sum`;
the docs warn about this.

Key rotation. The new key goes into `install.sh` and `src/config.ts` in one commit. Until a
release signed with the new key is published, the site deploy fails at the signature check and the
previous site stays online. This is intended: once that release is published, the deploy goes through by itself.

### Domain

- `site/public/CNAME` contains `wardenclaw.dev`, the `site` field in `astro.config.mjs` is
  `https://wardenclaw.dev` (canonical links). Both come from `DOMAIN` in
  `src/config.ts`, and the build checks CNAME against it.
- When deploying through Actions, Pages **does not read** the CNAME file (GitHub docs: when publishing
  with a custom workflow "any existing CNAME file is ignored and is not required"). The custom domain
  `wardenclaw.dev` is set on the repository; `www` redirects to the apex. The file stays so a publish
  from a branch would match.
- Apex DNS (GitHub Pages, set 2026-09-28, after the domain was verified on the personal account):
  A `185.199.108.153`, `185.199.109.153`, `185.199.110.153`, `185.199.111.153` and
  AAAA `2606:50c0:8000::153` … `2606:50c0:8003::153`, no wildcard records. `.dev` is HSTS-preloaded,
  so the site is HTTPS only. CAA allows only Let's Encrypt (Pages gets its certificates from it).

### What is left before publishing (by the maintainer, by hand)

The repository `xarvel/WardenClaw` is public, Pages serves `https://wardenclaw.dev`, the release key
and the tag-signing key are in the tree. Still by hand:

1. Turn on private vulnerability reporting (Settings → Code security). The API reported
   `enabled: false` on 2026-09-29, so `PRIVATE_REPORTING` in `site/src/config.ts` stays false and
   neither `security.txt` nor `/security/` links to the advisory form. Set the constant to `true`
   in the same change. Do not give the agent on the Pi write access to this repository: the `gh`
   token on the Pi (the agent's separate account) is invalid as of Sep 28; leave it that way.
2. The `release` environment and the rulesets (section "GitHub Settings").
3. The first daemon release, following "Release process", including `DAEMON_RELEASED = true` on `main`.
   Publishing puts `install.sh` on the site. Until then the site goes out without the installer, and the run says so.
4. Step 6 of the release process: the checksum of `install.sh` from the site against its line in the release's `checksums.txt`.

Rejected options:

- A redirect from `get.<domain>` to `releases/latest/download/install.sh` (the earlier plan): a second host at
  Cloudflare, and a tampered release asset goes straight to those who pipe, with no signature check.
- `raw.githubusercontent.com/<owner>/<repo>/<tag>/install.sh`: only with a tag, not `main`. With `main`
  any merged commit immediately becomes code running as root on other people's machines.
- Building `install.sh` for the site from the `main` tree: the same problem, plus the file on the site no longer
  matches the signed release.

## Tampering risk and what the signature covers

`curl … | sudo sh` runs the script **before** any check. The integrity of `install.sh` itself on this
path rests on TLS, on the domain's DNS and on GitHub, from which the workflow publishes the site. The signature does not
change that, and the docs say so honestly.

What the signature covers:

| attack | without a signature | with a minisign signature (offline key) |
|---|---|---|
| an archive in the release substituted (hijacked GitHub account or token, malicious workflow) | installs | refused: sha256 does not match the signed `checksums.txt` |
| the archive and `checksums.txt` substituted together | installs | refused: the signature does not verify |
| compromised CI builds a backdoor | installs | not signed: the maintainer's build will not match CI's |
| mirror, cache, proxy, `--from-dir` with someone else's files | installs | refused |
| rollback: an old vulnerable release passed off as `--version vX` | installs | refused: the version is in the signed comment |
| rollback or freeze: "latest" points to an old signed release | installs | refused on an installed system (version older than the installed one, without `--allow-downgrade`); a new install gets a warning if the signature is older than 180 days |
| a release with its own key: GitHub takeover, a new key in the release's `install.sh` and on the site | installs | an install pinned to the key refuses (no statement from the old key), and so does an upgrade with the installed copy; a new install from the pipe installs (last row) |
| a release signed with the test key (its secret is on a development machine) | installs | neither built nor signed (`release.sh`, `sign-release.sh`, CI); an installer with the test key installs nothing from the network |
| only the `install.sh` asset substituted in a release (a token with rights to releases) | installs | does not reach the site: the deploy checks the file against the signed checksums. Installs only for those who download `releases/latest/download/install.sh` directly |
| **`install.sh` itself** substituted on the site (GitHub with rights to change the workflow in `main`, the domain's DNS) | installs | **installs** for those who pipe: a tampered script simply does not check |

The last row is the residual risk. It is reduced by:

- **the "Before you pipe into sudo" block** in the docs: download `install.sh` from the site, and
  `checksums.txt` and `.minisig` from GitHub, verify the signature with the key, read the script, run it;
  each step only after the previous one succeeds (an `&&` chain). The check is only as good as the
  key in it: the site, the README and the release notes can all be tampered with through one GitHub access, so
  the docs ask to compare the key with the TXT record in the domain's DNS;
- **key pinning** on installed systems and upgrades with the installed copy: for an already
  installed wardend, a tampered site no longer decides what gets installed (section "Key pinning");
- a small, readable POSIX script: tampering shows up in a diff;
- one source of truth, the signed release: the site serves its copy, published only after the signature
  check, and builds nothing itself (section "GitHub Pages site");
- protection of `main` and review of changes in `.github/` and `site/scripts/`: whoever changes the deploy workflow
  also changes what goes to the site;
- protection against truncation: the whole body is in functions, `main "$@"` is the last line, a partially downloaded script is not
  executed (checked: a truncated file gives a syntax error and does nothing).

Bottom line: without a signature it is enough to tamper with any one of the release files; with a signature, for users who
pipe, one target is left (the text of `install.sh` on the site, that is, the Pages deploy or DNS), and
for those who verify nothing is left except the offline key.

## Work log: GitHub Pages site and `install.sh` from the site (2026-09-28)

Done (commits `3b27315`, `d753a36`, `497ccb1`, `660c256` and the commit with this log):

- Install address `https://wardenclaw.dev/install.sh` instead of `https://get.wardenclaw.dev`:
  `INSTALL_URL` in the "Project identity" block of `install.sh` and `uninstall.sh`, the site's `src/config.ts`
  (`SITE_URL` and `INSTALL_URL` derived from `DOMAIN`); the docs placeholders are the same. `install.sh`
  gained `RELEASES_URL` (`https://github.com/${GITHUB_REPO}/releases`): archives and checksums come, as
  before, from GitHub. The download URLs were checked with a stub `curl`; they are the same as before the change
  (`releases/latest/download/…`, `releases/download/daemon%2Fv1.2.3/…`).
- `.github/workflows/site-pages.yml`, `site/scripts/fetch-install-sh.sh`, `site/public/CNAME`,
  `site` in `astro.config.mjs` and the CNAME check against `DOMAIN` at build time.
- Docs: README, `daemon/README.md`, `daemon/docs/CLI.md`, `site/src/docs/install.en.md`.
  The "Before you pipe into sudo" block became a single `&&` chain with `--proto '=https' --tlsv1.2`
  (finding V1 of the supply chain review: before, the block still reached `sudo sh` after a `minisign` error); in
  `daemon/README.md` the tag form for a specific version was fixed (`daemon%2FvX.Y.Z`).

Checked on the Pi (clone in `/srv/scratch/pages-build`; minisign 0.12 from the Debian package, unpacked
into the same place without installing; test key):

- `sh -n`, `bash -n`, `dash -n` for `install.sh`, `uninstall.sh`, `fetch-install-sh.sh`,
  `release.sh`; the workflow YAML through `yaml.safe_load` (no yamllint on the Pi), all `uses:` pinned
  to a 40-character SHA, no `${{ }}` expressions in `run:`;
- site build (`npm ci`, `npm run build`, 16 pages): no placeholders in the HTML, `get.wardenclaw`
  nowhere, `https://wardenclaw.dev/install.sh` on the landing page and in the docs, `dist/CNAME` is
  `wardenclaw.dev`, canonical `https://wardenclaw.dev/…`;
- `release.sh --snapshot` (Go 1.26.8, the `install.sh`/`uninstall.sh` identity comparison passed) and signing by
  `sign-release.sh` with the test key; `install.sh --dry-run --from-dir` accepts the snapshot both via
  minisign and via OpenSSL;
- `fetch-install-sh.sh`: a good release is copied byte for byte. Refusal with a clear message and without
  writing the file for 14 broken ones: no `.minisig`; only the script; a foreign key; a modified script;
  modified checksums; the wrong version in the signed comment; rollback (a release under another tag);
  "latest" is not a daemon release; `install.sh` twice in the checksums; `GITHUB_REPO` as a placeholder; another key in the
  script; the old `get.` address; `RELEASES_URL` pointing to a mirror; another domain. `install.sh` from the tree
  with the `OWNER/REPO` placeholder (as it was before Sep 28) is rejected too. Without a release: exit 0, a warning, no file; in Actions mode, annotations
  `::warning`/`::error` and a line in the summary;
- the manual check block taken from the built page (downloads replaced with copies, `less` and
  `sudo` with `echo`): a good file gets as far as running; a file tampered with on the site, one a release behind, and
  a script substituted together with the checksums under the old signature all stop before `less`;
- workflow steps (checked while `src/config.ts` still held the test key): the test-key guard fired,
  `install.sh` landed in `dist/`, the tar contained `CNAME` and `install.sh`, a local HTTP server served
  `/install.sh` with the release checksum. That tar excluded dot names; the workflow now sets
  `include-hidden-files: true` and fails the job if `dist/.well-known/security.txt` is missing.

The Pages deploy has run on this repository: `https://wardenclaw.dev` is served from it, and
without a daemon release `install.sh` answers 404. Not run here yet: `release-daemon.yml` (there
is no `daemon/v*` tag), `apt-get install minisign` on that runner, and the `on-release` rerun.
