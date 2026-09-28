# Second factor (YubiKey): not in the first release, how to bring it back

The second factor (FIDO2 hardware keys, YubiKey) is not included in the first release. The code is
not cut out: it builds with the Go tag `hwkey`, its tests run in CI (`daemon.yml`, step
"Test with the second factor"), and the protocol of the second signature is described in
[protocol/HARDWARE.md](../../protocol/HARDWARE.md).

What the second signature proves, and what it does not: the key signs a `clientDataHash` that the
phone assembles (`hwkey/webauthn.go` verifies it against the ticket), and the key has no screen. A
touch proves that a person was at the key when the phone asked, not that the person saw this card.
A compromised phone can show card A and send the key a challenge for ticket B. Binding the touch to
what the person saw needs Android Protected Confirmation or a second device with its own display
(`wardenctl` on another machine). That is one more reason the feature stays out of the first
release.

## What is hidden

| Where | With the `hwkey` tag | Without the tag (release) |
|---|---|---|
| `wardend hw-register`, `wardend hw-keys` | work (`hwcmd.go`) | not in the help, answer "is not included in this release", exit code 2 (`hwcmd_off.go`) |
| `hardware_keys` in the config, `require_hardware` in the policy | take effect | `wardend run` doesn't start (exit code 2) and names the field: a silently dropped rule would leave a person sure that a root is approved only with a key touch (`hwfeature.go`) |
| `status` (socket and relay), the journal `start` record | `hardwareKeys`, `requireHardwareRules`, `requireHardware` | these fields are absent |
| a decision with the `hw` field | verified | no keys, rejected with `hardware_not_configured` |
| `wardenctl approve`, `watch` | allow with a YubiKey touch by default, `--no-hw`, `--uv`, `--device` | allow is signed with the device key; the flags are not in the help, answer "is not included in this release", exit code 2 |
| `wardenctl hw-register`, `hw-check`, the YubiKey line in `status` | present (`cmd/wardenctl/hwcmd.go`, `fido.go`) | not in the help, answer "is not included in this release", exit code 2 (`cmd/wardenctl/hw_off.go`); the FIDO code doesn't get into the binary |
| plugin: the `hw` field of a decision | the form is validated, the body goes to wardend | rejected with `hw_not_in_release` (`plugin/src/features.js`, `HARDWARE_KEY = false`) |

One switch for the whole module: `feature.HWKey` in `daemon/feature` (`hwkey_on.go` with the tag,
`hwkey_off.go` without it), used by wardend and wardenctl. The `hwkey` package (parsing and
verifying an assertion) is always built: the ticket format in `envelope` refers to its `Assertion`
type.

Why a tag and not a config key: the release binary has no FIDO commands or code, and a person can't
"turn on" a feature that nobody has tested in this build; bringing it back takes one line.

## How to bring it back

1. Release: in `daemon/scripts/release.sh` the line `TAGS=""` → `TAGS="hwkey"` (both binaries, all
   archives). Locally: `go build -tags hwkey .` and `go build -tags hwkey ./cmd/wardenctl`; in
   `cmd/wardenctl/build.sh` add `-tags hwkey` to `go build`.
2. Plugin: `plugin/src/features.js`, `HARDWARE_KEY = true`.
3. Site: `site/src/config.ts`, `FEATURES.hardwareKey = true` (and the README per `README_FEATURES`,
   see `site/README.md`, section "Features left out of a release").
4. Docs: remove the "Not in the first release" notes (`grep -rn 'hwkey.md' daemon plugin protocol`).
5. Check: `go vet -tags hwkey ./...`, `go test -tags hwkey -p 1 ./...` (the wardenctl e2e builds the
   binaries with the same tag), in the plugin `npm test` (the `hardware.test.js` tests stop being
   skipped).

When the feature goes into every build, the tag can be removed altogether: drop `//go:build hwkey`
from `hwcmd.go`, `cmd/wardenctl/hwcmd.go`, `cmd/wardenctl/fido.go`, `cmd/wardenctl/fido_test.go`,
delete `hwcmd_off.go`, `cmd/wardenctl/hw_off.go`, `feature/`, the `feature.HWKey` and `hwText`
branches (`grep -rn 'feature\.' --include=*.go`), the CI step "Test with the second factor" and
`TAGS` in release.sh.
