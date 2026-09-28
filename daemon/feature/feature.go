// SPDX-License-Identifier: AGPL-3.0-or-later

// Package feature holds flags that are compiled in only with a build tag. One place for the whole
// module: wardend and wardenctl both import this, so a single tag enables a feature in both
// binaries at once.
//
// HWKey: second factor (FIDO2 hardware keys, YubiKey): wardend hw-register/hw-keys,
// hardware_keys in config, require_hardware in policy, key touch in wardenctl approve/watch.
// Not included in the first release: scripts/release.sh and CI build without the tag.
// To enable: go build -tags hwkey (docs/hwkey.md). Tag rather than a config variable: the FIDO
// code (libfido2 CLI utilities in wardenctl, registration parsing in wardend hw-register) is
// excluded from the release binary entirely, while go test -tags hwkey ./... keeps it built and
// verified.
package feature

// HWKeyOff is the message returned by a build without the tag when the user requests a second factor.
const HWKeyOff = "second factor (FIDO2 hardware keys, YubiKey) is not included in this release; build with the tag: go build -tags hwkey (docs/hwkey.md)"
