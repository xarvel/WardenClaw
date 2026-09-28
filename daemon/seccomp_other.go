// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package main

import "errors"

// errGateLinuxOnly: the seccomp filter exists on Linux only; on macOS the gate is Endpoint
// Security in wardend itself and __child is not used (main.go).
var errGateLinuxOnly = errors.New("wardend: the seccomp gate is Linux-only; this build has no filter to install")

// installFilter: the helper child (childMain) stops here before exec: without a filter nothing
// may run under wardend.
func installFilter(waitKillable bool) (int, error) {
	return -1, errGateLinuxOnly
}
