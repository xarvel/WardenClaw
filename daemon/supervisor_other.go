// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux && !darwin

package main

// The exec gate exists on Linux (seccomp user notification, supervisor_linux.go) and macOS
// (Endpoint Security, supervisor_darwin.go). This build keeps the rest of wardend (config, policy,
// journal, pairing, relay, the client commands) and refuses to supervise anything instead of
// letting commands through unobserved: fail-closed.

import "errors"

// errGateUnsupported: the answer of every entry point that would need a gate.
var errGateUnsupported = errors.New("wardend: no exec gate on this OS (Linux and macOS are supported)")

// runSupervisor: nothing is started; the command is not run at all.
func runSupervisor(cfg *Config, o *runOpts) (int, error) {
	return 2, errGateUnsupported
}
