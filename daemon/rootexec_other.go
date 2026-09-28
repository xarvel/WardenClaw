// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux && !darwin

package main

// rootExecSocketRoot: the Linux location, so that the client's help names a path.
const rootExecSocketRoot = "/run/wardend/rootexec.sock"

// pinnedExecPath: no way to exec an open descriptor is known for this OS; startRootExec refuses
// to listen (rootexec.go).
func pinnedExecPath() string { return "" }

// peerUnderGate: there is no exec gate on this build, so nobody is under it.
func (s *supervisor) peerUnderGate(pid int) string { return "no exec gate on this build" }
