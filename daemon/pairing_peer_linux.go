// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

import "os"

// peerSupervised reports whether the socket's client process runs under this wardend's seccomp
// filter (the agent, the gateway and their descendants): it has more filters than the supervisor
// itself, or it descends from the supervisor's child. A /proc read error counts as "under the
// filter" (fail-closed).
func (s *supervisor) peerSupervised(pid int) bool {
	if pid <= 0 {
		return true
	}
	own, ok1 := seccompFilters(os.Getpid())
	peer, ok2 := seccompFilters(pid)
	if !ok1 || !ok2 || peer > own {
		return true
	}
	return underChild(pid, s.childPid, ppidOf)
}
