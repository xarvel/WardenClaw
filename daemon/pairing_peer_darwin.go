// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin

package main

// peerSupervised reports whether the socket's client process is in the supervised tree as the
// Endpoint Security gate sees it (supervisor_darwin.go). The socket itself admits only wardend's
// own uid (rpc.go peerAllowed, LOCAL_PEERCRED), and the command runs as another user, so a
// supervised peer here would be a root process inside the tree. A process that cannot be read
// counts as supervised (fail-closed).
func (s *supervisor) peerSupervised(pid int) bool {
	if pid <= 0 {
		return true
	}
	g := currentGate()
	if g == nil {
		return underChild(pid, s.childPid, ppidOf)
	}
	ppid, _, _, _, ok := procStat(pid)
	if !ok {
		return true
	}
	return g.member(pid, ppid)
}
