// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

import "os"

// rootExecSocketRoot is the rootexec socket of a root wardend: RuntimeDirectory=wardend in the unit.
const rootExecSocketRoot = "/run/wardend/rootexec.sock"

// pinnedExecPath: the path the approved command is exec'd through; fd 3 of the child is the open
// descriptor of the pinned file (rootexec.go serve).
func pinnedExecPath() string { return "/proc/self/fd/3" }

// peerUnderGate: "" if pid is under this wardend's filter and descends from the supervised
// command (or is an orphan of the tree re-parented to wardend), else why not. Every read error
// counts as "not under the gate".
func (s *supervisor) peerUnderGate(pid int) string {
	own, ok1 := seccompFilters(os.Getpid())
	peer, ok2 := seccompFilters(pid)
	if !ok1 || !ok2 {
		return "cannot read the seccomp filter count"
	}
	if peer <= own {
		return "not under the wardend filter"
	}
	if s.childPid <= 0 {
		return "the supervised command has not started"
	}
	cur := pid
	for i := 0; i < maxAncestors && cur > 1; i++ {
		if cur == s.childPid || cur == s.supPid {
			return ""
		}
		pp, ok := ppidOf(cur)
		if !ok {
			return "cannot read the parent chain"
		}
		cur = pp
	}
	return "not a descendant of the supervised command"
}
