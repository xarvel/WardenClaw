// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin

package main

// rootExecSocketRoot is the rootexec socket of a root wardend on macOS (/var/run is launchd's
// runtime directory; /run does not exist).
const rootExecSocketRoot = "/var/run/wardend/rootexec.sock"

// pinnedExecPath: macOS has no fexecve(2), but execve of a /dev/fd node runs the file behind the
// open descriptor; fd 3 of the child is the pinned file (rootexec.go serve).
func pinnedExecPath() string { return "/dev/fd/3" }

// peerUnderGate: "" if pid is a member of the supervised tree as the Endpoint Security gate sees
// it (supervisor_darwin.go: the fork/exit tree rooted at the supervised command; an orphan of the
// tree stays a member) and runs as the child user, else why not. Every read error counts as "not
// under the gate".
func (s *supervisor) peerUnderGate(pid int) string {
	if s.childPid <= 0 {
		return "the supervised command has not started"
	}
	g := currentGate()
	if g == nil {
		return "the exec gate is not running"
	}
	ppid, _, _, _, ok := procStat(pid)
	if !ok {
		return "cannot read the process"
	}
	if !g.member(pid, ppid) {
		return "not a descendant of the supervised command"
	}
	if uid, _ := procIDs(pid); uid != g.childUID() {
		return "not running as the child user"
	}
	return ""
}
