// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin

package main

// Process facts on macOS, pure Go through sysctl (no cgo): kern.proc.pid for ppid, start time,
// state and credentials; kern.procargs2 for the executable path and argv. kern.procargs2 of
// another user's process is readable by root only; wardend runs as root on macOS (Endpoint
// Security). Compiles under GOOS=darwin; not yet exercised on hardware.

import (
	"bytes"
	"errors"

	"golang.org/x/sys/unix"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// p_stat values of struct extern_proc (sys/proc.h).
const (
	darwinSSTOP = 4
	darwinSZOMB = 5
)

// procStat: ppid, start time (µs since the epoch), state ('R', 'T' stopped, 'Z' zombie) and the
// thread count from kern.proc.pid. The thread count is not in kinfo_proc: reported as 1.
func procStat(pid int) (ppid int, start uint64, state byte, threads int, ok bool) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp.Proc.P_pid != int32(pid) {
		return 0, 0, 0, 0, false
	}
	ppid = int(kp.Eproc.Ppid)
	start = uint64(kp.Proc.P_starttime.Sec)*1_000_000 + uint64(kp.Proc.P_starttime.Usec)
	state = 'R'
	switch kp.Proc.P_stat {
	case darwinSSTOP:
		state = 'T'
	case darwinSZOMB:
		state = 'Z'
	}
	return ppid, start, state, 1, true
}

// procIDs: effective uid and gid (Eproc.Ucred; Pcred holds the real and saved ids).
func procIDs(pid int) (uid, gid int) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp.Proc.P_pid != int32(pid) {
		return -1, -1
	}
	uid, gid = int(kp.Eproc.Ucred.Uid), -1
	if kp.Eproc.Ucred.Ngroups > 0 {
		gid = int(kp.Eproc.Ucred.Groups[0])
	}
	return uid, gid
}

// procArgs reads kern.procargs2: int32 argc, the executable path NUL-terminated, NUL padding,
// then argc argv strings NUL-separated (the environment follows; not returned).
func procArgs(pid int) (exe string, argv []string, err error) {
	b, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", nil, err
	}
	if len(b) < 4 {
		return "", nil, errors.New("procargs2: short read")
	}
	argc := int(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24)
	rest := b[4:]
	i := bytes.IndexByte(rest, 0)
	if i < 0 {
		return "", nil, errors.New("procargs2: no executable path")
	}
	exe, rest = string(rest[:i]), rest[i+1:]
	rest = bytes.TrimLeft(rest, "\x00")
	argv = []string{}
	for len(argv) < argc && len(argv) < maxArr && len(rest) > 0 {
		j := bytes.IndexByte(rest, 0)
		if j < 0 {
			argv = append(argv, string(rest))
			break
		}
		argv = append(argv, string(rest[:j]))
		rest = rest[j+1:]
	}
	if len(argv) < argc {
		return exe, argv, errors.New("procargs2: argv shorter than argc")
	}
	return exe, argv, nil
}

func procExe(pid int) string {
	exe, _, _ := procArgs(pid)
	return exe
}

func procCmdline(pid int) ([]string, error) {
	_, argv, err := procArgs(pid)
	if err != nil {
		return nil, err
	}
	return argv, nil
}

// chainOf: [pid, ppid, …] up to stopAt (exclusive) or launchd, at most maxChainDepth deep.
func chainOf(pid, stopAt int) []envelope.Link {
	var out []envelope.Link
	for p := pid; p > 1 && p != stopAt && len(out) < maxChainDepth; {
		out = append(out, envelope.Link{Pid: p, Exe: procExe(p)})
		pp, _, _, _, ok := procStat(p)
		if !ok || pp == p {
			break
		}
		p = pp
	}
	return out
}
