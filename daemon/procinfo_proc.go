// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !darwin

package main

// Process facts from /proc: ppid, starttime, state, ids, exe, cmdline, the ancestor chain.
// procinfo_darwin.go has the sysctl versions.

import (
	"bytes"
	"os"
	"strconv"
	"strings"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// procStat: ppid, starttime, state, threads from /proc/<pid>/stat.
func procStat(pid int) (ppid int, start uint64, state byte, threads int, ok bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, 0, 0, false
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 || i+2 >= len(b) {
		return 0, 0, 0, 0, false
	}
	f := strings.Fields(string(b[i+2:]))
	if len(f) < 20 {
		return 0, 0, 0, 0, false
	}
	// f[0]=state(3) f[1]=ppid(4) … f[17]=num_threads(20) f[19]=starttime(22)
	ppid, _ = strconv.Atoi(f[1])
	threads, _ = strconv.Atoi(f[17])
	start, _ = strconv.ParseUint(f[19], 10, 64)
	return ppid, start, f[0][0], threads, true
}

func procIDs(pid int) (uid, gid int) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return -1, -1
	}
	uid, gid = -1, -1
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Uid:"); ok {
			if f := strings.Fields(v); len(f) > 1 {
				uid, _ = strconv.Atoi(f[1])
			}
		} else if v, ok := strings.CutPrefix(line, "Gid:"); ok {
			if f := strings.Fields(v); len(f) > 1 {
				gid, _ = strconv.Atoi(f[1])
			}
		}
	}
	return
}

func procExe(pid int) string {
	s, _ := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	return s
}

func procCmdline(pid int) ([]string, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return []string{}, nil
	}
	b = bytes.TrimSuffix(b, []byte{0})
	return strings.Split(string(b), "\x00"), nil
}

// chainOf: [pid, ppid, …] up to stopAt (exclusive) or init, at most maxChainDepth deep.
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
