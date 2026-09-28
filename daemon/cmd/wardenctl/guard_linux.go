// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func procStatus(pid int, key string) (string, bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return "", false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, key+":"); ok {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

// isWardend: the process's exe, comm or argv[0] is named wardend.
func isWardend(pid int) (string, bool) {
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		if filepath.Base(strings.TrimSuffix(exe, " (deleted)")) == "wardend" {
			return exe, true
		}
	}
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil && strings.TrimSpace(string(b)) == "wardend" {
		return "wardend", true
	}
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		a0, _, _ := strings.Cut(string(b), "\x00")
		if filepath.Base(a0) == "wardend" {
			return a0, true
		}
	}
	return "", false
}

const (
	maxAncestors    = 256 // how far up the parent chain to look for wardend
	maxWardendProcs = 3   // how many wardend processes the refusal names
	seccompFilter   = "2" // the Seccomp mode in /proc/<pid>/status for a filter (SECCOMP_MODE_FILTER)
)

func platformProbe() guardProbe {
	return guardProbe{
		SelfFiltered: func() (bool, string) {
			mode, _ := procStatus(os.Getpid(), "Seccomp")
			n, _ := procStatus(os.Getpid(), "Seccomp_filters")
			return mode == seccompFilter, "Seccomp: " + mode + ", filters: " + n
		},
		WardendAncestor: func() (string, bool) {
			cur := os.Getppid()
			for i := 0; i < maxAncestors && cur > 1; i++ {
				if exe, ok := isWardend(cur); ok {
					return fmt.Sprintf("pid %d %s", cur, exe), true
				}
				v, ok := procStatus(cur, "PPid")
				if !ok {
					break
				}
				n, err := strconv.Atoi(v)
				if err != nil {
					break
				}
				cur = n
			}
			return "", false
		},
		WardendProcs: func() []string {
			ents, err := os.ReadDir("/proc")
			if err != nil {
				return nil
			}
			uid := strconv.Itoa(os.Getuid())
			var out []string
			for _, e := range ents {
				pid, err := strconv.Atoi(e.Name())
				if err != nil || pid == os.Getpid() {
					continue
				}
				u, ok := procStatus(pid, "Uid")
				if f := strings.Fields(u); !ok || len(f) == 0 || f[0] != uid {
					continue
				}
				if exe, ok := isWardend(pid); ok {
					out = append(out, fmt.Sprintf("pid %d %s", pid, exe))
				}
				if len(out) >= maxWardendProcs {
					break
				}
			}
			return out
		},
	}
}
