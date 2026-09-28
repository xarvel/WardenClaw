// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// collect builds an execEvent from a notification. The target process is stopped inside the
// syscall at this point; its memory is read via /proc/<tid>/mem (ptrace access: same uid,
// descendant of the supervisor).
func collect(n *seccompNotif, supervisorPid int) *execEvent {
	ev := &execEvent{ID: n.ID, Pid: int(n.Pid)}
	pid := ev.Pid
	var errs []string
	fail := func(what string, err error) { errs = append(errs, what+": "+err.Error()) }

	if _, _, _, _, ok := procStat(pid); !ok {
		fail("stat", errors.New("no such process"))
	}
	ev.Tgid = pid
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "Tgid:"); ok {
				ev.Tgid, _ = strconv.Atoi(strings.TrimSpace(v))
			}
		}
	}
	ev.PPid, ev.Start, _, ev.Threads, _ = procStat(ev.Tgid)
	ev.UID, ev.GID = procIDs(pid)
	ev.CallerExe = procExe(ev.Tgid)
	ev.CallerCmd, _ = procCmdline(ev.Tgid)
	if s, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
		ev.Cwd = s
	} else {
		fail("cwd", err)
	}
	ev.Chain = chainOf(ev.Tgid, supervisorPid)
	// caller's mount namespace: a mismatch with the supervisor's ns means the path resolves in a
	// namespace other than the one where the kernel will execute the file (see resolveTarget and
	// decide1).
	if s, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", pid)); err == nil {
		ev.MntNs = s
	}

	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		fail("mem", err)
		ev.ReadError = strings.Join(errs, "; ")
		return ev
	}
	defer mem.Close()

	var pathAddr, argvAddr, envpAddr uint64
	a := n.Data.Args
	switch n.Data.Nr {
	case unix.SYS_EXECVE:
		ev.Syscall = "execve"
		pathAddr, argvAddr, envpAddr = a[0], a[1], a[2]
	case unix.SYS_EXECVEAT:
		ev.Syscall = "execveat"
		pathAddr, argvAddr, envpAddr = a[1], a[2], a[3]
	default:
		ev.Syscall = fmt.Sprintf("nr=%d", n.Data.Nr)
	}

	if p, err := readCString(mem, pathAddr); err == nil {
		ev.Path = p
	} else {
		fail("path", err)
	}
	resolveBase := ev.Cwd
	if n.Data.Nr == unix.SYS_EXECVEAT {
		dirfd := int32(a[0])
		flags := a[4]
		if ev.Path == "" && flags&unix.AT_EMPTY_PATH != 0 {
			// fexecve(): path = the dirfd itself
			if s, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd)); err == nil {
				ev.Path = s
			} else {
				fail("dirfd", err)
			}
		} else if !filepath.IsAbs(ev.Path) && dirfd != unix.AT_FDCWD {
			if s, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd)); err == nil {
				resolveBase = s
			} else {
				fail("dirfd", err)
			}
		}
	}
	if v, err := readStrArray(mem, argvAddr); err == nil {
		ev.Argv, ev.ArgvOK = v, true
	} else {
		ev.Argv = v
		fail("argv", err)
	}
	if v, err := readStrArray(mem, envpAddr); err == nil {
		ev.EnvHash = envHash(v)
		ev.EnvCount = len(v)
		ev.Env = envelope.SelectEnv(v)
	} else {
		fail("envp", err)
	}
	resolveTarget(ev, resolveBase)
	ev.ReadError = strings.Join(errs, "; ")
	return ev
}
