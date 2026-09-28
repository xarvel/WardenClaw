// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

// The post-check itself: SIGSTOP on the calling thread, /proc polling of the new image, the kill.

import (
	"slices"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// armStop: before CONTINUE, SIGSTOP to the calling thread specifically.
func armStop(tgid, tid int) error { return unix.Tgkill(tgid, tid, unix.SIGSTOP) }

const (
	pollDeadline = 50 * time.Millisecond // poll mode: how long to watch for the new image
	stopDeadline = 3 * time.Second       // stop mode: how long to wait for the stop
	verifyTick   = 50 * time.Microsecond // /proc polling interval
)

// signalProc: through the pidfd when there is one (no race with pid reuse), otherwise by pid.
func signalProc(pidfd, tgid int, sig unix.Signal) {
	if pidfd >= 0 {
		_ = unix.PidfdSendSignal(pidfd, sig, nil, 0)
	} else {
		_ = unix.Kill(tgid, sig)
	}
}

// verifyExec: after CONTINUE. pidfd (if ≥0) is for SIGKILL without a race with pid reuse.
func verifyExec(mode toctouMode, tgid, pidfd int, x expectation) toctouResult {
	t0 := time.Now()
	res := toctouResult{Mode: string(mode)}
	kill := func() { signalProc(pidfd, tgid, unix.SIGKILL) }
	cont := func() { signalProc(pidfd, tgid, unix.SIGCONT) }
	deadline := pollDeadline
	if mode == toctouStop {
		deadline = stopDeadline
	}
	observed := false
	for {
		_, _, state, _, ok := procStat(tgid)
		if !ok || state == 'Z' || state == 'X' {
			res.Outcome, res.WaitUs = "gone", time.Since(t0).Microseconds()
			return res
		}
		if mode == toctouStop {
			if state == 'T' || state == 't' {
				observed = true
				break
			}
		} else {
			exe := procExe(tgid)
			cmd, _ := procCmdline(tgid)
			if exe != x.oldExe || !slices.Equal(cmd, x.oldArgv) {
				observed = true
				break
			}
		}
		if time.Since(t0) > deadline {
			break
		}
		time.Sleep(verifyTick)
	}
	res.GotExe = procExe(tgid)
	res.GotArgv, _ = procCmdline(tgid)
	res.WaitUs = time.Since(t0).Microseconds()
	match := res.GotExe == x.exe && slices.Equal(res.GotArgv, x.argv)
	if match && x.ino != 0 {
		var st unix.Stat_t
		if err := unix.Stat("/proc/"+strconv.Itoa(tgid)+"/exe", &st); err == nil && (st.Dev != x.dev || st.Ino != x.ino) {
			match = false
			res.Detail = "exe inode differs (file swapped after decision)"
		}
	}
	switch {
	case match:
		res.Outcome = "match"
		if !observed {
			res.Outcome = "match_unobserved"
		}
		if mode == toctouStop {
			cont()
		}
	case res.GotExe == x.oldExe && slices.Equal(res.GotArgv, x.oldArgv):
		// the image did not change: execve returned an error (or had not happened yet in poll mode)
		res.Outcome = "exec_failed"
		if !observed {
			res.Outcome = "not_observed"
		}
		if mode == toctouStop {
			cont()
		}
	default:
		kill()
		res.Outcome = "mismatch_killed"
		cont() // SIGKILL finishes it anyway; SIGCONT in case of a race with stop
	}
	return res
}
