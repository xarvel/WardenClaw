// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// TOCTOU post-check: argv/filename are read from the caller's memory BEFORE the reply to the
// kernel, while the kernel copies them again only AFTER CONTINUE. Other threads of the process,
// a vfork parent or process_vm_writev can manage to rewrite the buffer between these moments.
// The kernel cannot "pin" execve arguments, so we check the result: argv and exe of the new
// image.
//
// Modes:
//   stop: before CONTINUE we send SIGSTOP to the calling THREAD (tgkill). While the thread is
//         in the kernel, the signal stays pending; the first return to user space after a
//         successful execve is already in the new image, and the process stops BEFORE the
//         first instruction of the new program. Then we read /proc/<pid>/{exe,cmdline}
//         (untouched) and send SIGCONT or SIGKILL. There is no window: a substituted program
//         does not run a single instruction. Cost: the parent may see
//         CLD_STOPPED/CLD_CONTINUED (waitpid with WUNTRACED/WCONTINUED).
//   poll: CONTINUE without stopping, then we poll /proc until the image changes (≤ 50 ms) and
//         kill on a mismatch. There is a window: the new program gets to run for a while
//         (measured by the TestToctouEvil* test: echo manages to print).
//   off:  no check.

import (
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

type toctouMode string

const (
	toctouStop toctouMode = "stop"
	toctouPoll toctouMode = "poll"
	toctouOff  toctouMode = "off"
)

type expectation struct {
	exe      string // realpath of the expected image (for a script: the interpreter)
	dev, ino uint64 // 0: do not check
	argv     []string
	// old image (if execve returned an error, the process keeps running it)
	oldExe  string
	oldArgv []string
}

type toctouResult struct {
	Mode    string   `json:"mode"`
	Outcome string   `json:"outcome"` // match | match_unobserved | mismatch_killed | exec_failed | not_observed | gone
	GotExe  string   `json:"gotExe,omitempty"`
	GotArgv []string `json:"gotArgv,omitempty"`
	WaitUs  int64    `json:"waitUs"`
	Detail  string   `json:"detail,omitempty"`
}

func expectFor(ev *execEvent) expectation {
	x := expectation{exe: ev.Target, dev: ev.TargetDev, ino: ev.TargetIno, argv: ev.Argv, oldExe: ev.CallerExe, oldArgv: ev.CallerCmd}
	if interp, arg, ok := shebang(ev.Target); ok {
		// binfmt_script: argv' = [interp, (arg), filename, argv[1:]...]; filename as passed to execve
		interpPath := interp
		if rp, err := filepath.EvalSymlinks(interp); err == nil {
			interpPath = rp
		}
		// the interpreter's dev/ino is not checked; nested shebang and binfmt_misc are not
		// modeled (they yield mismatch → SIGKILL, i.e. fail-closed)
		x.exe, x.dev, x.ino = interpPath, 0, 0
		argv := []string{interp}
		if arg != "" {
			argv = append(argv, arg)
		}
		argv = append(argv, ev.Path)
		if len(ev.Argv) > 1 {
			argv = append(argv, ev.Argv[1:]...)
		}
		x.argv = argv
	}
	return x
}

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
