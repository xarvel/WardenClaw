// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Low-level seccomp user notification plumbing without cgo:
// kernel structs are described by hand (x/sys/unix v0.48 does not have them),
// the BPF filter is assembled by hand, ioctls go through unix.Syscall.

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// struct seccomp_data (64 bytes)
type seccompData struct {
	Nr   int32
	Arch uint32
	IP   uint64
	Args [6]uint64
}

// struct seccomp_notif (80 bytes = the size in SECCOMP_IOCTL_NOTIF_RECV 0xc0502100)
type seccompNotif struct {
	ID    uint64
	Pid   uint32
	Flags uint32
	Data  seccompData
}

// struct seccomp_notif_resp (24 bytes = the size in SECCOMP_IOCTL_NOTIF_SEND 0xc0182101)
type seccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

func init() {
	// Guard against a mismatch with the sizes baked into the ioctl numbers.
	if unsafe.Sizeof(seccompNotif{}) != 0x50 || unsafe.Sizeof(seccompNotifResp{}) != 0x18 {
		panic("seccomp struct sizes mismatch")
	}
}

func bpfStmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k}
}

func bpfJump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// execFilter:
//   - foreign arch (compat/32-bit) → ENOSYS (a bypass via a 32-bit exec is impossible);
//   - a number with the __X32_SYSCALL_BIT bit (the x32 ABI on x86_64 passes the arch check as
//     AUDIT_ARCH_X86_64, execve there is 0x40000208) → ENOSYS; arm64 has no such numbers;
//   - execve/execveat → USER_NOTIF (the supervisor decides);
//   - seccomp(SECCOMP_SET_MODE_FILTER, flags & NEW_LISTENER) → EPERM: protection against a
//     nested unotify filter. With equal actions the kernel delivers the notification to the most
//     recent filter, i.e. a process under wardend could install its own filter with a listener,
//     receive its own execve calls and answer CONTINUE bypassing us. Ordinary filters (without a
//     listener) are allowed: they can only tighten (actions with higher precedence), and our
//     USER_NOTIF outranks ALLOW/TRACE/LOG.
//   - everything else ALLOW.
//
// auditArch is the native architecture of the build (seccomp_arch_*.go); other GOARCH values
// do not build.
func execFilter() []unix.SockFilter {
	const (
		ld   = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeq  = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		jge  = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
		jset = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
		ret  = unix.BPF_RET | unix.BPF_K
	)
	const (
		offNr   = 0
		offArch = 4
		offArg0 = 16 // args[0], low word (little-endian)
		offArg1 = 24 // args[1], low word
		x32Bit  = 0x40000000
	)
	return []unix.SockFilter{
		/* 0 */ bpfStmt(ld, offArch),
		/* 1 */ bpfJump(jeq, auditArch, 1, 0),
		/* 2 */ bpfStmt(ret, unix.SECCOMP_RET_ERRNO|uint32(unix.ENOSYS)),
		/* 3 */ bpfStmt(ld, offNr),
		/* 4 */ bpfJump(jge, x32Bit, 0, 1), // x32 → 5, otherwise → 6
		/* 5 */ bpfStmt(ret, unix.SECCOMP_RET_ERRNO|uint32(unix.ENOSYS)),
		/* 6 */ bpfJump(jeq, unix.SYS_EXECVE, 9, 0), // → 16
		/* 7 */ bpfJump(jeq, unix.SYS_EXECVEAT, 8, 0), // → 16
		/* 8 */ bpfJump(jeq, unix.SYS_SECCOMP, 1, 0), // → 10
		/* 9 */ bpfStmt(ret, unix.SECCOMP_RET_ALLOW),
		/* 10 */ bpfStmt(ld, offArg0),
		/* 11 */ bpfJump(jeq, unix.SECCOMP_SET_MODE_FILTER, 0, 2), // not SET_MODE_FILTER → 14
		/* 12 */ bpfStmt(ld, offArg1),
		/* 13 */ bpfJump(jset, unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, 1, 0), // → 15
		/* 14 */ bpfStmt(ret, unix.SECCOMP_RET_ALLOW),
		/* 15 */ bpfStmt(ret, unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM)),
		/* 16 */ bpfStmt(ret, unix.SECCOMP_RET_USER_NOTIF),
	}
}

// installFilter sets no_new_privs and the filter on the CURRENT thread (call under
// LockOSThread, then execve from the same thread: the filter carries over to the new process
// image). Returns the listener fd (O_CLOEXEC).
func installFilter(waitKillable bool) (int, error) {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return -1, fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}
	f := execFilter()
	prog := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}
	flags := uintptr(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER)
	if waitKillable {
		flags |= unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
	}
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, flags, uintptr(unsafe.Pointer(&prog)))
	if errno != 0 {
		return -1, fmt.Errorf("seccomp(SET_MODE_FILTER, flags=%#x): %w", flags, errno)
	}
	return int(fd), nil
}

func notifRecv(fd int, n *seccompNotif) error {
	for {
		*n = seccompNotif{} // the kernel requires a zeroed struct
		_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_RECV, uintptr(unsafe.Pointer(n)))
		if e == unix.EINTR {
			continue
		}
		if e != 0 {
			return e
		}
		return nil
	}
}

func notifSend(fd int, r *seccompNotifResp) error {
	for {
		_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_SEND, uintptr(unsafe.Pointer(r)))
		if e == unix.EINTR {
			continue
		}
		if e != 0 {
			return e
		}
		return nil
	}
}

func notifIDValid(fd int, id uint64) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_ID_VALID, uintptr(unsafe.Pointer(&id)))
	if e != 0 {
		return e
	}
	return nil
}

// pollNotif: waits for events on the listener fd. Returns (readable, hup).
func pollNotif(fd int, timeoutMs int) (bool, bool, error) {
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(pfd, timeoutMs)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return false, false, err
		}
		if n == 0 {
			return false, false, nil
		}
		re := pfd[0].Revents
		return re&unix.POLLIN != 0, re&(unix.POLLHUP|unix.POLLERR) != 0, nil
	}
}
