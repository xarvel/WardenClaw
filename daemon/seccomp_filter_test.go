// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// runBPF executes the subset of classic BPF that execFilter uses, over seccomp_data.
func runBPF(t *testing.T, prog []unix.SockFilter, d seccompData) uint32 {
	t.Helper()
	buf := make([]byte, 64)
	binary.LittleEndian.PutUint32(buf[0:], uint32(d.Nr))
	binary.LittleEndian.PutUint32(buf[4:], d.Arch)
	binary.LittleEndian.PutUint64(buf[8:], d.IP)
	for i, a := range d.Args {
		binary.LittleEndian.PutUint64(buf[16+8*i:], a)
	}
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		ins := prog[pc]
		switch ins.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			acc = binary.LittleEndian.Uint32(buf[ins.K:])
		case unix.BPF_RET | unix.BPF_K:
			return ins.K
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			var cond bool
			switch ins.Code &^ (unix.BPF_JMP | unix.BPF_K) {
			case unix.BPF_JEQ:
				cond = acc == ins.K
			case unix.BPF_JGE:
				cond = acc >= ins.K
			case unix.BPF_JSET:
				cond = acc&ins.K != 0
			}
			if cond {
				pc += int(ins.Jt)
			} else {
				pc += int(ins.Jf)
			}
		default:
			t.Fatalf("pc %d: unsupported opcode %#x", pc, ins.Code)
		}
	}
	t.Fatalf("program fell off the end")
	return 0
}

func TestExecFilterDecisions(t *testing.T) {
	prog := execFilter()
	if len(prog) > 255 {
		t.Fatalf("filter too long for 8-bit jumps: %d", len(prog))
	}
	enosys := uint32(unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS))
	eperm := uint32(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM))
	cases := []struct {
		name string
		d    seccompData
		want uint32
	}{
		{"execve", seccompData{Nr: unix.SYS_EXECVE, Arch: auditArch}, unix.SECCOMP_RET_USER_NOTIF},
		{"execveat", seccompData{Nr: unix.SYS_EXECVEAT, Arch: auditArch}, unix.SECCOMP_RET_USER_NOTIF},
		{"getpid", seccompData{Nr: unix.SYS_GETPID, Arch: auditArch}, unix.SECCOMP_RET_ALLOW},
		{"foreign arch execve", seccompData{Nr: unix.SYS_EXECVE, Arch: unix.AUDIT_ARCH_I386}, enosys},
		{"foreign arch arm", seccompData{Nr: 11, Arch: unix.AUDIT_ARCH_ARM}, enosys},
		{"x32 execve", seccompData{Nr: 0x40000000 + 520, Arch: auditArch}, enosys},
		{"x32 getpid", seccompData{Nr: 0x40000000 + 39, Arch: auditArch}, enosys},
		{"seccomp new listener", seccompData{Nr: unix.SYS_SECCOMP, Arch: auditArch,
			Args: [6]uint64{unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_NEW_LISTENER}}, eperm},
		{"seccomp plain filter", seccompData{Nr: unix.SYS_SECCOMP, Arch: auditArch,
			Args: [6]uint64{unix.SECCOMP_SET_MODE_FILTER, 0}}, unix.SECCOMP_RET_ALLOW},
		{"seccomp get action avail", seccompData{Nr: unix.SYS_SECCOMP, Arch: auditArch,
			Args: [6]uint64{unix.SECCOMP_GET_ACTION_AVAIL, unix.SECCOMP_FILTER_FLAG_NEW_LISTENER}}, unix.SECCOMP_RET_ALLOW},
	}
	for _, c := range cases {
		if got := runBPF(t, prog, c.d); got != c.want {
			t.Errorf("%s: got %#x, want %#x", c.name, got, c.want)
		}
	}
}
