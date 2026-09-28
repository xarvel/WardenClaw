// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin

package main

// peerCred: pid and effective uid of the process on the other end of a unix socket.
// LOCAL_PEERCRED gives the credentials (xucred: euid and groups), LOCAL_PEERPID the pid; both
// are fixed at connect time, like SO_PEERCRED on Linux. Compiles under GOOS=darwin; not yet
// exercised on hardware.

import (
	"net"

	"golang.org/x/sys/unix"
)

func peerCred(c *net.UnixConn) (pid, uid int, ok bool) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, false
	}
	var cred *unix.Xucred
	var cerr, perr error
	_ = raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		pid, perr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if cerr != nil || perr != nil || cred == nil || pid <= 0 {
		return 0, 0, false
	}
	return pid, int(cred.Uid), true
}
