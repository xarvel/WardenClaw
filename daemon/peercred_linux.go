// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

// peerCred: pid and uid of the process on the other end of a unix socket (SO_PEERCRED).

import (
	"net"

	"golang.org/x/sys/unix"
)

func peerCred(c *net.UnixConn) (pid, uid int, ok bool) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, false
	}
	var cred *unix.Ucred
	_ = raw.Control(func(fd uintptr) {
		cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if cred == nil {
		return 0, 0, false
	}
	return int(cred.Pid), int(cred.Uid), true
}
