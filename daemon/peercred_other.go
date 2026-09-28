// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux && !darwin

package main

import "net"

// peerCred: no peer credentials on this build; ok=false means every connection is refused
// (rpc.go peerAllowed, rootexec.go serve). Linux: SO_PEERCRED; macOS: LOCAL_PEERCRED/PEERPID.
func peerCred(c *net.UnixConn) (pid, uid int, ok bool) {
	return 0, 0, false
}
