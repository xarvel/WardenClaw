// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

// pidfd(2): a stable handle on the caller for the TOCTOU post-check and the envelope cookie.

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// pidfdCookie: "pidfs:<inode>" (unique within a boot on kernels with pidfs ≥ 6.9),
// otherwise "start:<pid>:<starttime>". Also returns the pidfd itself (the caller closes it).
func pidfdCookie(tgid int, start uint64) (string, int) {
	fd, err := unix.PidfdOpen(tgid, 0)
	if err != nil {
		return fmt.Sprintf("start:%d:%d", tgid, start), -1
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) == nil && st.Ino > 1 {
		return fmt.Sprintf("pidfs:%d", st.Ino), fd
	}
	return fmt.Sprintf("start:%d:%d", tgid, start), fd
}

func (s *supervisor) pidfdIf(ev *execEvent, m toctouMode) int {
	if m == toctouOff {
		return -1
	}
	fd, err := unix.PidfdOpen(ev.Tgid, 0)
	if err != nil {
		return -1
	}
	return fd
}
