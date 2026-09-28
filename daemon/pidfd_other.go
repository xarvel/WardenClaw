// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package main

import "fmt"

// pidfdCookie: no pidfd(2); the cookie falls back to pid+starttime, as it does on old kernels.
func pidfdCookie(tgid int, start uint64) (string, int) {
	return fmt.Sprintf("start:%d:%d", tgid, start), -1
}

// pidfdIf: no handle; the TOCTOU post-check has nothing to kill through.
func (s *supervisor) pidfdIf(ev *execEvent, m toctouMode) int { return -1 }
