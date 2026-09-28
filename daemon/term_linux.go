// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

import "golang.org/x/sys/unix"

// isTerminal: fd is a terminal (termios can be read from it).
func isTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}
