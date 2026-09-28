// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// wardenctl forget: delete the paired server and the device key.
// readLine and isYes are also how approve and watch read a one-line answer.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

func (a *app) cmdForget(args []string) int {
	fs := a.flags("forget")
	yes := fs.Bool("yes", false, "no confirmation")
	// no guard: the key can always be deleted, even next to wardend
	if _, code, ok := a.parseCmd(fs, args, cmdSpec{}); !ok {
		return code
	}
	st, err := loadState(a.dir)
	if errors.Is(err, errNotPaired) {
		fmt.Fprintf(a.stdout, "Nothing to forget: %s is empty.\n", a.dir)
		os.Remove(fileStore{dir: a.dir}.path())
		return 0
	}
	if err != nil {
		return a.errf("%v (delete the directory %s by hand)", err, a.dir)
	}
	if !*yes {
		fmt.Fprintf(a.stdout, "Delete server %s (%s) and device key %s? This cannot be undone, only a new pairing. [y/N] ", st.Host, st.Relay, envelope.Fingerprint(st.DeviceID))
		line, _ := readLine(a.stdin)
		if !isYes(line) {
			fmt.Fprintln(a.stdout, "Cancelled.")
			return 1
		}
	}
	a.dropKey(st)
	os.Remove(fileStore{dir: a.dir}.path())
	if err := os.Remove(statePath(a.dir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return a.errf("%v", err)
	}
	fmt.Fprintf(a.stdout, "Forgotten. On the server, revoke the device: wardend pair revoke %s\n", revokeRef(st.DeviceID))
	if st.HW != nil {
		fmt.Fprintf(a.stdout, "The YubiKey stays in wardend hardware_keys (it can still sign from another device).\n")
	}
	return 0
}

// readLine: one trimmed line from r. It reads a byte at a time, without a buffer, so the input
// after the newline stays in r for the next reader.
func readLine(r io.Reader) (string, error) {
	var b []byte
	one := make([]byte, 1)
	for {
		n, err := r.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				return strings.TrimSpace(string(b)), nil
			}
			b = append(b, one[0])
		}
		if err != nil {
			return strings.TrimSpace(string(b)), err
		}
	}
}

func isYes(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "y", "yes":
		return true
	}
	return false
}
