// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !hwkey

package main

// Build without the hwkey tag (release): there are no second-factor commands, their help is not
// shown (usage), and a call answers that the feature is not in this release. Real commands: hwcmd.go.

import (
	"fmt"
	"io"
	"time"

	"github.com/xarvel/WardenClaw/daemon/feature"
)

func cmdHWRegister(args []string, stdout, stderr io.Writer, now time.Time) int {
	fmt.Fprintln(stderr, "wardend hw-register:", feature.HWKeyOff)
	return 2
}

func cmdHWKeys(args []string, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "wardend hw-keys:", feature.HWKeyOff)
	return 2
}
