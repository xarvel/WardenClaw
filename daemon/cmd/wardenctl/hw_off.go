// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !hwkey

package main

// Build without the hwkey tag (release): no YubiKey. hw-register and hw-check are not shown in the
// help and answer that the feature is not in this release; approve and watch sign allow with the
// device key only. The FIDO code (fido.go, hwcmd.go) is built only with the tag, docs/hwkey.md.

import (
	"errors"
	"fmt"
	"io"

	"github.com/xarvel/WardenClaw/daemon/feature"
	"github.com/xarvel/WardenClaw/daemon/hwkey"
)

func (a *app) cmdHWRegister(args []string) int { return a.hwOff("hw-register") }

func (a *app) cmdHWCheck(args []string) int { return a.hwOff("hw-check") }

func (a *app) hwOff(cmd string) int {
	fmt.Fprintf(a.stderr, "wardenctl %s: %s\n", cmd, feature.HWKeyOff)
	return exitUsage
}

func hwAssert(cred *HWCred, device string, uv bool, clientDataJSON []byte, stderr io.Writer) (*hwkey.Assertion, error) {
	return nil, errors.New(feature.HWKeyOff)
}
