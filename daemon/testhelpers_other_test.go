// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package main

// TestMain helper modes that need the Linux gate (rpcenv_linux_test.go, redteam_test.go). Here
// each one reports that instead of pretending.

import (
	"fmt"
	"os"
)

func noGateHelper(mode string) {
	fmt.Printf("%s: the exec gate is Linux-only on this build\n", mode)
	os.Exit(1)
}

func helperFiltered()   { noGateHelper("filtered") }
func redteamMemfdExec() { noGateHelper("memfd") }
func redteamLdSo()      { noGateHelper("ldso") }
