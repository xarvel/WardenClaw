// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"runtime"
	"testing"
)

// requireGate skips, on macOS, the tests that start the supervisor: the gate there is an
// Endpoint Security client, which needs root and, until the entitlement is granted, a machine
// with SIP off (docs/macos.md). On such a stand:
//
//	sudo WARDEND_ES_TESTS=1 WARDEND_TEST_CHILD_USER=<user> go test -p 1 ./...
func requireGate(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		return
	}
	if os.Geteuid() != 0 || os.Getenv("WARDEND_ES_TESTS") == "" {
		t.Skip("macOS: the Endpoint Security gate needs root and WARDEND_ES_TESTS=1 (docs/macos.md)")
	}
}

// gateTestConfig fills what the macOS supervisor insists on: the user the command runs as.
func gateTestConfig(cfg *Config) {
	if runtime.GOOS == "darwin" && cfg.ChildUser == "" {
		cfg.ChildUser = os.Getenv("WARDEND_TEST_CHILD_USER")
	}
}

// socketTempDir is a directory for a test's unix sockets. On macOS a socket path is at most
// 104 bytes and t.TempDir() under /var/folders/... is longer than that.
func socketTempDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "darwin" {
		return t.TempDir()
	}
	d, err := os.MkdirTemp("/tmp", "wd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}
