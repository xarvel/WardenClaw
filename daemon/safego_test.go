// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/journal"
)

// panicInWorker: the panic site that must show up in the stack of the report.
func panicInWorker() { panic("boom") }

// Daemon H-6: a goroutine started via goSafe panics in a test subprocess. The process exits with a
// non-zero code, stderr has "panic in <name>: <value>" and the stack down to the panic site, the
// wardend journal has a panic record (chain and signatures intact). The journal does not answer
// (lock held): the report is in stderr only, the exit still comes after panicJournalWait, without
// hanging.
func TestGoSafePanicExits(t *testing.T) {
	if mode := os.Getenv("WARDEND_TEST_PANIC"); mode != "" {
		var jf func(string, any)
		switch mode {
		case "journal":
			dir := os.Getenv("WARDEND_TEST_DIR")
			key, err := journal.LoadOrCreateKey(filepath.Join(dir, "key"))
			if err != nil {
				t.Fatal(err)
			}
			jr, err := journal.Open(filepath.Join(dir, "journal.jsonl"), key)
			if err != nil {
				t.Fatal(err)
			}
			jf = func(kind string, data any) { jr.Append(kind, data) }
		case "stuck":
			jf = func(string, any) { select {} }
		}
		goSafe("test-worker", os.Stderr, jf, panicInWorker)
		time.Sleep(20 * time.Second)
		os.Exit(0) // goSafe did not exit the process
	}
	for _, mode := range []string{"journal", "stuck"} {
		dir := t.TempDir()
		cmd := exec.Command(os.Args[0], "-test.run=^TestGoSafePanicExits$", "-test.count=1")
		cmd.Env = append(os.Environ(), "WARDEND_TEST_PANIC="+mode, "WARDEND_TEST_DIR="+dir)
		start := time.Now()
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() == 0 {
			t.Fatalf("%s: exit %v, expected a non-zero code\n%s", mode, err, out)
		}
		if d := time.Since(start); d > 15*time.Second {
			t.Errorf("%s: exit after %s", mode, d)
		}
		for _, want := range []string{"wardend: panic in test-worker: boom", "goroutine ", "panicInWorker(", "safego_test.go"} {
			if !strings.Contains(string(out), want) {
				t.Errorf("%s: no %q in the output:\n%s", mode, want, out)
			}
		}
		if mode == "stuck" {
			if !strings.Contains(string(out), "the journal did not answer") {
				t.Errorf("stuck: no message about the journal:\n%s", out)
			}
			continue
		}
		key, err := journal.LoadOrCreateKey(filepath.Join(dir, "key"))
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(filepath.Join(dir, "journal.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(f.Name())
		r := journal.Verify(f, key.Public().(ed25519.PublicKey))
		f.Close()
		if !r.OK || r.Entries != 1 || !strings.Contains(string(b), `"kind":"panic"`) || !strings.Contains(string(b), `"goroutine":"test-worker"`) {
			t.Errorf("journal: %+v\n%s", r, b)
		}
	}
}
