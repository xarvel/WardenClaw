// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Catching panics in long-lived wardend goroutines. An unhandled panic crashes the process, and
// that is correct (fail-closed: the seccomp listener closes, a pending exec gets an error, systemd
// restarts wardend), but the cause would be lost: nothing in the wardend journal, only the runtime
// trace in journald. On panic, a goroutine started via goSafe prints
// "panic in <name>: <value>" and the stack to stderr (journald), writes a panic record to the
// wardend journal when possible and exits the process with code 2, like the Go runtime.

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sync"
	"time"
)

// panicJournalWait: how long to wait for the panic record to reach the journal. The write runs in
// a separate goroutine and may not go through: the panic may have happened while someone else
// held the journal lock or the supervisor lock (under which the journal is written). Then the
// report stays only in stderr, and the process exits anyway.
const panicJournalWait = 2 * time.Second

// panicMu: the first panic writes the report; later ones wait on the lock until the process exits.
var panicMu sync.Mutex

// goSafe: go fn() with panic catching. name is the goroutine name in the report; journal (nil
// means stderr only) writes the record to the wardend journal.
func goSafe(name string, stderr io.Writer, journal func(kind string, data any), fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicExit(name, r, debug.Stack(), stderr, journal)
			}
		}()
		fn()
	}()
}

// goSafe: a long-lived supervisor goroutine; the panic report goes to its stderr and journal.
func (s *supervisor) goSafe(name string, fn func()) {
	var stderr io.Writer
	var journal func(string, any)
	if s != nil {
		stderr = s.stderr
		if s.jr != nil {
			journal = s.journal
		}
	}
	goSafe(name, stderr, journal, fn)
}

func panicExit(name string, r any, stack []byte, stderr io.Writer, journal func(string, any)) {
	panicMu.Lock() // never released: only the exit follows
	if stderr == nil {
		stderr = os.Stderr
	}
	fmt.Fprintf(stderr, "wardend: panic in %s: %v\n\n%s\n", name, r, stack)
	if journal != nil {
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(stderr, "wardend: panic record not written to the journal: %v\n", r)
				}
			}()
			const maxStack = 4 << 10
			journal("panic", map[string]any{"goroutine": name, "value": fmt.Sprint(r), "stack": string(stack[:min(len(stack), maxStack)])})
		}()
		select {
		case <-done:
		case <-time.After(panicJournalWait):
			fmt.Fprintf(stderr, "wardend: the journal did not answer in %s, the panic is recorded here only\n", panicJournalWait)
		}
	}
	os.Exit(2)
}
