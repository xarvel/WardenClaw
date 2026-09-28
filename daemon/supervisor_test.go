// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"os/exec"
	"testing"
	"time"
)

// wardend exits with the child's status, a signal as 128+N like a shell.
func TestChildExitCode(t *testing.T) {
	for _, c := range []struct {
		script string
		want   int
	}{{"exit 0", 0}, {"exit 3", 3}, {"kill -TERM $$", 128 + 15}} {
		err := exec.Command("sh", "-c", c.script).Run()
		if got := childExitCode(err); got != c.want {
			t.Errorf("%q: exit code %d, want %d (%v)", c.script, got, c.want, err)
		}
	}
	if got := childExitCode(errors.New("wait failed")); got != 1 {
		t.Errorf("non-exit error: %d, want 1", got)
	}
}

// A denial answers repeats of the same request until it expires; expired ones are swept.
func TestDenyCache(t *testing.T) {
	s := &supervisor{denyCache: map[string]deniedReq{}}
	if _, ok := s.recentDenial("k"); ok {
		t.Fatal("empty cache answered")
	}
	s.rememberDenial("k", "denied by device")
	if reason, ok := s.recentDenial("k"); !ok || reason != "denied by device" {
		t.Fatalf("recentDenial = %q, %v", reason, ok)
	}
	s.denyCache["old"] = deniedReq{until: time.Now().Add(-time.Second), reason: "ttl expired"}
	if _, ok := s.recentDenial("old"); ok {
		t.Error("expired denial answered")
	}
	s.rememberDenial("k2", "queue full")
	if _, ok := s.denyCache["old"]; ok {
		t.Error("expired denial not swept")
	}
}
