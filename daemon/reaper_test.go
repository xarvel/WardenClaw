// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"
)

// A child that did not run under the tree's filter is listed but left to its waiter.
func TestReaperLeavesOwnChildren(t *testing.T) {
	own, _ := seccompFilters(os.Getpid())
	c := exec.Command("true")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	pid := c.Process.Pid
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, _, state, _, ok := procStat(pid); ok && state == 'Z' {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("true did not exit")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if kids := ourChildren(); !slices.Contains(kids, pid) {
		t.Fatalf("ourChildren %v does not list %d", kids, pid)
	}
	if treeMember(pid, own) {
		t.Fatalf("a child of ours is not a member of the tree")
	}
	reapOrphans(-1, own)
	if _, _, state, _, ok := procStat(pid); !ok || state != 'Z' {
		t.Fatalf("the zombie %d was reaped by the sweep: ok=%v state=%c", pid, ok, state)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("Wait after the sweep: %v", err)
	}
}
