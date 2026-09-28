// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "testing"

// Fork chains, exit, Member with the ppid fallback, orphans staying members.
func TestGateTree(t *testing.T) {
	tr := newGateTree(100)
	if tr.Len() != 1 || !tr.Member(100, 1) {
		t.Fatalf("root: len %d", tr.Len())
	}
	// a chain of forks from the root
	tr.Fork(100, 200)
	tr.Fork(200, 300)
	tr.Fork(300, 400)
	if tr.Len() != 4 {
		t.Errorf("after forks: len %d", tr.Len())
	}
	for _, pid := range []int{200, 300, 400} {
		if !tr.Member(pid, 0) {
			t.Errorf("%d not a member", pid)
		}
	}
	// a fork from a stranger does not join, nor does a stranger's exec
	tr.Fork(999, 998)
	if tr.Member(998, 999) || tr.Member(999, 1) || tr.Len() != 4 {
		t.Errorf("stranger joined: len %d", tr.Len())
	}
	// exec seen before the fork notice: the child joins through its parent
	if !tr.Member(401, 400) || tr.Len() != 5 {
		t.Errorf("ppid fallback: len %d", tr.Len())
	}
	tr.Fork(400, 401) // the late notice is harmless
	if tr.Len() != 5 {
		t.Errorf("late fork: len %d", tr.Len())
	}
	// exit forgets the pid; the subtree stays (orphans are reparented to launchd)
	tr.Exit(300)
	if tr.Member(300, 1) || !tr.Member(400, 1) || !tr.Member(401, 1) || tr.Len() != 4 {
		t.Errorf("exit: len %d", tr.Len())
	}
	// a reused pid outside the tree is not a member
	if tr.Member(300, 1) {
		t.Error("reused pid is a member")
	}
	// the root exits: its descendants keep their membership
	tr.Exit(100)
	if tr.Member(100, 1) || !tr.Member(200, 100) || tr.Len() != 3 {
		t.Errorf("root exit: len %d", tr.Len())
	}
	// a child of the dead root that was never seen does not join (100 is gone)
	if tr.Member(102, 100) {
		t.Error("child of the dead root joined")
	}
}

// A tree without a root takes it later; Fork and Member on an empty tree never add anything.
func TestGateTreeSetRoot(t *testing.T) {
	tr := newGateTree(0)
	tr.Fork(0, 5)
	if tr.Len() != 0 || tr.Member(5, 0) || tr.Member(0, 0) {
		t.Fatalf("empty tree: len %d", tr.Len())
	}
	tr.SetRoot(7)
	tr.Fork(7, 8)
	if tr.Len() != 2 || !tr.Member(8, 7) || !tr.Member(9, 8) {
		t.Errorf("after SetRoot: len %d", tr.Len())
	}
}
