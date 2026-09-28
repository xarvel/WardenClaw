// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Membership of the supervised tree, for a gate that sees every exec on the host (the global
// Endpoint Security client, used when es_new_descendants_client is not available). Fork and
// exit notices keep the set; an exec whose pid is unknown but whose parent is a member joins
// (the fork notice may arrive after the exec of the child). Orphans stay members: on macOS they
// are reparented to launchd, and the tree is about lineage, not the current parent.

import "sync"

type gateTree struct {
	mu   sync.Mutex
	root int
	live map[int]bool
}

// newGateTree starts a tree whose only member is root (0: no root yet, SetRoot adds it).
func newGateTree(root int) *gateTree {
	t := &gateTree{live: map[int]bool{}}
	if root > 0 {
		t.root = root
		t.live[root] = true
	}
	return t
}

// SetRoot adds the root when it is known only after the gate started (the command is started
// after the client subscribed, so that its first exec is seen).
func (t *gateTree) SetRoot(root int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if root > 0 {
		t.root = root
		t.live[root] = true
	}
}

// Fork: child joins when parent is a member (root included).
func (t *gateTree) Fork(parent, child int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.live[parent] && child > 0 {
		t.live[child] = true
	}
}

// Exit forgets pid. The pid may be reused by a process outside the tree afterwards.
func (t *gateTree) Exit(pid int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.live, pid)
}

// Member reports whether pid is a member, or ppid is (fork notice not seen yet: pid joins).
func (t *gateTree) Member(pid, ppid int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.live[pid] {
		return true
	}
	if t.live[ppid] && pid > 0 {
		t.live[pid] = true
		return true
	}
	return false
}

// Len is the number of members, the root included while it lives.
func (t *gateTree) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.live)
}
