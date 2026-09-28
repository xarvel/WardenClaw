// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

// Tracker tracks subtrees of approved roots.
//
// A root is registered when the device has signed the ticket for its exec (before CONTINUE,
// so children that start immediately already see it). Every process whose exec passed as a
// descendant of a root is added to lineage (pid + starttime from /proc/<pid>/stat, protecting
// against pid reuse). Inheritance is checked by walking the PPid chain of the caller: if a
// live lineage member is found (starttime matches), the caller is in the approved subtree.
// Therefore the "subtree is alive" as long as any ancestor process is alive, not just the
// root itself: `bash -c 'ls & ...'` - ls passes even if bash has already exited, IF the
// chain to a live lineage member is unbroken.
//
// Where the chain breaks (honestly):
//   - the process orphaned BEFORE its first exec (the lineage parent died, the kernel
//     reparented it to the wardend subreaper or to init) - we never saw its fork, so it is
//     a new root for us -> ticket required (fail-closed). This is `setsid nohup cmd &` /
//     double-fork / daemonization: see README, "Delegating spawn and detaching from the tree: what happens (pinned by tests)".
//   - delegating execs (setsid, systemd-run, docker, tmux, ...) - always a new root by the
//     delegating rules, even if the chain is intact.

import (
	"sync"
	"time"
)

// Root is an approved root: the exec a device signed a ticket for.
type Root struct {
	Pid        int
	Start      uint64
	Digest     string
	DeviceID   string
	Hardware   bool // root ticket carried a valid second hardware-key signature
	ApprovedAt time.Time
	Children   int // how many execs passed by inheritance
	// Tripwire: family of the approved trigger (Hit.Family). Children inherit only triggers
	// of the same family (ImpliedBy) and within ImpliedTTL; "" means a root-mode root.
	Family string
}

// lineageEntry is a process known to descend from an approved root.
type lineageEntry struct {
	start uint64
	root  int // pid of the root (key in roots)
}

// maxAncestors bounds the PPid walk in InheritedRoot.
const maxAncestors = 64

// ProcReader provides access to /proc (substituted in tests).
type ProcReader interface {
	// Stat returns ppid, starttime; ok=false if the process is not found.
	Stat(pid int) (ppid int, start uint64, ok bool)
}

// Tracker records approved roots and their live descendants (see the file comment).
type Tracker struct {
	mu      sync.Mutex
	proc    ProcReader
	stopAt  int // pid of the supervisor: we do not walk above this
	roots   map[int]*Root
	lineage map[int]lineageEntry
}

// NewTracker returns an empty tracker; the ancestor walk stops at supervisorPid.
func NewTracker(proc ProcReader, supervisorPid int) *Tracker {
	return &Tracker{proc: proc, stopAt: supervisorPid, roots: map[int]*Root{}, lineage: map[int]lineageEntry{}}
}

// AddRoot registers an approved root (pid is tgid of the calling exec, start is its starttime).
func (t *Tracker) AddRoot(r *Root) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.roots[r.Pid] = r
	t.lineage[r.Pid] = lineageEntry{start: r.Start, root: r.Pid}
}

// InheritedRoot returns the root pid whose live subtree contains pid (pid itself or an
// ancestor), or 0. On success pid is added to lineage so its future children inherit even
// after their ancestors die.
func (t *Tracker) InheritedRoot(pid int) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.lineage) == 0 {
		return 0
	}
	type hop struct {
		pid   int
		start uint64
	}
	var path []hop
	for p, depth := pid, 0; p > 1 && p != t.stopAt && depth < maxAncestors; depth++ {
		ppid, start, ok := t.proc.Stat(p)
		if !ok {
			break
		}
		path = append(path, hop{p, start})
		l, known := t.lineage[p]
		if known && l.start == start {
			for _, h := range path {
				t.lineage[h.pid] = lineageEntry{start: h.start, root: l.root}
			}
			if r := t.roots[l.root]; r != nil {
				r.Children++
			}
			return l.root
		}
		if known {
			delete(t.lineage, p) // pid reused
		}
		p = ppid
	}
	return 0
}

// Root returns a copy of the root record for pid (nil if no such root).
func (t *Tracker) Root(pid int) *Root {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.roots[pid]
	if r == nil {
		return nil
	}
	c := *r
	return &c
}

// HasRoots reports whether there are any live roots (fast path, no chain walk).
func (t *Tracker) HasRoots() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.lineage) > 0
}

// RootHardware reports whether the root pid was approved with a hardware key.
func (t *Tracker) RootHardware(pid int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.roots[pid]
	return r != nil && r.Hardware
}

// Sweep removes dead processes from lineage and roots with no live descendants.
// It returns roots whose subtree has ended.
func (t *Tracker) Sweep() []*Root {
	t.mu.Lock()
	defer t.mu.Unlock()
	alive := map[int]bool{}
	for pid, l := range t.lineage {
		if _, start, ok := t.proc.Stat(pid); ok && start == l.start {
			alive[l.root] = true
		} else {
			delete(t.lineage, pid)
		}
	}
	var gone []*Root
	for pid, r := range t.roots {
		if !alive[pid] {
			gone = append(gone, r)
			delete(t.roots, pid)
		}
	}
	return gone
}

// TrackerStats holds tracker sizes for status and metrics.
type TrackerStats struct {
	Roots   int `json:"roots"`
	Lineage int `json:"lineage"`
}

// Stats returns the current number of roots and lineage entries.
func (t *Tracker) Stats() TrackerStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return TrackerStats{Roots: len(t.roots), Lineage: len(t.lineage)}
}
