// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Orphans of the tree. wardend is a child subreaper (prctl PR_SET_CHILD_SUBREAPER): a process
// whose parent exited is re-parented to wardend instead of init. Two reasons:
//   - Yama (kernel.yama.ptrace_scope=1, the default on Ubuntu) lets a process open
//     /proc/<pid>/mem only of its descendants. An orphan re-parented to init is no longer our
//     descendant and its exec cannot be read: `bash -c '(sleep 1; ls) & exit 0'` would lose its
//     ls with EPERM (class unreadable) instead of getting a ticket. Raspberry Pi OS has no Yama,
//     which is why TestOrphanBeforeExecIsNewRoot passed there and failed on the Ubuntu runner.
//   - a subreaper must reap: the orphans stay zombies until someone waits for them.
//
// Only orphans of the tree are reaped, and each one by its pid: our children are listed from
// /proc, and an exited one is waited for only if it ran under the tree's filter, that is with
// one seccomp filter more than wardend itself (the helper installs exactly one; Seccomp_filters
// in /proc/<pid>/status survives the exit). The supervised child and whatever wardend itself
// starts (sqlite3 for the gateway db, helpers in tests) keep their exit status for the code that
// waits for them. No wait(-1)/waitid(P_ALL): it would consume a stranger's status, or get stuck
// behind one nobody waits for.

import (
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// becomeSubreaper marks the process as the subreaper of its descendants (not inherited by
// children).
func becomeSubreaper() error {
	return unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
}

// ourChildren lists the pids of our children (live and zombies). A child belongs to the thread
// that forked it or that the kernel re-parented it to, hence /proc/self/task/*/children; without
// CONFIG_PROC_CHILDREN the fallback is a scan of /proc for PPid == us.
func ourChildren() []int {
	var out []int
	me := os.Getpid()
	tids, err := os.ReadDir("/proc/self/task")
	if err == nil {
		found := false
		for _, t := range tids {
			b, err := os.ReadFile("/proc/self/task/" + t.Name() + "/children")
			if err != nil {
				continue
			}
			found = true
			for _, f := range strings.Fields(string(b)) {
				if pid, err := strconv.Atoi(f); err == nil && pid > 1 {
					out = append(out, pid)
				}
			}
		}
		if found {
			return out
		}
	}
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if ppid, _, _, _, ok := procStat(pid); ok && ppid == me {
			out = append(out, pid)
		}
	}
	return out
}

// treeMember: the process ran under the tree's filter (more seccomp filters than wardend).
func treeMember(pid, ownFilters int) bool {
	n, ok := seccompFilters(pid)
	return ok && n > ownFilters
}

// reapOrphans reaps the exited orphans of the tree (see the file comment): our zombies with
// more seccomp filters than ownFilters, never keep (the supervised child). Returns the number
// reaped.
func reapOrphans(keep, ownFilters int) int {
	n := 0
	for _, pid := range ourChildren() {
		if pid == keep {
			continue
		}
		if _, _, state, _, ok := procStat(pid); !ok || state != 'Z' || !treeMember(pid, ownFilters) {
			continue
		}
		if _, err := unix.Wait4(pid, nil, unix.WNOHANG, nil); err == nil {
			n++
		}
	}
	return n
}

// treeChildrenLeft: is a member of the tree (live, exiting or zombie) still our child?
func treeChildrenLeft(ownFilters int) bool {
	for _, pid := range ourChildren() {
		if treeMember(pid, ownFilters) {
			return true
		}
	}
	return false
}

// reapAtExit: the last sweep. The listener's HUP comes from seccomp_filter_release() in
// do_exit(), a moment before the task turns into a waitable zombie, so the last orphans may
// not be reapable yet: retry briefly. Live orphans (the linger timeout) go to init with us.
func (s *supervisor) reapAtExit() {
	for i := 0; i < 40; i++ {
		reapOrphans(s.childPid, s.ownFilters)
		if !treeChildrenLeft(s.ownFilters) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}
