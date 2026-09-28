// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestResolveChildUserNumeric(t *testing.T) {
	uid, gid, groups, err := resolveChildUser("1234:5678")
	if err != nil || uid != 1234 || gid != 5678 {
		t.Fatalf("uid=%d gid=%d err=%v", uid, gid, err)
	}
	if len(groups) == 0 || groups[0] != 5678 {
		t.Fatalf("groups=%v", groups)
	}
}

func TestResolveChildUserByName(t *testing.T) {
	// the current user always resolves
	name := os.Getenv("USER")
	if name == "" {
		t.Skip("no $USER")
	}
	uid, _, _, err := resolveChildUser(name)
	if err != nil {
		t.Fatalf("lookup %s: %v", name, err)
	}
	if uid != os.Getuid() {
		t.Fatalf("uid=%d, expected %d", uid, os.Getuid())
	}
}

func TestDropPrivilegesRefusesRoot(t *testing.T) {
	if err := dropPrivileges("0"); err == nil {
		t.Fatal("dropPrivileges to uid=0 must refuse")
	}
	if err := dropPrivileges("0:0"); err == nil {
		t.Fatal("dropPrivileges to 0:0 must refuse")
	}
}

func TestDropPrivilegesNonRootCannotChangeUser(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("under root changing uid is allowed")
	}
	// non-root cannot change uid to someone else's → error (not a silent success)
	other := os.Getuid() + 1
	if err := dropPrivileges(strconv.Itoa(other)); err == nil {
		t.Fatalf("non-root must not be able to drop uid to %d", other)
	}
}

func TestResetOOMScoreAdjKeepsNonNegative(t *testing.T) {
	b, err := os.ReadFile("/proc/self/oom_score_adj")
	if err != nil {
		t.Skip("no /proc/self/oom_score_adj")
	}
	before := string(b)
	if n, _ := strconv.Atoi(strings.TrimSpace(before)); n < 0 {
		t.Skip("the test process already has a negative oom_score_adj")
	}
	if err := resetOOMScoreAdj(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile("/proc/self/oom_score_adj")
	if string(after) != before {
		t.Fatalf("non-negative value changed: %q -> %q", before, after)
	}
}
