// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuardRules(t *testing.T) {
	home := t.TempDir()
	withDir := t.TempDir()
	os.Mkdir(filepath.Join(withDir, ".wardend"), 0o700)
	yes := func() (bool, string) { return true, "Seccomp: 2" }
	no := func() (bool, string) { return false, "" }
	anc := func() (string, bool) { return "pid 1 wardend", true }
	procs := func() []string { return []string{"pid 7 /x/wardend"} }

	cases := []struct {
		name         string
		p            guardProbe
		refuse, hard bool
	}{
		{"clean machine", guardProbe{Home: home, SelfFiltered: no}, false, false},
		{"foreign seccomp without wardend (docker, systemd)", guardProbe{Home: home, SelfFiltered: yes}, false, false},
		{"under filter, wardend ancestor", guardProbe{Home: home, SelfFiltered: yes, WardendAncestor: anc}, true, true},
		{"under filter, ~/.wardend (daemonized agent)", guardProbe{Home: withDir, SelfFiltered: yes}, true, true},
		{"under filter, wardend process", guardProbe{Home: home, SelfFiltered: yes, WardendProcs: procs}, true, true},
		{"under filter + override does not help", guardProbe{Home: withDir, SelfFiltered: yes, AllowEnv: "1"}, true, true},
		{"not under filter, ~/.wardend", guardProbe{Home: withDir, SelfFiltered: no}, true, false},
		{"not under filter, wardend process", guardProbe{Home: home, SelfFiltered: no, WardendProcs: procs}, true, false},
		{"not under filter, override", guardProbe{Home: withDir, SelfFiltered: no, AllowEnv: "1"}, false, false},
	}
	for _, c := range cases {
		v := evalGuard(c.p)
		if v.Refuse != c.refuse || v.Hard != c.hard {
			t.Errorf("%s: refuse=%v hard=%v", c.name, v.Refuse, v.Hard)
		}
		if v.Refuse && !strings.Contains(guardMessage(v), "separate machine") {
			t.Errorf("%s: no explanation", c.name)
		}
	}
}
