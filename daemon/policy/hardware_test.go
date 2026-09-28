// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import "testing"

func TestRequireHardwareRules(t *testing.T) {
	c, err := Parse([]byte(`{
	  "delegating": [{"id": "sudo", "argv0": "^sudo$"}],
	  "require_hardware": [
	    {"id": "hw-delegating", "class": "delegating"},
	    {"id": "hw-git-push-force", "argv0": "^git$", "argv_text": " push( .*)? (-f|--force)( |$)"},
	    {"id": "hw-risky", "class": "root|delegating", "min_score": 70},
	    {"id": "hw-very-risky", "min_score": 90, "argv0": "^curl$"}
	  ]}`))
	if err != nil {
		t.Fatal(err)
	}
	ex := func(a ...string) *Exec { return &Exec{Path: "/usr/bin/" + a[0], Argv: a} }
	sudo := ex("sudo", "ls")
	v := c.Classify(sudo, 0)
	if r := c.HardwareStatic(sudo, v.Class); r == nil || r.ID != "hw-delegating" {
		t.Fatalf("sudo: %v %+v", v.Class, r)
	}
	push := ex("git", "push", "origin", "--force")
	for _, cl := range []Class{ClassRoot, ClassInherit, ClassDelegating} {
		if r := c.HardwareStatic(push, cl); r == nil {
			t.Errorf("force push as %s: no rule", cl)
		}
	}
	// exec -a: argv0 replaced, real file is git
	disguised := &Exec{Path: "/usr/bin/git", Argv: []string{"innocent", "push", "-f"}}
	if r := c.HardwareStatic(disguised, ClassRoot); r == nil {
		t.Error("exec -a disguise bypassed the rule")
	}
	if r := c.HardwareStatic(ex("git", "push"), ClassRoot); r != nil {
		t.Errorf("plain push: %s", r.ID)
	}
	// service/deny never require a key (non-ticket classes)
	if r := c.HardwareStatic(push, ClassService); r != nil {
		t.Error("service matched")
	}
	// score: minimum threshold hint and firing by risk
	ls := ex("ls")
	if m, ok := c.HardwareMinScore(ls, ClassRoot); !ok || m != 70 {
		t.Errorf("min score: %d %v", m, ok)
	}
	if m, ok := c.HardwareMinScore(ls, ClassInherit); ok {
		t.Errorf("inherit has no score rule: %d", m)
	}
	if r := c.HardwareByScore(ls, ClassRoot, 69); r != nil {
		t.Errorf("69: %s", r.ID)
	}
	if r := c.HardwareByScore(ls, ClassRoot, 70); r == nil || r.ID != "hw-risky" {
		t.Errorf("70: %+v", r)
	}
	if r := c.HardwareByScore(ex("curl", "x"), ClassInherit, 95); r == nil || r.ID != "hw-very-risky" {
		t.Errorf("curl inherit 95: %+v", r)
	}
	// config errors
	for _, bad := range []string{`{"require_hardware":[{"id":"x","min_score":101}]}`, `{"require_hardware":[{"id":"x","class":"("}]}`, `{"require_hardware":[{"class":"root"}]}`} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	// built-in rules: require_hardware is empty (otherwise everything would require a key)
	if d := mustDefaults(t); len(d.RequireHardware) != 0 {
		t.Error("defaults must not require hardware")
	}
}

func TestTrackerRootHardware(t *testing.T) {
	tr := NewTracker(fakeProc{}, 1)
	tr.AddRoot(&Root{Pid: 10, Hardware: true})
	tr.AddRoot(&Root{Pid: 11})
	if !tr.RootHardware(10) || tr.RootHardware(11) || tr.RootHardware(12) {
		t.Fatal("RootHardware")
	}
}

func TestHardwareRulesInfo(t *testing.T) {
	c, err := Parse([]byte(`{"require_hardware": [
	    {"id": "hw-push", "note": "force push", "argv0": "^git$", "argv_text": " push( .*)? (-f|--force)( |$)"},
	    {"id": "hw-risky", "class": "root|delegating", "category": "publish", "min_score": 70}
	  ]}`))
	if err != nil {
		t.Fatal(err)
	}
	got := c.HardwareRulesInfo()
	if len(got) != 2 || got[0].ID != "hw-push" || got[0].Note != "force push" || got[0].MinScore != nil ||
		got[1].Class != "root|delegating" || got[1].Category != "publish" || got[1].MinScore == nil || *got[1].MinScore != 70 {
		t.Fatalf("%+v", got)
	}
	// threshold copy: editing in status must not change the policy
	*got[1].MinScore = 1
	if *c.RequireHardware[1].MinScore != 70 {
		t.Fatal("HardwareRulesInfo shares min_score with the policy")
	}
	// no rules: empty slice, not null in JSON
	d, err := Parse([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := d.HardwareRulesInfo(); got == nil || len(got) != 0 {
		t.Fatalf("no rules: %#v", got)
	}
}
