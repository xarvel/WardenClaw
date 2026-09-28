// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/policy"
)

type fakeReplaySys struct{}

func (fakeReplaySys) NoNewPrivs(int) (bool, bool) { return true, true }
func (fakeReplaySys) Setuid(p string) bool        { return p == "/usr/bin/sudo" }

// Replay of a synthetic journal: classes, the scp → ssh pair, sudo refusal, skipped missing, window.
func TestReplaySynthetic(t *testing.T) {
	t0 := time.Date(2026, 9, 27, 12, 0, 0, 0, time.Local).UnixMilli()
	var buf bytes.Buffer
	seq := int64(0)
	add := func(kind string, dt int64, data any) {
		seq++
		b, _ := json.Marshal(map[string]any{"seq": seq, "ts": t0 + dt, "kind": kind, "data": data})
		buf.Write(append(b, '\n'))
	}
	link := func(pids ...int) []envelope.Link {
		var out []envelope.Link
		for _, p := range pids {
			out = append(out, envelope.Link{Pid: p, Exe: "/usr/bin/x"})
		}
		return out
	}
	ex := func(tgid int, exe string, argv []string, chain []envelope.Link, class string) map[string]any {
		return map[string]any{"tgid": tgid, "path": exe, "exe": exe, "callerExe": "/usr/bin/dash", "argv": argv, "cwd": "/tmp", "chain": chain, "class": class}
	}
	add("start", 0, map[string]any{"cmd": []string{"sh"}})
	add("exec", 1000, ex(10, "/usr/bin/dash", []string{"sh"}, link(10), "supervised_cmd"))
	add("exec", 2000, ex(11, "/usr/bin/ls", []string{"ls"}, link(11, 10), "root"))
	add("exec", 3000, ex(12, "", []string{"ssh"}, link(12, 10), "missing"))
	add("exec", 4000, ex(12, "/usr/bin/scp", []string{"scp", "a", "h:/tmp/"}, link(12, 10), "root"))
	add("exec", 5000, ex(13, "/usr/bin/ssh", []string{"/usr/bin/ssh", "-x", "h", "scp", "-t", "/tmp/"}, link(13, 12, 10), "inherit"))
	add("exec", 6000, ex(14, "/usr/bin/ssh", []string{"ssh", "h"}, link(14, 10), "delegating"))
	add("exec", 7000, ex(15, "/usr/bin/sudo", []string{"sudo", "-n", "true"}, link(15, 10), "delegating"))
	add("exec", 8000, ex(16, "/usr/bin/ssh", []string{"ssh", "late"}, link(16, 12, 10), "inherit")) // outside the --until window
	buf.WriteString(`{"seq": 99, "ts": 1, "kind": "exe`)                                            // a cut line

	cfg := &Config{PolicyMode: policy.ModeTripwire}
	pol, err := policy.Defaults()
	if err != nil {
		t.Fatal(err)
	}
	if err := pol.Setup(cfg.policyOptions(nil, "")); err != nil {
		t.Fatal(err)
	}
	pol.Sys = fakeReplaySys{}
	st, err := runReplay(&buf, cfg, pol, 0, t0+7000, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"logged": 1, "tripwire": 2, "implied": 1, "refuse": 1}
	for k, n := range want {
		if st.Classes[k] != n {
			t.Errorf("class %s: %d, want %d (%v)", k, st.Classes[k], n, st.Classes)
		}
	}
	if st.Cards.Total != 2 || st.Categories["remote"] != 2 || st.Implied["remote/ssh"] != 1 || st.Refused["privilege/sudo"] != 1 {
		t.Errorf("cards %+v cats %v implied %v refused %v", st.Cards, st.Categories, st.Implied, st.Refused)
	}
	if st.Skipped["missing"] != 1 || st.Skipped["supervised_cmd"] != 1 || st.Skipped["unparsable"] != 1 || st.Execs != 5 {
		t.Errorf("skipped %v execs %d", st.Skipped, st.Execs)
	}
	var out bytes.Buffer
	printReplay(&out, st, 5)
	for _, s := range []string{"cards       2", "implied     1: remote/ssh 1", "refused     1: privilege/sudo 1"} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("report lacks %q:\n%s", s, out.String())
		}
	}
	// no argv in the report
	if strings.Contains(out.String(), "h:/tmp/") || strings.Contains(out.String(), "late") {
		t.Errorf("argv leaked into the report:\n%s", out.String())
	}
	// root mode on the same records: agreement with the recorded classes
	cfg.PolicyMode = policy.ModeRoot
	buf.Reset()
	seq = 0
	add("start", 0, map[string]any{"cmd": []string{"sh"}})
	add("exec", 2000, ex(11, "/usr/bin/ls", []string{"ls"}, link(11, 10), "root"))
	add("exec", 3000, ex(12, "/usr/bin/cat", []string{"cat"}, link(12, 11, 10), "inherit"))
	st, err = runReplay(&buf, cfg, pol, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.Agreement == nil || st.Agreement.Total != 2 || st.Agreement.Agree != 2 {
		t.Errorf("agreement %+v classes %v", st.Agreement, st.Classes)
	}
}

func TestParseWhen(t *testing.T) {
	if n, err := parseWhen("1790543486000"); err != nil || n != 1790543486000 {
		t.Errorf("ms: %d %v", n, err)
	}
	if n, err := parseWhen("2026-09-27T23:11:26+02:00"); err != nil || n != 1790543486000 {
		t.Errorf("rfc3339: %d %v", n, err)
	}
	if _, err := parseWhen("yesterday"); err == nil {
		t.Error("bad time accepted")
	}
}
