// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// In watch a dangerous card is allowed only by the word allow in full (like the hold on the phone
// and the watch); y, yes and other short answers do not allow it. A regular card works as before.
func TestWatchAnswer(t *testing.T) {
	for _, c := range []struct {
		in        string
		dangerous bool
		want      watchAction
	}{
		{"y", false, watchAllow},
		{"Y", false, watchAllow},
		{"yes", false, watchAllow},
		{"allow", false, watchAllow},
		{"y", true, watchNeedAllowWord},
		{"yes", true, watchNeedAllowWord},
		{"allow", true, watchAllow},
		{"  ALLOW ", true, watchAllow},
		{"allo", true, watchUnknown},
		{"allowed", true, watchUnknown},
		{"a", true, watchUnknown},
		{"n", true, watchDeny},
		{"no", false, watchDeny},
		{"N", false, watchDeny},
		{"", true, watchSkip},
		{"", false, watchSkip},
		{"d", true, watchDetails},
		{"?", false, watchDetails},
		{"x", false, watchUnknown},
	} {
		if got := watchAnswer(c.in, c.dangerous); got != c.want {
			t.Errorf("watchAnswer(%q, dangerous=%v) = %v, want %v", c.in, c.dangerous, got, c.want)
		}
	}
}

// What watch considers dangerous: the same as "!!! DANGEROUS" (rules, flags, delegation from the
// signed envelope), plus meta about a delegating launch, which can only add caution.
func TestDangerOf(t *testing.T) {
	safe := checkItem(testItem(t, "bash", "-c", "git status"), testSup)
	if d, r := dangerOf(safe); d || len(r) != 0 {
		t.Fatalf("regular command: %v %v", d, r)
	}
	films := checkItem(testItem(t, "bash", "-c", `ls -la "/srv/media/Сериалы/Северный маяк/Сезон 2"`), testSup)
	if d, r := dangerOf(films); d {
		t.Fatalf("a Russian folder must not be dangerous: %v", r)
	}
	// the reason names the word and the substituted letter itself (a Cyrillic "у" in pуthon)
	homo := checkItem(testItem(t, "bash", "-c", "/usr/bin/pуthon -m http.server"), testSup)
	if d, r := dangerOf(homo); !d || !strings.Contains(strings.Join(r, ";"), "in the word \"pуthon\" a Cyrillic \"у\" among Latin letters") {
		t.Fatalf("homoglyph: %v %v", d, r)
	}
	rule := checkItem(testItem(t, "bash", "-c", "echo token-ran"), testSup)
	if d, _ := dangerOf(rule); !d {
		t.Fatal("secrets rule")
	}
	meta := testItem(t, "bash", "-c", "echo hi")
	meta.Meta = json.RawMessage(`{"class":"delegating","rule":"x","delegating":"rule text"}`)
	if d, r := dangerOf(checkItem(meta, testSup)); !d || !strings.Contains(strings.Join(r, ";"), "according to the server") {
		t.Fatalf("meta delegating: %v %v", d, r)
	}
	noEnv := testItem(t, "bash", "-c", "echo token")
	noEnv.Kind = "other"
	if c := checkItem(noEnv, testSup); c.Env != nil {
		t.Fatal("expected a card without a parsed envelope")
	} else if d, _ := dangerOf(c); d {
		t.Fatal("nothing to show without an envelope (such a card cannot be signed anyway)")
	}
}
