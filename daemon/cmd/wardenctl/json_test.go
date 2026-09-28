// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

func TestExtractJSONFlag(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want []string
	}{
		{[]string{"--json", "pending"}, []string{"pending"}},
		{[]string{"show", "wd-123456", "--json"}, []string{"show", "wd-123456"}},
		{[]string{"--dir", "/tmp/x", "approve", "abc", "--json"}, []string{"--dir", "/tmp/x", "approve", "abc"}},
	} {
		got, enabled := extractJSONFlag(tc.in)
		if !enabled || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("extractJSONFlag(%v) = %v, %v; want %v, true", tc.in, got, enabled, tc.want)
		}
	}
}

func TestJSONRejectsUnsupportedCommand(t *testing.T) {
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	a := &app{stdout: out, stderr: errOut}
	if code := a.run(context.Background(), []string{"status", "--json"}); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if out.Len() != 0 || errOut.String() != "wardenctl: --json is only supported by pending, show, approve, and deny\n" {
		t.Fatalf("stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

func TestCardJSON(t *testing.T) {
	c := Card{Item: Item{
		ID: "wd-1234", Kind: "exec", Digest: "abcd", CreatedAt: 10, ExpiresAt: 20,
		Envelope: json.RawMessage(`{"v":1}`), Meta: json.RawMessage(`{"class":"root"}`),
	}, Env: &Env{Argv: []string{"echo", "hello world"}}}
	out := newCardJSON(c)
	if !out.Verified || out.Command != "echo 'hello world'" || string(out.Envelope) != `{"v":1}` {
		t.Fatalf("unexpected JSON card: %#v", out)
	}
}
