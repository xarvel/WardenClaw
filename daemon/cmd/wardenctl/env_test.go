// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

func envItem(t *testing.T, env []envelope.EnvVar, argv ...string) Item {
	t.Helper()
	e := &envelope.Exec{Argv: argv, Cwd: "/home/me", Exe: "/usr/bin/ssh", UID: 1000, GID: 1000,
		PpidChain: []envelope.Link{{Pid: 10, Exe: "/usr/bin/dash"}}, Env: env,
		EnvHash: strings.Repeat("ab", 32), Requester: envelope.Requester{Host: "pi", SupervisorID: testSup},
		PidfdCookie: "pidfs:123", Ts: 1790454055103, Nonce: envelope.NewNonce()}
	canon, d, err := e.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return Item{ID: envelope.PendingID(d), Kind: "exec", Digest: d, Envelope: canon,
		Meta: json.RawMessage(`{"class":"tripwire","rule":"remote/ssh"}`), CreatedAt: 1, ExpiresAt: 30001}
}

// Crypto review finding 4: `ssh prod uptime` with LD_PRELOAD. The environment is visible in show, the card is dangerous.
func TestReviewLoaderEnvShown(t *testing.T) {
	c := checkItem(envItem(t, []envelope.EnvVar{{Name: "HOME", Value: "/home/me"}, {Name: "LD_PRELOAD", Value: "/tmp/x.so"}}, "ssh", "prod", "uptime"), testSup)
	if c.Err != nil {
		t.Fatal(c.Err)
	}
	var short, full bytes.Buffer
	printCard(&short, c, 1, false)
	printCard(&full, c, 1, true)
	for _, want := range []string{"!!! DANGEROUS", "LD_PRELOAD in the environment", "environment (2):", "! LD_PRELOAD=/tmp/x.so", "1 more"} {
		if !strings.Contains(short.String(), want) {
			t.Errorf("no %q in\n%s", want, short.String())
		}
	}
	if strings.Contains(short.String(), "HOME=/home/me") || !strings.Contains(full.String(), "HOME=/home/me") {
		t.Errorf("HOME: only in the full view\n%s\n%s", short.String(), full.String())
	}
	var list bytes.Buffer
	printShort(&list, c, 1)
	if !strings.Contains(list.String(), "[DANGEROUS]") {
		t.Errorf("list: %s", list.String())
	}
	// without loader variables and flags the `ssh prod uptime` card is not dangerous because of the environment
	c = checkItem(envItem(t, []envelope.EnvVar{{Name: "HOME", Value: "/home/me"}}, "ls"), testSup)
	if r := envReasons(envView(c.Env.Vars)); len(r) > 0 {
		t.Errorf("harmless environment: %v", r)
	}
}

func TestStrictEnvelopeEnv(t *testing.T) {
	good := envItem(t, []envelope.EnvVar{{Name: "PYTHONPATH", Value: strings.Repeat("я", envelope.EnvValueMax), Cut: 3}}, "python3")
	if c := checkItem(good, testSup); c.Err != nil {
		t.Fatalf("good: %v", c.Err)
	}
	var m map[string]any
	if err := json.Unmarshal(good.Envelope, &m); err != nil {
		t.Fatal(err)
	}
	bad := map[string]any{
		"extra key":   []any{map[string]any{"name": "A_PATH", "value": "x", "x": 1}},
		"cut 0":       []any{map[string]any{"name": "A_PATH", "value": "x", "cut": 0}},
		"cut 1.5":     []any{map[string]any{"name": "A_PATH", "value": "x", "cut": 1.5}},
		"long value":  []any{map[string]any{"name": "A_PATH", "value": strings.Repeat("я", envelope.EnvValueMax+1)}},
		"empty name":  []any{map[string]any{"name": "", "value": "x"}},
		"= in name":   []any{map[string]any{"name": "A=B", "value": "x"}},
		"not array":   map[string]any{"name": "A", "value": "x"},
		"null":        nil,
		"value types": []any{map[string]any{"name": "A_PATH", "value": 1}},
	}
	for name, env := range bad {
		m["env"] = env
		raw, _ := json.Marshal(m)
		if _, err := strictEnvelope(raw); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
	delete(m, "env")
	raw, _ := json.Marshal(m)
	if _, err := strictEnvelope(raw); err == nil {
		t.Error("an envelope without env must be rejected")
	}
}

// envView against the env key of the shared display vectors (reference: app/src/core/display.ts).
func TestDisplayVectorEnv(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "protocol", "vectors", "display_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Env []struct {
			Name   string            `json:"name"`
			Input  []envelope.EnvVar `json:"input"`
			Expect json.RawMessage   `json:"expect"`
		} `json:"env"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Env) < 5 {
		t.Fatalf("env vectors: %d", len(v.Env))
	}
	for _, c := range v.Env {
		if ok, got := sameJSON(t, envView(c.Input), c.Expect); !ok {
			t.Errorf("%s:\n got %s\nwant %s", c.Name, got, c.Expect)
		}
	}
}
