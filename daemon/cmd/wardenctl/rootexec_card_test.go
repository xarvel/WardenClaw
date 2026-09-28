// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// A rootexec envelope (type rootexec, uid/gid of the launch) passes the strict shape check, is
// always dangerous with the reason in words, and is printed with the RUNS AS ROOT banner; any
// other type is still refused.
func TestRootExecCard(t *testing.T) {
	e := &envelope.Exec{Type: envelope.TypeRootExec, Argv: []string{"docker", "restart", "searxng"}, Cwd: "/srv/stack", Exe: "/usr/bin/docker", UID: 0, GID: 0,
		PpidChain: []envelope.Link{{Pid: 10, Exe: "/usr/local/bin/wardend"}, {Pid: 9, Exe: "/usr/bin/dash"}},
		EnvHash:   strings.Repeat("ab", 32), Requester: envelope.Requester{Host: "pi", SupervisorID: testSup},
		PidfdCookie: "pidfs:123", Ts: 1790454055103, Nonce: envelope.NewNonce()}
	canon, d, err := e.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	it := Item{ID: envelope.PendingID(d), Kind: "exec", Digest: d, Envelope: canon,
		Meta: json.RawMessage(`{"class":"rootexec","rule":"docker-restart","path":"docker","syscall":"rootexec","delegating":"runs as root outside the gate"}`), CreatedAt: 1, ExpiresAt: 30001}
	c := checkItem(it, testSup)
	if c.Err != nil || !c.Env.Root() || c.Env.UID != 0 {
		t.Fatalf("rootexec card must verify: err %v env %+v", c.Err, c.Env)
	}
	danger, reasons := dangerOf(c)
	if !danger || len(reasons) == 0 || !strings.Contains(reasons[0], "runs as uid 0 (root)") {
		t.Fatalf("rootexec is always dangerous, first reason names root: %v %v", danger, reasons)
	}
	// docker is a delegating group on its own: that reason stays, the unsigned meta note is not repeated
	for _, r := range reasons[1:] {
		if strings.Contains(r, "according to the server") {
			t.Fatalf("meta note repeated: %v", reasons)
		}
	}
	var short, full bytes.Buffer
	printShort(&short, c, 2)
	printCard(&full, c, 2, true)
	if !strings.Contains(short.String(), "[RUNS AS ROOT]") || !strings.Contains(short.String(), "[DANGEROUS]") {
		t.Fatalf("short: %s", short.String())
	}
	if !strings.Contains(full.String(), "!!! RUNS AS ROOT (uid 0)") || !strings.Contains(full.String(), "uid/gid:  0/0 (root)") {
		t.Fatalf("full: %s", full.String())
	}
	// y does not allow it in watch, only the word allow
	if a := watchAnswer("y", true); a != watchNeedAllowWord {
		t.Fatalf("y must not allow a dangerous card: %v", a)
	}
	// an unknown type is refused, fail-closed
	other := it
	other.Envelope = bytes.Replace(canon, []byte(`"type":"rootexec"`), []byte(`"type":"sudoexec"`), 1)
	if c := checkItem(other, testSup); c.Err == nil {
		t.Fatal("unknown envelope type accepted")
	}
}
