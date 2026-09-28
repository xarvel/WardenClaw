// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/policy"
)

// startExecEnv: like startExec, but with an environment (the whole envp, selection as in collect).
func startExecEnv(t *testing.T, s *supervisor, tgid int, envp []string, argv ...string) (chan execOutcome, *pendingItem) {
	t.Helper()
	ev := &execEvent{Pid: tgid, Tgid: tgid, Start: uint64(tgid), Target: "/usr/bin/" + argv[0], Argv: argv, ArgvOK: true, Cwd: "/tmp", CallerExe: "/usr/bin/bash",
		Chain: []envelope.Link{{Pid: tgid, Exe: "/usr/bin/bash"}}, Env: envelope.SelectEnv(envp), EnvHash: envHash(envp), UID: 4242, GID: 4242}
	ch := make(chan execOutcome, 1)
	before := s.q.len()
	go func() {
		rec := &execRecord{}
		allow, errno, _, fd := s.decide1(ev, rec)
		closeFd(fd)
		ch <- execOutcome{allow, errno, rec}
	}()
	for i := 0; i < 200; i++ {
		select {
		case o := <-ch:
			ch <- o
			return ch, nil
		default:
		}
		if s.q.len() > before {
			_, items := s.q.snapshot()
			return ch, items[len(items)-1]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("exec neither pending nor decided")
	return nil, nil
}

// Crypto review finding 4: a harmless command with LD_PRELOAD. The environment is now in the
// envelope (under the digest) and in the card; outside an approved root such a launch is always a
// card of category loader-env.
func TestReviewLoaderEnvCard(t *testing.T) {
	d := newDevice()
	s := newHWSupervisor(t, `{}`, d)
	s.cfg.PolicyMode = policy.ModeTripwire
	envp := []string{"HOME=/home/u", "LD_PRELOAD=/tmp/x.so", "LANG=C"}

	// without LD_PRELOAD `uptime` is not a tripwire hit: allowed at once, without a card
	ch, it := startExecEnv(t, s, 300, []string{"HOME=/home/u", "LANG=C"}, "uptime")
	if it != nil {
		t.Fatalf("plain uptime must not be a card: %v", it.Meta)
	}
	if o := wait(t, ch); !o.allow || o.rec.Class != string(policy.ClassLogged) {
		t.Fatalf("plain uptime: allow=%v class=%s", o.allow, o.rec.Class)
	}

	// with LD_PRELOAD: a loader-env card, the variable is in the signed envelope
	ch, it = startExecEnv(t, s, 301, envp, "uptime")
	if it == nil {
		t.Fatal("uptime with LD_PRELOAD must be a card")
	}
	if it.Meta["category"] != policy.CatLoaderEnv || it.Meta["rule"] != "loader-env/ld_preload" {
		t.Fatalf("meta: %v", it.Meta)
	}
	if !reflect.DeepEqual(it.Meta["loaderEnv"], []string{"LD_PRELOAD"}) {
		t.Fatalf("meta.loaderEnv: %v", it.Meta["loaderEnv"])
	}
	env, _ := it.Envelope["env"].([]any)
	want := []any{map[string]any{"name": "HOME", "value": "/home/u"}, map[string]any{"name": "LD_PRELOAD", "value": "/tmp/x.so"}}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("envelope env: %#v", it.Envelope["env"])
	}
	if _, d2, _ := envelope.Digest(it.Envelope); d2 != it.Digest {
		t.Fatal("digest must cover the envelope with env")
	}
	r := decideRaw(s, ticket(d, it, "deny", -1))
	if r["ok"] != true {
		t.Fatalf("deny: %v", r)
	}
	if o := wait(t, ch); o.allow || o.rec.Category != policy.CatLoaderEnv || !reflect.DeepEqual(o.rec.LoaderEnv, []string{"LD_PRELOAD"}) {
		t.Fatalf("loader-env card: allow=%v category=%s loaderEnv=%v", o.allow, o.rec.Category, o.rec.LoaderEnv)
	}

	// `ssh prod uptime` is a card anyway (remote): its category and rule stay, env in the envelope
	ch, it = startExecEnv(t, s, 302, envp, "ssh", "prod", "uptime")
	if it == nil {
		t.Fatal("ssh must be a card")
	}
	if it.Meta["category"] == policy.CatLoaderEnv || !reflect.DeepEqual(it.Meta["loaderEnv"], []string{"LD_PRELOAD"}) {
		t.Fatalf("ssh keeps its category and carries loaderEnv: %v", it.Meta)
	}
	if env, _ := it.Envelope["env"].([]any); len(env) != 2 {
		t.Fatalf("ssh envelope env: %v", it.Envelope["env"])
	}
	decideRaw(s, ticket(d, it, "deny", -1))
	wait(t, ch)
}

// Root mode: the root is a card anyway; env is in the envelope. A child of an approved root with
// LD_PRELOAD inherits without a card, as before (the root is gated, not every child).
func TestLoaderEnvRootMode(t *testing.T) {
	d := newDevice()
	s := newHWSupervisor(t, `{}`, d)
	ch, it := startExecEnv(t, s, 100, []string{"LD_AUDIT=/tmp/a.so"}, "make")
	if it == nil {
		t.Fatal("root must be a card")
	}
	if it.Meta["class"] != string(policy.ClassRoot) || !reflect.DeepEqual(it.Meta["loaderEnv"], []string{"LD_AUDIT"}) {
		t.Fatalf("meta: %v", it.Meta)
	}
	if r := decideRaw(s, ticket(d, it, "allow", -1)); r["ok"] != true {
		t.Fatalf("allow: %v", r)
	}
	if o := wait(t, ch); !o.allow {
		t.Fatal("approved root must run")
	}
	ch, it = startExecEnv(t, s, 101, []string{"LD_PRELOAD=/tmp/x.so"}, "cc")
	if it != nil {
		t.Fatalf("a child of an approved root inherits: %v", it.Meta)
	}
	if o := wait(t, ch); !o.allow || o.rec.Class != string(policy.ClassInherit) {
		t.Fatalf("child: allow=%v class=%s", o.allow, o.rec.Class)
	}
}
