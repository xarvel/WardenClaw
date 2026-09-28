// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// A gate with a deadline of its own (Endpoint Security) caps the ticket wait per event: with
// ev.ttl below the config TTL decide1 gives up at ev.ttl ("ttl expired", EPERM) and the card
// expires at the same moment; without ev.ttl the config TTL stands.
func TestDecide1EventTTL(t *testing.T) {
	s := newHWSupervisor(t, `{"deny_always": [], "service_allow": [], "delegating": []}`, newDevice())
	s.cfg.TicketTTL.Duration = 30 * time.Second
	ev := &execEvent{Pid: 100, Tgid: 100, Start: 100, Target: "/usr/bin/rm", Argv: []string{"rm", "-rf", "/tmp/x"}, ArgvOK: true, Cwd: "/tmp",
		CallerExe: "/usr/bin/bash", Chain: []envelope.Link{{Pid: 100, Exe: "/usr/bin/bash"}}, ttl: 300 * time.Millisecond}
	rec := &execRecord{}
	t0 := time.Now()
	allow, errno, _, fd := s.decide1(ev, rec)
	closeFd(fd)
	took := time.Since(t0)
	if allow || errno != unix.EPERM || rec.Reason != "ttl expired" {
		t.Fatalf("decide1 = allow %v errno %v reason %q, want deny EPERM ttl expired", allow, errno, rec.Reason)
	}
	if took < 250*time.Millisecond || took > 5*time.Second {
		t.Fatalf("decide1 took %s, want about the event ttl (300ms), not the config TTL (30s)", took)
	}
	if s.q.len() != 0 {
		t.Errorf("queue not empty after the wait: %d", s.q.len())
	}

	// a ttl above the config TTL does not extend the wait: the card is queued with the config TTL
	ev2 := &execEvent{Pid: 101, Tgid: 101, Start: 101, Target: "/usr/bin/rm", Argv: []string{"rm", "-rf", "/tmp/y"}, ArgvOK: true, Cwd: "/tmp",
		CallerExe: "/usr/bin/bash", Chain: []envelope.Link{{Pid: 101, Exe: "/usr/bin/bash"}}, ttl: time.Hour}
	s.cfg.TicketTTL.Duration = 200 * time.Millisecond
	done := make(chan bool, 1)
	go func() {
		allow, _, _, fd := s.decide1(ev2, &execRecord{})
		closeFd(fd)
		done <- allow
	}()
	select {
	case allow := <-done:
		if allow {
			t.Error("allowed without a ticket")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("decide1 waited longer than the config TTL")
	}
}
