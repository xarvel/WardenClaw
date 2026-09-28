// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// The cross-language check of the relay transport: this supervisor and the app's TypeScript
// session (app/src/core/relaySession.ts, played by app/scripts/relay-live-device.mjs in node)
// meet on the deployed relay. The script gets the pair link, pairs, allows the first card and
// denies the second.

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// WARDEN_RELAY_LIVE=1 WARDEN_RELAY_NODE_DEVICE=../app/scripts/relay-live-device.mjs
// go test -run TestRelayLiveNodeDevice. Fresh keys on both sides, two connections, a dozen frames.
func TestRelayLiveNodeDevice(t *testing.T) {
	script := os.Getenv("WARDEN_RELAY_NODE_DEVICE")
	if os.Getenv("WARDEN_RELAY_LIVE") != "1" || script == "" {
		t.Skip("set WARDEN_RELAY_LIVE=1 and WARDEN_RELAY_NODE_DEVICE=<app/scripts/relay-live-device.mjs> to run through the live relay")
	}
	base := os.Getenv("WARDEN_RELAY_URL")
	if base == "" {
		base = "wss://relay.wardenclaw.dev"
	}
	s := startRelaySupervisor(t, base, nil)
	t.Logf("supervisor %s connected to %s", s.supervisorID, base)
	ps, err := s.pairStart(0)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	cmd := exec.Command("node", script, ps["link"].(string))
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		t.Logf("node device:\n%s", out.String())
	})

	// the request of the node device arrives; approve it as `wardend pair approve` does
	var id string
	for i := 0; id == ""; i++ {
		if l := s.pair.list(); len(l) > 0 {
			id = l[0].ID
			break
		}
		if i > 600 {
			t.Fatal("no pairing request from the node device")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := s.pairApprove(id); err != nil {
		t.Fatal(err)
	}
	t.Logf("pairing request %s of the node device approved", id)

	decided := func(ch chan execOutcome) execOutcome {
		select {
		case o := <-ch:
			return o
		case <-time.After(60 * time.Second):
			t.Fatal("the exec was not decided by the node device")
		}
		return execOutcome{}
	}
	ch, it := startExec(t, s, 300, "ls", "/tmp")
	if it == nil {
		t.Fatal("the exec did not become pending")
	}
	if o := decided(ch); !o.allow {
		t.Fatalf("allow ticket of the node device: denied, %q", o.rec.Reason)
	}
	t.Logf("card %s: the allow ticket of the node device let the command go on", it.ID)

	ch, it = startExec(t, s, 301, "ls", "/")
	if it == nil {
		t.Fatal("the second exec did not become pending")
	}
	if o := decided(ch); o.allow || o.errno != unix.EPERM {
		t.Fatalf("deny ticket of the node device: allow=%v errno=%v", o.allow, o.errno)
	}
	t.Logf("card %s: the deny ticket of the node device, EPERM", it.ID)

	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("node device: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the node device did not finish")
	}
}
