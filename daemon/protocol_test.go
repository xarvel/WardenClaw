// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// TestProtocolVersionInStatus checks the machine-readable protocol version: status returns
// protocol (protocol/README.md, "Protocol version"), over the socket and as a device gets it.
func TestProtocolVersionInStatus(t *testing.T) {
	if envelope.Protocol != 1 {
		t.Fatalf("protocol %d: the first release speaks protocol 1", envelope.Protocol)
	}
	e := newRPCEnv(t, newDevice())
	want := func(what string, m map[string]any) {
		t.Helper()
		if _, old := m["minClient"]; m["protocol"] != float64(envelope.Protocol) || old {
			t.Fatalf("%s: protocol %v, minClient %v", what, m["protocol"], m["minClient"])
		}
		if w, ok := m["warnings"].([]any); !ok || len(w) != 0 {
			t.Fatalf("%s with a trusted device: warnings %v", what, m["warnings"])
		}
	}
	var rs map[string]any
	if err := rpcDo(t, e.sock, "status", map[string]any{}, &rs); err != nil {
		t.Fatal(err)
	}
	want("RPC status", rs)
	raw, _ := json.Marshal(e.s.status())
	var st map[string]any
	json.Unmarshal(raw, &st)
	want("status", st)
}

// TestStatusWarnsNoTrustedDevices: in mode ticket without trusted devices, status (RPC and
// wardend status) warns no_trusted_devices; after pairing the warning goes away without a restart.
func TestStatusWarnsNoTrustedDevices(t *testing.T) {
	e := newRPCEnv(t) // ticket, device removed
	warnings := func() []any {
		t.Helper()
		var rs map[string]any
		if err := rpcDo(t, e.sock, "status", map[string]any{}, &rs); err != nil {
			t.Fatal(err)
		}
		w, ok := rs["warnings"].([]any)
		if !ok {
			t.Fatalf("RPC status: warnings %v", rs["warnings"])
		}
		return w
	}
	if w := warnings(); len(w) != 1 || w[0] != "no_trusted_devices" {
		t.Fatalf("ticket without devices: warnings %v", w)
	}
	raw, _ := json.Marshal(e.s.status())
	var out bytes.Buffer
	printStatusWarnings(&out, raw)
	if s := out.String(); !strings.Contains(s, "ticket") || !strings.Contains(s, "wardend pair start") || strings.Contains(s, "—") || strings.Count(s, "\n") != 1 {
		t.Fatalf("wardend status words: %q", s)
	}
	d := newDevice()
	e.s.devices.Add(d.trusted())
	if w := warnings(); len(w) != 0 {
		t.Fatalf("after pairing: warnings %v", w)
	}
	e.s.devices.Remove(d.id)
	for _, mode := range []string{"observe", "deny-list"} {
		e.s.cfg.Mode = mode
		if w := warnings(); len(w) != 0 {
			t.Fatalf("mode %s needs no tickets: warnings %v", mode, w)
		}
	}
	out.Reset()
	printStatusWarnings(&out, []byte(`{"ok":true,"warnings":[]}`))
	printStatusWarnings(&out, []byte(`not json`))
	if out.Len() != 0 {
		t.Fatalf("no warnings, no words: %q", out.String())
	}
}
