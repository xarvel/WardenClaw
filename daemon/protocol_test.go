// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// TestProtocolVersionInPingAndStatus checks the machine-readable protocol version: ping, HTTP
// status and RPC status return protocol and minClient (protocol/README.md, "Protocol version");
// "v": 1 in ping stays.
func TestProtocolVersionInPingAndStatus(t *testing.T) {
	if envelope.Protocol != 1 || envelope.MinClient != 1 {
		t.Fatalf("protocol %d, minClient %d: the first public release is 1 and 1", envelope.Protocol, envelope.MinClient)
	}
	d := newDevice()
	e := newHTTPEnv(t, d)
	want := func(what string, m map[string]any) {
		t.Helper()
		if m["protocol"] != float64(envelope.Protocol) || m["minClient"] != float64(envelope.MinClient) {
			t.Fatalf("%s: protocol %v, minClient %v", what, m["protocol"], m["minClient"])
		}
	}
	p := e.do(t, "GET", "/v1/ping?nonce=n-ping-01", nil, nil, "n-ping-01")
	if p.status != 200 || !p.sigOK || p.body["v"] != float64(1) || p.body["service"] != "wardend" {
		t.Fatalf("ping: %d %s (sig %v)", p.status, p.raw, p.sigOK)
	}
	want("ping", p.body)
	st := e.do(t, "GET", "/v1/status", signedHeaders(d.priv, e.s.supervisorID, "status", envelope.NowMs(), "n-status-02"), nil, "n-status-02")
	if st.status != 200 || !st.sigOK {
		t.Fatalf("status: %d %s (sig %v)", st.status, st.raw, st.sigOK)
	}
	want("HTTP status", st.body)
	if w, ok := st.body["warnings"].([]any); !ok || len(w) != 0 {
		t.Fatalf("HTTP status with a trusted device: warnings %v", st.body["warnings"])
	}
	var rs map[string]any
	if err := rpcDo(t, e.sock, "status", map[string]any{}, &rs); err != nil {
		t.Fatal(err)
	}
	want("RPC status", rs)
}

// TestStatusWarnsNoTrustedDevices: in mode ticket without trusted devices, status (HTTP, RPC and
// wardend status) warns no_trusted_devices; after pairing the warning goes away without a restart.
func TestStatusWarnsNoTrustedDevices(t *testing.T) {
	e := newHTTPEnv(t) // ticket, device removed
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
