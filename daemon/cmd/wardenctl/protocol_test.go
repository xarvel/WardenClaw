// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// TestCheckProtocol: the version contract (protocol/README.md, "Protocol version"): no protocol
// field or it is less than MIN_SERVER_PROTOCOL gives "update wardend"; PROTOCOL < minClient gives
// "update wardenctl"; both errors are ProtocolError with exit code 4.
func TestCheckProtocol(t *testing.T) {
	if clientProtocol != 1 || minServerProtocol != 1 {
		t.Fatalf("PROTOCOL %d, MIN_SERVER_PROTOCOL %d: the first public release is 1 and 1", clientProtocol, minServerProtocol)
	}
	n := func(s string) any { return json.Number(s) }
	for _, c := range []struct {
		name      string
		p, m      any
		serverOld bool
		ok        bool
	}{
		{"same version", n("1"), n("1"), false, true},
		{"newer server that still takes us", n("2"), n("1"), false, true},
		{"no minClient", n("1"), nil, false, true},
		{"no protocol (old wardend)", nil, nil, true, false},
		{"empty protocol", n(""), n(""), true, false},
		{"protocol 0", n("0"), n("1"), true, false},
		{"protocol not an integer", n("1.5"), n("1"), true, false},
		{"server needs a newer client", n("2"), n("2"), false, false},
	} {
		err := checkProtocol(c.p, c.m)
		if c.ok {
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			continue
		}
		var pe *ProtocolError
		if !errors.As(err, &pe) || pe.ServerOld != c.serverOld {
			t.Fatalf("%s: %#v", c.name, err)
		}
		want := "update wardenctl"
		if c.serverOld {
			want = "update wardend"
		}
		if msg := err.Error(); !strings.HasSuffix(msg, want) || strings.Contains(msg, "—") {
			t.Fatalf("%s: %q", c.name, msg)
		}
		if codeFor(err) != exitProtocol || codeFor(fmt.Errorf("status: %w", err)) != 4 {
			t.Fatalf("%s: exit code %d", c.name, codeFor(err))
		}
	}
	if codeFor(errors.New("connection refused")) != 1 {
		t.Fatal("other errors keep exit code 1")
	}
}

// protoServer: a wardend that signs ping and status with the pinned key; extra: version fields.
func protoServer(t *testing.T, sup ed25519.PrivateKey, extra map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{"ok": true, "service": "wardend", "v": 1, "supervisorId": envelope.DeviceID(sup.Public().(ed25519.PublicKey)), "now": envelope.NowMs()}
		for k, v := range extra {
			body[k] = v
		}
		raw, _ := json.Marshal(body)
		var sig string
		switch r.URL.Path {
		case "/v1/ping":
			sig = envelope.SignPing(sup, r.URL.Query().Get("nonce"), 200, raw)
		case "/v1/status":
			sig = envelope.SignResponse(sup, envelope.RespCtx{Action: "status", DeviceID: r.Header.Get("X-Wardenclaw-Device"), Nonce: r.Header.Get("X-Wardenclaw-Nonce")}, 200, raw)
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Wardend-Signature", sig)
		w.Write(raw)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestClientChecksProtocol: Ping and Status check the version in the signed response.
func TestClientChecksProtocol(t *testing.T) {
	supPub, supPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, dev, _ := ed25519.GenerateKey(rand.Reader)
	ctx := context.Background()
	for _, c := range []struct {
		name  string
		extra map[string]any
		want  string // "": accepted
	}{
		{"current", map[string]any{"protocol": 1, "minClient": 1}, ""},
		{"old wardend without the fields", nil, "update wardend"},
		{"wardend needs a newer wardenctl", map[string]any{"protocol": 3, "minClient": 2}, "update wardenctl"},
	} {
		cl := newClient(protoServer(t, supPriv, c.extra).URL, supPub, dev)
		_, perr := cl.Ping(ctx)
		_, serr := cl.Status(ctx)
		for what, err := range map[string]error{"ping": perr, "status": serr} {
			if c.want == "" {
				if err != nil {
					t.Fatalf("%s %s: %v", c.name, what, err)
				}
				continue
			}
			var pe *ProtocolError
			if !errors.As(err, &pe) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%s %s: %v", c.name, what, err)
			}
		}
	}
}

// TestNewerEnvelopeIsShownNotSigned: an envelope newer than wardenctl is not silently dropped and
// not taken for garbage: a card with a clear "update wardenctl" error, signing is not allowed.
func TestNewerEnvelopeIsShownNotSigned(t *testing.T) {
	for _, raw := range []string{
		`{"v":2,"type":"exec","argv":["ls"],"somethingNew":true}`,
		`{"v":2,"type":"exec2"}`,
	} {
		_, err := strictEnvelope(json.RawMessage(raw))
		if !errors.Is(err, ErrNewerEnvelope) || !strings.Contains(err.Error(), "envelope v2") || strings.Contains(err.Error(), "not v1") {
			t.Fatalf("%s: %v", raw, err)
		}
		c := checkItem(Item{ID: "wd-0123456789", Kind: "exec", Envelope: json.RawMessage(raw)}, "sup")
		if !errors.Is(c.Err, ErrNewerEnvelope) {
			t.Fatalf("card %s: %v", raw, c.Err)
		}
	}
	// v1 with a foreign shape and a garbage v: the previous shape errors
	for _, raw := range []string{`{"v":1,"type":"exec"}`, `{"v":"2","type":"exec"}`, `{"v":0,"type":"exec"}`} {
		if _, err := strictEnvelope(json.RawMessage(raw)); err == nil || errors.Is(err, ErrNewerEnvelope) {
			t.Fatalf("%s: %v", raw, err)
		}
	}
}
