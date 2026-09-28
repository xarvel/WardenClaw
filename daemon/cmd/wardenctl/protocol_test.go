// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xarvel/WardenClaw/daemon/relaylink"
)

// TestCheckProtocol: the version contract (protocol/README.md, "Protocol version"): no protocol
// field or a lower number gives "update wardend"; a higher number gives "update wardenctl"; both
// errors are ProtocolError with exit code 4.
func TestCheckProtocol(t *testing.T) {
	if clientProtocol != 1 {
		t.Fatalf("PROTOCOL %d: the first release speaks protocol 1", clientProtocol)
	}
	n := func(s string) any { return json.Number(s) }
	for _, c := range []struct {
		name      string
		p         any
		serverOld bool
		ok        bool
	}{
		{"same version", n("1"), false, true},
		{"no protocol", nil, true, false},
		{"empty protocol", n(""), true, false},
		{"protocol 0", n("0"), true, false},
		{"protocol not an integer", n("1.5"), true, false},
		{"newer server", n("2"), false, false},
	} {
		err := checkProtocol(c.p)
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

// A status of another protocol version is refused before anything of it is used.
func TestStatusChecksProtocol(t *testing.T) {
	for _, c := range []struct {
		name, body string
		want       string // "": accepted
	}{
		{"current", `{"ok":true,"protocol":1,"mode":"ticket","pending":[],"pendingCount":0}`, ""},
		{"wardend without the field", `{"ok":true,"mode":"ticket"}`, "update wardend"},
		{"a newer wardend", `{"ok":true,"protocol":2}`, "update wardenctl"},
	} {
		r, err := parseStatus([]byte(c.body))
		if c.want == "" {
			if err != nil || r.Queue.Mode != "ticket" {
				t.Fatalf("%s: %+v %v", c.name, r, err)
			}
			continue
		}
		var pe *ProtocolError
		if !errors.As(err, &pe) || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	// the relay of another protocol: the same exit code
	if codeFor(&relaylink.ProtocolError{Relay: 2}) != exitProtocol {
		t.Fatal("a relay of another protocol: exit code")
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
