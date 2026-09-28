// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestPairLinkRoundTrip(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	k := B64URL(priv.Public().(ed25519.PublicKey))
	sid := DeviceID(priv.Public().(ed25519.PublicKey)) // sid must be the id of key
	enc := B64URL(make([]byte, 32))
	l := PairLink{Relay: "wss://relay.example.com/v1/ws", SID: sid, Key: k, Enc: enc, Code: "ABCD2345", Host: "pi"}
	if got, err := ParsePairLink(l.String()); err != nil || got != l {
		t.Fatalf("%v %+v", err, got)
	}
	for _, bad := range []string{"https://x", strings.Replace(l.String(), "v=1", "v=2", 1), strings.Replace(l.String(), "&v=1", "", 1),
		"wardenclaw://pair?v=1&url=https%3A%2F%2Fw.example.com&key=" + k + "&code=c"} {
		if _, err := ParsePairLink(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, bad := range []PairLink{
		{Relay: "https://relay.example.com/v1/ws", SID: sid, Key: k, Enc: enc, Code: "c"},
		{Relay: "ws://relay.example.com/v1/ws", SID: sid, Key: k, Enc: enc, Code: "c"},
		{Relay: "ws://127.0.0.1:8787/v1/ws", SID: sid, Key: k, Enc: enc, Code: "c"},
		{Relay: l.Relay, SID: DeviceID(make(ed25519.PublicKey, 32)), Key: k, Enc: enc, Code: "c"},
		{Relay: l.Relay, SID: sid, Key: k, Enc: "AAAA", Code: "c"},
		{Relay: l.Relay, SID: sid, Key: "zz", Enc: enc, Code: "c"},
		{Relay: l.Relay, SID: sid, Key: k, Enc: enc},
	} {
		if _, err := ParsePairLink(bad.String()); err == nil {
			t.Errorf("accepted %q", bad.String())
		}
	}
	if NormalizeCode(" abcd-2345 ") != "ABCD2345" || Fingerprint("0123456789abcdef00") != "0123 4567 89ab cdef" {
		t.Fatal("normalize/fingerprint")
	}
}
