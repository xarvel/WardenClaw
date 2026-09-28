// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// The link of wardend pair start names the relay, the channel and the two keys of the supervisor;
// a link that names no relay is not a pairing link.
func TestPairLink(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	rl := envelope.PairLink{Relay: "wss://relay.example/v1/ws", SID: envelope.DeviceID(pub), Key: envelope.B64URL(pub), Enc: testEnc, Code: "3m73-aw54", Host: "pi"}.String()
	link, pinned, enc, err := parsePairLink(rl)
	if err != nil || link.Relay != "wss://relay.example" || link.Code != "3M73AW54" || !pinned.Equal(pub) || envelope.B64URL(enc.Bytes()) != testEnc {
		t.Fatalf("relay link: %+v %v", link, err)
	}
	for name, bad := range map[string]string{
		"no relay":       "wardenclaw://pair?code=3M73AW54&key=" + envelope.B64URL(pub) + "&v=1",
		"ws relay":       strings.Replace(rl, "wss%3A", "ws%3A", 1),
		"foreign sid":    strings.Replace(rl, envelope.DeviceID(pub), strings.Repeat("0", 64), 1),
		"relay path":     strings.Replace(rl, "%2Fv1%2Fws", "%2Fv2", 1),
		"no code":        strings.Replace(rl, "code=3m73-aw54", "code=-", 1),
		"another scheme": strings.Replace(rl, "wardenclaw://", "https://", 1),
	} {
		if _, _, _, err := parsePairLink(bad); err == nil {
			t.Fatalf("%s: link accepted: %s", name, bad)
		}
	}
}
