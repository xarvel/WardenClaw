// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Compatibility with the app: the same vectors the app test reads, in a single copy
// in protocol/vectors/ at the monorepo root. Ed25519 signatures
// are deterministic, so we compare byte-for-byte what the wardenctl code builds.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// fixtureDirs: the single copy of the protocol vectors (protocol/vectors at the monorepo root).
func fixtureDirs(t *testing.T) []string {
	return []string{filepath.Join("..", "..", "..", "protocol", "vectors")}
}

func loadJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		t.Fatal(err)
	}
}

func seedKey(t *testing.T, hexSeed string) ed25519.PrivateKey {
	s, err := hex.DecodeString(hexSeed)
	if err != nil || len(s) != 32 {
		t.Fatal("seed")
	}
	return ed25519.NewKeyFromSeed(s)
}

// testSecret: the device secret of a test key: its seed and a fixed X25519 private key.
func testSecret(priv ed25519.PrivateKey) []byte {
	return append(priv.Seed(), bytes.Repeat([]byte{0x22}, 32)...)
}

// testEnc: an X25519 public key for the supervisor of a test state.
var testEnc = envelope.B64URL(bytes.Repeat([]byte{0x09}, 32))

func TestHWVectorsCompat(t *testing.T) {
	for _, dir := range fixtureDirs(t) {
		var v struct {
			Cases []struct {
				Name, Seed, DeviceID, SigningString, Signature, Challenge, ClientDataJSON, ClientDataHashHex string
				Payload                                                                                      envelope.DecisionPayload
			}
		}
		loadJSON(t, filepath.Join(dir, "hw_vectors.json"), &v)
		if len(v.Cases) == 0 {
			t.Fatal("no cases")
		}
		for _, c := range v.Cases {
			priv := seedKey(t, c.Seed)
			if c.Payload.Risk != nil || c.Payload.Type != envelope.TicketExec {
				// the CLI does not sign risk and signs only exec tickets; the string with risk
				// and the plugin tool ticket are checked via the shared SignPayload
				b := envelope.SignPayload(priv, c.Payload)
				if b.Signature != c.Signature {
					t.Fatalf("%s/%s: signature with risk", dir, c.Name)
				}
				continue
			}
			ts, _ := c.Payload.Ts.Int64()
			body, cdj, err := signTicket(priv, c.Payload.SupervisorID, c.Payload.ID, c.Payload.Digest, c.Payload.Decision, ts, c.Payload.Nonce)
			if err != nil {
				t.Fatal(err)
			}
			if body.DeviceID != c.DeviceID || body.Signature != c.Signature {
				t.Fatalf("%s/%s: ticket signature %s", dir, c.Name, body.Signature)
			}
			if string(cdj) != c.ClientDataJSON {
				t.Fatalf("%s/%s: clientDataJSON\n got %s\nwant %s", dir, c.Name, cdj, c.ClientDataJSON)
			}
			h := sha256.Sum256(cdj)
			if hex.EncodeToString(h[:]) != c.ClientDataHashHex || !strings.Contains(string(cdj), c.Challenge) {
				t.Fatalf("%s/%s: clientDataHash/challenge", dir, c.Name)
			}
			// the ticket body is parsed the same way as in wardend
			raw, _ := json.Marshal(body)
			if _, err := envelope.ParseDecision(raw); err != nil {
				t.Fatalf("%s/%s: ParseDecision: %v", dir, c.Name, err)
			}
		}
	}
}
