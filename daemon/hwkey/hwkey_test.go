// SPDX-License-Identifier: AGPL-3.0-or-later

package hwkey_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/hwkey"
	"github.com/xarvel/WardenClaw/daemon/hwkey/hwkeytest"
)

func both() []*hwkeytest.Authenticator {
	return []*hwkeytest.Authenticator{hwkeytest.NewEd25519(hwkey.DefaultRPID), hwkeytest.NewES256(hwkey.DefaultRPID)}
}

func challenge(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

func TestRegistrationFormats(t *testing.T) {
	for _, a := range both() {
		for _, f := range []string{"none", "packed-self", "packed-x5c"} {
			cdj := hwkey.ClientDataJSON("webauthn.create", challenge("reg"))
			att := a.MakeCredential(cdj, f)
			r, err := hwkey.ParseRegistration(att, cdj, "", time.Now())
			if err != nil {
				t.Fatalf("%s/%s: %v", hwkey.AlgName(a.Alg), f, err)
			}
			if r.Key.ID != hwkey.B64(a.CredID) || r.Key.PublicKey != hwkey.B64(a.COSE()) || r.Key.Alg != hwkey.AlgName(a.Alg) || r.Key.RPID != "wardenclaw" {
				t.Fatalf("%s/%s: key %+v", hwkey.AlgName(a.Alg), f, r.Key)
			}
			if f == "packed-x5c" && !strings.Contains(r.Key.Attestation, "Soft FIDO EE") {
				t.Fatalf("attestation %q", r.Key.Attestation)
			}
			// via the app blob
			blob := (&hwkey.Blob{CredentialID: hwkey.B64(a.CredID), AttestationObject: hwkey.B64(att), ClientDataJSON: hwkey.B64(cdj), RPID: "wardenclaw", Name: "yk"}).Encode()
			if b, err := hwkey.ParseBlob(blob); err != nil || b.Name != "yk" {
				t.Fatal(err)
			}
		}
	}
}

func TestRegistrationRejects(t *testing.T) {
	a := hwkeytest.NewES256("wardenclaw")
	cdj := hwkey.ClientDataJSON("webauthn.create", challenge("reg"))
	att := a.MakeCredential(cdj, "packed-self")
	if _, err := hwkey.ParseRegistration(att, cdj, "evil.example", time.Now()); err == nil {
		t.Fatal("rp_id mismatch accepted")
	}
	other := hwkey.ClientDataJSON("webauthn.create", challenge("other"))
	if _, err := hwkey.ParseRegistration(att, other, "", time.Now()); err == nil {
		t.Fatal("packed signature over other clientData accepted")
	}
	if _, err := hwkey.ParseRegistration(att, hwkey.ClientDataJSON("webauthn.get", challenge("reg")), "", time.Now()); err == nil {
		t.Fatal("webauthn.get accepted for registration")
	}
	x := a.MakeCredential(cdj, "packed-x5c")
	x[len(x)-5] ^= 1 // corrupt signature/certificate
	if _, err := hwkey.ParseRegistration(x, cdj, "", time.Now()); err == nil {
		t.Fatal("corrupted x5c attestation accepted")
	}
	if _, err := hwkey.ParseRegistration([]byte{0xa0}, nil, "", time.Now()); err == nil {
		t.Fatal("empty map accepted")
	}
}

func store(t *testing.T, keys ...hwkey.Key) (*hwkey.Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hw_counters.json")
	s, err := hwkey.NewStore(keys, p)
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}

func TestAssertionOK(t *testing.T) {
	for _, a := range both() {
		s, p := store(t, a.Key())
		c := challenge("ticket-1")
		r, reason := s.VerifyAssertion(a.Assert(c), c)
		if reason != "" || r.SignCount != 1 {
			t.Fatalf("%s: %q %+v", hwkey.AlgName(a.Alg), reason, r)
		}
		// counter is persisted to disk and survives restart
		s2, err := hwkey.NewStore([]hwkey.Key{a.Key()}, p)
		if err != nil || s2.Counter(hwkey.B64(a.CredID)) != 1 {
			t.Fatalf("persisted counter: %v %d", err, s2.Counter(hwkey.B64(a.CredID)))
		}
		c2 := challenge("ticket-2")
		if _, reason := s2.VerifyAssertion(a.Assert(c2), c2); reason != "" {
			t.Fatal(reason)
		}
	}
}

func TestAssertionRejects(t *testing.T) {
	for _, a := range both() {
		name := hwkey.AlgName(a.Alg)
		stranger := hwkeytest.NewEd25519("wardenclaw")
		s, _ := store(t, a.Key())
		c := challenge("ticket")
		cases := []struct {
			name   string
			as     func() *hwkey.Assertion
			reason string
		}{
			{"missing", func() *hwkey.Assertion { return nil }, "hardware_required"},
			{"forged signature", func() *hwkey.Assertion {
				x := a.Assert(c)
				sig, _ := b64(x.Signature)
				sig[len(sig)-3] ^= 1
				x.Signature = hwkey.B64(sig)
				return x
			}, "hw_bad_signature"},
			{"tampered authData (UV bit)", func() *hwkey.Assertion {
				x := a.Assert(c)
				ad, _ := b64(x.AuthenticatorData)
				ad[32] |= hwkey.FlagUV
				x.AuthenticatorData = hwkey.B64(ad)
				return x
			}, "hw_bad_signature"},
			{"foreign key, unknown credential", func() *hwkey.Assertion { return stranger.Assert(c) }, "hw_unknown_credential"},
			{"foreign key under our credentialId", func() *hwkey.Assertion {
				x := stranger.Assert(c)
				x.CredentialID = hwkey.B64(a.CredID)
				return x
			}, "hw_bad_signature"},
			{"other digest", func() *hwkey.Assertion { return a.Assert(challenge("other-ticket")) }, "hw_challenge_mismatch"},
			{"wrong type", func() *hwkey.Assertion {
				a.Count++
				return a.AssertRaw(hwkey.ClientDataJSON("webauthn.create", c), hwkey.FlagUP, a.Count)
			}, "hw_client_data_type"},
			{"wrong origin", func() *hwkey.Assertion {
				a.Count++
				j, _ := json.Marshal(map[string]string{"type": "webauthn.get", "challenge": hwkey.B64(c), "origin": "https://evil.example"})
				return a.AssertRaw(j, hwkey.FlagUP, a.Count)
			}, "hw_origin"},
			{"no user presence", func() *hwkey.Assertion {
				a.Count++
				return a.AssertRaw(hwkey.ClientDataJSON("webauthn.get", c), 0, a.Count)
			}, "hw_user_presence"},
			{"other rp", func() *hwkey.Assertion {
				rp := a.RPID
				a.RPID = "evil.example"
				defer func() { a.RPID = rp }()
				return a.Assert(c)
			}, "hw_rpid_mismatch"},
		}
		for _, tc := range cases {
			if _, got := s.VerifyAssertion(tc.as(), c); got != tc.reason {
				t.Errorf("%s/%s: reason %q, want %q", name, tc.name, got, tc.reason)
			}
		}
		// stale signCount: valid signature but counter does not advance (cloned key / replay)
		ok := a.Assert(c)
		if _, r := s.VerifyAssertion(ok, c); r != "" {
			t.Fatalf("%s: %s", name, r)
		}
		if _, r := s.VerifyAssertion(ok, c); r != "hw_counter_replay" {
			t.Errorf("%s: replay: %q", name, r)
		}
		old := a.AssertRaw(hwkey.ClientDataJSON("webauthn.get", c), hwkey.FlagUP, a.Count-1)
		if _, r := s.VerifyAssertion(old, c); r != "hw_counter_replay" {
			t.Errorf("%s: old counter: %q", name, r)
		}
	}
}

func TestRequireUVAndZeroCounter(t *testing.T) {
	a := hwkeytest.NewEd25519("wardenclaw")
	k := a.Key()
	k.RequireUV = true
	s, _ := store(t, k)
	c := challenge("t")
	if _, r := s.VerifyAssertion(a.Assert(c), c); r != "hw_user_verification" {
		t.Fatalf("uv: %q", r)
	}
	a.Count++
	if _, r := s.VerifyAssertion(a.AssertRaw(hwkey.ClientDataJSON("webauthn.get", c), hwkey.FlagUP|hwkey.FlagUV, a.Count), c); r != "" {
		t.Fatalf("uv ok: %q", r)
	}
	// key without a counter (always 0) is accepted as long as the stored counter is also 0
	b := hwkeytest.NewES256("wardenclaw")
	s2, _ := store(t, b.Key())
	for i := 0; i < 2; i++ {
		if _, r := s2.VerifyAssertion(b.AssertRaw(hwkey.ClientDataJSON("webauthn.get", c), hwkey.FlagUP, 0), c); r != "" {
			t.Fatalf("zero counter: %q", r)
		}
	}
}

func TestStoreRejectsBadConfig(t *testing.T) {
	a := hwkeytest.NewEd25519("wardenclaw")
	k := a.Key()
	k.PublicKey = "AAAA"
	if _, err := hwkey.NewStore([]hwkey.Key{k}, ""); err == nil {
		t.Fatal("bad COSE accepted")
	}
	k = a.Key()
	k.RPID = ""
	if _, err := hwkey.NewStore([]hwkey.Key{k}, ""); err == nil {
		t.Fatal("empty rp_id accepted")
	}
	p := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(p, []byte("{broken"), 0o600)
	if _, err := hwkey.NewStore([]hwkey.Key{a.Key()}, p); err == nil {
		t.Fatal("corrupt counters accepted")
	}
	// unsupported algorithm (RS256 -257)
	bad := hwkey.EncodeCBOR(map[any]any{int64(1): int64(3), int64(3): int64(-257)})
	if _, err := hwkey.ParseCOSEKey(bad); err == nil {
		t.Fatal("RS256 accepted")
	}
}

func TestCBORRejectsMalformed(t *testing.T) {
	for _, b := range [][]byte{{0x5f}, {0x9f}, {0xa1, 0x01}, {0x42, 0x01}, {0xa2, 0x01, 0x01, 0x01, 0x02}, {0xfb, 0, 0, 0, 0, 0, 0, 0, 0}} {
		if _, err := hwkey.ParseCOSEKey(b); err == nil {
			t.Errorf("% x accepted", b)
		}
	}
}

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
