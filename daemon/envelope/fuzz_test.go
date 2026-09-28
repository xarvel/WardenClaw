// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

// Native fuzz targets for everything in this package that parses bytes from the other side of
// a connection: canonical JSON, tickets, pairing requests, pair links, base64url. The seed corpus
// is the protocol vectors (protocol/vectors/*.json), so each target starts from the inputs the
// app produces. daemon.yml runs every target for a short time on each push; a crash lands in
// testdata/fuzz/<Target>/ and runs as a regular test from then on (go test ./envelope).
//
//	go test -run='^$' -fuzz=FuzzCanonical -fuzztime=30s ./envelope
//
// The properties checked are those the rest of wardend relies on: no panic on any input; what
// parses re-encodes to the same bytes (the digest of an envelope and the signing string of a
// ticket are computed on both sides from a re-parse); what is refused stays refused.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"
)

func readVectors(f *testing.F, name string) []byte {
	f.Helper()
	b, err := os.ReadFile(filepath.FromSlash(vectorsDir + "/" + name))
	if err != nil {
		f.Fatal(err)
	}
	return b
}

// FuzzCanonical: ParseJSON + Canonical never panics, and the canonical form is a fixed point:
// parsing it again and encoding again gives the same bytes and therefore the same digest.
func FuzzCanonical(f *testing.F) {
	var vf vectorFile
	if err := json.Unmarshal(readVectors(f, "canonical_vectors.json"), &vf); err != nil {
		f.Fatal(err)
	}
	for _, c := range vf.Cases {
		f.Add([]byte(c.Value))
		f.Add([]byte(c.Canonical))
	}
	for _, s := range []string{
		`{}`, `[]`, `null`, `-0`, `1e21`, `1E-7`, `9007199254740993`, `-9007199254740992`,
		`{"b":1,"a":[true,false,null,"  <>&\u007f"]}`,
		`{"😀":1,"￿":2,"":3}`,
		`"` + "\xff" + `"`, `123456789012345678901234567890`, `0.1`, `1e400`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := ParseJSON(data)
		if err != nil {
			return
		}
		canon, digest, err := Digest(v)
		if err != nil {
			return
		}
		if !json.Valid(canon) {
			t.Fatalf("canonical form is not JSON: %q", canon)
		}
		if !utf8.Valid(canon) {
			t.Fatalf("canonical form is not UTF-8: %q", canon)
		}
		v2, err := ParseJSON(canon)
		if err != nil {
			t.Fatalf("canonical form does not parse: %q: %v", canon, err)
		}
		canon2, digest2, err := Digest(v2)
		if err != nil {
			t.Fatalf("canonical form does not re-encode: %q: %v", canon, err)
		}
		if !bytes.Equal(canon, canon2) || digest != digest2 {
			t.Fatalf("not a fixed point:\n first  %q\n second %q", canon, canon2)
		}
	})
}

// FuzzEnvelope: an Exec built from arbitrary field values either refuses (invalid UTF-8) or
// canonicalizes to bytes that re-parse and re-encode to the same digest, which is what the
// app does on its side before signing a ticket.
func FuzzEnvelope(f *testing.F) {
	f.Add("exec", "/bin/sh", "-c", "/home/user", "/usr/bin/bash", 1000, int64(1790447985039), "00112233445566778899aabbccddeeff", "HOME", "/home/user")
	f.Add("rootexec", "/usr/bin/systemctl", "restart", "/", "/usr/bin/systemctl", 0, int64(0), "", "", "")
	f.Add("", "\xff", "", "", "", -1, int64(-1), " ", "PATH", "\x00")
	f.Fuzz(func(t *testing.T, typ, argv0, argv1, cwd, exe string, uid int, ts int64, nonce, envName, envValue string) {
		e := Exec{
			Type: typ, Argv: []string{argv0, argv1}, Cwd: cwd, Exe: exe, UID: uid, GID: uid,
			PpidChain: []Link{{Pid: uid, Exe: exe}}, Env: []EnvVar{{Name: envName, Value: envValue, Cut: uid}},
			EnvHash: SHA256Hex([]byte(envValue)), Requester: Requester{Host: cwd, SupervisorID: nonce},
			PidfdCookie: "pidfs:1", Ts: ts, Nonce: nonce,
		}
		canon, digest, err := e.Canonical()
		if err != nil {
			return
		}
		v, err := ParseJSON(canon)
		if err != nil {
			t.Fatalf("envelope does not parse: %q: %v", canon, err)
		}
		canon2, digest2, err := Digest(v)
		if err != nil || !bytes.Equal(canon, canon2) || digest != digest2 {
			t.Fatalf("envelope is not a fixed point (%v):\n first  %q\n second %q", err, canon, canon2)
		}
		if len(digest) != 64 {
			t.Fatalf("digest %q", digest)
		}
		_ = PendingID(digest)
	})
}

// FuzzTicket: ParseDecision never panics; a ticket it accepts has a signing string and a
// second-factor challenge, and survives a JSON round trip with the same signing string (a journal
// entry that carries the ticket re-parses to the bytes that were signed).
func FuzzTicket(f *testing.F) {
	var hw struct {
		Cases []struct {
			DeviceID string          `json:"deviceId"`
			Payload  json.RawMessage `json:"payload"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(readVectors(f, "hw_vectors.json"), &hw); err != nil {
		f.Fatal(err)
	}
	for _, c := range hw.Cases {
		f.Add([]byte(`{"deviceId":"` + c.DeviceID + `","payload":` + string(c.Payload) + `,"signature":"AQID"}`))
	}
	hex64 := SHA256Hex([]byte("seed"))
	hw0 := `{"credentialId":"AQID","clientDataJSON":"AQID","authenticatorData":"AQID","signature":"AQID"}`
	f.Add([]byte(`{"deviceId":"` + hex64 + `","payload":{"type":"wardenclaw.ticket.exec.v1","supervisorId":"` + hex64 +
		`","id":"wd-0","digest":"` + hex64 + `","decision":"deny","ts":1,"nonce":"12345678","risk":100},"signature":"AQID","hw":` + hw0 + `}`))
	f.Add([]byte(`{"deviceId":"` + hex64 + `","payload":{"type":"wardenclaw.ticket.exec.v1","supervisorId":"` + hex64 +
		`","id":"wd-0","digest":"` + hex64 + `","decision":"allow","ts":"1","nonce":"12345678","risk":1.0},"signature":"AQID"}`))
	f.Add([]byte(`{"deviceId":"` + hex64 + `","payload":{"type":"wardenclaw.ticket.exec.v1","supervisorId":"` + hex64 +
		`","id":"wd-0","digest":"` + hex64 + `","decision":"allow","ts":9007199254740993,"nonce":"12345678"},"signature":"AQID"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := ParseDecision(data)
		if err != nil {
			return
		}
		msg, err := SigningString(b.DeviceID, b.Payload)
		if err != nil {
			t.Fatalf("accepted ticket has no signing string: %s: %v", data, err)
		}
		if _, err := HWChallenge(b.DeviceID, b.Payload); err != nil {
			t.Fatalf("accepted ticket has no hw challenge: %s: %v", data, err)
		}
		if _, ok := b.Payload.RiskScore(); ok != (b.Payload.Risk != nil) {
			t.Fatalf("risk present but unreadable: %s", data)
		}
		again, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("accepted ticket does not marshal: %s: %v", data, err)
		}
		b2, err := ParseDecision(again)
		if err != nil {
			t.Fatalf("re-marshaled ticket refused (%v): %s -> %s", err, data, again)
		}
		msg2, err := SigningString(b2.DeviceID, b2.Payload)
		if err != nil || !bytes.Equal(msg, msg2) {
			t.Fatalf("signing string changed over a round trip (%v):\n first  %s\n second %s", err, msg, msg2)
		}
	})
}

// FuzzPairPayload: a pairing request body of any shape has a signing string or an error, never
// a panic, and the signing string re-parses as canonical JSON.
func FuzzPairPayload(f *testing.F) {
	var rv struct {
		Pair struct {
			Payload json.RawMessage `json:"payload"`
		} `json:"pair"`
	}
	if err := json.Unmarshal(readVectors(f, "relay_vectors.json"), &rv); err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(rv.Pair.Payload))
	f.Add([]byte(`{"code":"K7Q4M2XD","deviceId":"` + SHA256Hex([]byte("seed")) + `","pubkey":"AQID","alg":"ed25519","name":"n","supervisorId":"s","ts":1,"nonce":"0f1e2d3c"}`))
	f.Add([]byte(`{"name":"\xff"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var p PairPayload
		if err := json.Unmarshal(data, &p); err != nil {
			return
		}
		msg, err := PairSigningString(p)
		if err != nil {
			return
		}
		v, err := ParseJSON(msg)
		if err != nil {
			t.Fatalf("signing string is not JSON: %q", msg)
		}
		msg2, err := Canonical(v)
		if err != nil || !bytes.Equal(msg, msg2) {
			t.Fatalf("signing string is not a fixed point (%v): %q vs %q", err, msg, msg2)
		}
		if _, err := NormalizeAlg(p.Alg); err == nil {
			_, _ = ParseDeviceKey(p.Alg, p.Pubkey)
		}
		_ = NormalizeCode(p.Code)
		_ = Fingerprint(p.DeviceID)
	})
}

// FuzzPairLink: ParsePairLink never panics, and a link it accepts prints back to a link that
// parses to the same values (the QR content round trip between wardend and wardenctl pair).
func FuzzPairLink(f *testing.F) {
	var rv struct {
		Link struct {
			Text string `json:"text"`
		} `json:"link"`
	}
	if err := json.Unmarshal(readVectors(f, "relay_vectors.json"), &rv); err != nil {
		f.Fatal(err)
	}
	f.Add(rv.Link.Text)
	f.Add("wardenclaw://pair?v=1")
	f.Add("wardenclaw://pair?code=&enc=&key=&relay=ws://x&sid=&v=2")
	f.Add("https://example.com/?v=1")
	f.Add("wardenclaw://pair?%zz")
	f.Fuzz(func(t *testing.T, s string) {
		l, err := ParsePairLink(s)
		if err != nil {
			return
		}
		l2, err := ParsePairLink(l.String())
		if err != nil {
			t.Fatalf("printed link refused: %q -> %q: %v", s, l.String(), err)
		}
		if l2 != l {
			t.Fatalf("link changed over a round trip: %+v vs %+v", l, l2)
		}
	})
}

// FuzzB64URL: DecodeB64URL accepts exactly one spelling of any byte string, the one B64URL
// prints, and DecodeKey refuses everything that is not a 32-byte key of full order.
func FuzzB64URL(f *testing.F) {
	for _, s := range []string{"", "-_8BAg", "AQI=", "AR", "A", "+/8BAg", " AQI",
		"ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ",
		"65b60673d6ed884bf01c2c222d82ada0740f29ac3355d6a925c81f17f47a27b8",
		"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if b, err := DecodeB64URL(s); err == nil {
			if B64URL(b) != s {
				t.Fatalf("%q decodes to %x, which prints as %q", s, b, B64URL(b))
			}
			if _, err := DecodeB64URL(s + "="); err == nil {
				t.Fatalf("padded spelling of %q accepted", s)
			}
		}
		if k, err := DecodeKey(s); err == nil {
			if len(k) != 32 || smallOrderEd25519(k) {
				t.Fatalf("DecodeKey(%q) = %x", s, k)
			}
			if DeviceID(k) == "" {
				t.Fatal("empty device id")
			}
		}
	})
}
