// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type vectorFile struct {
	Cases []struct {
		Name      string          `json:"name"`
		Envelope  bool            `json:"envelope"`
		Value     json.RawMessage `json:"value"`
		Canonical string          `json:"canonical"`
		Sha256    string          `json:"sha256"`
	} `json:"cases"`
}

func loadVectors(t *testing.T, path string) vectorFile {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(b, &vf); err != nil {
		t.Fatal(err)
	}
	if len(vf.Cases) == 0 {
		t.Fatal("no cases")
	}
	return vf
}

// Cross-test: fixtures were built by the plugin's canonical.js (== app canonical.ts);
// the Go encoder must produce identical bytes and the same sha256.
func TestCanonicalVectors(t *testing.T) {
	vf := loadVectors(t, filepath.FromSlash(vectorsDir+"/canonical_vectors.json"))
	for _, c := range vf.Cases {
		v, err := ParseJSON(c.Value)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		got, err := Canonical(v)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if string(got) != c.Canonical {
			t.Errorf("%s:\n got  %s\n want %s", c.Name, got, c.Canonical)
		}
		if SHA256Hex(got) != c.Sha256 {
			t.Errorf("%s: sha256 mismatch", c.Name)
		}
		if c.Envelope {
			// same envelope built with typed structs, as the supervisor does
			var raw struct {
				Argv        []string  `json:"argv"`
				Cwd         string    `json:"cwd"`
				Exe         string    `json:"exe"`
				UID         int       `json:"uid"`
				GID         int       `json:"gid"`
				PpidChain   []Link    `json:"ppidChain"`
				Env         []EnvVar  `json:"env"`
				EnvHash     string    `json:"envHash"`
				Requester   Requester `json:"requester"`
				PidfdCookie string    `json:"pidfdCookie"`
				Ts          int64     `json:"ts"`
				Nonce       string    `json:"nonce"`
			}
			if err := json.Unmarshal(c.Value, &raw); err != nil {
				t.Fatal(err)
			}
			e := Exec{Argv: raw.Argv, Cwd: raw.Cwd, Exe: raw.Exe, UID: raw.UID, GID: raw.GID, PpidChain: raw.PpidChain,
				Env: raw.Env, EnvHash: raw.EnvHash, Requester: raw.Requester, PidfdCookie: raw.PidfdCookie, Ts: raw.Ts, Nonce: raw.Nonce}
			canon, d, err := e.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			if string(canon) != c.Canonical || d != c.Sha256 {
				t.Errorf("%s: typed envelope differs:\n got  %s\n want %s", c.Name, canon, c.Canonical)
			}
		}
	}
}

// vectorsDir: the single copy of protocol vectors in the monorepo (protocol/vectors).
// Daemon, app, and plugin tests read it directly; no copies.
const vectorsDir = "../../protocol/vectors"

func TestCanonicalRejectsInvalidUTF8(t *testing.T) {
	e := Exec{Argv: []string{"ls", "\xff\xfe"}}
	if _, _, err := e.Canonical(); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("want UTF-8 error, got %v", err)
	}
}

func TestTicketSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	did := DeviceID(pub)
	devs := NewDevices([]TrustedDevice{{ID: did, Pubkey: B64URL(pub)}}, "")
	e := Exec{Argv: []string{"rm", "-rf", "/tmp/x"}, Cwd: "/tmp", Exe: "/usr/bin/rm", Ts: NowMs(), Nonce: NewNonce()}
	_, digest, _ := e.Canonical()
	id := PendingID(digest)
	pending := map[string]string{id: digest}
	nonces := NewNonceCache(time.Minute)
	sup := SHA256Hex([]byte("supervisor key"))
	ctx := func() VerifyCtx {
		return VerifyCtx{Now: time.Now(), TsWindow: time.Minute, SupervisorID: sup, Devices: devs, Nonces: nonces, Pending: func(i string) string { return pending[i] }}
	}
	b := Sign(priv, sup, id, digest, "allow", NowMs(), NewNonce())
	// via JSON, as over the socket
	raw, _ := json.Marshal(b)
	pb, err := ParseDecision(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r := Verify(pb, ctx()); r != "" {
		t.Fatalf("valid ticket rejected: %s", r)
	}
	if r := Verify(pb, ctx()); r != "nonce_reused" {
		t.Fatalf("replay: %s", r)
	}
	// foreign key impersonating a trusted deviceId
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	f := Sign(priv2, sup, id, digest, "allow", NowMs(), NewNonce())
	f.DeviceID = did
	if r := Verify(&f, ctx()); r != "bad_signature" {
		t.Fatalf("forged: %s", r)
	}
	// untrusted device
	u := Sign(priv2, sup, id, digest, "allow", NowMs(), NewNonce())
	if r := Verify(&u, ctx()); r != "untrusted_device" {
		t.Fatalf("untrusted: %s", r)
	}
	// signature over a different digest
	e2 := e
	e2.Argv = []string{"rm", "-rf", "/tmp/y"}
	_, d2, _ := e2.Canonical()
	x := Sign(priv, sup, id, d2, "allow", NowMs(), NewNonce())
	if r := Verify(&x, ctx()); r != "digest_mismatch" {
		t.Fatalf("digest: %s", r)
	}
	// stale timestamp
	s := Sign(priv, sup, id, digest, "allow", NowMs()-120_000, NewNonce())
	if r := Verify(&s, ctx()); r != "stale_timestamp" {
		t.Fatalf("stale: %s", r)
	}
	// foreign db key under id of a pinned device: not its key (sha256 != id), config key is used
	devs2 := NewDevices([]TrustedDevice{{ID: did, Pubkey: B64URL(pub)}}, "/nonexistent")
	devs2.Lookup = func(string) (string, error) { return B64URL(priv2.Public().(ed25519.PublicKey)), nil }
	if k, r := devs2.Key(did); r != "" || !k.Equal(Ed25519Key(pub)) {
		t.Fatalf("foreign db key with pinned config key: %s", r)
	}
	// key from DB only
	devs3 := NewDevices([]TrustedDevice{{ID: did}}, "/x")
	devs3.Lookup = func(string) (string, error) { return B64URL(pub), nil }
	if k, r := devs3.Key(did); r != "" || !k.Equal(Ed25519Key(pub)) {
		t.Fatalf("db key: %s", r)
	}
}
