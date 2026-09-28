// SPDX-License-Identifier: AGPL-3.0-or-later

package journal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

func TestJournalChainAndTamper(t *testing.T) {
	dir := t.TempDir()
	key, err := LoadOrCreateKey(filepath.Join(dir, "k"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "j.jsonl")
	j, err := Open(p, key)
	if err != nil {
		t.Fatal(err)
	}
	j.Append("start", map[string]any{"journalKey": j.PublicKey()})
	j.Append("exec", map[string]any{"argv": []string{"ls", "<&>", "bad\xffutf8"}, "decision": "allow"})
	j.Close()
	// chain resumption after reopen
	j2, _ := Open(p, key)
	j2.Append("exec", map[string]any{"argv": []string{"rm", "-rf", "/"}, "decision": "deny"})
	j2.Close()

	f, _ := os.Open(p)
	pub := key.Public().(ed25519.PublicKey)
	if r := Verify(f, pub); !r.OK || r.Entries != 3 {
		t.Fatalf("verify: %+v", r)
	}
	f.Close()
	b, _ := os.ReadFile(p)
	if r := Verify(bytes.NewReader(b), nil); !r.OK {
		t.Fatalf("self-key verify: %+v", r)
	}
	// content tampering
	bad := strings.Replace(string(b), `"deny"`, `"allow"`, 1)
	if r := Verify(strings.NewReader(bad), pub); r.OK || r.Error != "hash_mismatch" {
		t.Fatalf("tamper not detected: %+v", r)
	}
	// line removal
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	cut := lines[0] + "\n" + lines[2] + "\n"
	if r := Verify(strings.NewReader(cut), pub); r.OK {
		t.Fatal("line removal not detected")
	}
	// wrong key
	other, _ := LoadOrCreateKey(filepath.Join(dir, "k2"))
	if r := Verify(bytes.NewReader(b), other.Public().(ed25519.PublicKey)); r.OK || r.Error != "bad_signature" {
		t.Fatalf("wrong key: %+v", r)
	}
	tail, _ := Tail(p, 2)
	if len(tail) != 2 || !strings.Contains(string(tail[1]), `"rm"`) {
		t.Fatalf("tail: %s", tail)
	}
}

// TestJournalSigDomain: crypto review, finding 8: the entry is signed over SigDomain + hash;
// an entry signed by the same key over the bare hash (the old format, no domain prefix) is rejected.
func TestJournalSigDomain(t *testing.T) {
	dir := t.TempDir()
	key, err := LoadOrCreateKey(filepath.Join(dir, "k"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "j.jsonl")
	j, err := Open(p, key)
	if err != nil {
		t.Fatal(err)
	}
	j.Append("start", map[string]any{"journalKey": j.PublicKey()})
	j.Close()
	pub := key.Public().(ed25519.PublicKey)
	b, _ := os.ReadFile(p)
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(b), &m); err != nil {
		t.Fatal(err)
	}
	hash, _ := m["hash"].(string)
	sig, err := envelope.DecodeB64URL(m["sig"].(string))
	if err != nil || !ed25519.Verify(pub, []byte("wardenclaw.journal.v1\n"+hash), sig) || ed25519.Verify(pub, []byte(hash), sig) {
		t.Fatal("the record must be signed over the domain-prefixed hash only")
	}
	old := strings.Replace(string(b), m["sig"].(string), envelope.B64URL(ed25519.Sign(key, []byte(hash))), 1)
	if r := Verify(strings.NewReader(old), pub); r.OK || r.Error != "bad_signature" {
		t.Fatalf("bare-hash signature accepted: %+v", r)
	}
}
