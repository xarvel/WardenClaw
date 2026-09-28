// SPDX-License-Identifier: AGPL-3.0-or-later

package journal

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestJournalRejectsUnsafeNumbers: crypto review 2026-09-28, finding 6: an entry with a number that
// is not an integer within the JS safe range is refused at Append instead of being hashed rounded,
// a refused entry does not advance the chain, and Verify reports such a line as bad_number.
func TestJournalRejectsUnsafeNumbers(t *testing.T) {
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
	if _, err := j.Append("exec", map[string]any{"ino": uint64(1<<53 + 1)}); err == nil {
		t.Error("inode beyond 2^53 accepted")
	}
	if _, err := j.Append("exec", map[string]any{"pct": 1.5}); err == nil {
		t.Error("fraction accepted")
	}
	if _, err := j.Append("exec", map[string]any{"chain": []any{map[string]any{"ino": uint64(1<<53 + 1)}}}); err == nil {
		t.Error("nested inode beyond 2^53 accepted")
	}
	if _, err := j.Append("exec", map[string]any{"pid": 42, "nested": []any{map[string]any{"n": 1<<53 - 1, "m": -(1<<53 - 1)}}}); err != nil {
		t.Fatalf("safe integers refused: %v", err)
	}
	j.Close()
	j2, err := Open(p, key)
	if err != nil || j2.seq != 1 {
		t.Fatalf("refused entries must not advance the chain: seq %d, %v", j2.seq, err)
	}
	j2.Close()
	pub := key.Public().(ed25519.PublicKey)
	b, _ := os.ReadFile(p)
	if r := Verify(strings.NewReader(string(b)), pub); !r.OK || r.Entries != 1 {
		t.Fatalf("verify: %+v", r)
	}
	for _, bad := range []string{`"pid":42.5`, `"pid":9007199254740993`, `"pid":1e3`} {
		line := strings.Replace(string(b), `"pid":42`, bad, 1)
		if r := Verify(strings.NewReader(line), pub); r.OK || r.Error != "bad_number" || r.BadSeq != 1 {
			t.Fatalf("%s in the file: %+v", bad, r)
		}
	}
}
