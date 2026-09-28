// SPDX-License-Identifier: AGPL-3.0-or-later

package journal

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestJournalHeadAndCutTail: crypto review 2026-09-28, finding 6: deleting the last lines of a
// journal leaves a chain that verifies on its own. The head (seq and hash of the last entry) is
// reported by the journal for the signed status and by Verify, and ExpectHead turns a pinned head
// into a failure when the file ends elsewhere.
func TestJournalHeadAndCutTail(t *testing.T) {
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
	if h := j.Head(); h.Seq != 0 || h.Hash != Genesis {
		t.Fatalf("empty head: %+v", h)
	}
	for i := 0; i < 3; i++ {
		if _, err := j.Append("exec", map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	head := j.Head()
	j.Close()
	j2, err := Open(p, key) // the head survives a reopen
	if err != nil || j2.Head() != head || head.Seq != 3 {
		t.Fatalf("head after reopen: %+v (%v), want %+v", j2.Head(), err, head)
	}
	j2.Close()

	pub := key.Public().(ed25519.PublicKey)
	b, _ := os.ReadFile(p)
	r := Verify(bytes.NewReader(b), pub)
	if !r.OK || r.Head == nil || *r.Head != head {
		t.Fatalf("verify head: %+v, want %+v", r, head)
	}
	if r2 := r.ExpectHead(head); !r2.OK {
		t.Fatalf("right head: %+v", r2)
	}
	// the tail cut off: still a valid chain on its own, only the pinned head shows it
	lines := strings.SplitAfter(string(b), "\n")
	cut := strings.Join(lines[:2], "")
	rc := Verify(strings.NewReader(cut), pub)
	if !rc.OK || rc.Entries != 2 || rc.Head == nil || rc.Head.Seq != 2 {
		t.Fatalf("cut tail must verify on its own: %+v", rc)
	}
	if rc2 := rc.ExpectHead(head); rc2.OK || rc2.Error != "head_mismatch" || rc2.BadSeq != 2 || rc2.Head.Seq != 2 {
		t.Fatalf("cut tail against the pinned head: %+v", rc2)
	}
	if r3 := r.ExpectHead(Head{Seq: 3, Hash: strings.Repeat("00", 32)}); r3.OK || r3.Error != "head_mismatch" {
		t.Fatalf("wrong hash: %+v", r3)
	}
	if r4 := Verify(strings.NewReader(""), pub).ExpectHead(head); r4.OK || r4.Error != "head_mismatch" || r4.BadSeq != 0 {
		t.Fatalf("empty file against the pinned head: %+v", r4)
	}
	if r5 := Verify(strings.NewReader(""), pub).ExpectHead(Head{Hash: Genesis}); !r5.OK {
		t.Fatalf("empty file with the genesis head: %+v", r5)
	}
	// a failed verification keeps its own error
	bad := strings.Replace(string(b), `"i":1`, `"i":7`, 1)
	if r6 := Verify(strings.NewReader(bad), pub).ExpectHead(head); r6.OK || r6.Error != "hash_mismatch" {
		t.Fatalf("tampered file: %+v", r6)
	}

	// --expect-head takes the head as one string
	if h, err := ParseHead(fmt.Sprintf("%d:%s", head.Seq, head.Hash)); err != nil || h != head {
		t.Fatalf("ParseHead: %+v %v", h, err)
	}
	for _, s := range []string{"", "3", ":" + head.Hash, "x:" + head.Hash, "3:" + head.Hash[:63], "-1:" + head.Hash,
		"3:" + strings.ToUpper(head.Hash), "3:" + head.Hash + "0", "3:" + strings.Repeat("zz", 32)} {
		if h, err := ParseHead(s); err == nil {
			t.Errorf("ParseHead(%q) = %+v", s, h)
		}
	}
}
