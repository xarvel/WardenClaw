// SPDX-License-Identifier: AGPL-3.0-or-later

// Package journal is the append-only wardend journal: JSONL, hash chain, signature by the
// supervisor key.
//
// The format matches the wardenclaw-gate plugin journal (src/journal.js) so both sides are
// verified the same way:
//
//	body = {seq, ts, kind, data, prevHash}
//	hash = sha256hex(prevHash + canonicalJson(body))
//	sig  = Ed25519(supervisor key, "wardenclaw.journal.v1\n" + hash) base64url
//	line = {...body, hash, sig}
//
// The "wardenclaw.journal.v1\n" prefix is the signing domain (crypto review, finding 8): the
// same supervisor key signs HTTP API responses (envelope.ResponseSigningString), so a journal
// entry signature must not be a valid signature over a string that can be read as something else.
//
// data is passed through encoding/json (invalid UTF-8 -> U+FFFD) and then canonicalized.
package journal

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// Genesis is the prevHash of the first entry.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Line limits for Verify: initial scanner buffer and the longest accepted entry.
const (
	scanBufSize  = 1 << 20
	maxEntrySize = 64 << 20
)

// Journal appends signed entries to a journal file; safe for concurrent use.
type Journal struct {
	mu       sync.Mutex
	f        *os.File
	key      ed25519.PrivateKey
	seq      int64
	lastHash string
}

// Open opens (or creates) the journal file and resumes the chain from the last entry.
func Open(path string, key ed25519.PrivateKey) (*Journal, error) {
	j := &Journal{key: key, lastHash: Genesis}
	if b, err := os.ReadFile(path); err == nil {
		lines := bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
		if last := lines[len(lines)-1]; len(last) > 0 {
			var e struct {
				Seq  int64  `json:"seq"`
				Hash string `json:"hash"`
			}
			if err := json.Unmarshal(last, &e); err != nil {
				return nil, fmt.Errorf("journal %s: last line: %w", path, err)
			}
			j.seq, j.lastHash = e.Seq, e.Hash
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	j.f = f
	return j, nil
}

// Close closes the journal file.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.f.Close()
}

// PublicKey returns the journal verification key as base64url.
func (j *Journal) PublicKey() string { return envelope.B64URL(j.key.Public().(ed25519.PublicKey)) }

// Head is the chain head: seq and hash of the last entry (0 and Genesis for an empty journal).
type Head struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
}

// Head returns the chain head. It goes into the signed status so a reader can pin the file's
// tail: a journal whose last lines were deleted still verifies on its own (crypto review 2026-09-28,
// finding 6), only a pinned head shows the loss.
func (j *Journal) Head() Head {
	j.mu.Lock()
	defer j.mu.Unlock()
	return Head{Seq: j.seq, Hash: j.lastHash}
}

// ParseHead parses "<seq>:<hash>", the form of --expect-head (status.journalHead in one string).
func ParseHead(s string) (Head, error) {
	seqS, hash, ok := strings.Cut(s, ":")
	seq, err := strconv.ParseInt(seqS, 10, 64)
	if _, herr := hex.DecodeString(hash); !ok || err != nil || seq < 0 || herr != nil || len(hash) != 64 || strings.ToLower(hash) != hash {
		return Head{}, fmt.Errorf("want <seq>:<sha256 hex>, got %q", s)
	}
	return Head{Seq: seq, Hash: hash}, nil
}

// ExpectHead fails a successful verification when the file does not end at h: head_mismatch, with
// BadSeq the last entry the file has.
func (r VerifyResult) ExpectHead(h Head) VerifyResult {
	if !r.OK {
		return r
	}
	got := Head{Hash: Genesis}
	if r.Head != nil {
		got = *r.Head
	}
	if got != h {
		r.OK, r.Error, r.BadSeq = false, "head_mismatch", got.Seq
	}
	return r
}

// Append writes an entry and returns it with hash and sig; data is any JSON-serializable value.
func (j *Journal) Append(kind string, data any) (map[string]any, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	dv, err := envelope.ParseJSON(raw)
	if err != nil {
		return nil, err
	}
	if err := checkNumbers(dv); err != nil {
		return nil, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	body := map[string]any{"seq": j.seq + 1, "ts": time.Now().UnixMilli(), "kind": kind, "data": dv, "prevHash": j.lastHash}
	canon, err := envelope.Canonical(body)
	if err != nil {
		return nil, err
	}
	hash := envelope.SHA256Hex(append([]byte(j.lastHash), canon...))
	body["hash"] = hash
	body["sig"] = envelope.B64URL(ed25519.Sign(j.key, SigMessage(hash)))
	// file line is also canonical (deterministic and no HTML escaping)
	line, err := envelope.Canonical(body)
	if err != nil {
		return nil, err
	}
	if _, err := j.f.Write(append(line, '\n')); err != nil {
		return nil, err
	}
	j.seq++
	j.lastHash = hash
	return body, nil
}

// checkNumbers rejects any number in an entry that is not an integer within the JS safe range.
// The daemon writes only integers (pids, counters, millisecond times), so a fraction or a large
// identifier is a bug or a foreign value; hashing it rounded would sign a number nobody produced.
func checkNumbers(v any) error {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		if err != nil || n > envelope.MaxSafeInt || n < -envelope.MaxSafeInt || x.String() != strconv.FormatInt(n, 10) {
			return fmt.Errorf("journal: number %s is not a safe integer", x)
		}
	case map[string]any:
		for k, e := range x {
			if err := checkNumbers(e); err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
		}
	case []any:
		for _, e := range x {
			if err := checkNumbers(e); err != nil {
				return err
			}
		}
	}
	return nil
}

// SigDomain is the prefix of the journal entry signing string.
const SigDomain = "wardenclaw.journal.v1\n"

// SigMessage returns what the supervisor key signs for an entry: SigDomain + hash.
func SigMessage(hash string) []byte { return []byte(SigDomain + hash) }

// VerifyResult is the outcome of Verify: on failure Error names the check and BadSeq the entry.
// Head is the last verified entry, to compare with status.journalHead (ExpectHead).
type VerifyResult struct {
	OK      bool   `json:"ok"`
	Entries int64  `json:"entries"`
	Error   string `json:"error,omitempty"`
	BadSeq  int64  `json:"badSeq,omitempty"`
	Key     string `json:"key,omitempty"`
	Head    *Head  `json:"head,omitempty"`
}

// Verify checks the chain and signatures. pub == nil: the key is taken from the first entry
// with kind=start (data.journalKey), which verifies integrity only; pass the key explicitly
// for trust verification.
func Verify(r io.Reader, pub ed25519.PublicKey) VerifyResult {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, scanBufSize), maxEntrySize)
	prev := Genesis
	var n int64
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		v, err := envelope.ParseJSON(line)
		m, ok := v.(map[string]any)
		if err != nil || !ok {
			return VerifyResult{Entries: n, Error: "invalid_json", BadSeq: n + 1}
		}
		hash, _ := m["hash"].(string)
		sig, _ := m["sig"].(string)
		delete(m, "hash")
		delete(m, "sig")
		seq, _ := m["seq"].(json.Number).Int64()
		if seq != n+1 {
			return VerifyResult{Entries: n, Error: "seq_gap", BadSeq: seq}
		}
		if m["prevHash"] != prev {
			return VerifyResult{Entries: n, Error: "prev_hash_mismatch", BadSeq: seq}
		}
		if checkNumbers(m) != nil {
			return VerifyResult{Entries: n, Error: "bad_number", BadSeq: seq}
		}
		canon, err := envelope.Canonical(m)
		if err != nil || envelope.SHA256Hex(append([]byte(prev), canon...)) != hash {
			return VerifyResult{Entries: n, Error: "hash_mismatch", BadSeq: seq}
		}
		if pub == nil && m["kind"] == "start" {
			if d, ok := m["data"].(map[string]any); ok {
				if k, ok := d["journalKey"].(string); ok {
					pub, _ = envelope.DecodeKey(k)
				}
			}
		}
		if pub == nil {
			return VerifyResult{Entries: n, Error: "no_key", BadSeq: seq}
		}
		s, err := envelope.DecodeB64URL(sig)
		if err != nil || !ed25519.Verify(pub, SigMessage(hash), s) {
			return VerifyResult{Entries: n, Error: "bad_signature", BadSeq: seq}
		}
		prev = hash
		n++
	}
	if err := sc.Err(); err != nil {
		return VerifyResult{Entries: n, Error: err.Error()}
	}
	res := VerifyResult{OK: true, Entries: n}
	if pub != nil {
		res.Key = envelope.B64URL(pub)
	}
	if n > 0 {
		res.Head = &Head{Seq: n, Hash: prev}
	}
	return res
}

// Tail returns the last n lines of the file (for journal.tail).
func Tail(path string, n int) ([]json.RawMessage, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	lines := bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := make([]json.RawMessage, 0, len(lines))
	for _, l := range lines {
		if len(l) > 0 {
			out = append(out, json.RawMessage(l))
		}
	}
	return out, nil
}

// LoadOrCreateKey loads or generates the Ed25519 supervisor key (seed hex, mode 0600).
func LoadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		seed, err := hex.DecodeString(string(bytes.TrimSpace(b)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s: bad key", path)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}
