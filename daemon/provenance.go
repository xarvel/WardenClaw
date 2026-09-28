// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Provenance of the executable. A file owned by the agent or writable by it could have been made
// from anything, whatever its name (a renamed curl, a copy of busybox, a custom ELF). Such a launch,
// not recognized by the rules, becomes a card with facts about the file for the judge and the
// human:
//   - sha256 of the file, to recognize what is already approved and issue a mandate for that hash;
//   - for a script with a shebang: the interpreter and the start of the text (safely truncated);
//   - for an ELF: static or dynamic, NEEDED libraries, whether there are network imports.
// The rule for the judge is simple: if a program is not from packages and its content is unclear,
// ask, do not guess.

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"io"
	"os"
	"slices"
	"strings"
)

const (
	provHeadMax = 512      // how many bytes of the script start to show the judge and on the card
	provHashMax = 64 << 20 // hash at most 64 MB (protection against giant files)
)

type provInfo struct {
	Kind   string   `json:"kind"`             // elf-dynamic | elf-static | script | other
	SHA256 string   `json:"sha256,omitempty"` // hash of the target file (for the mandate and recognition)
	Interp string   `json:"interp,omitempty"` // shebang interpreter (kind=script)
	Head   string   `json:"head,omitempty"`   // start of the script text, without control bytes
	Libs   []string `json:"libs,omitempty"`   // ELF: NEEDED libraries
	Net    bool     `json:"net,omitempty"`    // ELF: some imports give network access
}

// netSyms: substrings of imported symbols that indicate network capabilities (a heuristic for
// dynamic ELF; a static one has no import table, so the flag is not determined there).
var netSyms = []string{"socket", "connect", "getaddrinfo", "gethostbyname", "sendto", "recvfrom",
	"curl_easy", "SSL_connect"}

// importsNetwork: some imported symbol contains one of netSyms.
func importsNetwork(syms []elf.ImportedSymbol) bool {
	for _, s := range syms {
		for _, n := range netSyms {
			if strings.Contains(s.Name, n) {
				return true
			}
		}
	}
	return false
}

// agentWritable: the target file belongs to the caller (the agent) or is writable by group/others,
// i.e. the agent could have created or rewritten it. Costs next to nothing: uid/mode are already
// collected in resolveTarget.
func agentWritable(ev *execEvent) bool {
	if ev.Target == "" {
		return false
	}
	if int(ev.TargetUID) == ev.UID {
		return true
	}
	return ev.TargetMode&0o022 != 0
}

func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, provHashMax)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// provenance: a summary of the target file. Called only when the launch becomes a card anyway (a
// rare path), so the cost of reading the file and parsing the ELF is acceptable.
func provenance(target string) *provInfo {
	p := &provInfo{Kind: "other", SHA256: fileSHA256(target)}
	if interp, _, ok := shebang(target); ok {
		p.Kind, p.Interp, p.Head = "script", interp, scriptHead(target)
		return p
	}
	f, err := elf.Open(target)
	if err != nil {
		return p
	}
	defer f.Close()
	if !slices.ContainsFunc(f.Progs, func(prog *elf.Prog) bool { return prog.Type == elf.PT_DYNAMIC }) {
		p.Kind = "elf-static"
		return p
	}
	p.Kind = "elf-dynamic"
	if libs, err := f.ImportedLibraries(); err == nil {
		p.Libs = libs
	}
	if syms, err := f.ImportedSymbols(); err == nil {
		p.Net = importsNetwork(syms)
	}
	return p
}

func scriptHead(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, provHeadMax)
	n, _ := f.Read(buf)
	return sanitizeHead(buf[:n])
}

// sanitizeHead: a printable prefix without control bytes: raw terminal control sequences must not
// get into the journal or onto the card. Printable ASCII, \n, \t and high bytes (UTF-8 text) pass;
// everything else (including ESC) is dropped.
func sanitizeHead(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c == '\n' || c == '\t' || (c >= 0x20 && c != 0x7f) {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// provKind: the Hit rule for the journal ("self-built/<kind>").
func provKind(p *provInfo) string {
	if p == nil {
		return "unknown"
	}
	return p.Kind
}
