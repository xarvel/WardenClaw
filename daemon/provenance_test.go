// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentWritable(t *testing.T) {
	cases := []struct {
		name string
		ev   *execEvent
		want bool
	}{
		{"owner is the agent", &execEvent{Target: "/x", TargetUID: 1000, UID: 1000, TargetMode: 0o755}, true},
		{"root-owned 0755 system file", &execEvent{Target: "/usr/bin/ls", TargetUID: 0, UID: 1000, TargetMode: 0o755}, false},
		{"group/other writable", &execEvent{Target: "/x", TargetUID: 0, UID: 1000, TargetMode: 0o757}, true},
		{"no target", &execEvent{Target: "", TargetUID: 1000, UID: 1000, TargetMode: 0o755}, false},
	}
	for _, k := range cases {
		if got := agentWritable(k.ev); got != k.want {
			t.Errorf("%s: agentWritable = %v, want %v", k.name, got, k.want)
		}
	}
}

// Control bytes (ESC, BEL, NUL) are dropped, printable text and \n\t are kept: terminal escape
// sequences must not get onto the card or into the journal.
func TestSanitizeHead(t *testing.T) {
	got := sanitizeHead([]byte("#!/bin/sh\n\x1b[31mrm\x07 -rf\t.\x00end"))
	want := "#!/bin/sh\n[31mrm -rf\t.end"
	if got != want {
		t.Errorf("sanitizeHead = %q, want %q", got, want)
	}
}

func TestProvenanceScriptAndOther(t *testing.T) {
	dir := t.TempDir()
	sc := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(sc, []byte("#!/bin/bash\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := provenance(sc)
	if p.Kind != "script" || !strings.HasSuffix(p.Interp, "bash") || !strings.Contains(p.Head, "echo hi") || p.SHA256 == "" {
		t.Fatalf("script provenance: %+v", p)
	}
	f := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(f, []byte("plain data, not elf, no shebang"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p := provenance(f); p.Kind != "other" || p.SHA256 == "" {
		t.Fatalf("other provenance: %+v", p)
	}
}

func TestProvenanceELF(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "net.c")
	if err := os.WriteFile(src, []byte("#include <sys/socket.h>\nint main(){return socket(2,1,0)<0;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	netbin := filepath.Join(dir, "netbin")
	if b, err := exec.Command(cc, "-o", netbin, src).CombinedOutput(); err != nil {
		t.Fatalf("cc: %v %s", err, b)
	}
	p := provenance(netbin)
	if p.Kind != "elf-dynamic" || !p.Net || len(p.Libs) == 0 || p.SHA256 == "" {
		t.Fatalf("dynamic net elf provenance: %+v", p)
	}
	stbin := filepath.Join(dir, "stbin")
	if b, err := exec.Command(cc, "-static", "-o", stbin, src).CombinedOutput(); err != nil {
		t.Skipf("no static libc available: %v %s", err, b)
	}
	if ps := provenance(stbin); ps.Kind != "elf-static" {
		t.Fatalf("static elf provenance: %+v", ps)
	}
}
