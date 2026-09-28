// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// argv as execve sees it: a NULL-terminated array of pointers to C strings in the caller's memory.
// A regular file stands in for /proc/<pid>/mem (readMem only needs ReadAt).
func TestReadStrArray(t *testing.T) {
	const arrayAt, stringsAt = 64, 1024
	mem := make([]byte, 4096)
	want := []string{"sh", "-c", "echo hi", ""}
	next := uint64(stringsAt)
	for i, s := range want {
		binary.LittleEndian.PutUint64(mem[arrayAt+8*i:], next)
		copy(mem[next:], s+"\x00")
		next += uint64(len(s) + 1)
	}
	// the NULL pointer after the last element is already zero
	path := filepath.Join(t.TempDir(), "mem")
	if err := os.WriteFile(path, mem, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if got, err := readStrArray(f, arrayAt); err != nil || !slices.Equal(got, want) {
		t.Errorf("readStrArray = %q, %v; want %q", got, err, want)
	}
	if got, err := readStrArray(f, 0); got != nil || err != nil {
		t.Errorf("NULL array: %q, %v; want nil, nil", got, err)
	}
	// an array that runs off the end of memory is an error, not a shorter argv
	if _, err := readStrArray(f, uint64(len(mem)-4)); err == nil {
		t.Error("array cut by the end of memory: no error")
	}
}
