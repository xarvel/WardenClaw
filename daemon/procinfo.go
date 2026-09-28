// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// The exec event and what is read for it: on Linux argv/envp/filename from the memory of the
// calling thread (on entry to execve they are still in the caller's user space), the realpath
// of the file being executed, the environment hash. Per-OS process facts (ppid, start time,
// ids, exe, cmdline, the ancestor chain) are in procinfo_proc.go and procinfo_darwin.go.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

const (
	maxStr        = 128 * 1024 // max length of one string
	maxArr        = 4096       // max argv/envp elements
	maxChainDepth = 32         // ancestors recorded per exec
	maxSymlinks   = 40         // symlinks followed while resolving a path, as the kernel's MAXSYMLINKS
)

type execEvent struct {
	ID         uint64
	Pid        int // tid of the calling thread (seccomp_notif.pid)
	Tgid       int
	PPid       int
	Start      uint64 // process (tgid) starttime, ticks since boot
	Threads    int
	UID, GID   int // effective
	Syscall    string
	Path       string // filename as passed (for execveat: resolved via dirfd)
	Target     string // realpath of the file being executed ("" if it did not resolve)
	TargetErr  error
	TargetDev  uint64
	TargetIno  uint64
	TargetUID  uint32 // owner of the target file (exe provenance: agent's file or system file)
	TargetMode uint32 // mode of the target file
	MntNs      string // caller's /proc/<pid>/ns/mnt ("" if not read)
	CallerExe  string // caller's /proc/<tgid>/exe (before exec)
	CallerCmd  []string
	Cwd        string
	Argv       []string
	ArgvOK     bool // argv read in full
	EnvHash    string
	EnvCount   int
	Env        []envelope.EnvVar // variables that change program behavior (for envelope and card)
	Chain      []envelope.Link   // [0] is the caller, then parents up to the supervisor (exclusive)
	ReadError  string
	ttl        time.Duration // a gate with a deadline of its own caps the ticket wait (0: the config TTL)
}

// ---------- process facts (procinfo_proc.go: /proc; procinfo_darwin.go: sysctl) ----------

// sysProc implements policy.ProcReader.
type sysProc struct{}

func (sysProc) Stat(pid int) (int, uint64, bool) {
	ppid, start, _, _, ok := procStat(pid)
	return ppid, start, ok
}

// ---------- memory ----------

func readMem(mem *os.File, addr uint64, buf []byte) (int, error) {
	if addr >= 1<<63 {
		return 0, fmt.Errorf("bad addr %#x", addr)
	}
	return mem.ReadAt(buf, int64(addr))
}

func readCString(mem *os.File, addr uint64) (string, error) {
	var out []byte
	buf := make([]byte, 256)
	for len(out) < maxStr {
		n, err := readMem(mem, addr+uint64(len(out)), buf)
		if n == 0 && err != nil {
			return string(out), err
		}
		if i := bytes.IndexByte(buf[:n], 0); i >= 0 {
			out = append(out, buf[:i]...)
			return string(out), nil
		}
		out = append(out, buf[:n]...)
		if err != nil {
			return string(out), err
		}
	}
	return string(out), errors.New("string too long")
}

func readPtrArray(mem *os.File, addr uint64) ([]uint64, error) {
	var ptrs []uint64
	buf := make([]byte, 8*32)
	for len(ptrs) < maxArr {
		n, err := readMem(mem, addr+uint64(8*len(ptrs)), buf)
		if n < 8 {
			if err == nil {
				err = errors.New("short read")
			}
			return ptrs, err
		}
		for i := 0; i+8 <= n; i += 8 {
			p := binary.LittleEndian.Uint64(buf[i:])
			if p == 0 {
				return ptrs, nil
			}
			ptrs = append(ptrs, p)
			if len(ptrs) >= maxArr {
				break
			}
		}
	}
	return ptrs, errors.New("array too long")
}

func readStrArray(mem *os.File, addr uint64) ([]string, error) {
	if addr == 0 {
		return nil, nil
	}
	ptrs, err := readPtrArray(mem, addr)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ptrs))
	for _, p := range ptrs {
		s, err := readCString(mem, p)
		if err != nil {
			return out, err
		}
		out = append(out, s)
	}
	return out, nil
}

func envHash(env []string) string {
	s := append([]string(nil), env...)
	sort.Strings(s)
	h := sha256.New()
	for _, e := range s {
		h.Write([]byte(e))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// resolveTarget: realpath of the file being executed + dev/ino (for the post-check against file
// substitution). Resolved in the supervisor's namespace. If the caller sits in a DIFFERENT mount
// ns (unshare via the syscall, not via a delegating binary), this realpath may point to a file
// other than the one the kernel will execute; such a case is caught by the MntNs mismatch in
// decide1 (a card) instead of passing as a silent logged. /proc/self, /proc/thread-self and
// whatever links to them (/dev/fd/N, /dev/stdin …) are resolved via the caller's process:
// otherwise `exec /proc/self/exe` (how browsers restart themselves) would point to the binary of
// wardend itself.
func resolveTarget(ev *execEvent, base string) {
	p := ev.Path
	if p == "" {
		ev.TargetErr = syscall.ENOENT
		return
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(base, p)
	}
	rp, err := evalSymlinksAs(p, ev.Tgid, ev.Pid)
	if err != nil {
		ev.TargetErr = err
		return
	}
	var st unix.Stat_t
	if err := unix.Stat(rp, &st); err != nil {
		ev.TargetErr = err
		return
	}
	ev.Target, ev.TargetDev, ev.TargetIno = rp, uint64(st.Dev), st.Ino // Dev/Mode widths differ per OS
	ev.TargetUID, ev.TargetMode = st.Uid, uint32(st.Mode)
}

// evalSymlinksAs: filepath.EvalSymlinks as seen by process tgid (thread tid): the components
// /proc/self and /proc/thread-self, including inside symlink targets (/dev/fd → /proc/self/fd),
// are replaced with /proc/<tgid> and /proc/<tgid>/task/<tid>. The magic links /proc/<pid>/exe
// and /proc/<pid>/fd/N are read as ordinary symlinks: memory (memfd) and deleted files do not
// resolve, which is an error (fail-closed).
func evalSymlinksAs(path string, tgid, tid int) (string, error) {
	self := "/proc/" + strconv.Itoa(tgid)
	thread := self + "/task/" + strconv.Itoa(tid)
	resolved, rest, links := "/", path, 0
	for {
		rest = strings.TrimLeft(rest, "/")
		if rest == "" {
			return resolved, nil
		}
		comp := rest
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			comp, rest = rest[:i], rest[i:]
		} else {
			rest = ""
		}
		switch comp {
		case ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, comp)
		switch next {
		case "/proc/self":
			resolved = self
			continue
		case "/proc/thread-self":
			resolved = thread
			continue
		}
		fi, err := os.Lstat(next)
		if err != nil {
			return "", err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			resolved = next
			continue
		}
		if links++; links > maxSymlinks {
			return "", syscall.ELOOP
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			resolved = "/"
		}
		rest = target + rest
	}
}

// shebang: interpreter and optional argument from the first line of the file (like binfmt_script).
func shebang(path string) (interp, arg string, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", false
	}
	defer f.Close()
	buf := make([]byte, 256)
	n, _ := f.Read(buf)
	buf = buf[:n]
	if !bytes.HasPrefix(buf, []byte("#!")) {
		return "", "", false
	}
	line := buf[2:]
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	s := strings.Trim(string(line), " \t")
	interp, arg, _ = strings.Cut(strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		return r
	}, s), " ")
	return interp, strings.Trim(arg, " \t"), interp != ""
}
