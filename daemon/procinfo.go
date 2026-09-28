// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Reads the context of a stopped process from /proc: argv/envp/filename from the memory of the
// calling thread (on entry to execve they are still in the caller's user space), cwd, exe,
// uid/gid, starttime, the ancestor chain, the realpath of the file being executed.

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
}

// ---------- /proc ----------

// procStat: ppid, starttime, state, threads from /proc/<pid>/stat.
func procStat(pid int) (ppid int, start uint64, state byte, threads int, ok bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, 0, 0, false
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 || i+2 >= len(b) {
		return 0, 0, 0, 0, false
	}
	f := strings.Fields(string(b[i+2:]))
	if len(f) < 20 {
		return 0, 0, 0, 0, false
	}
	// f[0]=state(3) f[1]=ppid(4) … f[17]=num_threads(20) f[19]=starttime(22)
	ppid, _ = strconv.Atoi(f[1])
	threads, _ = strconv.Atoi(f[17])
	start, _ = strconv.ParseUint(f[19], 10, 64)
	return ppid, start, f[0][0], threads, true
}

// sysProc implements policy.ProcReader.
type sysProc struct{}

func (sysProc) Stat(pid int) (int, uint64, bool) {
	ppid, start, _, _, ok := procStat(pid)
	return ppid, start, ok
}

func procIDs(pid int) (uid, gid int) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return -1, -1
	}
	uid, gid = -1, -1
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Uid:"); ok {
			if f := strings.Fields(v); len(f) > 1 {
				uid, _ = strconv.Atoi(f[1])
			}
		} else if v, ok := strings.CutPrefix(line, "Gid:"); ok {
			if f := strings.Fields(v); len(f) > 1 {
				gid, _ = strconv.Atoi(f[1])
			}
		}
	}
	return
}

func procExe(pid int) string {
	s, _ := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	return s
}

func procCmdline(pid int) ([]string, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return []string{}, nil
	}
	b = bytes.TrimSuffix(b, []byte{0})
	return strings.Split(string(b), "\x00"), nil
}

// chainOf: [pid, ppid, …] up to stopAt (exclusive) or init, at most maxChainDepth deep.
func chainOf(pid, stopAt int) []envelope.Link {
	var out []envelope.Link
	for p := pid; p > 1 && p != stopAt && len(out) < maxChainDepth; {
		out = append(out, envelope.Link{Pid: p, Exe: procExe(p)})
		pp, _, _, _, ok := procStat(p)
		if !ok || pp == p {
			break
		}
		p = pp
	}
	return out
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

// collect builds an execEvent from a notification. The target process is stopped inside the
// syscall at this point; its memory is read via /proc/<tid>/mem (ptrace access: same uid,
// descendant of the supervisor).
func collect(n *seccompNotif, supervisorPid int) *execEvent {
	ev := &execEvent{ID: n.ID, Pid: int(n.Pid)}
	pid := ev.Pid
	var errs []string
	fail := func(what string, err error) { errs = append(errs, what+": "+err.Error()) }

	if _, _, _, _, ok := procStat(pid); !ok {
		fail("stat", errors.New("no such process"))
	}
	ev.Tgid = pid
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "Tgid:"); ok {
				ev.Tgid, _ = strconv.Atoi(strings.TrimSpace(v))
			}
		}
	}
	ev.PPid, ev.Start, _, ev.Threads, _ = procStat(ev.Tgid)
	ev.UID, ev.GID = procIDs(pid)
	ev.CallerExe = procExe(ev.Tgid)
	ev.CallerCmd, _ = procCmdline(ev.Tgid)
	if s, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
		ev.Cwd = s
	} else {
		fail("cwd", err)
	}
	ev.Chain = chainOf(ev.Tgid, supervisorPid)
	// caller's mount namespace: a mismatch with the supervisor's ns means the path resolves in a
	// namespace other than the one where the kernel will execute the file (see resolveTarget and
	// decide1).
	if s, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", pid)); err == nil {
		ev.MntNs = s
	}

	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		fail("mem", err)
		ev.ReadError = strings.Join(errs, "; ")
		return ev
	}
	defer mem.Close()

	var pathAddr, argvAddr, envpAddr uint64
	a := n.Data.Args
	switch n.Data.Nr {
	case unix.SYS_EXECVE:
		ev.Syscall = "execve"
		pathAddr, argvAddr, envpAddr = a[0], a[1], a[2]
	case unix.SYS_EXECVEAT:
		ev.Syscall = "execveat"
		pathAddr, argvAddr, envpAddr = a[1], a[2], a[3]
	default:
		ev.Syscall = fmt.Sprintf("nr=%d", n.Data.Nr)
	}

	if p, err := readCString(mem, pathAddr); err == nil {
		ev.Path = p
	} else {
		fail("path", err)
	}
	resolveBase := ev.Cwd
	if n.Data.Nr == unix.SYS_EXECVEAT {
		dirfd := int32(a[0])
		flags := a[4]
		if ev.Path == "" && flags&unix.AT_EMPTY_PATH != 0 {
			// fexecve(): path = the dirfd itself
			if s, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd)); err == nil {
				ev.Path = s
			} else {
				fail("dirfd", err)
			}
		} else if !filepath.IsAbs(ev.Path) && dirfd != unix.AT_FDCWD {
			if s, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd)); err == nil {
				resolveBase = s
			} else {
				fail("dirfd", err)
			}
		}
	}
	if v, err := readStrArray(mem, argvAddr); err == nil {
		ev.Argv, ev.ArgvOK = v, true
	} else {
		ev.Argv = v
		fail("argv", err)
	}
	if v, err := readStrArray(mem, envpAddr); err == nil {
		ev.EnvHash = envHash(v)
		ev.EnvCount = len(v)
		ev.Env = envelope.SelectEnv(v)
	} else {
		fail("envp", err)
	}
	resolveTarget(ev, resolveBase)
	ev.ReadError = strings.Join(errs, "; ")
	return ev
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
	ev.Target, ev.TargetDev, ev.TargetIno = rp, st.Dev, st.Ino
	ev.TargetUID, ev.TargetMode = st.Uid, st.Mode
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

// pidfdCookie: "pidfs:<inode>" (unique within a boot on kernels with pidfs ≥ 6.9),
// otherwise "start:<pid>:<starttime>". Also returns the pidfd itself (the caller closes it).
func pidfdCookie(tgid int, start uint64) (string, int) {
	fd, err := unix.PidfdOpen(tgid, 0)
	if err != nil {
		return fmt.Sprintf("start:%d:%d", tgid, start), -1
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) == nil && st.Ino > 1 {
		return fmt.Sprintf("pidfs:%d", st.Ino), fd
	}
	return fmt.Sprintf("start:%d:%d", tgid, start), fd
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
