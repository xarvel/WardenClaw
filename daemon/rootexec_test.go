// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// rootexec under a real seccomp filter (the same run() as the integration tests): the client
// under the gate asks, the card appears, a signed allow runs the command with the client's
// descriptors and cwd, a deny or an expired card returns 126/124, no rule / observe mode / the
// built-in guard refuse without a card (125), a process outside the gate is refused, and the
// approved file is the pinned inode even when the path is swapped between the card and the
// decision. wardend runs as the test user here, so "as root" is "as wardend's own uid": the code
// path is the same, the Credential is set only under euid 0.

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/policy"
)

// rootExecPolicy: the built-in rules, the test binary as a service launch (so that the client's
// own exec is not a self-built card) and the given root_exec rules.
func rootExecPolicy(t *testing.T, rules ...map[string]any) string {
	t.Helper()
	return rootExecPolicyOpts(t, true, rules...)
}

// rootExecPolicyOpts: selfService=false leaves the test binary out of service_allow, so that its
// exec is judged by the built-in rules (the sudo shim test: RootExecClient must make it a service).
func rootExecPolicyOpts(t *testing.T, selfService bool, rules ...map[string]any) string {
	t.Helper()
	var pol map[string]any
	if err := json.Unmarshal(policy.DefaultsJSON(), &pol); err != nil {
		t.Fatal(err)
	}
	self, _ := filepath.EvalSymlinks(os.Args[0])
	pol["service_allow"] = []map[string]any{}
	if selfService {
		pol["service_allow"] = []map[string]any{{"id": "test-binary", "path": "^" + regexpQuote(self) + "$"}}
	}
	pol["root_exec"] = rules
	b, _ := json.Marshal(pol)
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func regexpQuote(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\.+*?()|[]{}^$`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// rootExecCfg: ticket mode, tripwire, root_exec on the given socket.
func rootExecCfg(d device, ttl time.Duration, sock, policyPath string) Config {
	c := twCfg(d, ttl)
	c.Policy = policyPath
	c.RootExec = &RootExecConfig{Enabled: true, Socket: sock, Timeout: duration{20 * time.Second}}
	return c
}

// rootExecCmd: the supervised command: a shell that runs the client (this test binary in its
// "rootexec" role) and prints the exit code.
func rootExecCmd(sock string, argv ...string) []string {
	q := make([]string, 0, len(argv))
	for _, a := range argv {
		q = append(q, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
	}
	return []string{"sh", "-c", "WARDEND_TEST_HELPER=rootexec " + os.Args[0] + " rootexec --socket " + sock + " -- " + strings.Join(q, " ") + "; echo rc=$?"}
}

type rootExecJournal struct {
	req  []rootExecRecord
	exit []map[string]any
}

func (r *result) rootExecRecords(t *testing.T) rootExecJournal {
	t.Helper()
	var out rootExecJournal
	for _, e := range r.entries {
		switch e.Kind {
		case "rootexec":
			var x rootExecRecord
			if err := json.Unmarshal(e.Data, &x); err != nil {
				t.Fatal(err)
			}
			out.req = append(out.req, x)
		case "rootexec_exit":
			var m map[string]any
			_ = json.Unmarshal(e.Data, &m)
			out.exit = append(out.exit, m)
		}
	}
	return out
}

func TestRootExecApprovedRunsWithClientDescriptors(t *testing.T) {
	need(t, "sh", "id")
	d := newDevice()
	sock := filepath.Join(t.TempDir(), "rx.sock")
	pol := rootExecPolicy(t, map[string]any{"id": "id-cmd", "argv0": "^id$", "note": "who am I"})
	r := run(t, rootExecCfg(d, 10*time.Second, sock, pol), rootExecCmd(sock, "id", "-u"), approveN(d, 1, "", "allow"))
	want := strconv.Itoa(os.Getuid()) + "\nrc=0"
	if !strings.Contains(r.out, want) {
		t.Fatalf("approved id -u must print the uid and exit 0, got:\n%s", r.dump())
	}
	j := r.rootExecRecords(t)
	if len(j.req) != 1 || j.req[0].Decision != "allow" || j.req[0].Rule != "id-cmd" || j.req[0].Ticket == nil || j.req[0].Pid == 0 {
		t.Fatalf("rootexec record: %+v", j.req)
	}
	env := j.req[0].Envelope
	if env["type"] != envelope.TypeRootExec || env["uid"] != float64(os.Getuid()) || env["gid"] != float64(os.Getgid()) {
		t.Fatalf("envelope: type %v uid %v gid %v", env["type"], env["uid"], env["gid"])
	}
	real, _ := filepath.EvalSymlinks(j.req[0].Exe)
	if env["exe"] != real || filepath.Base(real) != "id" {
		t.Fatalf("envelope exe %v, record %v", env["exe"], j.req[0].Exe)
	}
	if got, _ := env["argv"].([]any); len(got) != 2 || got[0] != "id" || got[1] != "-u" {
		t.Fatalf("envelope argv %v", env["argv"])
	}
	if chain, _ := env["ppidChain"].([]any); len(chain) < 2 {
		t.Fatalf("ppidChain must lead from the client to the supervised command: %v", env["ppidChain"])
	}
	if len(j.exit) != 1 || j.exit[0]["exit"] != float64(0) || j.exit[0]["timedOut"] != false {
		t.Fatalf("rootexec_exit: %v", j.exit)
	}
	if !strings.Contains(r.errOut, "is on the phone") || !strings.Contains(r.errOut, "approved, running") {
		t.Fatalf("client progress lines missing:\n%s", r.errOut)
	}
	// the client's exec itself is a service launch, not a card: exactly one ticket was signed
	if n := r.count("rootexec"); n != 0 {
		t.Fatalf("rootexec is not an exec record class: %d", n)
	}
}

func TestRootExecDeniedAndExpired(t *testing.T) {
	need(t, "sh", "id")
	d := newDevice()
	sock := filepath.Join(t.TempDir(), "rx.sock")
	pol := rootExecPolicy(t, map[string]any{"id": "id-cmd", "argv0": "^id$"})
	r := run(t, rootExecCfg(d, 10*time.Second, sock, pol), rootExecCmd(sock, "id", "-u"), approveN(d, 1, "", "deny"))
	if !strings.Contains(r.out, "rc=126") || strings.Contains(r.out, strconv.Itoa(os.Getuid())+"\n") {
		t.Fatalf("denied: exit 126 and no output:\n%s", r.dump())
	}
	j := r.rootExecRecords(t)
	if len(j.req) != 1 || j.req[0].Decision != "deny" || j.req[0].Ticket == nil || !strings.Contains(j.req[0].Reason, "denied by device") || len(j.exit) != 0 {
		t.Fatalf("denied record: %+v exits %v", j.req, j.exit)
	}
	r = run(t, rootExecCfg(d, 1500*time.Millisecond, sock, pol), rootExecCmd(sock, "id", "-u"), nil)
	if !strings.Contains(r.out, "rc=124") {
		t.Fatalf("expired card: exit 124:\n%s", r.dump())
	}
	j = r.rootExecRecords(t)
	if len(j.req) != 1 || j.req[0].Decision != "deny" || !strings.Contains(j.req[0].Reason, "ttl expired") {
		t.Fatalf("expired record: %+v", j.req)
	}
}

func TestRootExecRefusedWithoutCard(t *testing.T) {
	need(t, "sh", "id", "true", "unshare")
	d := newDevice()
	sock := filepath.Join(t.TempDir(), "rx.sock")
	pol := rootExecPolicy(t, map[string]any{"id": "id-cmd", "argv0": "^id$"}, map[string]any{"id": "sh", "argv0": "^sh$"},
		map[string]any{"id": "unshare", "argv0": "^unshare$"})
	cases := []struct {
		name   string
		cfg    func() Config
		argv   []string
		reason string
	}{
		{"no rule", func() Config { return rootExecCfg(d, 5*time.Second, sock, pol) }, []string{"true"}, "no root_exec rule"},
		{"guard: wardend files", func() Config { return rootExecCfg(d, 5*time.Second, sock, pol) }, []string{"sh", "-c", "cat /etc/wardend/config.json"}, "off limits"},
		{"guard: privilege tool", func() Config { return rootExecCfg(d, 5*time.Second, sock, pol) }, []string{"unshare", "-r", "id"}, "privilege and namespace tools"},
		{"guard: account tool", func() Config { return rootExecCfg(d, 5*time.Second, sock, pol) }, []string{"sh", "-c", "gpasswd -a agent docker"}, "off limits"},
		{"not found", func() Config { return rootExecCfg(d, 5*time.Second, sock, pol) }, []string{"no-such-program-xyz"}, "not found"},
		{"empty argv0", func() Config { return rootExecCfg(d, 5*time.Second, sock, pol) }, []string{""}, "not a program name"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := run(t, c.cfg(), rootExecCmd(sock, c.argv...), nil)
			if !strings.Contains(r.out, "rc=125") {
				t.Fatalf("refused: exit 125:\n%s", r.dump())
			}
			j := r.rootExecRecords(t)
			if len(j.req) != 1 || j.req[0].Decision != "deny" || !strings.Contains(j.req[0].Reason, c.reason) || j.req[0].ID != "" {
				t.Fatalf("refused record (no card, reason %q): %+v", c.reason, j.req)
			}
			if !strings.Contains(r.errOut, "refused: ") {
				t.Fatalf("client must print the reason:\n%s", r.errOut)
			}
		})
	}
}

// A process outside the tree (the test itself) is refused even with the right uid.
func TestRootExecOutsideGateRefused(t *testing.T) {
	need(t, "sh", "id")
	d := newDevice()
	sock := filepath.Join(t.TempDir(), "rx.sock")
	pol := rootExecPolicy(t, map[string]any{"id": "id-cmd", "argv0": "^id$"})
	var code int
	var err error
	r := run(t, rootExecCfg(d, 5*time.Second, sock, pol), []string{"sh", "-c", "sleep 1; echo done"}, func(string) {
		code, err = rootExecClient(sock, []string{"id", "-u"}, "/", "", true, io.Discard)
	})
	if code != rootExecExitRefused || err == nil || !strings.Contains(err.Error(), "not under the gate") {
		t.Fatalf("outside the gate: code %d err %v\n%s", code, err, r.dump())
	}
	j := r.rootExecRecords(t)
	if len(j.req) != 1 || !strings.Contains(j.req[0].Reason, "not under the gate") {
		t.Fatalf("record: %+v", j.req)
	}
}

// The pinned inode: the path is swapped between the card and the decision, the approved file runs.
func TestRootExecPinnedInodeSurvivesSwap(t *testing.T) {
	need(t, "sh")
	d := newDevice()
	dir := t.TempDir()
	sock := filepath.Join(dir, "rx.sock")
	script := filepath.Join(dir, "tool.sh")
	write := func(p, out string) {
		if err := os.WriteFile(p, []byte("#!/bin/sh\necho "+out+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(script, "APPROVED")
	pol := rootExecPolicy(t, map[string]any{"id": "tool", "path": "^" + regexpQuote(dir) + "/"})
	r := run(t, rootExecCfg(d, 10*time.Second, sock, pol), rootExecCmd(sock, script), func(s string) {
		// wait for the card, swap the file behind the path, then approve
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			var p struct {
				Pending []struct{ ID string } `json:"pending"`
			}
			if callOnce(s, "pending", map[string]any{}, &p) == nil && len(p.Pending) > 0 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		other := filepath.Join(dir, "other.sh")
		write(other, "SWAPPED")
		if err := os.Rename(other, script); err != nil {
			t.Error(err)
		}
		approveN(d, 1, "", "allow")(s)
	})
	if !strings.Contains(r.out, "APPROVED\nrc=0") || strings.Contains(r.out, "SWAPPED") {
		t.Fatalf("the approved inode must run, not the swapped file:\n%s", r.dump())
	}
}

// A group- or world-writable file, or one under the agent's home, is not a candidate.
func TestRootExecRefusesWritableFile(t *testing.T) {
	need(t, "sh")
	d := newDevice()
	dir := t.TempDir()
	sock := filepath.Join(dir, "rx.sock")
	script := filepath.Join(dir, "loose.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hi\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	// WriteFile's mode goes through the umask (022 on CI runners gives 0755, which is not
	// writable by others and would be pinned): set the loose mode explicitly
	if err := os.Chmod(script, 0o777); err != nil {
		t.Fatal(err)
	}
	pol := rootExecPolicy(t, map[string]any{"id": "any", "argv_text": "."})
	r := run(t, rootExecCfg(d, 5*time.Second, sock, pol), rootExecCmd(sock, script), nil)
	if !strings.Contains(r.out, "rc=125") {
		t.Fatalf("writable file: refused:\n%s", r.dump())
	}
	j := r.rootExecRecords(t)
	if len(j.req) != 1 || !strings.Contains(j.req[0].Reason, "writable by group or others") {
		t.Fatalf("record: %+v", j.req)
	}
}

// The sudo shim: a symlink named sudo to the gate binary. Under the gate it is `wardend rootexec`
// with sudo's spelling (one card, the shim's own exec is a service launch, not a card); shells,
// other users and the environment are refused with a message; -l and --help answer without a
// request.
func TestRootExecSudoShim(t *testing.T) {
	need(t, "sh", "id")
	d := newDevice()
	dir := t.TempDir()
	sock := filepath.Join(dir, "rx.sock")
	shim := filepath.Join(dir, "sudo")
	if err := os.Symlink(os.Args[0], shim); err != nil {
		t.Fatal(err)
	}
	pol := rootExecPolicyOpts(t, false, map[string]any{"id": "id-cmd", "argv0": "^id$"})
	sudo := func(rest string) []string {
		return []string{"sh", "-c", "WARDEND_TEST_HELPER=shim WARDEND_ROOTEXEC_SOCKET=" + sock + " " + shim + " " + rest + "; echo rc=$?"}
	}
	r := run(t, rootExecCfg(d, 10*time.Second, sock, pol), sudo("-n -u root -- id -u"), approveN(d, 1, "", "allow"))
	if !strings.Contains(r.out, strconv.Itoa(os.Getuid())+"\nrc=0") {
		t.Fatalf("sudo id -u through the shim:\n%s", r.dump())
	}
	j := r.rootExecRecords(t)
	if len(j.req) != 1 || j.req[0].Decision != "allow" || j.req[0].Rule != "id-cmd" {
		t.Fatalf("one approved request: %+v", j.req)
	}
	shimExecs := 0
	for _, e := range r.execs {
		if filepath.Base(e.Argv[0]) == "sudo" {
			shimExecs++
			if e.Class != "service" || e.Rule != "rootexec-client" || e.Decision != "allow" {
				t.Fatalf("the shim's exec is a service launch, not a card: %+v", e)
			}
		}
	}
	if shimExecs != 1 {
		t.Fatalf("shim execs: %d\n%s", shimExecs, r.dump())
	}
	for _, c := range []struct{ rest, want string }{
		{"-i", "rc=125"}, {"-s", "rc=125"}, {"-u nobody id", "rc=125"}, {"-E id", "rc=125"}, {"FOO=1 id", "rc=125"}, {"", "rc=125"},
		{"-l", "no sudoers rights"}, {"--help", "sudo shim"}, {"-V", "sudo shim of wardend"},
	} {
		r := run(t, rootExecCfg(d, 3*time.Second, sock, pol), sudo(c.rest), nil)
		if !strings.Contains(r.out, c.want) {
			t.Fatalf("sudo %s: want %q:\n%s", c.rest, c.want, r.dump())
		}
		if strings.Contains(c.want, "rc=125") && !strings.Contains(r.errOut, "sudo (wardend rootexec):") {
			t.Fatalf("sudo %s: the refusal names the shim:\n%s", c.rest, r.errOut)
		}
		if j := r.rootExecRecords(t); len(j.req) != 0 {
			t.Fatalf("sudo %s: no request must reach wardend: %+v", c.rest, j.req)
		}
	}
}

// No card: a rule with "ticket": false runs at once (journaled, reason "policy: no ticket"); in
// observe and deny-list modes every allowed request runs and the journal says a ticket would have
// been asked. The docker shim is the same request with docker's spelling. Refusals stay
// refusals in every mode.
func TestRootExecNoCardPaths(t *testing.T) {
	need(t, "sh", "id", "true")
	d := newDevice()
	dir := t.TempDir()
	sock := filepath.Join(dir, "rx.sock")
	f := false
	pol := rootExecPolicyOpts(t, false, map[string]any{"id": "id-free", "argv0": "^id$", "ticket": f}, map[string]any{"id": "true-card", "argv0": "^true$"})
	// ticket: false in ticket mode: runs, no card, nobody approves
	r := run(t, rootExecCfg(d, 3*time.Second, sock, pol), rootExecCmd(sock, "id", "-u"), nil)
	if !strings.Contains(r.out, strconv.Itoa(os.Getuid())+"\nrc=0") {
		t.Fatalf("ticket:false must run without a card:\n%s", r.dump())
	}
	j := r.rootExecRecords(t)
	if len(j.req) != 1 || j.req[0].Decision != "allow" || !strings.Contains(j.req[0].Reason, "policy: no ticket (id-free)") || j.req[0].Ticket != nil {
		t.Fatalf("no-ticket record: %+v", j.req)
	}
	if strings.Contains(r.errOut, "is on the phone") {
		t.Fatalf("no card must be announced:\n%s", r.errOut)
	}
	// a rule that needs a ticket, in observe: runs, the journal says what a ticket would be
	c := rootExecCfg(d, 3*time.Second, sock, pol)
	c.Mode = "observe"
	r = run(t, c, rootExecCmd(sock, "true"), nil)
	if !strings.Contains(r.out, "rc=0") {
		t.Fatalf("observe must run:\n%s", r.dump())
	}
	j = r.rootExecRecords(t)
	if len(j.req) != 1 || j.req[0].Decision != "allow" || !strings.Contains(j.req[0].Reason, "observe: would require ticket (true-card)") {
		t.Fatalf("observe record: %+v", j.req)
	}
	// observe does not lift the guard or the policy
	r = run(t, c, rootExecCmd(sock, "sh", "-c", "cat /etc/wardend/config.json"), nil)
	if !strings.Contains(r.out, "rc=125") {
		t.Fatalf("observe: no rule for sh, refused:\n%s", r.dump())
	}
	// the docker shim: a symlink named docker; `docker ps` is `wardend rootexec -- docker ps`
	shim := filepath.Join(dir, "docker")
	if err := os.Symlink(os.Args[0], shim); err != nil {
		t.Fatal(err)
	}
	pol = rootExecPolicyOpts(t, false, map[string]any{"id": "docker-ps", "argv0": "^docker$", "argv_text": "^docker ps", "ticket": f})
	r = run(t, rootExecCfg(d, 3*time.Second, sock, pol), []string{"sh", "-c", "WARDEND_TEST_HELPER=shim WARDEND_ROOTEXEC_SOCKET=" + sock + " " + shim + " ps -a; echo rc=$?"}, nil)
	j = r.rootExecRecords(t)
	// docker itself is not on this box's root PATH as a pinnable file under the test binary's name:
	// the request reaches wardend with argv [docker ps -a] and is judged; what happens next depends
	// on /usr/bin/docker being installed, so only the request is checked
	if len(j.req) != 1 || len(j.req[0].Argv) != 3 || j.req[0].Argv[0] != "docker" || j.req[0].Argv[1] != "ps" {
		t.Fatalf("docker shim request: %+v\n%s", j.req, r.dump())
	}
	for _, e := range r.execs {
		if filepath.Base(e.Argv[0]) == "docker" && (e.Class != "service" || e.Rule != "rootexec-client") {
			t.Fatalf("the docker shim's exec is a service launch: %+v", e)
		}
	}
}

// The built-in policy carries root_exec defaults: read-only docker and systemctl without a
// card, everything else a card; they compile and match as intended.
func TestPolicyRootExecDefaults(t *testing.T) {
	c, err := policy.Defaults()
	if err != nil {
		t.Fatal(err)
	}
	ex := func(argv ...string) *policy.Exec { return &policy.Exec{Path: "/usr/bin/" + argv[0], Argv: argv} }
	for _, tc := range []struct {
		argv   []string
		rule   string
		ticket bool
	}{
		{[]string{"docker", "ps", "-a"}, "docker-read", false},
		{[]string{"docker", "compose", "logs", "--tail", "50", "x"}, "docker-read", false},
		{[]string{"docker", "restart", "x"}, "docker", true},
		{[]string{"docker", "compose", "up", "-d"}, "docker", true},
		{[]string{"docker", "run", "-v", "/:/host", "alpine"}, "docker", true},
		{[]string{"systemctl", "status", "nginx"}, "systemctl-read", false},
		{[]string{"systemctl", "restart", "nginx"}, "root-any", true},
		{[]string{"apt-get", "install", "-y", "jq"}, "root-any", true},
		{[]string{"mount", "/dev/sda1", "/mnt/x"}, "root-any", true},
	} {
		r := c.MatchRootExec(ex(tc.argv...))
		if r == nil || r.ID != tc.rule || r.NeedsTicket() != tc.ticket {
			t.Fatalf("%v: rule %v ticket %v, want %s/%v", tc.argv, r, r.NeedsTicket(), tc.rule, tc.ticket)
		}
	}
}

// Policy: the gate binary run as the rootexec client or through the sudo shim is a service
// launch; a real sudo and an unrelated symlink named sudo are not.
func TestPolicyRootExecClient(t *testing.T) {
	c, err := policy.Parse([]byte(`{"deny_always":[],"service_allow":[],"delegating":[],"require_hardware":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Setup(policy.Options{GuardExe: []string{"/usr/local/bin/wardend"}}); err != nil {
		t.Fatal(err)
	}
	ex := func(path string, argv ...string) *policy.Exec { return &policy.Exec{Path: path, Argv: argv} }
	for _, e := range []*policy.Exec{ex("/usr/local/bin/wardend", "sudo", "id"), ex("/usr/local/bin/wardend", "wardend", "rootexec", "--", "id"),
		ex("/usr/local/bin/wardend", "/usr/local/libexec/wardend/bin/sudo", "-n", "id")} {
		if !c.RootExecClient(e) {
			t.Fatalf("client: %v", e.Argv)
		}
		if v := c.ClassifyTripwire(e, nil, time.Now()); v.Class != policy.ClassService || v.RuleID() != "rootexec-client" {
			t.Fatalf("tripwire: %v → %+v", e.Argv, v)
		}
		if v := c.Classify(e, 0); v.Class != policy.ClassService {
			t.Fatalf("root mode: %v → %+v", e.Argv, v)
		}
	}
	for _, e := range []*policy.Exec{ex("/usr/bin/sudo", "sudo", "id"), ex("/usr/local/bin/wardend", "wardend", "pair", "start"), ex("/opt/evil/wardend", "sudo", "id")} {
		if c.RootExecClient(e) {
			t.Fatalf("not a client: %v", e.Argv)
		}
	}
}

// Policy: root_exec rules compile with the rest and match strictly on argv0 (no lenient basename
// of the real file) and on the other rule fields.
func TestPolicyRootExecRules(t *testing.T) {
	c, err := policy.Parse([]byte(`{"deny_always":[],"service_allow":[],"delegating":[],"require_hardware":[],
		"root_exec":[{"id":"docker-restart","argv0":"^docker$","argv":["docker","restart","[a-z0-9_-]+"]},
		             {"id":"compose","argv0":"^docker$","argv_text":"^docker compose (up -d|restart)( [a-z0-9_-]+)?$","cwd":"x"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	ex := func(argv ...string) *policy.Exec { return &policy.Exec{Path: "/usr/bin/docker", Argv: argv} }
	if r := c.MatchRootExec(ex("docker", "restart", "searxng")); r == nil || r.ID != "docker-restart" {
		t.Fatalf("restart: %v", r)
	}
	if r := c.MatchRootExec(ex("docker", "compose", "up", "-d")); r == nil || r.ID != "compose" {
		t.Fatalf("compose: %v", r)
	}
	if r := c.MatchRootExec(ex("docker", "run", "-v", "/:/host", "alpine")); r != nil {
		t.Fatalf("run must not match: %v", r.ID)
	}
	if r := c.MatchRootExec(ex("evil", "restart", "x")); r != nil {
		t.Fatalf("argv0 is strict: %v", r.ID)
	}
	if len(c.RootExec) != 2 {
		t.Fatalf("rules: %d", len(c.RootExec))
	}
}
