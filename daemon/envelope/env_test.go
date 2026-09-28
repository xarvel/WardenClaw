// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

import (
	"reflect"
	"strings"
	"testing"
)

func TestSelectEnv(t *testing.T) {
	long := "/opt/" + strings.Repeat("я", EnvValueMax+10)
	envp := []string{
		"LANG=C.UTF-8", "LD_PRELOAD=/tmp/x.so", "HOME=/home/u", "GIT_SSH_COMMAND=ssh -i /tmp/k", "NOEQUALS",
		"https_proxy=http://p:3128", "npm_config_script_shell=/tmp/sh", "GITHUB_TOKEN=ghp_x", "NODE_AUTH_TOKEN=t",
		"NPM_CONFIG__AUTH=abc", "GIT_CONFIG_KEY_0=core.sshCommand", "GIT_CONFIG_VALUE_0=/tmp/evil", "KUBECONFIG=/tmp/kc",
		"NODE_OPTIONS=--require /tmp/r.js", "PYTHONPATH=" + long, "BASH_FUNC_ls%%=() { evil; }", "LD_PRELOAD=/tmp/y.so",
		"LESS=-R", "TERM=xterm", "=weird",
	}
	got := SelectEnv(envp)
	want := []EnvVar{
		{Name: "LD_PRELOAD", Value: "/tmp/x.so"}, {Name: "HOME", Value: "/home/u"},
		{Name: "GIT_SSH_COMMAND", Value: "ssh -i /tmp/k"}, {Name: "https_proxy", Value: "http://p:3128"},
		{Name: "npm_config_script_shell", Value: "/tmp/sh"}, {Name: "GIT_CONFIG_KEY_0", Value: "core.sshCommand"},
		{Name: "GIT_CONFIG_VALUE_0", Value: "/tmp/evil"}, {Name: "KUBECONFIG", Value: "/tmp/kc"},
		{Name: "NODE_OPTIONS", Value: "--require /tmp/r.js"},
		{Name: "PYTHONPATH", Value: string([]rune(long)[:EnvValueMax]), Cut: len([]rune(long)) - EnvValueMax},
		{Name: "BASH_FUNC_ls%%", Value: "() { evil; }"}, {Name: "LD_PRELOAD", Value: "/tmp/y.so"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SelectEnv:\n got  %+v\n want %+v", got, want)
	}
	if ld := LoaderVars(got); !reflect.DeepEqual(ld, []string{"LD_PRELOAD"}) {
		t.Fatalf("LoaderVars = %v", ld)
	}
	if ld := LoaderVars(SelectEnv([]string{"LD_LIBRARY_PATH=", "LD_AUDIT=/a.so", "LD_BIND_NOW=1"})); !reflect.DeepEqual(ld, []string{"LD_AUDIT"}) {
		t.Fatalf("empty LD_LIBRARY_PATH or LD_BIND_NOW must not count: %v", ld)
	}
	if SelectEnv(nil) == nil {
		t.Fatal("env must be an empty array, not nil")
	}
}

// Scenario for crypto-review finding 4: harmless command with LD_PRELOAD. Environment in the
// envelope and covered by the digest: a different LD_PRELOAD changes the digest, and a non-UTF-8
// value prevents the envelope from being built.
func TestEnvInDigest(t *testing.T) {
	base := Exec{Argv: []string{"ssh", "prod", "uptime"}, Cwd: "/tmp", Exe: "/usr/bin/ssh", Ts: 1, Nonce: "n",
		Env: SelectEnv([]string{"LD_PRELOAD=/tmp/x.so"}), EnvHash: "h"}
	c1, d1, err := base.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(c1), `"env":[{"name":"LD_PRELOAD","value":"/tmp/x.so"}]`) {
		t.Fatalf("env not in the canonical envelope: %s", c1)
	}
	other := base
	other.Env = SelectEnv([]string{"LD_PRELOAD=/tmp/z.so"})
	if _, d2, _ := other.Canonical(); d2 == d1 {
		t.Fatal("a different LD_PRELOAD must change the digest")
	}
	none := base
	none.Env = nil
	if c, _, _ := none.Canonical(); !strings.Contains(string(c), `"env":[]`) {
		t.Fatalf("no env must be [] in the envelope: %s", c)
	}
	bad := base
	bad.Env = SelectEnv([]string{"GIT_DIR=\xff"})
	if _, _, err := bad.Canonical(); err == nil {
		t.Fatal("non-UTF-8 env value must fail the envelope")
	}
}
