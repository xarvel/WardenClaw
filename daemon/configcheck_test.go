// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xarvel/WardenClaw/daemon/feature"
	"github.com/xarvel/WardenClaw/daemon/policy"
)

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Unknown keys (nested ones too) give a warning with a hint, not an error.
func TestConfigUnknownKeysWarn(t *testing.T) {
	p := writeFile(t, t.TempDir(), "config.json", `{
  "moed": "ticket",
  "Policy_Mode": "root",
  "apns": {"key_file": "k.p8", "team_idd": "T"},
  "trusted_devices": [{"id": "ab", "pubkye": "x"}]
}`)
	c, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != "" || c.PolicyMode != "root" {
		t.Errorf("mode %q policy_mode %q: want empty mode and root (keys are case-insensitive, as in encoding/json)", c.Mode, c.PolicyMode)
	}
	got := strings.Join(c.warnings(), "\n")
	for _, want := range []string{`unknown key "moed" is ignored (did you mean "mode"?)`, `"apns.team_idd"`, `"trusted_devices[0].pubkye"`} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in the warnings:\n%s", want, got)
		}
	}
	if n := len(c.warnings()); n != 3 {
		t.Errorf("%d warnings, want 3:\n%s", n, got)
	}
}

func TestConfigSyntaxErrorHasLineAndColumn(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "config.json", "{\n  \"mode\": \"ticket\",\n  \"linger\": \"2s\"\n  \"http_listen\": \"off\"\n}\n")
	_, err := loadConfig(p)
	if err == nil || !strings.Contains(err.Error(), "line 4, column 3: ") {
		t.Errorf("error %v: want line 4, column 3", err)
	}
	p = writeFile(t, dir, "type.json", "{\n  \"max_pending\": \"64\"\n}\n")
	if _, err = loadConfig(p); err == nil || !strings.Contains(err.Error(), "line 2, ") {
		t.Errorf("type error %v: want line 2", err)
	}
}

func TestConfigVersion(t *testing.T) {
	dir := t.TempDir()
	for body, ok := range map[string]bool{`{}`: true, `{"version": 1}`: true, `{"version": 2}`: false, `{"version": -1}`: false} {
		_, err := loadConfig(writeFile(t, dir, "c.json", body))
		switch {
		case ok && err != nil:
			t.Errorf("%s: %v", body, err)
		case !ok && err == nil:
			t.Errorf("%s: accepted", body)
		case body == `{"version": 2}` && !strings.Contains(err.Error(), "update wardend"):
			t.Errorf("%s: %v: no advice to update wardend", body, err)
		}
	}
}

// Example configs and the built-in policy: no unknown keys (otherwise everyone gets a warning).
func TestShippedFilesHaveNoUnknownKeys(t *testing.T) {
	c, err := loadConfig("deploy/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if w := c.warnings(); len(w) > 0 || c.Version != configVersion {
		t.Errorf("config.example.json: version %d, %v", c.Version, w)
	}
	if k := unknownKeys(policy.DefaultsJSON(), reflect.TypeFor[policy.Config]()); len(k) > 0 {
		t.Errorf("policy defaults: %v", k)
	}
}

func runConfigCheck(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := cmdConfigCheck(args, &out, &errb)
	if errb.Len() > 0 {
		t.Errorf("stderr: %s", errb.String())
	}
	return code, out.String()
}

func TestConfigCheckCommand(t *testing.T) {
	t.Setenv("WARDEND_SELFCHECK", "off") // permissions of the test temp dirs are irrelevant here
	dir := t.TempDir()
	state := filepath.Join(dir, "state") // config-check does not create it
	cases := []struct {
		name, config, policy string
		code                 int
		want                 []string
	}{
		{"ok", `{"version": 1, "mode": "observe"}`, "", 0, []string{"mode observe, policy_mode tripwire", "config-check: ok"}},
		{"typo-key", `{"mdoe": "ticket"}`, "", 0, []string{`warning: config`, `unknown key "mdoe" is ignored (did you mean "mode"?)`, "mode observe", "config-check: ok"}},
		{"bad-mode", `{"mode": "tiket"}`, "", 1, []string{`error: mode "tiket"`, "1 error(s)"}},
		{"syntax", "{\n  \"mode\": \"observe\",\n}", "", 1, []string{"error: config", "line 3, column 1: "}},
		{"version", `{"version": 7}`, "", 1, []string{"version 7 is newer", "update wardend"}},
		{"ticket-no-devices", `{"mode": "ticket"}`, "", 0, []string{"warning: mode ticket without trusted_devices", "config-check: ok"}},
		{"policy-unknown", `{}`, `{"deny_always": [{"id": "x", "path": "^/x$", "argvv": "y"}], "tripwires": []}`, 0,
			[]string{`unknown key "deny_always[0].argvv" is ignored (did you mean "argv"?)`, `"tripwires" is ignored (did you mean "tripwire"?)`, "config-check: ok"}},
		{"policy-syntax", `{}`, "{\n\"deny_always\": [}\n", 1, []string{"error: policy", "line 2, column 17: "}},
	}
	for _, c := range cases {
		cfg := writeFile(t, dir, c.name+".json", c.config)
		args := []string{"--config", cfg, "--state-dir", state}
		if c.policy != "" {
			args = append(args, "--policy", writeFile(t, dir, c.name+".policy.json", c.policy))
		}
		code, out := runConfigCheck(t, args...)
		if code != c.code {
			t.Errorf("%s: code %d, want %d\n%s", c.name, code, c.code, out)
		}
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: no %q:\n%s", c.name, w, out)
			}
		}
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Errorf("config-check created the state directory: %v", err)
	}
}

// hardware_keys: without the hwkey tag, the same error as at start, in words and with a link to docs/hwkey.md.
func TestConfigCheckHardwareKeysWithoutTag(t *testing.T) {
	t.Setenv("WARDEND_SELFCHECK", "off")
	dir := t.TempDir()
	cfg := writeFile(t, dir, "config.json", `{"mode": "ticket", "hardware_keys": [{"id": "AAAA", "rp_id": "wardenclaw", "alg": "EdDSA", "public_key": "AAAA"}]}`)
	code, out := runConfigCheck(t, "--config", cfg, "--state-dir", filepath.Join(dir, "state"))
	if feature.HWKey {
		if strings.Contains(out, "built without the hwkey tag") {
			t.Errorf("a build with the hwkey tag says it is missing:\n%s", out)
		}
		return
	}
	if code != 1 {
		t.Errorf("code %d, want 1:\n%s", code, out)
	}
	for _, w := range []string{"error: config: hardware_keys (1)", "built without the hwkey tag", "-tags hwkey", "daemon/docs/hwkey.md"} {
		if !strings.Contains(out, w) {
			t.Errorf("no %q:\n%s", w, out)
		}
	}
}
