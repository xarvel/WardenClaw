// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/feature"
)

// Without the hwkey tag (release) there is no YubiKey: the help does not show it, hw-register and
// hw-check and the flags --hw, --no-hw, --uv, --device answer that the feature is not in this
// release (code 2, before guard and network), and allow is signed with the device key only. With
// the tag everything is as before.
func TestHWFeatureTagCLI(t *testing.T) {
	var u bytes.Buffer
	(&app{}).usage(&u)
	for _, w := range []string{"hw-register", "hw-check", "--no-hw", "YubiKey"} {
		if got := strings.Contains(u.String(), w); got != feature.HWKey {
			t.Fatalf("%s in help: %v, hwkey tag: %v\n%s", w, got, feature.HWKey, u.String())
		}
	}
	if feature.HWKey {
		return
	}
	for _, args := range [][]string{
		{"approve", "wd-0123456789abcdef", "--no-hw"}, {"approve", "wd-0123456789abcdef", "--hw"},
		{"approve", "wd-0123456789abcdef", "--uv"}, {"approve", "wd-0123456789abcdef", "--device", "/dev/hidraw0"},
		{"watch", "--no-hw"}, {"watch", "--uv"}, {"hw-register"}, {"hw-check"}, {"help", "hw-register"},
	} {
		out, errb := &bytes.Buffer{}, &bytes.Buffer{}
		a := &app{dir: t.TempDir(), stdin: strings.NewReader(""), stdout: out, stderr: errb, now: time.Now,
			guard: func() guardVerdict { return guardVerdict{Refuse: true, Reasons: []string{"test"}} }}
		if code := a.run(context.Background(), args); code != 2 || out.Len() != 0 || !strings.Contains(errb.String(), "is not included in this release") {
			t.Errorf("%q: code %d, stdout %q, stderr %q", args, code, out.String(), errb.String())
		}
	}
	// card from a wardend built with the tag (meta.hardware.required): nothing to sign with, refusal before signing
	priv := seedKey(t, strings.Repeat("22", 32))
	s := &session{st: &State{DeviceID: deviceIDOf(priv)}, priv: priv}
	c := checkItem(testItem(t, "bash", "-c", "git status"), testSup)
	c.Meta.Hardware = &HWMeta{Required: true, Rule: "hw-bash"}
	a, _, _ := testApp(t.TempDir(), "")
	if _, err := a.decide(context.Background(), s, c, "allow", decideOpts{}); err == nil || !strings.Contains(err.Error(), "is not included in this release") {
		t.Fatalf("card with require_hardware: %v", err)
	}
}

// writeTestState and testApp: shared test helpers (formerly in fido_test.go, which is now hwkey-tag only).
func writeTestState(t *testing.T, dir string) *State {
	t.Helper()
	priv := seedKey(t, strings.Repeat("11", 32))
	st := &State{Relay: "wss://127.0.0.1:1", SupervisorKey: envelope.B64URL(make([]byte, 32)), SupervisorEnc: testEnc, SupervisorID: strings.Repeat("0", 64),
		DeviceID: deviceIDOf(priv), Name: "t", KeyStore: "file", PairStatus: "approved"}
	if err := saveState(dir, st); err != nil {
		t.Fatal(err)
	}
	if err := (fileStore{dir: dir}).Save(st.DeviceID, testSecret(priv)); err != nil {
		t.Fatal(err)
	}
	return st
}

func testApp(dir string, in string) (*app, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	return &app{dir: dir, stdin: strings.NewReader(in), stdout: &out, stderr: &errb, now: time.Now,
		guard: func() guardVerdict { return guardVerdict{} }}, &out, &errb
}

// blobRe: the wchw1 blob in the output of wardenctl hw-register (fido_test.go and e2e with the hwkey tag).
var blobRe = regexp.MustCompile(`wardend hw-register '(wchw1:[A-Za-z0-9_-]+)'`)
