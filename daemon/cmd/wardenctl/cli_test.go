// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/feature"
)

const testPairLink = "wardenclaw://pair?code=ABCDEF&key=AAAA&relay=wss%3A%2F%2F127.0.0.1%3A1%2Fv1%2Fws&v=1"

// Commands that need the device key, the network or a YubiKey check guard after parsing the
// arguments and before any action: on refusal code 3, stdout is empty, the state directory is not
// created. -h as a flag value (--device -h) does not count as help and does not bypass guard.
func TestGuardAfterParsing(t *testing.T) {
	refuse := func() guardVerdict { return guardVerdict{Refuse: true, Reasons: []string{"test"}} }
	cases := [][]string{
		{"pair", testPairLink}, {"pending"}, {"--json", "pending"}, {"show", "wd-0123456789"},
		{"approve", "wd-0123456789"}, {"deny", "wd-0123456789"}, {"watch"}, {"status"},
	}
	if feature.HWKey {
		cases = append(cases, []string{"approve", "wd-0123456789", "--device", "-h"}, []string{"watch", "--device", "--help"},
			[]string{"hw-register"}, []string{"hw-check", "--device", "-h"})
	}
	for _, args := range cases {
		dir := filepath.Join(t.TempDir(), "state")
		out, errb := &bytes.Buffer{}, &bytes.Buffer{}
		a := &app{dir: dir, stdin: strings.NewReader(""), stdout: out, stderr: errb, now: time.Now, guard: refuse}
		if code := a.run(context.Background(), args); code != 3 || out.Len() != 0 || !strings.Contains(errb.String(), "refused") {
			t.Errorf("%q: code %d, stdout %q, stderr %q", args, code, out.String(), errb.String())
		}
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%q: state directory created (%v)", args, err)
		}
	}
}

// Help answers before guard and before --json: next to wardend (and even in the agent tree) it is
// printed to stdout with code 0 and does nothing else.
func TestHelpBeforeGuard(t *testing.T) {
	refuse := func() guardVerdict { return guardVerdict{Refuse: true, Hard: true, Reasons: []string{"test"}} }
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--help"}, "wardenctl <command> --help"},
		{[]string{"help", "watch"}, "usage: wardenctl watch"},
		{[]string{"approve", "--help"}, "usage: wardenctl approve <id>"},
		{[]string{"approve", "wd-0123456789", "-h"}, "usage: wardenctl approve <id>"},
		{[]string{"pair", "help"}, "usage: wardenctl pair"},
		{[]string{"status", "--json", "--help"}, "usage: wardenctl status"},
		{[]string{"forget", "--yes", "-help"}, "usage: wardenctl forget"},
		{[]string{"version", "--help"}, "usage: wardenctl version"},
	} {
		dir := filepath.Join(t.TempDir(), "state")
		out, errb := &bytes.Buffer{}, &bytes.Buffer{}
		a := &app{dir: dir, stdin: strings.NewReader(""), stdout: out, stderr: errb, now: time.Now, guard: refuse}
		if code := a.run(context.Background(), tc.args); code != 0 || errb.Len() != 0 || !strings.Contains(out.String(), tc.want) {
			t.Errorf("%q: code %d, stdout %q, stderr %q", tc.args, code, out.String(), errb.String())
		}
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%q: state directory created (%v)", tc.args, err)
		}
	}
}
