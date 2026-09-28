// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/feature"
)

// The second factor is enabled by the hwkey tag (docs/hwkey.md). Without the tag (release): wardend
// does not start with hardware_keys or require_hardware, hw-register and hw-keys answer that the
// feature is not in this release and are not shown in the help, status and the start record have
// no second-factor fields.
func TestHWFeatureTag(t *testing.T) {
	var usageOut bytes.Buffer
	usage(&usageOut)
	if got := strings.Contains(usageOut.String(), "hw-register"); got != feature.HWKey {
		t.Fatalf("hw-register in help: %v, hwkey tag: %v\n%s", got, feature.HWKey, usageOut.String())
	}
	st := hwStatus(map[string]any{"ok": true}, []map[string]string{}, 2, []int{})
	if _, ok := st["requireHardwareRules"]; ok != feature.HWKey {
		t.Fatalf("status without the hwkey tag must not carry second-factor fields: %v", st)
	}
	if err := hwFeatureCheck(0, 0); err != nil {
		t.Fatal(err)
	}
	if feature.HWKey {
		if err := hwFeatureCheck(1, 2); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, c := range []struct {
		keys, rules int
		want        string
	}{{1, 0, "hardware_keys (1)"}, {0, 2, "require_hardware (2)"}, {3, 1, "hardware_keys (3)"}} {
		err := hwFeatureCheck(c.keys, c.rules)
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "-tags hwkey") {
			t.Fatalf("hwFeatureCheck(%d, %d): %v", c.keys, c.rules, err)
		}
	}
	for name, run := range map[string]func(out, errb *bytes.Buffer) int{
		"hw-register": func(out, errb *bytes.Buffer) int {
			return cmdHWRegister([]string{"--dry-run", "wchw1:AAAA"}, out, errb, time.Now())
		},
		"hw-keys": func(out, errb *bytes.Buffer) int { return cmdHWKeys(nil, out, errb) },
	} {
		var out, errb bytes.Buffer
		if code := run(&out, &errb); code != 2 || out.Len() != 0 || !strings.Contains(errb.String(), "not included in this release") {
			t.Fatalf("%s: code %d, stdout %q, stderr %q", name, code, out.String(), errb.String())
		}
	}
}
