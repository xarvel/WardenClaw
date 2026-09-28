// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

import (
	"crypto/ed25519"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// TestParseDecisionTsInteger: the ticket timestamp is Date.now(), so ParseDecision takes only an
// integer literal within the JS safe range; a fraction, an exponent, a negative or a larger number
// is ts_invalid. That keeps every number the journal stores from a ticket a safe integer.
func TestParseDecisionTsInteger(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sup, digest := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	b := Sign(priv, sup, PendingID(digest), digest, "allow", NowMs(), NewNonce())
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseDecision(raw); err != nil {
		t.Fatalf("valid ticket: %v", err)
	}
	tsRx := regexp.MustCompile(`"ts":[0-9]+`)
	if !tsRx.Match(raw) {
		t.Fatalf("no integer ts in %s", raw)
	}
	for _, ts := range []string{"1.5", "1e12", "1727700000000.0", "9007199254740993", "-1"} {
		bad := tsRx.ReplaceAllString(string(raw), `"ts":`+ts)
		if _, err := ParseDecision([]byte(bad)); err == nil || err.Error() != "ts_invalid" {
			t.Errorf("ts %s: %v", ts, err)
		}
	}
}
