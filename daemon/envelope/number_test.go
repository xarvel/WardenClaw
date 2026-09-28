// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

import (
	"encoding/json"
	"testing"
)

// TestCanonicalNumberLiterals: crypto review 2026-09-28, finding 6: a JSON integer literal is never
// rounded on its way through json.Number. Within the safe range it is written exactly; beyond it
// only a literal whose ECMAScript form has the same digits passes. Fractions and exponents keep
// the vector semantics.
func TestCanonicalNumberLiterals(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"0", "0"}, {"-0", "0"}, {"42", "42"}, {"-7", "-7"},
		{"9007199254740991", "9007199254740991"}, {"-9007199254740991", "-9007199254740991"},
		{"9007199254740992", "9007199254740992"},           // 2^53 prints as itself
		{"100000000000000000000", "100000000000000000000"}, // 1e20, as in the canonical vectors
		{"1.5", "1.5"}, {"-0.5", "-0.5"}, {"1e21", "1e+21"}, {"1E-7", "1e-7"},
	} {
		got, err := Canonical(json.Number(c.in))
		if err != nil || string(got) != c.want {
			t.Errorf("%s: got %s, %v; want %s", c.in, got, err, c.want)
		}
	}
	for _, in := range []string{
		"9007199254740993", "-9007199254740993", // 2^53 + 1: would become 2^53
		"1152921504606846976",     // 2^60: exact as a double, but JS prints 1152921504606847000
		"18446744073709551617",    // beyond int64
		"12345678901234567890123", // beyond int64, not exact
	} {
		if got, err := Canonical(json.Number(in)); err == nil {
			t.Errorf("%s: accepted as %s, would be rounded", in, got)
		}
	}
	// the same through ParseJSON, as the journal and the ticket verifier see numbers
	v, err := ParseJSON([]byte(`{"ino":9007199254740993}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Canonical(v); err == nil {
		t.Errorf("parsed inode beyond 2^53 accepted as %s", got)
	}
	v, _ = ParseJSON([]byte(`{"ino":9007199254740991,"x":[1.25,-2]}`))
	if got, err := Canonical(v); err != nil || string(got) != `{"ino":9007199254740991,"x":[1.25,-2]}` {
		t.Errorf("safe numbers: %s %v", got, err)
	}
}
