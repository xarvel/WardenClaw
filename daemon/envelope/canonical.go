// SPDX-License-Identifier: AGPL-3.0-or-later

// Package envelope implements the v1 exec request envelope, canonical JSON, digest, signed
// decisions (tickets) from a WardenClaw device, and the trusted-device registry.
//
// Canonical JSON here matches canonicalJson() from app/src/core/canonical.ts and
// plugin/src/canonical.js byte-for-byte; both are built on JSON.stringify.
// Therefore the rules are ECMAScript rules, not encoding/json rules:
//
//   - object keys are sorted as in Array.prototype.sort() default order: by UTF-16
//     code units (differs from UTF-8 bytes for characters outside BMP vs. U+E000..U+FFFF);
//   - no whitespace; arrays preserve order; nil/undefined object fields in a map
//     must not be passed (JS drops undefined, keeps null);
//   - strings: only `"`, `\`, and control chars < 0x20 are escaped: \b \t \n \f \r, others
//     as \u00xx (lowercase hex). `< > &`, U+2028/U+2029, DEL (0x7f) and all non-ASCII are
//     written as-is (encoding/json escapes U+2028/2029 even with SetEscapeHTML(false),
//     hence the custom encoder);
//   - numbers: ECMAScript Number::toString (shortest representation, exponent with e+/e-
//     when n > 21 or n <= -6); NaN/Inf are forbidden (JSON.stringify would produce null);
//   - invalid UTF-8 is an error (JS cannot produce such strings; an envelope with such bytes
//     is not built; policy handles the decision).
package envelope

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrInvalidUTF8 is returned when a string contains invalid UTF-8.
var ErrInvalidUTF8 = errors.New("canonical: invalid UTF-8 in string")

// Canonical encodes a value: nil, bool, string, integers/float, json.Number,
// map[string]any (and map[string]T), []any (and []T). Structs are not supported;
// build maps explicitly so field order and presence are visible in code.
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := enc(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Digest returns the canonical encoding of v and its digest: hex(sha256(canonical)).
func Digest(v any) (canon []byte, digest string, err error) {
	canon, err = Canonical(v)
	if err != nil {
		return nil, "", err
	}
	return canon, SHA256Hex(canon), nil
}

// SHA256Hex returns the SHA-256 of b as lowercase hex.
func SHA256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func enc(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		return encString(b, x)
	case json.Number:
		return encNumber(b, x)
	case float64:
		return encFloat(b, x)
	case float32:
		return encFloat(b, float64(x))
	case int:
		return encInt(b, int64(x))
	case int32:
		return encInt(b, int64(x))
	case int64:
		return encInt(b, x)
	case uint32:
		return encInt(b, int64(x))
	case uint64:
		if x > jsIntLimit {
			return fmt.Errorf("canonical: integer %d beyond 2^53", x)
		}
		return encInt(b, int64(x))
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := enc(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case []string:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encString(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sortUTF16(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encString(b, k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := enc(b, x[k]); err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
		}
		b.WriteByte('}')
	default:
		// []T / map[string]T via reflect
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Slice, reflect.Array:
			arr := make([]any, rv.Len())
			for i := range arr {
				arr[i] = rv.Index(i).Interface()
			}
			return enc(b, arr)
		case reflect.Map:
			if rv.Type().Key().Kind() != reflect.String {
				return fmt.Errorf("canonical: map key must be string, got %s", rv.Type().Key())
			}
			m := make(map[string]any, rv.Len())
			it := rv.MapRange()
			for it.Next() {
				m[it.Key().String()] = it.Value().Interface()
			}
			return enc(b, m)
		}
		return fmt.Errorf("canonical: unsupported type %T", v)
	}
	return nil
}

// jsIntLimit is 2^53: every integer in [-2^53, 2^53] is exact as a JS number, so the app and
// the plugin print it with the same digits.
const jsIntLimit = 1 << 53

// MaxSafeInt is Number.MAX_SAFE_INTEGER: integer literals up to it are read back exactly by
// JSON.parse on the other side; beyond it two different literals can become one number.
const MaxSafeInt = 1<<53 - 1

// encNumber encodes a JSON number literal (json.Number). An integer literal within the safe range
// is written exactly. Beyond it the literal is accepted only when the ECMAScript form has the very
// same digits (1e20 prints as 100000000000000000000): an identifier such as an inode is never
// rounded on its way into a hash or a signed entry, it is refused instead. Fractions and exponents
// follow ECMAScript Number::toString like any other float; that is what the vectors fix.
func encNumber(b *bytes.Buffer, x json.Number) error {
	s := string(x)
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("canonical: number %q: %w", s, err)
	}
	if !isIntLiteral(s) {
		return encFloat(b, f)
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n <= MaxSafeInt && n >= -MaxSafeInt {
		b.WriteString(strconv.FormatInt(n, 10))
		return nil
	}
	var t bytes.Buffer
	if err := encFloat(&t, f); err != nil {
		return err
	}
	if t.String() != s {
		return fmt.Errorf("canonical: integer %s beyond 2^53 would be rounded to %s", s, t.String())
	}
	b.Write(t.Bytes())
	return nil
}

// isIntLiteral reports whether s is a JSON integer literal: an optional minus and digits only.
func isIntLiteral(s string) bool {
	if strings.HasPrefix(s, "-") {
		s = s[1:]
	}
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func encInt(b *bytes.Buffer, x int64) error {
	if x > jsIntLimit || x < -jsIntLimit {
		return fmt.Errorf("canonical: integer %d beyond 2^53", x)
	}
	b.WriteString(strconv.FormatInt(x, 10))
	return nil
}

// encFloat implements ECMAScript Number::toString(10) for finite values.
func encFloat(b *bytes.Buffer, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return errors.New("canonical: NaN/Inf not allowed")
	}
	if f == 0 {
		b.WriteByte('0') // -0 also becomes "0", as in JS
		return nil
	}
	if f < 0 {
		b.WriteByte('-')
		f = -f
	}
	// shortest digits: d.ddddde±XX
	s := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expS, _ := strings.Cut(s, "e")
	digits := strings.Replace(mant, ".", "", 1)
	e, _ := strconv.Atoi(expS)
	k := len(digits)
	n := e + 1 // decimal point position
	switch {
	case k <= n && n <= 21:
		b.WriteString(digits)
		b.WriteString(strings.Repeat("0", n-k))
	case 0 < n && n <= 21:
		b.WriteString(digits[:n])
		b.WriteByte('.')
		b.WriteString(digits[n:])
	case -6 < n && n <= 0:
		b.WriteString("0.")
		b.WriteString(strings.Repeat("0", -n))
		b.WriteString(digits)
	default:
		b.WriteByte(digits[0])
		if k > 1 {
			b.WriteByte('.')
			b.WriteString(digits[1:])
		}
		b.WriteByte('e')
		if n-1 >= 0 {
			b.WriteByte('+')
		}
		b.WriteString(strconv.Itoa(n - 1))
	}
	return nil
}

const hexLower = "0123456789abcdef"

func encString(b *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return ErrInvalidUTF8
	}
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if c < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hexLower[c>>4])
				b.WriteByte(hexLower[c&0xf])
			} else {
				b.WriteByte(c) // multi-byte UTF-8 sequences are copied as-is
			}
		}
	}
	b.WriteByte('"')
	return nil
}

// sortUTF16 sorts keys in Array.prototype.sort() default order (UTF-16 code unit comparison).
func sortUTF16(keys []string) {
	sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
}

func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// ParseJSON parses JSON while preserving numbers as json.Number (for re-canonicalization).
func ParseJSON(data []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}
