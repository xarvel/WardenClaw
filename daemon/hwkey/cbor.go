// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hwkey implements second-factor verification via hardware key (FIDO2/WebAuthn, YubiKey 5):
// attestation parsing at registration, COSE keys EdDSA/ES256, assertion verification
// (rpIdHash, UP/UV flags, monotonic signCount, signature, challenge binding).
//
// A minimal CBOR decoder is included (only what appears in CTAP2: integers, byte strings,
// text strings, arrays, maps, true/false/null; tags are skipped) to avoid external
// dependencies in code that decides whether to allow execve.
package hwkey

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"unicode/utf8"
)

var errCBOR = errors.New("cbor: malformed")

// maxDepth bounds nesting so that a hostile blob cannot exhaust the stack.
const maxDepth = 16

// CBOR major types (RFC 8949, section 3.1).
const (
	majorUint   = 0
	majorNegInt = 1
	majorBytes  = 2
	majorText   = 3
	majorArray  = 4
	majorMap    = 5
	majorTag    = 6
	majorSimple = 7
)

// Simple values of major type 7.
const (
	simpleFalse     = 20
	simpleTrue      = 21
	simpleNull      = 22
	simpleUndefined = 23
)

// cborDecode decodes one item and returns the number of bytes consumed.
// Values: int64, []byte, string, []any, map[any]any (keys int64|string), bool, nil.
func cborDecode(b []byte) (any, int, error) {
	d := decoder{b: b}
	v, err := d.item(0)
	if err != nil {
		return nil, 0, err
	}
	return v, d.off, nil
}

// cborDecodeAll decodes an item that must consume the entire buffer.
func cborDecodeAll(b []byte) (any, error) {
	v, n, err := cborDecode(b)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, fmt.Errorf("cbor: %d trailing bytes", len(b)-n)
	}
	return v, nil
}

type decoder struct {
	b   []byte
	off int
}

func (d *decoder) need(n uint64) error {
	if n > uint64(len(d.b)-d.off) {
		return errCBOR
	}
	return nil
}

func (d *decoder) head() (major byte, arg uint64, err error) {
	if err = d.need(1); err != nil {
		return
	}
	ib := d.b[d.off]
	d.off++
	major, info := ib>>5, ib&0x1f
	switch {
	case info < 24:
		arg = uint64(info)
	case info == 24:
		if err = d.need(1); err == nil {
			arg = uint64(d.b[d.off])
			d.off++
		}
	case info == 25:
		if err = d.need(2); err == nil {
			arg = uint64(binary.BigEndian.Uint16(d.b[d.off:]))
			d.off += 2
		}
	case info == 26:
		if err = d.need(4); err == nil {
			arg = uint64(binary.BigEndian.Uint32(d.b[d.off:]))
			d.off += 4
		}
	case info == 27:
		if err = d.need(8); err == nil {
			arg = binary.BigEndian.Uint64(d.b[d.off:])
			d.off += 8
		}
	default: // 28..30 reserved, 31 = indefinite length (CTAP2 forbids it)
		err = fmt.Errorf("cbor: unsupported additional info %d", info)
	}
	return
}

func (d *decoder) item(depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("cbor: too deep")
	}
	major, arg, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case majorUint:
		if arg > math.MaxInt64 {
			return nil, errors.New("cbor: uint overflow")
		}
		return int64(arg), nil
	case majorNegInt:
		if arg > math.MaxInt64 {
			return nil, errors.New("cbor: nint overflow")
		}
		return -1 - int64(arg), nil
	case majorBytes, majorText:
		if err := d.need(arg); err != nil {
			return nil, err
		}
		s := d.b[d.off : d.off+int(arg)]
		d.off += int(arg)
		if major == majorBytes {
			return append([]byte(nil), s...), nil
		}
		if !utf8.Valid(s) {
			return nil, errors.New("cbor: invalid utf-8 text")
		}
		return string(s), nil
	case majorArray:
		if arg > uint64(len(d.b)) {
			return nil, errCBOR
		}
		out := make([]any, 0, arg)
		for i := uint64(0); i < arg; i++ {
			v, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case majorMap:
		if arg > uint64(len(d.b)) {
			return nil, errCBOR
		}
		out := make(map[any]any, arg)
		for i := uint64(0); i < arg; i++ {
			k, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, errors.New("cbor: map key must be int or text")
			}
			v, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			if _, dup := out[k]; dup {
				return nil, errors.New("cbor: duplicate map key")
			}
			out[k] = v
		}
		return out, nil
	case majorTag: // skip the tag, decode the content
		return d.item(depth + 1)
	case majorSimple:
		switch arg {
		case simpleFalse:
			return false, nil
		case simpleTrue:
			return true, nil
		case simpleNull, simpleUndefined:
			return nil, nil
		}
		return nil, fmt.Errorf("cbor: unsupported simple/float %d", arg)
	}
	return nil, errCBOR
}

// ---- encoding (test registration, COSE keys) ----

// cborEncode produces canonical CTAP2 encoding: map keys sorted by encoding bytes
// (shorter first). Supports int, int64, uint32, []byte, string, bool, []any, map[any]any.
func cborEncode(v any) []byte {
	var buf bytes.Buffer
	encodeTo(&buf, v)
	return buf.Bytes()
}

func writeHead(buf *bytes.Buffer, major byte, n uint64) {
	m := major << 5
	switch {
	case n < 24:
		buf.WriteByte(m | byte(n))
	case n <= 0xff:
		buf.WriteByte(m | 24)
		buf.WriteByte(byte(n))
	case n <= 0xffff:
		buf.WriteByte(m | 25)
		buf.Write(binary.BigEndian.AppendUint16(nil, uint16(n)))
	case n <= 0xffffffff:
		buf.WriteByte(m | 26)
		buf.Write(binary.BigEndian.AppendUint32(nil, uint32(n)))
	default:
		buf.WriteByte(m | 27)
		buf.Write(binary.BigEndian.AppendUint64(nil, n))
	}
}

func encodeTo(buf *bytes.Buffer, v any) {
	switch x := v.(type) {
	case int:
		encodeTo(buf, int64(x))
	case uint32:
		encodeTo(buf, int64(x))
	case int64:
		if x >= 0 {
			writeHead(buf, majorUint, uint64(x))
		} else {
			writeHead(buf, majorNegInt, uint64(-1-x))
		}
	case []byte:
		writeHead(buf, majorBytes, uint64(len(x)))
		buf.Write(x)
	case string:
		writeHead(buf, majorText, uint64(len(x)))
		buf.WriteString(x)
	case bool:
		if x {
			writeHead(buf, majorSimple, simpleTrue)
		} else {
			writeHead(buf, majorSimple, simpleFalse)
		}
	case nil:
		writeHead(buf, majorSimple, simpleNull)
	case []any:
		writeHead(buf, majorArray, uint64(len(x)))
		for _, e := range x {
			encodeTo(buf, e)
		}
	case map[any]any:
		type kv struct{ k, v []byte }
		kvs := make([]kv, 0, len(x))
		for k, e := range x {
			kvs = append(kvs, kv{cborEncode(k), cborEncode(e)})
		}
		sort.Slice(kvs, func(i, j int) bool {
			if len(kvs[i].k) != len(kvs[j].k) {
				return len(kvs[i].k) < len(kvs[j].k)
			}
			return bytes.Compare(kvs[i].k, kvs[j].k) < 0
		})
		writeHead(buf, majorMap, uint64(len(kvs)))
		for _, e := range kvs {
			buf.Write(e.k)
			buf.Write(e.v)
		}
	default:
		panic(fmt.Sprintf("cborEncode: unsupported %T", v))
	}
}

// EncodeCBOR is exported for tests (software authenticator in hwkey/hwkeytest).
func EncodeCBOR(v any) []byte { return cborEncode(v) }
