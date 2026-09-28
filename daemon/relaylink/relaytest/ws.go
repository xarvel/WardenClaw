// SPDX-License-Identifier: AGPL-3.0-or-later

// Package relaytest is the server side of a WebSocket for the tests of the relay transport:
// unmasked frames out, masked frames in.
package relaytest

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Opcodes of RFC 6455.
const (
	OpCont   = 0x0
	OpText   = 0x1
	OpBinary = 0x2
	OpClose  = 0x8
	OpPing   = 0x9
	OpPong   = 0xA
)

// Conn is the server side of a WebSocket for tests: unmasked frames out, masked frames in.
type Conn struct {
	c  net.Conn
	br *bufio.Reader
	mu sync.Mutex
}

func Accept(t *testing.T, w http.ResponseWriter, r *http.Request) *Conn {
	t.Helper()
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "upgrade required", http.StatusUpgradeRequired)
		return nil
	}
	c, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Error(err)
		return nil
	}
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + guid))
	_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n")
	_ = rw.Flush()
	return &Conn{c: c, br: rw.Reader}
}

func (s *Conn) Frame(fin bool, op byte, payload []byte) {
	b := []byte{op}
	if fin {
		b[0] |= 0x80
	}
	switch n := len(payload); {
	case n < 126:
		b = append(b, byte(n))
	case n < 1<<16:
		b = binary.BigEndian.AppendUint16(append(b, 126), uint16(n))
	default:
		b = binary.BigEndian.AppendUint64(append(b, 127), uint64(n))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.c.Write(append(b, payload...))
}

func (s *Conn) Text(v string) { s.Frame(true, OpText, []byte(v)) }

func (s *Conn) CloseWith(code int, reason string) {
	s.Frame(true, OpClose, append(binary.BigEndian.AppendUint16(nil, uint16(code)), reason...))
}

// read returns the next frame of the client; an unmasked client frame is an error.
func (s *Conn) Read() (op byte, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(s.br, h[:]); err != nil {
		return 0, nil, err
	}
	if h[1]&0x80 == 0 {
		return 0, nil, errors.New("client frame is not masked")
	}
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		_, _ = io.ReadFull(s.br, b[:])
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		_, _ = io.ReadFull(s.br, b[:])
		n = binary.BigEndian.Uint64(b[:])
	}
	var mask [4]byte
	if _, err = io.ReadFull(s.br, mask[:]); err != nil {
		return 0, nil, err
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(s.br, payload); err != nil {
		return 0, nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i&3]
	}
	return h[0] & 0x0f, payload, nil
}

// Raw writes bytes to the connection as they are (malformed frames).
func (s *Conn) Raw(b []byte) { _, _ = s.c.Write(b) }

// Close drops the connection.
func (s *Conn) Close() { s.c.Close() }
