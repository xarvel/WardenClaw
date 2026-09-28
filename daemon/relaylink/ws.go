// SPDX-License-Identifier: AGPL-3.0-or-later

package relaylink

// A small client-only WebSocket (RFC 6455) for the relay transport: text messages, masking on
// write, ping/pong, close, fragmented messages on read, a message size limit. No extensions and
// no subprotocols are offered, so none may come back. It is written here instead of taken from a
// library to keep wardend's dependency set what it is; the relay speaks JSON text frames only
// (protocol/README.md section 5.2).

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

	wsOpCont   = 0x0
	wsOpText   = 0x1
	wsOpBinary = 0x2
	wsOpClose  = 0x8
	wsOpPing   = 0x9
	wsOpPong   = 0xA

	CloseNormal   = 1000
	CloseProtocol = 1002
	CloseData     = 1003
	CloseBadUTF8  = 1007
	CloseTooBig   = 1009

	wsHandshakeTimeout = 15 * time.Second
	wsWriteTimeout     = 15 * time.Second
)

// CloseError is returned by ReadText when the peer closed the connection with a close frame.
type CloseError struct {
	Code   int
	Reason string
}

func (e *CloseError) Error() string {
	return fmt.Sprintf("websocket closed: %d %s", e.Code, e.Reason)
}

type Conn struct {
	c   net.Conn
	br  *bufio.Reader
	max int // largest message accepted, bytes

	wmu    sync.Mutex // one frame at a time on the wire
	closed bool       // a close frame was sent (under wmu)
}

// Dial opens a WebSocket to rawURL (ws:// or wss://). maxMsg bounds a received message.
func Dial(ctx context.Context, rawURL string, header http.Header, maxMsg int) (*Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	var secure bool
	switch u.Scheme {
	case "ws":
	case "wss":
		secure = true
	default:
		return nil, fmt.Errorf("websocket: scheme %q: ws|wss", u.Scheme)
	}
	addr := u.Host
	if u.Port() == "" {
		if secure {
			addr = net.JoinHostPort(u.Hostname(), "443")
		} else {
			addr = net.JoinHostPort(u.Hostname(), "80")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, wsHandshakeTimeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if secure {
		// HTTP/1.1 only: the upgrade handshake does not exist in h2 without RFC 8441
		tc := tls.Client(c, &tls.Config{ServerName: u.Hostname(), NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			c.Close()
			return nil, err
		}
		c = tc
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	w, err := wsHandshake(c, u, header, maxMsg)
	if err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return w, nil
}

// wsHandshake does the HTTP upgrade on an established connection.
func wsHandshake(c net.Conn, u *url.URL, header http.Header, maxMsg int) (*Conn, error) {
	kb := make([]byte, 16)
	if _, err := rand.Read(kb); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(kb)
	req := &http.Request{Method: http.MethodGet, URL: u, Host: u.Host, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{}}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Version", "13")
	if err := req.Write(c); err != nil {
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Body.Close()
		return nil, fmt.Errorf("websocket: handshake status %d", resp.StatusCode)
	}
	sum := sha1.Sum([]byte(key + wsGUID))
	switch {
	case !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket"):
		return nil, errors.New("websocket: no Upgrade: websocket in the response")
	case !headerHasToken(resp.Header, "Connection", "upgrade"):
		return nil, errors.New("websocket: no Connection: Upgrade in the response")
	case resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]):
		return nil, errors.New("websocket: bad Sec-WebSocket-Accept")
	case resp.Header.Get("Sec-WebSocket-Extensions") != "" || resp.Header.Get("Sec-WebSocket-Protocol") != "":
		return nil, errors.New("websocket: the server chose an extension or subprotocol that was not offered")
	}
	return &Conn{c: c, br: br, max: maxMsg}, nil
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// writeFrame sends one masked frame (a client masks everything it sends).
func (w *Conn) writeFrame(op byte, payload []byte) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	if w.closed {
		return net.ErrClosed
	}
	if op == wsOpClose {
		w.closed = true
	}
	hdr := make([]byte, 0, 14)
	hdr = append(hdr, 0x80|op)
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n < 1<<16:
		hdr = append(hdr, 0x80|126)
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(n))
	default:
		hdr = append(hdr, 0x80|127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	buf := make([]byte, len(hdr)+4+n)
	copy(buf, hdr)
	copy(buf[len(hdr):], mask[:])
	body := buf[len(hdr)+4:]
	for i, b := range payload {
		body[i] = b ^ mask[i&3]
	}
	_ = w.c.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
	_, err := w.c.Write(buf)
	return err
}

func (w *Conn) WriteText(b []byte) error { return w.writeFrame(wsOpText, b) }

// SetReadDeadline bounds the next ReadText: the caller's idle timeout.
func (w *Conn) SetReadDeadline(t time.Time) { _ = w.c.SetReadDeadline(t) }

// ReadText returns the next text message. Pings are answered, pongs dropped, a close frame is
// echoed and reported as *CloseError. Anything the relay protocol does not use (binary
// messages, reserved bits, masked server frames, an oversized message) fails the connection.
func (w *Conn) ReadText() ([]byte, error) {
	var msg []byte
	inMsg := false
	for {
		var h [2]byte
		if _, err := io.ReadFull(w.br, h[:]); err != nil {
			return nil, err
		}
		fin, op := h[0]&0x80 != 0, h[0]&0x0f
		if h[0]&0x70 != 0 || h[1]&0x80 != 0 {
			return nil, w.fail(CloseProtocol, "reserved bits or a masked server frame")
		}
		n := uint64(h[1] & 0x7f)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(w.br, b[:]); err != nil {
				return nil, err
			}
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(w.br, b[:]); err != nil {
				return nil, err
			}
			n = binary.BigEndian.Uint64(b[:])
		}
		if op >= 0x8 { // control frame
			if !fin || n > 125 {
				return nil, w.fail(CloseProtocol, "bad control frame")
			}
			p := make([]byte, n)
			if _, err := io.ReadFull(w.br, p); err != nil {
				return nil, err
			}
			switch op {
			case wsOpPing:
				if err := w.writeFrame(wsOpPong, p); err != nil {
					return nil, err
				}
			case wsOpPong:
			case wsOpClose:
				ce := &CloseError{Code: 1005}
				if len(p) >= 2 {
					ce.Code, ce.Reason = int(binary.BigEndian.Uint16(p)), string(p[2:])
				}
				_ = w.writeFrame(wsOpClose, p[:min(len(p), 2)])
				w.c.Close()
				return nil, ce
			default:
				return nil, w.fail(CloseProtocol, "unknown control frame")
			}
			continue
		}
		switch {
		case op == wsOpText && !inMsg:
			inMsg = true
		case op == wsOpCont && inMsg:
		case op == wsOpBinary && !inMsg:
			return nil, w.fail(CloseData, "binary message")
		default:
			return nil, w.fail(CloseProtocol, "unexpected data frame")
		}
		if n > uint64(w.max) || uint64(len(msg))+n > uint64(w.max) {
			return nil, w.fail(CloseTooBig, "message too large")
		}
		off := len(msg)
		msg = append(msg, make([]byte, n)...)
		if _, err := io.ReadFull(w.br, msg[off:]); err != nil {
			return nil, err
		}
		if fin {
			if !utf8.Valid(msg) {
				return nil, w.fail(CloseBadUTF8, "invalid UTF-8")
			}
			return msg, nil
		}
	}
}

// fail closes the connection with a status code and returns the reason as an error.
func (w *Conn) fail(code int, reason string) error {
	w.Close(code, reason)
	return fmt.Errorf("websocket: %s", reason)
}

// CloseHandshake is the clean close: a close frame, then the peer's echo within timeout. It
// returns the peer's close code. Only the reading goroutine may call it.
func (w *Conn) CloseHandshake(code int, reason string, timeout time.Duration) (int, error) {
	p := binary.BigEndian.AppendUint16(nil, uint16(code))
	if err := w.writeFrame(wsOpClose, append(p, reason...)); err != nil {
		w.c.Close()
		return 0, err
	}
	defer w.c.Close()
	w.SetReadDeadline(time.Now().Add(timeout))
	for {
		_, err := w.ReadText()
		var ce *CloseError
		if errors.As(err, &ce) {
			return ce.Code, nil
		}
		if err != nil {
			return 0, err
		}
	}
}

// close sends a close frame (once) and drops the connection; the peer's echo is not awaited.
func (w *Conn) Close(code int, reason string) {
	p := binary.BigEndian.AppendUint16(nil, uint16(code))
	_ = w.writeFrame(wsOpClose, append(p, reason[:min(len(reason), 123)]...))
	w.c.Close()
}

// Drop closes the underlying connection without a close frame.
func (w *Conn) Drop() { w.c.Close() }
