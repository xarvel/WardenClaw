// SPDX-License-Identifier: AGPL-3.0-or-later

package relaylink_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/relaylink"
	"github.com/xarvel/WardenClaw/daemon/relaylink/relaytest"
)

// wsTestServer runs fn on the server side of one connection and returns the dialed client.
func wsTestServer(t *testing.T, maxMsg int, fn func(s *relaytest.Conn)) *relaylink.Conn {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s := relaytest.Accept(t, w, r); s != nil {
			defer s.Close()
			fn(s)
		}
	}))
	t.Cleanup(srv.Close)
	ws, err := relaylink.Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), nil, maxMsg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.Drop() })
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	return ws
}

func TestWSEchoAllLengths(t *testing.T) {
	ws := wsTestServer(t, 1<<20, func(s *relaytest.Conn) {
		for {
			op, p, err := s.Read()
			if err != nil || op != relaytest.OpText {
				return
			}
			s.Frame(true, relaytest.OpText, p)
		}
	})
	for _, n := range []int{0, 1, 125, 126, 65535, 65536, 70000} { // 7-bit, 16-bit and 64-bit lengths
		msg := bytes.Repeat([]byte("a"), n)
		if err := ws.WriteText(msg); err != nil {
			t.Fatal(err)
		}
		got, err := ws.ReadText()
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("len %d: got %d bytes, err %v", n, len(got), err)
		}
	}
}

func TestWSFragmentsPingAndClose(t *testing.T) {
	pong := make(chan []byte, 1)
	closed := make(chan []byte, 1)
	ws := wsTestServer(t, 1024, func(s *relaytest.Conn) {
		s.Frame(false, relaytest.OpText, []byte("he"))
		s.Frame(true, relaytest.OpPing, []byte("p1")) // a control frame between fragments
		s.Frame(false, relaytest.OpCont, []byte("ll"))
		s.Frame(true, relaytest.OpCont, []byte("o"))
		if op, p, _ := s.Read(); op == relaytest.OpPong {
			pong <- p
		}
		s.CloseWith(4001, "superseded")
		if op, p, _ := s.Read(); op == relaytest.OpClose {
			closed <- p
		}
	})
	got, err := ws.ReadText()
	if err != nil || string(got) != "hello" {
		t.Fatalf("fragmented message: %q, %v", got, err)
	}
	if p := <-pong; string(p) != "p1" {
		t.Fatalf("pong payload %q", p)
	}
	_, err = ws.ReadText()
	var ce *relaylink.CloseError
	if !errors.As(err, &ce) || ce.Code != 4001 || ce.Reason != "superseded" {
		t.Fatalf("close: %v", err)
	}
	if p := <-closed; len(p) != 2 || binary.BigEndian.Uint16(p) != 4001 {
		t.Fatalf("close echo %x", p)
	}
}

func TestWSRefuses(t *testing.T) {
	cases := []struct {
		name string
		send func(s *relaytest.Conn)
		code uint16
	}{
		{"oversized", func(s *relaytest.Conn) { s.Text(strings.Repeat("a", 65)) }, relaylink.CloseTooBig},
		{"oversized fragments", func(s *relaytest.Conn) {
			s.Frame(false, relaytest.OpText, bytes.Repeat([]byte("a"), 40))
			s.Frame(true, relaytest.OpCont, bytes.Repeat([]byte("a"), 40))
		}, relaylink.CloseTooBig},
		{"binary", func(s *relaytest.Conn) { s.Frame(true, relaytest.OpBinary, []byte{1}) }, relaylink.CloseData},
		{"bad utf8", func(s *relaytest.Conn) { s.Frame(true, relaytest.OpText, []byte{0xff}) }, relaylink.CloseBadUTF8},
		{"stray continuation", func(s *relaytest.Conn) { s.Frame(true, relaytest.OpCont, []byte("a")) }, relaylink.CloseProtocol},
		{"masked server frame", func(s *relaytest.Conn) { s.Raw([]byte{0x81, 0x81, 0, 0, 0, 0, 'a'}) }, relaylink.CloseProtocol},
		{"reserved bit", func(s *relaytest.Conn) { s.Raw([]byte{0xc1, 0x01, 'a'}) }, relaylink.CloseProtocol},
		{"fragmented control", func(s *relaytest.Conn) { s.Frame(false, relaytest.OpPing, nil) }, relaylink.CloseProtocol},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := make(chan uint16, 1)
			ws := wsTestServer(t, 64, func(s *relaytest.Conn) {
				tc.send(s)
				if op, p, _ := s.Read(); op == relaytest.OpClose && len(p) >= 2 {
					code <- binary.BigEndian.Uint16(p)
				} else {
					code <- 0
				}
			})
			if msg, err := ws.ReadText(); err == nil {
				t.Fatalf("accepted %q", msg)
			}
			if got := <-code; got != tc.code {
				t.Fatalf("close code %d, want %d", got, tc.code)
			}
			if err := ws.WriteText([]byte("x")); err == nil {
				t.Fatal("write after a failed connection succeeded")
			}
		})
	}
}

func TestWSHandshakeRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/badaccept" {
			c, rw, _ := w.(http.Hijacker).Hijack()
			defer c.Close()
			_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: AAAA\r\n\r\n")
			_ = rw.Flush()
			return
		}
		http.Error(w, "no", http.StatusNotFound)
	}))
	defer srv.Close()
	base := "ws" + strings.TrimPrefix(srv.URL, "http")
	for _, u := range []string{base + "/nope", base + "/badaccept", "http://127.0.0.1:1/"} {
		if ws, err := relaylink.Dial(context.Background(), u, nil, 64); err == nil {
			ws.Drop()
			t.Fatalf("%s: handshake accepted", u)
		}
	}
}
