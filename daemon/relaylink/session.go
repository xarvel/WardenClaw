// SPDX-License-Identifier: AGPL-3.0-or-later

package relaylink

// A device's live connection: one goroutine reads, opens what the supervisor sent and acks it;
// the owner sends frames and takes what arrived, in the order of arrival.

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	pingEvery   = 30 * time.Second // the relay closes a connection silent for 90 s
	idleTimeout = 90 * time.Second // and so does the device
	ackTimeout  = 10 * time.Second
	inboxSize   = 256
)

var (
	// ErrClosed: the connection to the relay ended (Session.Err says why).
	ErrClosed = errors.New("relay: connection closed")
	// ErrTimeout: the relay did not answer a frame.
	ErrTimeout = errors.New("relay: no answer from the relay")
)

// Message is what a session hands to its owner: a frame of the supervisor, opened (Kind and
// Body), or a frame of the relay itself that answers no envelope (Frame.Type: resumed, peer).
type Message struct {
	Kind  string // card, card.done, status, ticket.result, pair.status; "": a relay frame
	Body  []byte // the plaintext
	Frame Frame
}

// Session is a connected device.
type Session struct {
	d    *Device
	c    *DeviceConn
	in   chan Message
	done chan struct{}

	mu              sync.Mutex
	err             error
	waiters         []sessionWaiter // envelopes sent and not answered yet
	peer, peerKnown bool            // the supervisor's connection, as the relay last reported it
}

type sessionWaiter struct {
	id string
	ch chan error
}

// Connect dials the relay at base, says hello and starts reading.
func (d *Device) Connect(ctx context.Context, base string) (*Session, error) {
	c, err := d.Dial(ctx, base)
	if err != nil {
		return nil, err
	}
	s := &Session{d: d, c: c, in: make(chan Message, inboxSize), done: make(chan struct{})}
	go s.read()
	go s.keepalive()
	return s, nil
}

// Messages is the inbox; it is closed when the connection ends.
func (s *Session) Messages() <-chan Message { return s.in }

// Err is why the connection ended (nil while it is up).
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *Session) read() {
	defer close(s.done)
	defer close(s.in)
	for {
		f, err := s.c.Read(time.Now().Add(idleTimeout))
		if err != nil {
			s.end(err)
			return
		}
		switch f.Type {
		case "msg":
			// a frame that does not open is not from the paired supervisor: no ack, never shown
			pt, err := s.d.Open(f.Envelope)
			if err != nil {
				continue
			}
			_ = s.c.Ack(f)
			s.deliver(Message{Kind: f.Kind, Body: pt, Frame: f})
		case "ack":
			if f.ID != "" {
				s.answer(f.ID, nil)
			}
		case "error":
			// the error names the envelope it refuses; one that names nothing cannot be
			// attributed, and the session ends rather than guess
			if f.ID == "" || !s.answer(f.ID, &Error{Code: f.Code}) {
				s.end(&Error{Code: f.Code})
				s.c.Drop()
				return
			}
		case "peer":
			s.mu.Lock()
			s.peer, s.peerKnown = f.Online, true
			s.mu.Unlock()
			s.deliver(Message{Frame: f})
		case "resumed":
			s.deliver(Message{Frame: f})
		}
	}
}

// deliver never blocks the reader: an owner that stopped taking loses the connection, and
// learns the state again with its next status.
func (s *Session) deliver(m Message) {
	select {
	case s.in <- m:
	default:
		s.end(errors.New("relay: inbox overflow"))
		s.c.Drop()
	}
}

// Peer is what the relay last said about the supervisor's connection (a peer frame); known is
// false until it said anything.
func (s *Session) Peer() (online, known bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peer, s.peerKnown
}

// answer resolves the waiter of envelope id.
func (s *Session) answer(id string, err error) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, w := range s.waiters {
		if w.id == id {
			s.waiters = append(s.waiters[:i], s.waiters[i+1:]...)
			w.ch <- err
			return true
		}
	}
	return false
}

func (s *Session) end(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	ws := s.waiters
	s.waiters = nil
	s.mu.Unlock()
	for _, w := range ws {
		w.ch <- ErrClosed
	}
}

func (s *Session) keepalive() {
	t := time.NewTicker(pingEvery)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			if err := s.c.Write(map[string]any{"type": "ping"}); err != nil {
				return
			}
		}
	}
}

// Send hands an envelope to the relay and waits for its answer: nil once the relay stored the
// frame, *Error when it refused it. Neither says anything about the supervisor.
func (s *Session) Send(ctx context.Context, e Envelope) error {
	w := sessionWaiter{id: e.ID, ch: make(chan error, 1)}
	s.mu.Lock()
	if s.err != nil {
		s.mu.Unlock()
		return ErrClosed
	}
	s.waiters = append(s.waiters, w)
	s.mu.Unlock()
	if err := s.c.Write(e); err != nil {
		s.answer(e.ID, nil)
		return err
	}
	t := time.NewTimer(ackTimeout)
	defer t.Stop()
	select {
	case err := <-w.ch:
		return err
	case <-ctx.Done():
		s.answer(e.ID, nil)
		return ctx.Err()
	case <-t.C:
		s.answer(e.ID, nil)
		return ErrTimeout
	}
}

// Request boxes plaintext as a msg of this kind and sends it.
func (s *Session) Request(ctx context.Context, kind string, plaintext []byte) error {
	e, err := s.d.Seal(kind, plaintext)
	if err != nil {
		return err
	}
	return s.Send(ctx, e)
}

// Resume asks for what the relay queued while the device was away; the frames arrive in the
// inbox before the relay's resumed frame.
func (s *Session) Resume() error { return s.c.Resume() }

// Close ends the connection: a close frame, then the socket.
func (s *Session) Close() {
	s.c.Close()
	select {
	case <-s.done:
	case <-time.After(3 * time.Second):
	}
	s.c.Drop()
	<-s.done
}
