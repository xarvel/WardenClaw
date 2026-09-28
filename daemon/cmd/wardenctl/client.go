// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// wardenctl is a device on the supervisor's relay channel (protocol/README.md), like the phone
// app: it dials <relay>/v1/ws/<supervisorId>, and everything it shows or signs comes out of a box
// only the supervisor of the pairing link could have sealed.
//
//	device → supervisor: pair (the pairing request), status.req, ticket
//	supervisor → device: pair.status, status (the state and the pending cards), card, card.done,
//	                     ticket.result
//
// The relay is an untrusted carrier: it can delay or drop a frame, which is a timeout here and
// never a decision.

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/relaylink"
)

// How long wardend may take to answer over the relay, and how long the cards a status left out
// (pendingTruncated) may take to follow it.
const (
	requestTimeout = 15 * time.Second
	decideTimeout  = 30 * time.Second
	cardsTimeout   = 3 * time.Second
)

// Client is this device's connection to one wardend through the relay.
type Client struct {
	dev  *relaylink.Device
	base string

	mu      sync.Mutex
	s       *relaylink.Session
	in      chan relaylink.Message          // what the supervisor sent, except ticket results
	results map[string]chan json.RawMessage // card id → the ticket.result a Decide waits for
}

func newClient(relay, supervisorID string, supervisorEnc *ecdh.PublicKey, key ed25519.PrivateKey, enc *ecdh.PrivateKey) *Client {
	return &Client{base: relay, results: map[string]chan json.RawMessage{},
		dev: &relaylink.Device{Key: key, Enc: enc, SupervisorID: supervisorID, SupervisorEnc: supervisorEnc, Client: "wardenctl", Version: version}}
}

// ServerError is a refusal with a machine reason: of wardend (out of a box) or of the relay
// (Relay: the frame never reached wardend).
type ServerError struct {
	Reason string
	Relay  bool
}

func (e *ServerError) Error() string {
	who := "wardend"
	if e.Relay {
		who = "relay"
	}
	if h, ok := reasonText[e.Reason]; ok {
		return fmt.Sprintf("%s (%s: %s)", h, who, e.Reason)
	}
	return who + ": " + e.Reason
}

// errNoAnswer: the relay took the frame and wardend did not answer in time.
type errNoAnswer struct {
	what    string
	offline bool // the relay says wardend is not connected
}

func (e *errNoAnswer) Error() string {
	if e.offline {
		return "wardend is offline: it is not connected to the relay (no " + e.what + ")"
	}
	return "no " + e.what + " from wardend through the relay"
}

// reasonText: human-readable reasons for refusals of wardend and of the relay.
var reasonText = map[string]string{
	"response_mismatch":       "wardend's answer is not about this ticket (the decision does not match)",
	"pairing_closed":          "no active code on the server: run wardend pair start again",
	"pairing_not_active":      "no active code on the server: run wardend pair start again",
	"bad_code":                "code did not match or was already used: run wardend pair start again",
	"wrong_supervisor":        "link is from a different server",
	"device_id_mismatch":      "deviceId does not match the key",
	"device_mismatch":         "the ticket is signed by another device than the one that sent it",
	"stale_timestamp":         "clocks of this machine and the server differ by more than ts_window (60 s by default)",
	"bad_signature":           "signature verification failed",
	"not_trusted":             "the server does not trust this device: approve the pairing (wardend pair approve) or pair again",
	"untrusted_device":        "the server does not trust this device: approve the pairing (wardend pair approve) or pair again",
	"unknown_device":          "the server does not know this device's key",
	"too_many_requests":       "too many pending pairing requests on the server",
	"rate_limited":            "the relay refuses frames from this device for now: too many in a short time",
	"nonce_reused":            "nonce already used",
	"name_invalid":            "invalid device name",
	"unknown_pending":         "this card no longer exists: expired or decided by another device",
	"already_decided":         "card already decided",
	"digest_mismatch":         "digest does not match the pending exec",
	"pubkey_conflict":         "device key in the wardend config differs from the gateway DB",
	"config_pubkey_invalid":   "device key in the wardend config cannot be parsed or does not match its deviceId",
	"gateway_pubkey_mismatch": "device key in the gateway DB does not match its deviceId (spoofing?): pair the device with wardend again",
	"hardware_required":       "this command requires a second YubiKey signature",
	"hardware_not_configured": "no hardware key is registered in wardend (wardend hw-register)",
	"hw_unknown_credential":   "wardend does not know this YubiKey: wardend hw-register and restart wardend",
	"hw_challenge_mismatch":   "YubiKey assertion is not for this ticket",
	"hw_rpid_mismatch":        "key rpId does not match",
	"hw_user_presence":        "YubiKey did not confirm a touch (UP flag)",
	"hw_user_verification":    "wardend requires the YubiKey PIN (UV flag): wardenctl hw-register --uv or --require-uv",
	"hw_bad_signature":        "YubiKey signature verification failed",
	"hw_counter_replay":       "YubiKey counter did not increase (replay or cloned key)",
	"hw_counter_persist":      "wardend could not save the YubiKey counter",
}

func reasonHuman(r string) string {
	if h, ok := reasonText[r]; ok {
		return h + " (" + r + ")"
	}
	return r
}

func isReason(err error, reason string) bool {
	var se *ServerError
	return errors.As(err, &se) && se.Reason == reason
}

// connect dials the relay unless the connection is up.
func (c *Client) connect(ctx context.Context) (*relaylink.Session, chan relaylink.Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.s != nil && c.s.Err() == nil {
		return c.s, c.in, nil
	}
	dctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	s, err := c.dev.Connect(dctx, c.base)
	if err != nil {
		var re *relaylink.Error
		if errors.As(err, &re) {
			return nil, nil, &ServerError{Reason: re.Code, Relay: true}
		}
		var pe *relaylink.ProtocolError
		if errors.As(err, &pe) {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("no connection to the relay %s: %w", c.base, err)
	}
	c.s, c.in = s, make(chan relaylink.Message, 256)
	go c.pump(s, c.in)
	return c.s, c.in, nil
}

// pump hands a ticket.result to the Decide that waits for it and everything else to the reader
// of the connection.
func (c *Client) pump(s *relaylink.Session, in chan relaylink.Message) {
	defer close(in)
	for m := range s.Messages() {
		if m.Kind == "ticket.result" {
			var r struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(m.Body, &r)
			c.mu.Lock()
			ch := c.results[r.ID]
			c.mu.Unlock()
			if ch != nil {
				select {
				case ch <- m.Body:
				default:
				}
			}
			continue
		}
		in <- m
	}
}

// Close ends the connection, if there is one.
func (c *Client) Close() {
	c.mu.Lock()
	s := c.s
	c.s = nil
	c.mu.Unlock()
	if s != nil {
		s.Close()
	}
}

// send hands an envelope to the relay; a refusal of the relay is a *ServerError.
func (c *Client) send(ctx context.Context, s *relaylink.Session, e relaylink.Envelope) error {
	err := s.Send(ctx, e)
	var re *relaylink.Error
	if errors.As(err, &re) {
		return &ServerError{Reason: re.Code, Relay: true}
	}
	return err
}

// recv is the next frame of kind from the supervisor, within d.
func (c *Client) recv(ctx context.Context, s *relaylink.Session, in chan relaylink.Message, kind string, d time.Duration) (relaylink.Message, error) {
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		select {
		case m, ok := <-in:
			if !ok {
				return m, fmt.Errorf("the connection to the relay ended: %v", s.Err())
			}
			if m.Kind == kind {
				return m, nil
			}
		case <-ctx.Done():
			return relaylink.Message{}, ctx.Err()
		case <-t.C:
			online, known := s.Peer()
			return relaylink.Message{}, &errNoAnswer{what: kind, offline: known && !online}
		}
	}
}

// Protocol version of wardenctl as a client (protocol/README.md, "Protocol version"): the one it
// speaks (signatures from envelope, the same tree as wardend).
const clientProtocol = envelope.Protocol

// ProtocolError: wardenctl and wardend speak different protocol versions. Not a wardend rejection
// and not a signature error: fixed by updating whichever side is older (exit code 4).
type ProtocolError struct {
	ServerOld bool  // wardend is older than wardenctl; otherwise wardenctl is older than wardend
	Server    int64 // protocol from the status, 0: field absent
}

func (e *ProtocolError) Error() string {
	switch {
	case e.ServerOld && e.Server == 0:
		return fmt.Sprintf("wardend does not report a protocol version, but wardenctl speaks protocol %d: update wardend", clientProtocol)
	case e.ServerOld:
		return fmt.Sprintf("wardend speaks protocol %d, but wardenctl speaks protocol %d: update wardend", e.Server, clientProtocol)
	}
	return fmt.Sprintf("wardend speaks protocol %d, but wardenctl speaks protocol %d: update wardenctl", e.Server, clientProtocol)
}

// checkProtocol: checks a status against the version contract: the protocol field must be the
// number wardenctl speaks; anything else is refused.
func checkProtocol(protocol any) error {
	num := func(v any) (int64, bool) {
		n, ok := v.(json.Number)
		if !ok {
			return 0, false
		}
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	}
	p, _ := num(protocol) // field absent or not an integer: 0
	if p != clientProtocol {
		return &ProtocolError{ServerOld: p < clientProtocol, Server: p}
	}
	return nil
}

// PairStatus is the plaintext of a pair.status frame. Re is the id of the pair frame it answers.
type PairStatus struct {
	Re          string `json:"re"`
	ID          string `json:"id"`
	Status      string `json:"status"` // pending | approved | rejected | refused
	Reason      string `json:"reason"`
	Fingerprint string `json:"fingerprint"`
	Host        string `json:"host"`
}

// Pair sends the pairing request with the one-time code of the link and returns the id of its
// frame and wardend's first answer about it.
func (c *Client) Pair(ctx context.Context, code, name string) (string, *PairStatus, error) {
	s, _, err := c.connect(ctx)
	if err != nil {
		return "", nil, err
	}
	pt, err := c.dev.PairRequest(code, name)
	if err != nil {
		return "", nil, err
	}
	e, err := c.dev.SealPair(pt)
	if err != nil {
		return "", nil, err
	}
	if err := c.send(ctx, s, e); err != nil {
		return "", nil, err
	}
	ps, err := c.PairStatus(ctx, e.ID, requestTimeout)
	return e.ID, ps, err
}

// PairStatus waits up to d for the next pair.status about the request sent in frame re; what
// answers another request is not about this one and is dropped. A refusal is a *ServerError.
func (c *Client) PairStatus(ctx context.Context, re string, d time.Duration) (*PairStatus, error) {
	s, in, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	end := time.Now().Add(d)
	for {
		m, err := c.recv(ctx, s, in, "pair.status", time.Until(end))
		if err != nil {
			return nil, err
		}
		var ps PairStatus
		if json.Unmarshal(m.Body, &ps) != nil || ps.Re != re {
			continue
		}
		if ps.Status == "refused" {
			return nil, &ServerError{Reason: ps.Reason}
		}
		return &ps, nil
	}
}

// Resume asks the relay for what it queued while this device was away.
func (c *Client) Resume(ctx context.Context) error {
	s, _, err := c.connect(ctx)
	if err != nil {
		return err
	}
	return s.Resume()
}

// PendingResp: the wardend queue as a status frame gives it. Each entry's envelope is kept raw:
// we recompute the digest ourselves.
type PendingResp struct {
	Seq          int64  `json:"seq"`
	Mode         string `json:"mode"`
	SupervisorID string `json:"supervisorId"`
	Host         string `json:"host"`
	Now          int64  `json:"now"`
	Pending      []Item `json:"pending"`
	// more cards than one frame holds: the rest follows as card frames
	PendingCount     int  `json:"pendingCount"`
	PendingTruncated bool `json:"pendingTruncated"`
}

// StatusResp is a status frame: the raw members and the queue.
type StatusResp struct {
	Raw   map[string]any
	Queue PendingResp
}

func parseStatus(pt []byte) (*StatusResp, error) {
	var r StatusResp
	d := json.NewDecoder(bytes.NewReader(pt))
	d.UseNumber()
	if err := d.Decode(&r.Raw); err != nil {
		return nil, fmt.Errorf("status: not JSON: %w", err)
	}
	if err := checkProtocol(r.Raw["protocol"]); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(pt, &r.Queue); err != nil {
		return nil, fmt.Errorf("status: %w", err)
	}
	return &r, nil
}

// Status asks wardend for its state and the pending cards. wardend answers a trusted device
// only, so an answer also says that the pairing is approved. A status of an incompatible
// protocol version is *ProtocolError.
func (c *Client) Status(ctx context.Context) (*StatusResp, error) {
	s, in, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	e, err := c.dev.Seal("status.req", []byte("{}"))
	if err != nil {
		return nil, err
	}
	if err := c.send(ctx, s, e); err != nil {
		return nil, err
	}
	m, err := c.recv(ctx, s, in, "status", requestTimeout)
	if err != nil {
		return nil, err
	}
	r, err := parseStatus(m.Body)
	if err != nil {
		return nil, err
	}
	// the cards that did not fit into the status frame
	for end := time.Now().Add(cardsTimeout); r.Queue.PendingTruncated && len(r.Queue.Pending) < r.Queue.PendingCount; {
		m, err := c.recv(ctx, s, in, "card", time.Until(end))
		if err != nil {
			break
		}
		var it Item
		if json.Unmarshal(m.Body, &it) == nil {
			r.Queue.Pending = append(r.Queue.Pending, it)
		}
	}
	return r, nil
}

type DecideResp struct {
	OK           bool   `json:"ok"`
	Reason       string `json:"reason"`
	ID           string `json:"id"`
	Decision     string `json:"decision"`
	HardwareRule string `json:"hardwareRule"`
}

// Decide sends a signed ticket and waits for wardend's ticket.result about the same card.
// ok:false is not a transport error but a wardend rejection.
func (c *Client) Decide(ctx context.Context, b envelope.DecisionBody) (*DecideResp, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	s, _, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	e, err := c.dev.Seal("ticket", raw)
	if err != nil {
		return nil, err
	}
	ch := make(chan json.RawMessage, 1)
	c.mu.Lock()
	c.results[b.Payload.ID] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.results, b.Payload.ID)
		c.mu.Unlock()
	}()
	if err := c.send(ctx, s, e); err != nil {
		return nil, err
	}
	t := time.NewTimer(decideTimeout)
	defer t.Stop()
	select {
	case body := <-ch:
		var r DecideResp
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, fmt.Errorf("ticket.result: not JSON: %w", err)
		}
		if r.OK && r.Decision != b.Payload.Decision {
			return nil, &ServerError{Reason: "response_mismatch"}
		}
		return &r, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.C:
		online, known := s.Peer()
		return nil, &errNoAnswer{what: "ticket.result", offline: known && !online}
	}
}
