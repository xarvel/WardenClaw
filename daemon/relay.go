// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// The relay transport, supervisor side (protocol/README.md): wardend keeps one outbound WebSocket
// to <relay_url>/v1/ws/<supervisorId>, so the phone reaches it without a public address. The
// relay is an untrusted carrier: it routes frames by identity and queues what it could not
// deliver. Cards and tickets stay signed by the ends and travel in an AEAD box (relaylink/box.go).
//
//	relay  → {type:"challenge", nonce, ts}
//	client → {type:"hello", role:"supervisor", key, enc, ts, nonce, client, sig}
//	relay  → {type:"welcome", id, role, protocol, ts, limits}
//	client → {type:"devices", ids}, {type:"pairing", open, until}, {type:"resume"}
//	both   → {type:"msg", id, to, from, seq, ts, exp, body, kind}, {type:"ack", id, seq}
//
// Fail closed: nothing here produces a decision. A message that does not reach the relay is an
// error for the caller, a frame that does not open is dropped and journaled (relay_tamper), a
// lost connection is retried forever while the cards expire on the daemon as they always did.

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/relaylink"
)

const (
	relayProtocol    = envelope.Protocol
	relayPingEvery   = 30 * time.Second // the relay closes a connection silent for 90 s
	relayIdleTimeout = 90 * time.Second // and so does the client
	relayAckTimeout  = 10 * time.Second
	relayBackoffMin  = time.Second
	relayBackoffMax  = 60 * time.Second
	relaySeenMax     = 4096 // dedupe set: ids of processed frames, dropped at their exp

	// The relay allows a connection 20 frames at once and one more every second (protocol/README.md 13;
	// the first deployed version: 80 per minute). The client stays below both: 15 at once, then
	// one every 1.2 s, which is 65 in the first minute.
	relayRateBurst   = 15
	relayRateEvery   = 1200 * time.Millisecond
	relayRateRetry   = 3 * time.Second
	relayRateRetries = 2

	relayCloseSuperseded = 4001

	// relayFlushTimeout bounds the wait for the sends in flight when wardend exits: one ack
	// timeout, so a frame the relay is about to store is not cut off, and a dead relay does not
	// hold the exit longer than a send would have waited anyway.
	relayFlushTimeout = relayAckTimeout
)

var (
	errRelayOffline = errors.New("relay: not connected")
	errRelayTimeout = errors.New("relay: no answer from the relay")
)

// relayHandlers is what the supervisor gives the client. All are called on the reading goroutine,
// one frame at a time; a slow handler delays the next frame, and a handler that waits for an ack
// itself (send, sendDevices, setPairing) would wait for a frame nobody reads: answer from another
// goroutine.
type relayHandlers struct {
	// Devices returns the ids of the trusted devices (sent to the relay after every hello).
	Devices func() []string
	// PeerKey returns the X25519 key of a trusted device; false: unknown, its frames are dropped.
	PeerKey func(deviceID string) (*ecdh.PublicKey, bool)
	// Message gets an opened msg frame from a trusted device. Returning false leaves the frame
	// unacknowledged: the relay sends it again on the next resume.
	Message func(from, kind string, plaintext []byte, env relaylink.Envelope) bool
	// Pair gets an opened pair frame from a device that is not trusted yet, and the X25519 key
	// the frame named for itself (relayOpenPair): nothing but the signed payload inside vouches
	// for that key, the handler must compare the two. Returning false leaves it unacknowledged.
	Pair func(plaintext []byte, enc string, env relaylink.Envelope) bool
	// Connected is called after welcome, devices and resume are on the wire: the supervisor
	// re-sends what must not depend on the relay's queue.
	Connected func()
	// Event journals relay_connected, relay_disconnected, relay_tamper, relay_dropped.
	Event func(event string, fields map[string]any)
}

type relayWaiter struct {
	key string // "msg:<id>" or the `what` of a relay frame
	ch  chan relayResult
}

type relayResult struct {
	seq int64
	err error
}

type relayClient struct {
	url     string // ws(s)://host[/prefix], without /v1/ws/<id>
	key     ed25519.PrivateKey
	enc     *ecdh.PrivateKey
	id      string // supervisorId
	h       relayHandlers
	now     func() time.Time
	backoff func(attempt int) time.Duration

	mu      sync.Mutex
	conn    *relaylink.Conn
	waiters []relayWaiter    // frames waiting for the relay's ack
	seen    map[string]int64 // processed frame id → exp
	pairing int64            // an open pairing window: until (ms), 0 none
	frame   int              // the relay's frame limit from welcome
	ttl     int64            // the relay's queue TTL from welcome, ms
	busy    int              // frames being handled and sends without an answer yet (begin, flush)

	// outgoing budget (pace): a token bucket kept below the relay's limit
	rateBurst float64
	rateEvery time.Duration // one more frame per rateEvery
	rateRetry time.Duration // the pause before a frame refused as rate_limited goes out again
	tokens    float64
	refilled  time.Time
}

func newRelayClient(url string, key ed25519.PrivateKey, enc *ecdh.PrivateKey, h relayHandlers) *relayClient {
	return &relayClient{url: strings.TrimRight(url, "/"), key: key, enc: enc, id: envelope.DeviceID(key.Public().(ed25519.PublicKey)), h: h,
		now: time.Now, backoff: relayBackoff, seen: map[string]int64{}, frame: relaylink.FrameMax,
		rateBurst: relayRateBurst, rateEvery: relayRateEvery, rateRetry: relayRateRetry}
}

// relayBackoff: 1 s, 2 s, 4 s … 60 s, each with jitter in [d/2, d].
func relayBackoff(attempt int) time.Duration {
	d := relayBackoffMax
	if attempt < 6 {
		d = relayBackoffMin << attempt
	}
	return d/2 + time.Duration(mrand.Int64N(int64(d/2)+1))
}

func (r *relayClient) event(name string, fields map[string]any) {
	if r.h.Event != nil {
		r.h.Event(name, fields)
	}
}

func (r *relayClient) endpoint() string { return r.url + "/v1/ws/" + r.id }

// encPublic is the supervisor's X25519 key for the QR and the hello.
func (r *relayClient) encPublic() string { return envelope.B64URL(r.enc.PublicKey().Bytes()) }

func (r *relayClient) connected() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.conn != nil
}

// begin marks work that must not be cut off by the exit of wardend: a frame being handled, a send
// that has no answer from the relay yet. The caller calls the returned func when it is over.
func (r *relayClient) begin() (end func()) {
	r.mu.Lock()
	r.busy++
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			r.busy--
			r.mu.Unlock()
		})
	}
}

// flush waits until nothing is in flight (begin), at most d, and returns how many were left. The
// supervisor calls it before it ends the connection: the answer to the last ticket is sent from a
// goroutine, and without the wait wardend could exit before the device had it.
func (r *relayClient) flush(d time.Duration) int {
	deadline := time.Now().Add(d)
	for {
		r.mu.Lock()
		n := r.busy
		r.mu.Unlock()
		if n == 0 || !time.Now().Before(deadline) {
			return n
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// run keeps the connection up until ctx is done: reconnects with backoff, never gives up.
func (r *relayClient) run(ctx context.Context) {
	reported := false // the journal gets one relay_disconnected per outage, not one per attempt
	for attempt := 0; ctx.Err() == nil; attempt++ {
		welcomed, err := r.session(ctx)
		if welcomed {
			attempt, reported = 0, false
		}
		if ctx.Err() != nil {
			return
		}
		if !reported {
			r.event("relay_disconnected", map[string]any{"error": fmt.Sprint(err)})
			reported = true
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(r.backoff(attempt)):
		}
	}
}

// session is one connection: hello, then frames until an error. welcomed reports that the relay
// accepted the hello (the backoff starts over).
func (r *relayClient) session(ctx context.Context) (welcomed bool, err error) {
	ws, err := relaylink.Dial(ctx, r.endpoint(), http.Header{"User-Agent": {"wardend/" + version}}, relaylink.FrameMax)
	if err != nil {
		return false, err
	}
	defer ws.Drop()
	stop := context.AfterFunc(ctx, func() { ws.Close(relaylink.CloseNormal, "shutdown") })
	defer stop()
	if err := r.hello(ws); err != nil {
		return false, err
	}
	r.mu.Lock()
	r.conn = ws
	until := r.pairing
	r.mu.Unlock()
	defer r.dropConn(ws)

	// the relay forgets both lists when the supervisor disconnects: send them on every hello
	if err := r.write(ws, map[string]any{"type": "devices", "ids": r.deviceIDs()}); err != nil {
		return true, err
	}
	if until > r.now().UnixMilli() {
		if err := r.write(ws, map[string]any{"type": "pairing", "open": true, "until": until}); err != nil {
			return true, err
		}
	}
	if err := r.write(ws, map[string]any{"type": "resume"}); err != nil {
		return true, err
	}
	r.event("relay_connected", map[string]any{"url": r.url})
	if r.h.Connected != nil {
		go r.h.Connected()
	}

	done := make(chan struct{})
	defer close(done)
	go func() { // keepalive; a failed write ends the read loop through the closed connection
		t := time.NewTicker(relayPingEvery)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if r.write(ws, map[string]any{"type": "ping", "ts": r.now().UnixMilli()}) != nil {
					ws.Drop()
					return
				}
			}
		}
	}()
	for {
		ws.SetReadDeadline(time.Now().Add(relayIdleTimeout))
		raw, err := ws.ReadText()
		if err != nil {
			return true, err
		}
		var f relaylink.Frame
		if json.Unmarshal(raw, &f) != nil || f.Type == "" {
			continue
		}
		if err := r.handle(ws, &f); err != nil {
			return true, err
		}
	}
}

// hello answers the relay's challenge with the signed hello and waits for welcome.
func (r *relayClient) hello(ws *relaylink.Conn) error {
	ws.SetReadDeadline(time.Now().Add(relaylink.HelloTimeout))
	var f relaylink.Frame
	raw, err := ws.ReadText()
	if err != nil {
		return err
	}
	if json.Unmarshal(raw, &f) != nil || f.Type != "challenge" || f.Nonce == "" {
		return errors.New("relay: no challenge")
	}
	frame, err := relaylink.Hello("supervisor", "wardend", version, r.key, r.encPublic(), f.Nonce, r.now().UnixMilli())
	if err != nil {
		return err
	}
	if err := r.write(ws, frame); err != nil {
		return err
	}
	for {
		if raw, err = ws.ReadText(); err != nil {
			return err
		}
		f = relaylink.Frame{}
		if json.Unmarshal(raw, &f) != nil {
			continue
		}
		switch f.Type {
		case "error":
			return &relaylink.Error{Code: f.Code}
		case "welcome":
			// the relay is not trusted, but a welcome for another id or role means the two ends
			// disagree about who is connected: nothing good comes of going on
			if f.ID != r.id || f.Role != "supervisor" {
				return errors.New("relay: welcome for another identity")
			}
			if f.Protocol != relayProtocol {
				return fmt.Errorf("relay: it speaks protocol %d, wardend speaks protocol %d", f.Protocol, relayProtocol)
			}
			r.mu.Lock()
			if f.Limits.Frame > 0 {
				r.frame = min(f.Limits.Frame, relaylink.FrameMax)
			}
			r.ttl = f.Limits.TTL
			r.mu.Unlock()
			return nil
		}
	}
}

func (r *relayClient) deviceIDs() []string {
	ids := []string{}
	if r.h.Devices != nil {
		ids = append(ids, r.h.Devices()...)
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

func (r *relayClient) write(ws *relaylink.Conn, frame any) error {
	_ = r.pace(context.Background(), false)
	return r.writeNow(ws, frame)
}

// writeNow is write for a frame whose token is already taken.
func (r *relayClient) writeNow(ws *relaylink.Conn, frame any) error {
	b, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	r.mu.Lock()
	limit := r.frame
	r.mu.Unlock()
	if len(b) > limit {
		return &relaylink.Error{Code: "too_large"}
	}
	return ws.WriteText(b)
}

// dropConn forgets a closed connection and fails everything that waited for an ack on it.
func (r *relayClient) dropConn(ws *relaylink.Conn) {
	r.mu.Lock()
	if r.conn == ws {
		r.conn = nil
	}
	waiting := r.waiters
	r.waiters = nil
	r.mu.Unlock()
	for _, w := range waiting {
		w.ch <- relayResult{err: errRelayOffline}
	}
}

// resolve answers the waiter with this key; an answer nobody waits for (the error for an ack or a
// resume, a late ack) is dropped.
func (r *relayClient) resolve(key string, res relayResult) {
	r.mu.Lock()
	i := slices.IndexFunc(r.waiters, func(w relayWaiter) bool { return w.key == key })
	if i < 0 {
		r.mu.Unlock()
		return
	}
	w := r.waiters[i]
	r.waiters = slices.Delete(r.waiters, i, i+1)
	r.mu.Unlock()
	w.ch <- res
}

// pace takes one token of the outgoing budget. With wait it blocks until there is one (requests:
// cards, status, results); without, the frame goes out anyway and the budget goes into debt
// (acks, pings, the hello: they must not be late, and the relay counts them too).
func (r *relayClient) pace(ctx context.Context, wait bool) error {
	for {
		r.mu.Lock()
		now := r.now()
		if r.refilled.IsZero() {
			r.tokens, r.refilled = r.rateBurst, now
		}
		r.tokens = min(r.rateBurst, r.tokens+float64(now.Sub(r.refilled))/float64(r.rateEvery))
		r.refilled = now
		if r.tokens >= 1 || !wait {
			r.tokens = max(r.tokens-1, -r.rateBurst)
			r.mu.Unlock()
			return nil
		}
		d := time.Duration((1 - r.tokens) * float64(r.rateEvery))
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
	}
}

// request writes a frame and waits for the relay's ack (or error) for it.
func (r *relayClient) request(ctx context.Context, key string, frame any) (int64, error) {
	w := relayWaiter{key: key, ch: make(chan relayResult, 1)}
	if !r.connected() {
		return 0, errRelayOffline
	}
	if err := r.pace(ctx, true); err != nil {
		return 0, err
	}
	r.mu.Lock()
	ws := r.conn
	if ws == nil {
		r.mu.Unlock()
		return 0, errRelayOffline
	}
	r.waiters = append(r.waiters, w)
	r.mu.Unlock()
	forget := func() {
		r.mu.Lock()
		r.waiters = slices.DeleteFunc(r.waiters, func(x relayWaiter) bool { return x.ch == w.ch })
		r.mu.Unlock()
	}
	if err := r.writeNow(ws, frame); err != nil {
		forget()
		return 0, err
	}
	t := time.NewTimer(relayAckTimeout)
	defer t.Stop()
	select {
	case res := <-w.ch:
		return res.seq, res.err
	case <-ctx.Done():
		forget()
		return 0, ctx.Err()
	case <-t.C:
		forget()
		return 0, errRelayTimeout
	}
}

// handle processes one frame after welcome. An error return ends the session.
func (r *relayClient) handle(ws *relaylink.Conn, f *relaylink.Frame) error {
	switch f.Type {
	case "ping":
		return r.write(ws, map[string]any{"type": "pong", "ts": r.now().UnixMilli()})
	case "ack":
		if f.What != "" {
			r.resolve(f.What, relayResult{})
		} else if f.ID != "" {
			r.resolve("msg:"+f.ID, relayResult{seq: f.Seq})
		}
	case "error":
		// the error names the frame it refuses (id of an envelope, what for the rest); one that
		// names nothing cannot be attributed, and the connection ends rather than guess
		switch {
		case f.ID != "":
			r.resolve("msg:"+f.ID, relayResult{err: &relaylink.Error{Code: f.Code}})
		case f.What != "":
			r.resolve(f.What, relayResult{err: &relaylink.Error{Code: f.Code}})
		default:
			return &relaylink.Error{Code: f.Code}
		}
		if f.Close {
			return &relaylink.Error{Code: f.Code}
		}
	case "msg", "pair":
		r.envelope(ws, f.Envelope)
	}
	// pong, resumed, welcome and unknown types: nothing to do (forward compatibility)
	return nil
}

// envelope handles a frame from a device: dedupe by id, open, hand over, ack. A frame that is not
// for this supervisor, from an unknown device, expired or does not open is never acked.
func (r *relayClient) envelope(ws *relaylink.Conn, e relaylink.Envelope) {
	defer r.begin()() // the handler starts its answer (a send of its own) before this one ends
	now := r.now().UnixMilli()
	if e.To != r.id || !hex64re(e.From) || e.ID == "" || e.Exp <= now {
		r.event("relay_dropped", map[string]any{"id": e.ID, "from": e.From, "reason": "routing"})
		return
	}
	ack := func() { _ = r.write(ws, map[string]any{"type": "ack", "id": e.ID, "seq": e.Seq}) }
	r.mu.Lock()
	_, dup := r.seen[e.ID]
	r.mu.Unlock()
	if dup { // delivered twice (the first ack was lost): processed once, acked again
		ack()
		return
	}
	ok := false
	if e.Type == "pair" {
		e.Kind = "pair" // the relay sets it; the box is bound to this kind whatever the frame says
		pt, enc, err := relayOpenPair(r.enc, r.id, e)
		if err != nil {
			r.event("relay_tamper", map[string]any{"id": e.ID, "from": e.From, "kind": e.Kind, "reason": err.Error()})
			return
		}
		ok = r.h.Pair != nil && r.h.Pair(pt, enc, e)
	} else {
		pt, err := r.open(e)
		if err != nil {
			reason := "relay_dropped"
			if errors.Is(err, relaylink.ErrBox) {
				reason = "relay_tamper"
			}
			r.event(reason, map[string]any{"id": e.ID, "from": e.From, "kind": e.Kind, "reason": err.Error()})
			return
		}
		ok = r.h.Message != nil && r.h.Message(e.From, e.Kind, pt, e)
	}
	if !ok {
		return
	}
	r.mu.Lock()
	if len(r.seen) >= relaySeenMax {
		for id, exp := range r.seen {
			if exp <= now {
				delete(r.seen, id)
			}
		}
		if len(r.seen) >= relaySeenMax { // still full of live ids: refuse to grow, the relay resends
			r.mu.Unlock()
			return
		}
	}
	r.seen[e.ID] = e.Exp
	r.mu.Unlock()
	ack()
}

// open decrypts a msg frame from a trusted device.
func (r *relayClient) open(e relaylink.Envelope) ([]byte, error) {
	if r.h.PeerKey == nil || !slices.Contains(r.deviceIDs(), e.From) {
		return nil, errors.New("device is not trusted")
	}
	peer, ok := r.h.PeerKey(e.From)
	if !ok {
		return nil, errors.New("no encryption key for the device")
	}
	return relayOpenFrom(r.enc, peer, r.id, e)
}

// relayOpenFrom opens a frame a device sent to the supervisor with the device's X25519 key.
func relayOpenFrom(enc *ecdh.PrivateKey, peer *ecdh.PublicKey, supervisorID string, e relaylink.Envelope) ([]byte, error) {
	key, err := relaylink.BoxKey(enc, peer, supervisorID, e.From)
	if err != nil {
		return nil, relaylink.ErrBox
	}
	aad, err := relaylink.AAD(e.ID, e.From, e.To, e.Kind, e.Exp)
	if err != nil {
		return nil, err
	}
	return relaylink.Open(key, e.Body, aad)
}

// relayOpenPair opens a pair frame. The device is not known yet, so its X25519 key travels in
// front of the box (protocol/README.md 6):
//
//	body = b64url(devEncPub(32) || nonce(24) || ciphertext)
//
// The key is returned as the frame gave it: it is authenticated only by the signed pairing
// payload inside, which must repeat it.
func relayOpenPair(enc *ecdh.PrivateKey, supervisorID string, e relaylink.Envelope) (plaintext []byte, devEnc string, err error) {
	raw, err := envelope.DecodeB64URL(e.Body)
	if err != nil || len(raw) <= 32 {
		return nil, "", relaylink.ErrBox
	}
	peer, err := ecdh.X25519().NewPublicKey(raw[:32])
	if err != nil {
		return nil, "", relaylink.ErrBox
	}
	e.Body = envelope.B64URL(raw[32:])
	pt, err := relayOpenFrom(enc, peer, supervisorID, e)
	return pt, envelope.B64URL(raw[:32]), err
}

// send encrypts plaintext for a device and hands it to the relay; it returns when the relay has
// stored the frame (ack) or refused it. exp is when the relay may drop it undelivered (a card:
// its expiresAt). An error means the device will not get this frame: the caller treats it as
// "not delivered", never as a decision.
func (r *relayClient) send(ctx context.Context, deviceID, kind string, plaintext []byte, exp time.Time) (id string, err error) {
	if r.h.PeerKey == nil {
		return "", errors.New("relay: no encryption key for the device")
	}
	peer, ok := r.h.PeerKey(deviceID)
	if !ok {
		return "", errors.New("relay: no encryption key for the device")
	}
	return r.sendTo(ctx, deviceID, peer, kind, plaintext, exp)
}

// sendTo is send with the device's X25519 key given by the caller: pair.status goes to a device
// that is not trusted yet, boxed for the key of its pending request.
func (r *relayClient) sendTo(ctx context.Context, deviceID string, peer *ecdh.PublicKey, kind string, plaintext []byte, exp time.Time) (id string, err error) {
	key, err := relaylink.BoxKey(r.enc, peer, r.id, deviceID)
	if err != nil {
		return "", err
	}
	now := r.now().UnixMilli()
	expMs := exp.UnixMilli()
	r.mu.Lock()
	ttl := r.ttl
	r.mu.Unlock()
	// the relay caps exp at now + ttl; exp is in the AAD, so a capped one would never open
	if ttl > 0 && expMs > now+ttl-60_000 {
		expMs = now + ttl - 60_000
	}
	id = relaylink.MsgID()
	aad, err := relaylink.AAD(id, r.id, deviceID, kind, expMs)
	if err != nil {
		return "", err
	}
	body, err := relaylink.Seal(key, nil, plaintext, aad)
	if err != nil {
		return "", err
	}
	// the relay refuses a frame over its rate limit without storing it: the same frame again,
	// later, rather than a card that never arrives
	for attempt := 0; ; attempt++ {
		_, err = r.request(ctx, "msg:"+id, relaylink.Envelope{Type: "msg", ID: id, To: deviceID, Ts: now, Exp: expMs, Body: body, Kind: kind})
		var re *relaylink.Error
		if !errors.As(err, &re) || re.Code != "rate_limited" || attempt >= relayRateRetries {
			return id, err
		}
		select {
		case <-ctx.Done():
			return id, ctx.Err()
		case <-time.After(r.rateRetry):
		}
	}
}

// sendDevices re-sends the trusted list (after pair approve and revoke).
func (r *relayClient) sendDevices(ctx context.Context) error {
	_, err := r.request(ctx, "devices", map[string]any{"type": "devices", "ids": r.deviceIDs()})
	return err
}

// setPairing opens the pairing window on the relay until `until`, or closes it (zero time). The
// window is remembered and re-opened after a reconnect.
func (r *relayClient) setPairing(ctx context.Context, until time.Time) error {
	frame := map[string]any{"type": "pairing", "open": false}
	var ms int64
	if !until.IsZero() {
		ms = until.UnixMilli()
		frame = map[string]any{"type": "pairing", "open": true, "until": ms}
	}
	r.mu.Lock()
	r.pairing = ms
	r.mu.Unlock()
	_, err := r.request(ctx, "pairing", frame)
	return err
}
