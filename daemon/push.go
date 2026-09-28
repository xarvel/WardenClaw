// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Device push tokens and delivery via APNs when a card appears.
//
//	POST /v1/push/register    {deviceId, platform:"apns", token, topic, environment:"sandbox"|"production"}
//	POST /v1/push/unregister  {deviceId[, platform:"apns"][, token]}  (no token: all tokens of the device)
//
// Both requests are signed with a trusted device key in X-Wardenclaw-* headers over
// envelope.RequestBodySigningString(supervisorId, action, deviceId, ts, nonce, body): action
// "push.register" / "push.unregister", window ts_window, single-use nonce. The deviceId in the body
// must match the header: a device manages only its own tokens.
//
// Tokens are stored in <state_dir>/push_tokens.json (0600, atomic write). Revoking a device
// (`wardend pair revoke`) removes its tokens too; an APNs 410 Unregistered response removes the
// token. A token is a delivery address, not a trust secret: it only lets one send a notification,
// nothing can be approved with it.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"sync"
	"time"
)

const (
	maxTokensPerDevice = 4
	maxPushTokens      = 64
)

var apnsTokenRe = regexp.MustCompile(`^[0-9a-f]{64,200}$`)

type pushToken struct {
	DeviceID     string `json:"deviceId"`
	Platform     string `json:"platform"` // apns
	Token        string `json:"token"`    // hex, lowercase
	Topic        string `json:"topic"`
	Environment  string `json:"environment"` // sandbox | production
	RegisteredAt int64  `json:"registeredAt"`
}

type pushStore struct {
	mu   sync.Mutex
	path string
	list []pushToken
}

// loadPushStore: the token file; no file means empty. A corrupt file is an error (we do not invent
// tokens: the supervisor warns and runs with an empty list, leaving the file alone until the first
// write).
func loadPushStore(path string) (*pushStore, error) {
	p := &pushStore{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	var f struct {
		Tokens []pushToken `json:"tokens"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return p, fmt.Errorf("%s: %w", path, err)
	}
	p.list = f.Tokens
	return p, nil
}

func (p *pushStore) saveLocked() error {
	b, _ := json.MarshalIndent(map[string]any{"tokens": p.list}, "", "  ")
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return err
	}
	tmp := p.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p.path)
}

// register: add or update a token. The same token on another device moves over (app reinstall);
// a device has at most maxTokensPerDevice tokens (older ones are evicted).
func (p *pushStore) register(t pushToken) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.list[:0:0]
	for _, x := range p.list {
		if x.Token != t.Token {
			out = append(out, x)
		}
	}
	out = append(out, t)
	sort.SliceStable(out, func(i, j int) bool { return out[i].RegisteredAt > out[j].RegisteredAt })
	per := map[string]int{}
	kept := out[:0]
	for _, x := range out {
		if per[x.DeviceID] < maxTokensPerDevice && len(kept) < maxPushTokens {
			per[x.DeviceID]++
			kept = append(kept, x)
		}
	}
	old := p.list
	p.list = kept
	if err := p.saveLocked(); err != nil {
		p.list = old
		return err
	}
	return nil
}

// remove: delete the tokens for which match == true; return how many were removed.
func (p *pushStore) remove(match func(pushToken) bool) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var kept []pushToken
	for _, x := range p.list {
		if !match(x) {
			kept = append(kept, x)
		}
	}
	n := len(p.list) - len(kept)
	if n == 0 {
		return 0, nil
	}
	old := p.list
	p.list = kept
	if err := p.saveLocked(); err != nil {
		p.list = old
		return 0, err
	}
	return n, nil
}

func (p *pushStore) snapshot() []pushToken {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]pushToken(nil), p.list...)
}

// ---------- delivery ----------

type pushCard struct {
	id      string
	expires time.Time
}

// pushService: tokens + (optional) APNs client + queue of cards to deliver.
type pushService struct {
	store   *pushStore
	apns    *apnsClient // nil: apns is not configured or the key failed to load (apnsErr)
	apnsErr string
	cfg     *APNSConfig
	cards   chan pushCard
	trusted func(id string) bool
	journal func(kind string, data any)
	logf    func(format string, a ...any)
	sent    func(cardID string, results map[string]apnsResult) // for tests
}

func (p *pushService) enabled() bool { return p != nil && p.apns != nil }

// notify: a new card (non-blocking; if the queue is full the notification is lost, the card is
// still visible via long-poll).
func (p *pushService) notify(id string, expires time.Time) {
	if !p.enabled() {
		return
	}
	select {
	case p.cards <- pushCard{id, expires}:
	default:
		p.logf("wardend: push: notification queue full, %s without push\n", id)
	}
}

func (p *pushService) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-p.cards:
			p.deliver(ctx, c)
		}
	}
}

// deliver: the notification to all tokens of trusted devices.
func (p *pushService) deliver(ctx context.Context, c pushCard) map[string]apnsResult {
	res := map[string]apnsResult{}
	if !time.Now().Before(c.expires) {
		return res
	}
	sent, failed, removed := 0, 0, 0
	for _, t := range p.store.snapshot() {
		if p.trusted != nil && !p.trusted(t.DeviceID) {
			continue
		}
		r, err := p.apns.push(ctx, t, c.id, c.expires)
		if err != nil {
			failed++
			p.logf("wardend: apns %s…: %v\n", clip8(t.Token), err)
			continue
		}
		res[t.Token] = r
		switch {
		case r.Status == http.StatusOK:
			sent++
		case r.Status == http.StatusGone: // Unregistered: the app was removed or the token changed
			failed++
			tok := t.Token
			if n, err := p.store.remove(func(x pushToken) bool { return x.Token == tok }); err == nil && n > 0 {
				removed++
				p.journal("push_token_removed", map[string]any{"deviceId": t.DeviceID, "token": clip8(tok), "reason": r.Reason, "status": r.Status})
			}
		default:
			failed++
			p.logf("wardend: apns %s…: HTTP %d %s\n", clip8(t.Token), r.Status, r.Reason)
		}
	}
	if sent+failed > 0 {
		p.journal("push", map[string]any{"cardId": c.id, "sent": sent, "failed": failed, "removed": removed})
	}
	if p.sent != nil {
		p.sent(c.id, res)
	}
	return res
}

func clip8(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func (p *pushService) removeDevice(id string) {
	if p == nil {
		return
	}
	if n, err := p.store.remove(func(x pushToken) bool { return x.DeviceID == id }); err == nil && n > 0 {
		p.journal("push_token_removed", map[string]any{"deviceId": id, "count": n, "reason": "device_revoked"})
	}
}

// info: for status (without the tokens themselves).
func (p *pushService) info() map[string]any {
	if p == nil {
		return map[string]any{"apns": false}
	}
	m := map[string]any{"apns": p.apns != nil, "tokens": len(p.store.snapshot())}
	if p.cfg != nil {
		m["topics"] = p.cfg.topics()
	}
	if p.apnsErr != "" {
		m["error"] = p.apnsErr
	}
	return m
}

// ---------- HTTP ----------

type pushBody struct {
	DeviceID    string `json:"deviceId"`
	Platform    string `json:"platform"`
	Token       string `json:"token"`
	Topic       string `json:"topic"`
	Environment string `json:"environment"`
}

// signedJSON: parse the body (an object) and verify the header signature over it.
func (h *httpAPI) signedJSON(w http.ResponseWriter, r *http.Request, action string) (*pushBody, respTo, bool) {
	if !h.method(w, r, http.MethodPost, action) {
		return nil, respTo{}, false
	}
	raw, err := readBody(r)
	if err != nil {
		h.reply(w, unauth(action), http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "reason": err.Error()})
		return nil, respTo{}, false
	}
	var obj map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var b pushBody
	if err := d.Decode(&obj); err != nil || obj == nil || json.Unmarshal(raw, &b) != nil {
		h.reply(w, unauth(action), http.StatusBadRequest, map[string]any{"ok": false, "reason": "body_invalid_json"})
		return nil, respTo{}, false
	}
	id, reason := h.authBody(r, action, obj, h.trustedKey)
	if reason != "" {
		h.reply(w, unauth(action), http.StatusUnauthorized, map[string]any{"ok": false, "reason": reason})
		return nil, respTo{}, false
	}
	to := bound(action, id, r.Header.Get("X-Wardenclaw-Nonce"))
	if b.DeviceID != id {
		h.reply(w, to, http.StatusForbidden, map[string]any{"ok": false, "reason": "device_mismatch"})
		return nil, respTo{}, false
	}
	return &b, to, true
}

func (h *httpAPI) pushRegister(w http.ResponseWriter, r *http.Request) {
	b, to, ok := h.signedJSON(w, r, "push.register")
	if !ok {
		return
	}
	p := h.s.push
	fail := func(code int, reason string) {
		h.s.journal("push_register_reject", map[string]any{"deviceId": b.DeviceID, "reason": reason})
		h.reply(w, to, code, map[string]any{"ok": false, "reason": reason})
	}
	switch {
	case !p.enabled():
		fail(http.StatusConflict, "push_not_configured")
		return
	case b.Platform != "apns":
		fail(http.StatusBadRequest, "platform_unsupported")
		return
	case !apnsTokenRe.MatchString(b.Token):
		fail(http.StatusBadRequest, "token_invalid")
		return
	case b.Environment != "sandbox" && b.Environment != "production":
		fail(http.StatusBadRequest, "environment_invalid")
		return
	}
	if !slices.Contains(p.cfg.topics(), b.Topic) {
		fail(http.StatusBadRequest, "topic_not_allowed")
		return
	}
	t := pushToken{DeviceID: b.DeviceID, Platform: b.Platform, Token: b.Token, Topic: b.Topic, Environment: b.Environment, RegisteredAt: time.Now().UnixMilli()}
	if err := p.store.register(t); err != nil {
		h.s.logf("wardend: push_tokens: %v\n", err)
		h.reply(w, to, http.StatusInternalServerError, map[string]any{"ok": false, "reason": "store_failed"})
		return
	}
	h.s.journal("push_register", map[string]any{"deviceId": b.DeviceID, "alg": h.s.devices.Alg(b.DeviceID), "topic": b.Topic, "environment": b.Environment, "token": clip8(b.Token)})
	h.reply(w, to, http.StatusOK, map[string]any{"ok": true, "deviceId": b.DeviceID, "topic": b.Topic, "environment": b.Environment})
}

func (h *httpAPI) pushUnregister(w http.ResponseWriter, r *http.Request) {
	b, to, ok := h.signedJSON(w, r, "push.unregister")
	if !ok {
		return
	}
	if b.Platform != "" && b.Platform != "apns" {
		h.reply(w, to, http.StatusBadRequest, map[string]any{"ok": false, "reason": "platform_unsupported"})
		return
	}
	n := 0
	if h.s.push != nil {
		var err error
		n, err = h.s.push.store.remove(func(x pushToken) bool {
			return x.DeviceID == b.DeviceID && (b.Token == "" || x.Token == b.Token)
		})
		if err != nil {
			h.reply(w, to, http.StatusInternalServerError, map[string]any{"ok": false, "reason": "store_failed"})
			return
		}
	}
	h.s.journal("push_unregister", map[string]any{"deviceId": b.DeviceID, "removed": n})
	h.reply(w, to, http.StatusOK, map[string]any{"ok": true, "removed": n})
}
