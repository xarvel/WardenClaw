// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// APNs (Apple Push Notification service) client: HTTP/2, token-based auth.
//
//	POST https://api.push.apple.com/3/device/<token>          (environment "production")
//	POST https://api.sandbox.push.apple.com/3/device/<token>  (environment "sandbox")
//	authorization: bearer <JWT ES256 {alg, kid: key_id} {iss: team_id, iat}>, .p8 key from Apple Developer
//	apns-topic: bundle id of the app (topic_ios) or of the watch app (topic_watch)
//	apns-push-type: alert, apns-priority: 10, apns-expiration: card expiry (Unix, s),
//	apns-collapse-id: card id
//
// The JWT is cached for 50 minutes (Apple accepts a token for at most an hour and asks to refresh
// it no more often than once every 20 minutes). The payload carries only the card id: the command,
// host and paths never reach Apple, the app fetches the card itself over the signed channel
// (/v1/pending).

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

const (
	apnsJWTTTL         = 50 * time.Minute
	apnsHostProd       = "https://api.push.apple.com"
	apnsHostSandbox    = "https://api.sandbox.push.apple.com"
	apnsCategory       = "WARDEN_APPROVAL"
	apnsRequestTimeout = 15 * time.Second
	apnsMaxReplyBody   = 4096 // Apple's reply body is at most a small {"reason": …} object
)

// APNSConfig is the "apns" section of config.json. Without it APNs push is off; ntfy and
// long-poll work either way.
type APNSConfig struct {
	KeyFile    string `json:"key_file"`    // AuthKey_<KEYID>.p8 (PKCS#8 PEM, P-256), mode 0600
	KeyID      string `json:"key_id"`      // Key ID from Apple Developer → Keys (10 characters)
	TeamID     string `json:"team_id"`     // Team ID (10 characters)
	TopicIOS   string `json:"topic_ios"`   // bundle id of the iOS app, com.wardenclaw.app
	TopicWatch string `json:"topic_watch"` // bundle id of the watchOS app, com.wardenclaw.app.watchkitapp
}

// topics: the allowed apns-topic values (empty ones do not count).
func (c *APNSConfig) topics() []string {
	var out []string
	for _, t := range []string{c.TopicIOS, c.TopicWatch} {
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func (c *APNSConfig) validate() error {
	switch {
	case c.KeyFile == "":
		return errors.New("apns.key_file is not set")
	case len(c.KeyID) != 10 || !isAlnum(c.KeyID):
		return fmt.Errorf("apns.key_id %q: must be a 10-character Key ID", c.KeyID)
	case len(c.TeamID) != 10 || !isAlnum(c.TeamID):
		return fmt.Errorf("apns.team_id %q: must be a 10-character Team ID", c.TeamID)
	case len(c.topics()) == 0:
		return errors.New("apns: at least one of topic_ios, topic_watch is required")
	}
	return nil
}

func isAlnum(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
			return false
		}
	}
	return true
}

type apnsClient struct {
	cfg   APNSConfig
	key   *ecdsa.PrivateKey
	hc    *http.Client
	hosts map[string]string // environment → base URL (tests override it)
	now   func() time.Time

	mu    sync.Mutex
	jwt   string
	jwtAt time.Time
}

// newAPNSClient validates cfg and reads the key; it is called once, at startup.
func newAPNSClient(cfg APNSConfig) (*apnsClient, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("apns.key_file: %w", err)
	}
	key, err := parseP8(b)
	if err != nil {
		return nil, fmt.Errorf("apns.key_file %s: %w", cfg.KeyFile, err)
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true,
		IdleConnTimeout: 10 * time.Minute, TLSHandshakeTimeout: 10 * time.Second}
	tr.Protocols = new(http.Protocols)
	tr.Protocols.SetHTTP2(true) // APNs speaks HTTP/2 only
	return &apnsClient{cfg: cfg, key: key, hc: &http.Client{Transport: tr, Timeout: apnsRequestTimeout},
		hosts: map[string]string{"production": apnsHostProd, "sandbox": apnsHostSandbox}, now: time.Now}, nil
}

// parseP8: the APNs key, PEM "PRIVATE KEY" (PKCS#8) with ECDSA P-256.
func parseP8(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("not PEM (expected AuthKey_XXXXXXXXXX.p8 from Apple Developer)")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve.Params().Name != "P-256" {
		return nil, errors.New("expected an ECDSA P-256 key")
	}
	return ek, nil
}

// bearer: the provider JWT (cached for apnsJWTTTL).
func (c *apnsClient) bearer() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.jwt != "" && now.Sub(c.jwtAt) < apnsJWTTTL {
		return c.jwt, nil
	}
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": c.cfg.KeyID})
	p, _ := json.Marshal(map[string]any{"iss": c.cfg.TeamID, "iat": now.Unix()})
	signing := envelope.B64URL(h) + "." + envelope.B64URL(p)
	sig := envelope.SignES256(c.key, []byte(signing)) // JWS ES256 = raw r||s
	if sig == "" {
		return "", errors.New("apns: failed to sign JWT")
	}
	c.jwt, c.jwtAt = signing+"."+sig, now
	return c.jwt, nil
}

// invalidate: drop the cache (Apple answered ExpiredProviderToken/InvalidProviderToken).
func (c *apnsClient) invalidate(tok string) {
	c.mu.Lock()
	if c.jwt == tok {
		c.jwt = ""
	}
	c.mu.Unlock()
}

// apnsPayload: exactly this and nothing more, no command, host or paths.
func apnsPayload(cardID string) []byte {
	id, _ := json.Marshal(cardID)
	return []byte(`{"aps":{"alert":{"title":"Approval request","body":"Open to review"},"category":"` + apnsCategory +
		`","sound":"default","interruption-level":"time-sensitive"},"cardId":` + string(id) + `}`)
}

type apnsResult struct {
	Status int
	Reason string // from Apple's response body: BadDeviceToken, Unregistered, …
	ID     string // apns-id
}

// push: one notification; retried once if Apple rejected the JWT as expired.
func (c *apnsClient) push(ctx context.Context, t pushToken, cardID string, expires time.Time) (apnsResult, error) {
	base, ok := c.hosts[t.Environment]
	if !ok {
		return apnsResult{}, fmt.Errorf("environment %q", t.Environment)
	}
	for attempt := 0; ; attempt++ {
		jwt, err := c.bearer()
		if err != nil {
			return apnsResult{}, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/3/device/"+t.Token, bytes.NewReader(apnsPayload(cardID)))
		if err != nil {
			return apnsResult{}, err
		}
		hd := req.Header
		hd.Set("authorization", "bearer "+jwt)
		hd.Set("apns-topic", t.Topic)
		hd.Set("apns-push-type", "alert")
		hd.Set("apns-priority", "10")
		hd.Set("apns-expiration", strconv.FormatInt(expires.Unix(), 10))
		hd.Set("apns-collapse-id", cardID)
		hd.Set("content-type", "application/json")
		resp, err := c.hc.Do(req)
		if err != nil {
			return apnsResult{}, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, apnsMaxReplyBody))
		resp.Body.Close()
		r := apnsResult{Status: resp.StatusCode, ID: resp.Header.Get("apns-id")}
		var e struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(body, &e)
		r.Reason = e.Reason
		if resp.StatusCode == http.StatusForbidden && (r.Reason == "ExpiredProviderToken" || r.Reason == "InvalidProviderToken") && attempt == 0 {
			c.invalidate(jwt)
			continue
		}
		return r, nil
	}
}
