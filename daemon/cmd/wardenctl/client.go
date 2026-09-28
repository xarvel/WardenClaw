// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// HTTP client for the wardend endpoint, same protocol as app/src/core/wardendClient.ts:
//
//	GET  /v1/ping?nonce          the server at the link's address answers with the link's key
//	POST /v1/pair                pairing request (one-time code, signature of the new key)
//	GET  /v1/pair/status?id      waiting for `wardend pair approve` on the server
//	GET  /v1/pending?since&wait  long-poll ≤ 25 s
//	GET  /v1/status
//	POST /v1/decide              ticket (envelope.SignPayload [+ hw])
//
// Every response must be signed by the pinned supervisor key and bound to the request
// (envelope.ResponseSigningString: action, deviceId, nonce, for decide also the ticket id and
// digest; ping: envelope.PingSigningString); otherwise the whole response is discarded. A signed
// rejection before authentication (envelope.UnauthSigningString) is an error with Unbound: the
// server's reason is visible, but it does not count as the answer to this request. Redirects are
// not followed.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

const bodyLimit = 4 << 20

// Request timeouts. A pending long-poll gets pendingSlack on top of its wait.
const (
	requestTimeout = 15 * time.Second
	decideTimeout  = 30 * time.Second
	pendingSlack   = 20 * time.Second
)

// Client talks to one wardend: the pinned supervisor key checks every response, the device key
// signs the requests.
type Client struct {
	Base   string
	Pinned ed25519.PublicKey
	Priv   ed25519.PrivateKey // nil: ping/pair only
	HTTP   *http.Client
}

func newClient(base string, pinned ed25519.PublicKey, priv ed25519.PrivateKey) *Client {
	return &Client{Base: strings.TrimRight(base, "/"), Pinned: pinned, Priv: priv, HTTP: &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (c *Client) deviceID() string { return deviceIDOf(c.Priv) }

// HTTPError is a server rejection (signed) or an unsigned response. Unbound: a rejection before the
// request signature check; an intermediary gets such a response for any request, it is not bound to
// this one.
type HTTPError struct {
	Status  int
	Reason  string
	Unbound bool
}

func (e *HTTPError) Error() string {
	note := ""
	if e.Unbound {
		note = "; rejected before the request signature check, not bound to this request"
	}
	if h, ok := reasonText[e.Reason]; ok {
		return fmt.Sprintf("%s (%s, HTTP %d%s)", h, e.Reason, e.Status, note)
	}
	return fmt.Sprintf("wardend: %s (HTTP %d%s)", e.Reason, e.Status, note)
}

// reasonText: human-readable reasons for wardend rejections (HTTP and decide).
var reasonText = map[string]string{
	"unsigned_response":       "response is not signed by the server key from the link for this request: spoofing (for example, a response to another request), a proxy page (Cloudflare Access?) or a different server",
	"response_mismatch":       "signed wardend response is not about this ticket (id or decision does not match)",
	"pairing_not_active":      "no active code on the server: run wardend pair start again",
	"bad_code":                "code did not match or was already used: run wardend pair start again",
	"wrong_supervisor":        "link is from a different server",
	"device_id_mismatch":      "deviceId does not match the key",
	"stale_timestamp":         "clocks of this machine and the server differ by more than ts_window (60 s by default)",
	"bad_signature":           "signature verification failed",
	"untrusted_device":        "the server does not trust this device: approve the pairing (wardend pair approve) or pair again",
	"unknown_device":          "the server does not know this device's key",
	"too_many_requests":       "too many pending pairing requests on the server",
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
	"not_found":               "no such path: is this really a wardend endpoint?",
}

func reasonHuman(r string) string {
	if h, ok := reasonText[r]; ok {
		return h + " (" + r + ")"
	}
	return r
}

// expect: which response the client accepts: for ping only a ping response with its own nonce,
// otherwise the response to its own request (envelope.RespCtx).
type expect struct {
	ping bool
	ctx  envelope.RespCtx
}

func (c *Client) expectFor(action, nonce string) expect {
	return expect{ctx: envelope.RespCtx{Action: action, DeviceID: c.deviceID(), Nonce: nonce}}
}

// call: request with a response signature check. Returns status and body (ok:false is not an error).
func (c *Client) call(ctx context.Context, method, path string, hdr map[string]string, body []byte, want expect, timeout time.Duration) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "wardenctl/"+version)
	res, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("no connection to %s: %w", c.Base, err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, bodyLimit))
	if err != nil {
		return 0, nil, fmt.Errorf("%s: reading response: %w", path, err)
	}
	switch verifyResponse(c.Pinned, want, res.StatusCode, raw, res.Header.Get("X-Wardend-Signature")) {
	case respBound:
		return res.StatusCode, raw, nil
	case respUnbound:
		var rec struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(raw, &rec)
		if rec.Reason == "" {
			rec.Reason = "HTTP " + strconv.Itoa(res.StatusCode)
		}
		return res.StatusCode, nil, &HTTPError{Status: res.StatusCode, Reason: rec.Reason, Unbound: true}
	}
	return res.StatusCode, nil, &HTTPError{Status: res.StatusCode, Reason: "unsigned_response"}
}

// callOK: call + JSON parsing, ok:false/non-2xx → HTTPError.
func (c *Client) callOK(ctx context.Context, method, path string, hdr map[string]string, body []byte, want expect, timeout time.Duration, out any) error {
	st, raw, err := c.call(ctx, method, path, hdr, body, want, timeout)
	if err != nil {
		return err
	}
	var rec struct {
		OK     *bool  `json:"ok"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(raw, &rec)
	if st < 200 || st > 299 || (rec.OK != nil && !*rec.OK) {
		r := rec.Reason
		if r == "" {
			r = "HTTP " + strconv.Itoa(st)
		}
		return &HTTPError{Status: st, Reason: r}
	}
	if out != nil {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if err := d.Decode(out); err != nil {
			return fmt.Errorf("%s: response is not JSON: %w", path, err)
		}
	}
	return nil
}

// respKind: what a response is for the request that was sent.
type respKind int

const (
	respInvalid respKind = iota
	respBound            // signed by the pinned key and bound to this request
	respUnbound          // signed rejection before authentication (UnauthSigningString of the same action)
)

// verifyResponse: what the response is for request want (checkResponse in wardendProto.ts).
// An unauth rejection is accepted only with a rejection body and never for ping.
func verifyResponse(pinned ed25519.PublicKey, want expect, status int, body []byte, sig string) respKind {
	var msg []byte
	var err error
	if want.ping {
		msg, err = envelope.PingSigningString(want.ctx.Nonce, status, body)
	} else {
		msg, err = envelope.ResponseSigningString(want.ctx, status, body)
	}
	if err == nil && envelope.VerifySig(pinned, msg, sig) {
		return respBound
	}
	if want.ping {
		return respInvalid
	}
	if msg, err = envelope.UnauthSigningString(want.ctx.Action, status, body); err == nil && envelope.VerifySig(pinned, msg, sig) && isRejectionBody(body) {
		return respUnbound
	}
	return respInvalid
}

// isRejectionBody: an unauth response counts only as a rejection, so its body must say ok:false
// (isRejectionBody in wardendProto.ts). The status is not checked: decide answers 200 to a
// rejection too.
func isRejectionBody(body []byte) bool {
	var rec struct {
		OK *bool `json:"ok"`
	}
	return json.Unmarshal(body, &rec) == nil && rec.OK != nil && !*rec.OK
}

func (c *Client) signedHeaders(action, nonce string) map[string]string {
	return signedHeadersAt(c.Priv, envelope.DeviceID(c.Pinned), action, nonce, time.Now().UnixMilli())
}

// signedHeadersAt: headers of a signed request (signedHeaders in wardendClient.ts).
// supervisorID is that of the pinned key: the request is valid only for this wardend.
func signedHeadersAt(priv ed25519.PrivateKey, supervisorID, action, nonce string, ts int64) map[string]string {
	id := deviceIDOf(priv)
	msg, _ := envelope.RequestSigningString(supervisorID, action, id, ts, nonce)
	return map[string]string{
		"X-Wardenclaw-Device":    id,
		"X-Wardenclaw-Ts":        strconv.FormatInt(ts, 10),
		"X-Wardenclaw-Nonce":     nonce,
		"X-Wardenclaw-Signature": envelope.B64URL(ed25519.Sign(priv, msg)),
	}
}

// Protocol version of wardenctl as a client (protocol/README.md, "Protocol version"): the one it
// speaks (signatures from envelope, the same tree as wardend) and the oldest wardend it works
// with.
const (
	clientProtocol    = envelope.Protocol // PROTOCOL
	minServerProtocol = 1                 // MIN_SERVER_PROTOCOL
)

// ProtocolError: wardenctl and wardend protocol versions are incompatible. Not a wardend rejection
// and not a signature error: fixed by updating whichever side is older (exit code 4).
type ProtocolError struct {
	ServerOld bool  // wardend is older than wardenctl; otherwise wardenctl is older than wardend
	Server    int64 // protocol from the response, 0: field absent
	MinClient int64 // minClient from the response
}

func (e *ProtocolError) Error() string {
	switch {
	case e.ServerOld && e.Server == 0:
		return fmt.Sprintf("wardend does not report a protocol version, so it is older than wardenctl (protocol %d): update wardend", clientProtocol)
	case e.ServerOld:
		return fmt.Sprintf("wardend speaks protocol %d, but wardenctl works with wardend of protocol %d or newer: update wardend", e.Server, minServerProtocol)
	}
	return fmt.Sprintf("wardend accepts clients of protocol %d or newer, but wardenctl speaks protocol %d: update wardenctl", e.MinClient, clientProtocol)
}

// checkProtocol: checks a ping or status response against the version contract: no protocol field
// or protocol < MIN_SERVER_PROTOCOL means the server is older; PROTOCOL < minClient means the
// client is older.
func checkProtocol(protocol, minClient any) error {
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
	if p < minServerProtocol {
		return &ProtocolError{ServerOld: true, Server: p}
	}
	if m, ok := num(minClient); ok && clientProtocol < m {
		return &ProtocolError{Server: p, MinClient: m}
	}
	return nil
}

type PingResp struct {
	OK           bool        `json:"ok"`
	Service      string      `json:"service"`
	SupervisorID string      `json:"supervisorId"`
	Now          json.Number `json:"now"`
	Protocol     json.Number `json:"protocol"`
	MinClient    json.Number `json:"minClient"`
}

// Ping: signed ping; a response with an incompatible protocol version is *ProtocolError.
func (c *Client) Ping(ctx context.Context) (*PingResp, error) {
	n := envelope.NewNonce()
	var r PingResp
	if err := c.callOK(ctx, "GET", "/v1/ping?nonce="+url.QueryEscape(n), nil, nil, expect{ping: true, ctx: envelope.RespCtx{Nonce: n}}, requestTimeout, &r); err != nil {
		return nil, err
	}
	if err := checkProtocol(r.Protocol, r.MinClient); err != nil {
		return nil, err
	}
	return &r, nil
}

type PairResp struct {
	ID           string      `json:"id"`
	Status       string      `json:"status"`
	Fingerprint  string      `json:"fingerprint"`
	SupervisorID string      `json:"supervisorId"`
	Host         string      `json:"host"`
	ExpiresAt    json.Number `json:"expiresAt"`
}

// Pair: the pairing request for the device key in c.Priv with the one-time code from the link.
func (c *Client) Pair(ctx context.Context, code, supervisorID, name string) (*PairResp, error) {
	pub := c.Priv.Public().(ed25519.PublicKey)
	p := envelope.PairPayload{Code: code, DeviceID: envelope.DeviceID(pub), Pubkey: envelope.B64URL(pub), Name: name,
		SupervisorID: supervisorID, Ts: time.Now().UnixMilli(), Nonce: envelope.NewNonce()}
	body, err := pairBody(c.Priv, p)
	if err != nil {
		return nil, err
	}
	var r PairResp
	want := expect{ctx: envelope.RespCtx{Action: "pair", DeviceID: p.DeviceID, Nonce: p.Nonce}}
	if err := c.callOK(ctx, "POST", "/v1/pair", nil, body, want, requestTimeout, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// pairBody: body of POST /v1/pair: the payload and the new key's signature over PairSigningString.
func pairBody(priv ed25519.PrivateKey, p envelope.PairPayload) ([]byte, error) {
	msg, err := envelope.PairSigningString(p)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		envelope.PairPayload
		Signature string `json:"signature"`
	}{p, envelope.B64URL(ed25519.Sign(priv, msg))})
}

type PairStatusResp struct {
	ID          string `json:"id"`
	Status      string `json:"status"` // pending | approved | rejected | revoked | unknown
	Fingerprint string `json:"fingerprint"`
	Host        string `json:"host"`
}

// PairStatus: where pairing request id stands on the server.
func (c *Client) PairStatus(ctx context.Context, id string) (*PairStatusResp, error) {
	n := envelope.NewNonce()
	var r PairStatusResp
	if err := c.callOK(ctx, "GET", "/v1/pair/status?id="+url.QueryEscape(id), c.signedHeaders("pair.status", n), nil, c.expectFor("pair.status", n), requestTimeout, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// PendingResp: the wardend queue. Each entry's envelope is kept raw: we recompute the digest ourselves.
type PendingResp struct {
	Seq          int64  `json:"seq"`
	Mode         string `json:"mode"`
	SupervisorID string `json:"supervisorId"`
	Host         string `json:"host"`
	Now          int64  `json:"now"`
	Pending      []Item `json:"pending"`
}

// Pending: the queue; with wait > 0 wardend holds the request until the queue changes after seq
// since or the wait runs out (long-poll).
func (c *Client) Pending(ctx context.Context, since int64, wait time.Duration) (*PendingResp, error) {
	n := envelope.NewNonce()
	path := fmt.Sprintf("/v1/pending?since=%d&wait=%d", since, wait.Milliseconds())
	st, raw, err := c.call(ctx, "GET", path, c.signedHeaders("pending", n), nil, c.expectFor("pending", n), wait+pendingSlack)
	if err != nil {
		return nil, err
	}
	var r struct {
		OK     bool   `json:"ok"`
		Reason string `json:"reason"`
		PendingResp
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("/v1/pending: response is not JSON: %w", err)
	}
	if st != 200 || !r.OK {
		return nil, &HTTPError{Status: st, Reason: r.Reason}
	}
	return &r.PendingResp, nil
}

// Status: signed status; a response with an incompatible protocol version is *ProtocolError.
func (c *Client) Status(ctx context.Context) (map[string]any, error) {
	n := envelope.NewNonce()
	var r map[string]any
	if err := c.callOK(ctx, "GET", "/v1/status", c.signedHeaders("status", n), nil, c.expectFor("status", n), requestTimeout, &r); err != nil {
		return nil, err
	}
	if err := checkProtocol(r["protocol"], r["minClient"]); err != nil {
		return nil, err
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

// Decide: send a signed ticket. ok:false is not a transport error but a wardend rejection.
func (c *Client) Decide(ctx context.Context, b envelope.DecisionBody) (*DecideResp, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	want := expect{ctx: envelope.RespCtx{Action: "decide", DeviceID: b.DeviceID, Nonce: b.Payload.Nonce, ID: b.Payload.ID, Digest: b.Payload.Digest}}
	st, body, err := c.call(ctx, "POST", "/v1/decide", nil, raw, want, decideTimeout)
	if err != nil {
		return nil, err
	}
	var r DecideResp
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("/v1/decide: response is not JSON (HTTP %d)", st)
	}
	// the signature already binds the response to the ticket id and digest; the body must be about it too
	if r.ID != b.Payload.ID || (r.OK && r.Decision != b.Payload.Decision) {
		return nil, &HTTPError{Status: st, Reason: "response_mismatch"}
	}
	if st != 200 && r.Reason == "" {
		r.Reason = "HTTP " + strconv.Itoa(st)
	}
	return &r, nil
}

func isHTTPReason(err error, reason string) bool {
	var he *HTTPError
	return errors.As(err, &he) && he.Reason == reason
}
