// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Own transport: HTTP endpoint for the WardenClaw app (http_listen, default 127.0.0.1:8787;
// exposed through a separate hostname in a Cloudflare tunnel, deploy/CLOUDFLARE.md).
//
//	GET  /v1/ping?nonce=…            no authentication: {ok, service, supervisorId, v, now}
//	GET  /v1/pending?since&wait      long-poll ≤ 25 s, device signature in headers (action "pending")
//	GET  /v1/status                  device signature (action "status")
//	POST /v1/decide                  ticket (self-signed): {deviceId, payload, signature[, hw]}
//	POST /v1/pair                    pairing request (one-time code + signature of the new key)
//	GET  /v1/pair/status?id=p-…      signature with the key from the request (action "pair.status")
//	POST /v1/push/register           device APNs token; header signature over the body (action "push.register")
//	POST /v1/push/unregister         token revocation (action "push.unregister"), push.go
//
// Request headers: X-Wardenclaw-Device / -Ts / -Nonce / -Signature
// (envelope.RequestSigningString: type "wardenclaw.req.v1" and the supervisorId of this wardend, not
// the wardenclaw-gate plugin format).
// Every response is signed with the supervisor key (X-Wardend-Signature, envelope/transport.go):
// a response to an authenticated request is ResponseSigningString(action, deviceId, nonce[, ticket
// id, digest], status, sha256 of the body), the nonce comes from the X-Wardenclaw-Nonce header, for
// decide from the ticket, for pair from the body; ping is PingSigningString(?nonce); a rejection
// before authentication is UnauthSigningString(action) without the caller's nonce and deviceId (respTo).
// There is no pairing approval here: only `wardend pair approve` over the unix socket on the server.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

const httpBodyLimit = 256 << 10

// Request signature headers.
const (
	headerDevice    = "X-Wardenclaw-Device"
	headerTs        = "X-Wardenclaw-Ts"
	headerNonce     = "X-Wardenclaw-Nonce"
	headerSignature = "X-Wardenclaw-Signature"
)

type httpAPI struct {
	s      *supervisor
	srv    *http.Server
	ln     net.Listener
	nonces *envelope.NonceCache // nonces of signed GETs (separate from ticket nonces)
}

func newHTTPAPI(s *supervisor) *httpAPI {
	return &httpAPI{s: s, nonces: envelope.NewNonceCache(s.cfg.TsWindow.Duration)}
}

func startHTTP(addr string, s *supervisor) (*httpAPI, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	h := newHTTPAPI(s)
	h.ln = ln
	h.srv = &http.Server{Handler: h.handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: longPollMax + 20*time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 16 << 10}
	go h.srv.Serve(ln)
	return h, nil
}

func (h *httpAPI) addr() string {
	if h.ln == nil {
		return ""
	}
	return h.ln.Addr().String()
}

func (h *httpAPI) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := h.srv.Shutdown(ctx); err != nil {
		h.srv.Close()
	}
}

func (h *httpAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ping", h.ping)
	mux.HandleFunc("/v1/pending", h.pending)
	mux.HandleFunc("/v1/status", h.status)
	mux.HandleFunc("/v1/decide", h.decide)
	mux.HandleFunc("/v1/pair", h.pair)
	mux.HandleFunc("/v1/pair/status", h.pairStatus)
	mux.HandleFunc("/v1/push/register", h.pushRegister)
	mux.HandleFunc("/v1/push/unregister", h.pushUnregister)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		h.reply(w, unauth(""), http.StatusNotFound, map[string]any{"ok": false, "reason": "not_found"})
	})
	return mux
}

// respTo: what the response signature is bound to. bound: the request signature is valid and its
// nonce is claimed by this request, the response string carries action, deviceId and nonce (for
// decide also the ticket id and digest). Otherwise the response is signed as unauth (action only):
// the nonce and deviceId of such a request could be chosen by anyone, and a middleman could pass a
// response carrying them off to the phone as the answer to its own request.
// ping has its own type with the caller's nonce.
type respTo struct {
	ping  bool
	bound bool
	ctx   envelope.RespCtx
}

func unauth(action string) respTo { return respTo{ctx: envelope.RespCtx{Action: action}} }

func bound(action, deviceID, nonce string) respTo {
	return respTo{bound: true, ctx: envelope.RespCtx{Action: action, DeviceID: deviceID, Nonce: nonce}}
}

// reply: JSON response signed by the supervisor.
func (h *httpAPI) reply(w http.ResponseWriter, to respTo, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		status, body = http.StatusInternalServerError, []byte(`{"ok":false,"reason":"encode"}`)
	}
	var sig string
	switch {
	case to.ping:
		sig = envelope.SignPing(h.s.key, to.ctx.Nonce, status, body)
	case to.bound:
		sig = envelope.SignResponse(h.s.key, to.ctx, status, body)
	default:
		sig = envelope.SignUnauth(h.s.key, to.ctx.Action, status, body)
	}
	hd := w.Header()
	hd.Set("Content-Type", "application/json; charset=utf-8")
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Wardend-Supervisor", h.s.supervisorID)
	hd.Set("X-Wardend-Signature", sig)
	w.WriteHeader(status)
	w.Write(body)
}

func (h *httpAPI) method(w http.ResponseWriter, r *http.Request, m, action string) bool {
	if r.Method == m {
		return true
	}
	h.reply(w, unauth(action), http.StatusMethodNotAllowed, map[string]any{"ok": false, "reason": "method_not_allowed"})
	return false
}

// auth: request signature in headers. keyFor returns the device key or the rejection reason.
func (h *httpAPI) auth(r *http.Request, action string, keyFor func(id string) (envelope.DeviceKey, string)) (string, string) {
	return h.authBody(r, action, nil, keyFor)
}

// authBody: the same for a request with a body: body (the parsed JSON object) is part of the
// signing string (envelope.RequestBodySigningString); nil is a GET without a body
// (envelope.RequestSigningString).
func (h *httpAPI) authBody(r *http.Request, action string, body any, keyFor func(id string) (envelope.DeviceKey, string)) (string, string) {
	id := strings.ToLower(r.Header.Get(headerDevice))
	nonce := r.Header.Get(headerNonce)
	sig := r.Header.Get(headerSignature)
	ts, err := strconv.ParseInt(r.Header.Get(headerTs), 10, 64)
	switch {
	case !hex64re(id):
		return "", "device_id_invalid"
	case err != nil:
		return "", "ts_invalid"
	case len(nonce) < minNonceLen || len(nonce) > maxNonceLen:
		return "", "nonce_invalid"
	case sig == "":
		return "", "signature_missing"
	}
	now := time.Now()
	if d := now.Sub(time.UnixMilli(ts)); d > h.s.cfg.TsWindow.Duration || d < -h.s.cfg.TsWindow.Duration {
		return "", "stale_timestamp"
	}
	pub, reason := keyFor(id)
	if reason != "" {
		return "", reason
	}
	var msg []byte
	if body != nil {
		msg, err = envelope.RequestBodySigningString(h.s.supervisorID, action, id, ts, nonce, body)
	} else {
		msg, err = envelope.RequestSigningString(h.s.supervisorID, action, id, ts, nonce)
	}
	if err != nil || !pub.Verify(msg, sig) {
		return "", "bad_signature"
	}
	if !h.nonces.Claim(id, action+"\n"+nonce, now) {
		return "", "nonce_reused"
	}
	return id, ""
}

func (h *httpAPI) trustedKey(id string) (envelope.DeviceKey, string) { return h.s.devices.Key(id) }

func (h *httpAPI) ping(w http.ResponseWriter, r *http.Request) {
	if !h.method(w, r, http.MethodGet, "ping") {
		return
	}
	nonce := r.URL.Query().Get("nonce")
	if len(nonce) > maxNonceLen {
		nonce = ""
	}
	h.reply(w, respTo{ping: true, ctx: envelope.RespCtx{Nonce: nonce}}, http.StatusOK, map[string]any{"ok": true, "service": "wardend", "v": 1,
		"protocol": envelope.Protocol, "minClient": envelope.MinClient, "supervisorId": h.s.supervisorID, "now": time.Now().UnixMilli()})
}

func (h *httpAPI) pending(w http.ResponseWriter, r *http.Request) {
	if !h.method(w, r, http.MethodGet, "pending") {
		return
	}
	dev, reason := h.auth(r, "pending", h.trustedKey)
	if reason != "" {
		h.reply(w, unauth("pending"), http.StatusUnauthorized, map[string]any{"ok": false, "reason": reason})
		return
	}
	to := bound("pending", dev, r.Header.Get(headerNonce))
	q := r.URL.Query()
	since, _ := strconv.ParseInt(q.Get("since"), 10, 64)
	wait, _ := strconv.ParseInt(q.Get("wait"), 10, 64)
	if wait > 0 {
		h.s.q.waitChange(r.Context(), since, min(time.Duration(wait)*time.Millisecond, longPollMax))
	}
	if r.Context().Err() != nil {
		return
	}
	h.reply(w, to, http.StatusOK, h.s.pendingSnapshot())
}

func (h *httpAPI) status(w http.ResponseWriter, r *http.Request) {
	if !h.method(w, r, http.MethodGet, "status") {
		return
	}
	dev, reason := h.auth(r, "status", h.trustedKey)
	if reason != "" {
		h.reply(w, unauth("status"), http.StatusUnauthorized, map[string]any{"ok": false, "reason": reason})
		return
	}
	st := h.s.status()
	// the app does not need the journal, socket and config paths
	delete(st, "journal")
	delete(st, "http")
	h.reply(w, bound("status", dev, r.Header.Get(headerNonce)), http.StatusOK, st)
}

func readBody(r *http.Request) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, httpBodyLimit+1))
	if err != nil {
		return nil, err
	}
	if len(b) > httpBodyLimit {
		return nil, errors.New("payload_too_large")
	}
	return b, nil
}

func (h *httpAPI) decide(w http.ResponseWriter, r *http.Request) {
	if !h.method(w, r, http.MethodPost, "decide") {
		return
	}
	raw, err := readBody(r)
	if err != nil {
		h.reply(w, unauth("decide"), http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "reason": err.Error()})
		return
	}
	res, b := h.s.decideTicket(raw)
	if b == nil {
		// the ticket failed the signature check or its nonce is already claimed: the response is
		// not bound to the nonce, id and digest, which anyone could have chosen
		h.reply(w, unauth("decide"), http.StatusOK, res)
		return
	}
	to := bound("decide", b.DeviceID, b.Payload.Nonce)
	to.ctx.ID, to.ctx.Digest = b.Payload.ID, b.Payload.Digest
	h.reply(w, to, http.StatusOK, res)
}

func remoteOf(r *http.Request) string {
	if ip := r.Header.Get("Cf-Connecting-Ip"); ip != "" {
		return ip + " (cloudflare, " + r.RemoteAddr + ")"
	}
	return r.RemoteAddr
}

func (h *httpAPI) pair(w http.ResponseWriter, r *http.Request) {
	if !h.method(w, r, http.MethodPost, "pair") {
		return
	}
	raw, err := readBody(r)
	if err != nil {
		h.reply(w, unauth("pair"), http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "reason": err.Error()})
		return
	}
	var body struct {
		envelope.PairPayload
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		h.reply(w, unauth("pair"), http.StatusBadRequest, map[string]any{"ok": false, "reason": "body_invalid_json"})
		return
	}
	// the new key's signature is verified and the code is burned: from here on the response is
	// bound to the request
	to := bound("pair", body.DeviceID, body.Nonce)
	req, reason, code := h.s.pair.submit(body.PairPayload, body.Signature, h.s.supervisorID, remoteOf(r), h.s.cfg.TsWindow.Duration,
		h.s.trustedDevice)
	if reason != "" {
		if reason != "pairing_not_active" {
			h.s.journal("pair_reject_request", map[string]any{"reason": reason, "deviceId": body.DeviceID, "remote": remoteOf(r)})
		}
		if !pairClaimed(reason) {
			to = unauth("pair")
		}
		h.reply(w, to, code, map[string]any{"ok": false, "reason": reason})
		return
	}
	h.s.journal("pair_request", map[string]any{"id": req.ID, "deviceId": req.DeviceID, "name": req.Name, "remote": req.Remote, "status": req.Status})
	if !h.s.quiet {
		h.s.logf("wardend: pairing request %s: \"%s\", fingerprint %s (wardend pair approve %s)\n", req.ID, req.Name, req.Fingerprint, req.ID)
	}
	h.reply(w, to, http.StatusOK, map[string]any{"ok": true, "id": req.ID, "status": req.Status, "fingerprint": req.Fingerprint,
		"supervisorId": h.s.supervisorID, "host": h.s.host, "expiresAt": req.ExpiresAt})
}

// pairClaimed: a pairing rejection after a valid signature of the new key (the code is already
// burned): such a response is bound to the request; before the signature it is unauth.
func pairClaimed(reason string) bool { return reason == "too_many_requests" }

func (h *httpAPI) pairStatus(w http.ResponseWriter, r *http.Request) {
	if !h.method(w, r, http.MethodGet, "pair.status") {
		return
	}
	id := r.URL.Query().Get("id")
	req := h.s.pair.get(id)
	dev, reason := h.auth(r, "pair.status", func(devID string) (envelope.DeviceKey, string) {
		if req != nil && req.DeviceID == devID {
			k, err := envelope.ParseDeviceKey(req.Alg, req.Pubkey)
			if err != nil {
				return envelope.DeviceKey{}, "pubkey_invalid"
			}
			return k, ""
		}
		return h.trustedKey(devID) // the request is already forgotten, but the device is trusted
	})
	if reason != "" {
		h.reply(w, unauth("pair.status"), http.StatusUnauthorized, map[string]any{"ok": false, "reason": reason})
		return
	}
	status := "unknown"
	if req != nil && req.DeviceID == dev {
		status = req.Status
	}
	if h.s.trustedDevice(dev) {
		status = "approved" // trusted (including when the request is already forgotten)
	} else if status == "approved" {
		status = "revoked"
	}
	h.reply(w, bound("pair.status", dev, r.Header.Get(headerNonce)), http.StatusOK, map[string]any{"ok": true, "id": id, "status": status, "fingerprint": envelope.Fingerprint(dev), "host": h.s.host})
}
