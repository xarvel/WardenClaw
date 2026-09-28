// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

// wardend transport (HTTP, httpapi.go): signing strings. All are canonical JSON,
// byte-for-byte with app/src/core/wardendProto.ts (cross-fixture protocol/vectors/transport_vectors.json).
//
// App request (GET /v1/pending, /v1/status, /v1/pair/status): headers
//	X-Wardenclaw-Device, X-Wardenclaw-Ts, X-Wardenclaw-Nonce, X-Wardenclaw-Signature
// signed with the device key over RequestSigningString: type "wardenclaw.req.v1" and
// supervisorId of this wardend (crypto review, finding 8), so a request signed for the
// wardenclaw-gate plugin (its string {action, deviceId, ts, nonce} without type) or for
// another wardend is rejected here. Decisions (POST /v1/decide) are self-signed (ticket, ticket.go).
//
// Pairing request (POST /v1/pair) is signed by the NEW device key together with the one-time
// code and supervisor ID from the QR: another supervisor cannot replay the request against itself.
//
// Supervisor response: header X-Wardend-Signature = Ed25519(supervisor key, response signing string).
// The string is bound to the request, not just the nonce (crypto review, finding 3):
//   - response to an authenticated request (device signature valid, its nonce claimed by
//     this request): ResponseSigningString = {type:"wardenclaw.resp.v1", action, deviceId, nonce,
//     status, bodySha256[, id, digest]} (id and digest of the ticket for decide);
//   - ping (unauthenticated, nonce chosen by the caller): PingSigningString with its own type
//     "wardenclaw.ping.v1"; the client will not accept it as a response to another request;
//   - rejection before authentication (bad signature, nonce reuse, unknown key, 404, 405,
//     malformed body): UnauthSigningString = {type:"wardenclaw.resp.unauth.v1", action, status,
//     bodySha256}, without the caller's nonce and deviceId: any client gets this for any request,
//     so the client does not treat it as a response to its own (neither success nor final rejection).
// The app knows the public key from the QR (pinning) and accepts only responses signed by it.

import (
	"crypto/ed25519"
	"errors"
	"net/url"
	"strings"
)

// Signing string types: the domain of each signed transport message.
const (
	ReqType    = "wardenclaw.req.v1"
	PairType   = "wardenclaw.pair.v1"
	RespType   = "wardenclaw.resp.v1"
	PingType   = "wardenclaw.ping.v1"
	UnauthType = "wardenclaw.resp.unauth.v1"
)

// RequestSigningString returns canonicalJson({type:"wardenclaw.req.v1", supervisorId, action, deviceId, ts, nonce}).
func RequestSigningString(supervisorID, action, deviceID string, ts int64, nonce string) ([]byte, error) {
	return Canonical(map[string]any{"type": ReqType, "supervisorId": supervisorID, "action": action, "deviceId": deviceID, "ts": ts, "nonce": nonce})
}

// RequestBodySigningString returns the signing string for JSON-body requests
// (POST /v1/push/register, /v1/push/unregister):
// canonicalJson({type:"wardenclaw.req.v1", supervisorId, action, body, deviceId, ts, nonce}),
// body is the parsed request body (object). Same X-Wardenclaw-* headers, same window and
// one-time nonce as GET requests.
func RequestBodySigningString(supervisorID, action, deviceID string, ts int64, nonce string, body any) ([]byte, error) {
	return Canonical(map[string]any{"type": ReqType, "supervisorId": supervisorID, "action": action, "body": body, "deviceId": deviceID, "ts": ts, "nonce": nonce})
}

// PairPayload is the body of POST /v1/pair (unsigned).
type PairPayload struct {
	Code         string `json:"code"`
	DeviceID     string `json:"deviceId"`
	Pubkey       string `json:"pubkey"`        // ed25519: base64url raw 32 bytes; es256: base64url SEC1 65 bytes
	Alg          string `json:"alg,omitempty"` // "ed25519" (default) | "es256"; when present it is included in the signature
	Name         string `json:"name"`
	SupervisorID string `json:"supervisorId"`
	Ts           int64  `json:"ts"`
	Nonce        string `json:"nonce"`
}

// PairSigningString returns canonicalJson({type:"wardenclaw.pair.v1", code, deviceId, pubkey, name, supervisorId, ts, nonce[, alg]}).
// alg is included when present in the body (es256 must send it): the algorithm cannot be
// replaced without breaking the new key's signature. Without alg the string is unchanged
// (Ed25519 clients v1).
func PairSigningString(p PairPayload) ([]byte, error) {
	m := map[string]any{"type": PairType, "code": p.Code, "deviceId": p.DeviceID, "pubkey": p.Pubkey,
		"name": p.Name, "supervisorId": p.SupervisorID, "ts": p.Ts, "nonce": p.Nonce}
	if p.Alg != "" {
		m["alg"] = p.Alg
	}
	return Canonical(m)
}

// RespCtx holds the request that the response is bound to: action ("pending", "status",
// "decide", "pair", "pair.status", "push.register", "push.unregister"), deviceId and nonce
// of the request; for decide also the ticket id and digest.
type RespCtx struct {
	Action   string
	DeviceID string
	Nonce    string
	ID       string
	Digest   string
}

// ResponseSigningString returns canonicalJson({type:"wardenclaw.resp.v1", action, deviceId, nonce,
// status, bodySha256[, id, digest]}); id and digest are included when set (decide).
func ResponseSigningString(c RespCtx, status int, body []byte) ([]byte, error) {
	m := map[string]any{"type": RespType, "action": c.Action, "deviceId": c.DeviceID, "nonce": c.Nonce,
		"status": status, "bodySha256": SHA256Hex(body)}
	if c.ID != "" || c.Digest != "" {
		m["id"], m["digest"] = c.ID, c.Digest
	}
	return Canonical(m)
}

// PingSigningString returns canonicalJson({type:"wardenclaw.ping.v1", nonce, status, bodySha256}).
func PingSigningString(nonce string, status int, body []byte) ([]byte, error) {
	return Canonical(map[string]any{"type": PingType, "nonce": nonce, "status": status, "bodySha256": SHA256Hex(body)})
}

// UnauthSigningString returns canonicalJson({type:"wardenclaw.resp.unauth.v1", action, status, bodySha256}).
func UnauthSigningString(action string, status int, body []byte) ([]byte, error) {
	return Canonical(map[string]any{"type": UnauthType, "action": action, "status": status, "bodySha256": SHA256Hex(body)})
}

// SignResponse returns the base64url signature over an authenticated request response.
func SignResponse(priv ed25519.PrivateKey, c RespCtx, status int, body []byte) string {
	msg, _ := ResponseSigningString(c, status, body)
	return B64URL(ed25519.Sign(priv, msg))
}

// SignPing returns the signature over a /v1/ping response.
func SignPing(priv ed25519.PrivateKey, nonce string, status int, body []byte) string {
	msg, _ := PingSigningString(nonce, status, body)
	return B64URL(ed25519.Sign(priv, msg))
}

// SignUnauth returns the signature over a pre-authentication rejection.
func SignUnauth(priv ed25519.PrivateKey, action string, status int, body []byte) string {
	msg, _ := UnauthSigningString(action, status, body)
	return B64URL(ed25519.Sign(priv, msg))
}

// VerifySig verifies a base64url signature over msg.
func VerifySig(pub ed25519.PublicKey, msg []byte, sig string) bool {
	b, err := DecodeB64URL(sig)
	return err == nil && len(b) == ed25519.SignatureSize && len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, msg, b)
}

// NormalizeCode strips dashes and spaces from a pairing code and uppercases it.
func NormalizeCode(s string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(s)))
}

// Fingerprint returns a human-readable device fingerprint: first 16 hex chars of deviceId in groups of 4.
func Fingerprint(deviceID string) string {
	if len(deviceID) < 16 {
		return deviceID
	}
	d := deviceID[:16]
	return d[0:4] + " " + d[4:8] + " " + d[8:12] + " " + d[12:16]
}

// PairLink is the QR content: wardenclaw://pair?code=***&host=...&key=***&url=...&v=1
// (url: public address of the wardend HTTP endpoint; key: supervisor public key base64url;
// code: one-time code; host: display-only hostname).
type PairLink struct {
	URL  string
	Key  string
	Code string
	Host string
}

// String returns the link as encoded in the QR code.
func (l PairLink) String() string {
	q := url.Values{}
	q.Set("v", "1")
	q.Set("url", l.URL)
	q.Set("key", l.Key)
	q.Set("code", l.Code)
	if l.Host != "" {
		q.Set("host", l.Host)
	}
	return "wardenclaw://pair?" + q.Encode()
}

// ParsePairLink parses a wardenclaw://pair link (used by tests and `wardend pair` for self-check).
func ParsePairLink(s string) (PairLink, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme != "wardenclaw" || u.Host != "pair" {
		return PairLink{}, errors.New("not a wardenclaw://pair link")
	}
	q := u.Query()
	if q.Get("v") != "1" {
		return PairLink{}, errors.New("unsupported link version")
	}
	l := PairLink{URL: q.Get("url"), Key: q.Get("key"), Code: q.Get("code"), Host: q.Get("host")}
	if l.URL == "" || l.Key == "" || l.Code == "" {
		return PairLink{}, errors.New("link: url, key and code are required")
	}
	if _, err := DecodeKey(l.Key); err != nil {
		return PairLink{}, err
	}
	return l, nil
}
