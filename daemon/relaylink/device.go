// SPDX-License-Identifier: AGPL-3.0-or-later

package relaylink

// The device side of a supervisor's channel (protocol/README.md sections 5.3, 5.5, 6, 11): an approver
// that dials <relay>/v1/ws/<supervisorId>, says hello with role device, pairs, gets cards and
// sends tickets. The relay is an untrusted carrier here too: what a device shows or signs comes
// out of a box only the supervisor of the pairing link could have sealed.

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// MsgTTL is how long a frame of a device may wait on the relay for the supervisor.
const MsgTTL = time.Minute

// Device is one approver and the supervisor it talks to.
type Device struct {
	Key           ed25519.PrivateKey // identity: signs the hello, the pairing request, the tickets
	Enc           *ecdh.PrivateKey   // encryption key of the boxes
	SupervisorID  string
	SupervisorEnc *ecdh.PublicKey // from the pairing link
	Client        string          // program name and version for the hello and the User-Agent
	Version       string
}

// ID is the device id: sha256 of the identity key.
func (d *Device) ID() string { return envelope.DeviceID(d.Key.Public().(ed25519.PublicKey)) }

// EncPublic is the device's X25519 public key, base64url.
func (d *Device) EncPublic() string { return envelope.B64URL(d.Enc.PublicKey().Bytes()) }

func (d *Device) boxKey() ([]byte, error) {
	return BoxKey(d.Enc, d.SupervisorEnc, d.SupervisorID, d.ID())
}

// Seal boxes plaintext for the supervisor as a msg frame of this kind.
func (d *Device) Seal(kind string, plaintext []byte) (Envelope, error) {
	now := time.Now()
	e := Envelope{Type: "msg", ID: MsgID(), To: d.SupervisorID, From: d.ID(), Seq: 1, Ts: now.UnixMilli(), Exp: now.Add(MsgTTL).UnixMilli(), Kind: kind}
	key, err := d.boxKey()
	if err != nil {
		return e, err
	}
	aad, err := AAD(e.ID, e.From, e.To, e.Kind, e.Exp)
	if err != nil {
		return e, err
	}
	e.Body, err = Seal(key, nil, plaintext, aad)
	return e, err
}

// PairRequest is the plaintext of a pair frame: {payload, signature} of a pairing request with
// this one-time code. The signed payload names the device's encryption key.
func (d *Device) PairRequest(code, name string) ([]byte, error) {
	pp := envelope.PairPayload{Code: code, DeviceID: d.ID(), Pubkey: envelope.B64URL(d.Key.Public().(ed25519.PublicKey)), Enc: d.EncPublic(),
		Name: name, SupervisorID: d.SupervisorID, Ts: envelope.NowMs(), Nonce: envelope.NewNonce()}
	msg, err := envelope.PairSigningString(pp)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"payload": pp, "signature": envelope.B64URL(ed25519.Sign(d.Key, msg))})
}

// SealPair boxes a pairing request as a pair frame: the supervisor does not know the device yet,
// so its X25519 key travels in front of the box (section 6).
func (d *Device) SealPair(plaintext []byte) (Envelope, error) {
	e, err := d.Seal("pair", plaintext)
	if err != nil {
		return e, err
	}
	raw, err := envelope.DecodeB64URL(e.Body)
	if err != nil {
		return e, err
	}
	e.Type, e.Body = "pair", envelope.B64URL(append(d.Enc.PublicKey().Bytes(), raw...))
	return e, nil
}

// Open decrypts a frame the supervisor sent to this device. A frame from anybody else, or one
// whose routing members were rewritten, does not open.
func (d *Device) Open(e Envelope) ([]byte, error) {
	if e.From != d.SupervisorID || e.To != d.ID() {
		return nil, ErrBox
	}
	key, err := d.boxKey()
	if err != nil {
		return nil, ErrBox
	}
	aad, err := AAD(e.ID, e.From, e.To, e.Kind, e.Exp)
	if err != nil {
		return nil, err
	}
	return Open(key, e.Body, aad)
}

// DeviceConn is a device connected to the relay, after the welcome.
type DeviceConn struct {
	d  *Device
	ws *Conn
}

// Dial connects to the supervisor's channel on the relay at base (wss://host[/path], ws:// for a
// relay on this machine) and answers the challenge with the signed hello.
func (d *Device) Dial(ctx context.Context, base string) (*DeviceConn, error) {
	ua := d.Client + "/" + d.Version
	ws, err := Dial(ctx, strings.TrimRight(base, "/")+"/v1/ws/"+d.SupervisorID, http.Header{"User-Agent": {ua}}, FrameMax)
	if err != nil {
		return nil, err
	}
	c := &DeviceConn{d: d, ws: ws}
	if err := c.hello(); err != nil {
		ws.Drop()
		return nil, err
	}
	return c, nil
}

func (c *DeviceConn) hello() error {
	deadline := time.Now().Add(HelloTimeout)
	ch, err := c.Read(deadline)
	if err != nil {
		return err
	}
	if ch.Type != "challenge" || ch.Nonce == "" {
		return errors.New("relay: no challenge")
	}
	h, err := Hello("device", c.d.Client, c.d.Version, c.d.Key, c.d.EncPublic(), ch.Nonce, time.Now().UnixMilli())
	if err != nil {
		return err
	}
	if err := c.Write(h); err != nil {
		return err
	}
	for {
		w, err := c.Read(deadline)
		if err != nil {
			return err
		}
		switch w.Type {
		case "error":
			return &Error{Code: w.Code}
		case "welcome":
			if w.ID != c.d.ID() || w.Role != "device" {
				return errors.New("relay: welcome for another identity")
			}
			if w.Protocol != envelope.Protocol {
				return &ProtocolError{Relay: w.Protocol}
			}
			return nil
		}
	}
}

// ProtocolError: the relay speaks another protocol number than this program.
type ProtocolError struct{ Relay int }

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("relay: it speaks protocol %d, this program speaks protocol %d", e.Relay, envelope.Protocol)
}

// Read returns the next frame of the relay; a frame that is not JSON is skipped.
func (c *DeviceConn) Read(deadline time.Time) (Frame, error) {
	c.ws.SetReadDeadline(deadline)
	for {
		raw, err := c.ws.ReadText()
		if err != nil {
			return Frame{}, err
		}
		var f Frame
		if json.Unmarshal(raw, &f) == nil {
			return f, nil
		}
	}
}

// Write sends one frame.
func (c *DeviceConn) Write(frame any) error {
	b, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	if len(b) > FrameMax {
		return &Error{Code: "too_large"}
	}
	return c.ws.WriteText(b)
}

// Ack tells the relay that a msg frame is stored or handled: it will not come again.
func (c *DeviceConn) Ack(f Frame) error {
	return c.Write(map[string]any{"type": "ack", "id": f.ID, "seq": f.Seq})
}

// Resume asks the relay for the frames it queued for this device and did not get an ack for;
// they come before the answering resumed frame.
func (c *DeviceConn) Resume() error {
	return c.Write(map[string]any{"type": "resume", "seq": 0})
}

// Close sends a close frame and drops the connection.
func (c *DeviceConn) Close() { c.ws.Close(CloseNormal, "bye") }

// Drop closes the connection without a close frame.
func (c *DeviceConn) Drop() { c.ws.Drop() }
