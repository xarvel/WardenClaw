// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// wardenctl approve and deny: show the card, sign the ticket, send it back.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/feature"
	"github.com/xarvel/WardenClaw/daemon/hwkey"
)

type decideOpts struct {
	forceHW bool // allow with a YubiKey signature even if wardend does not require it (default yes)
	noHW    bool // --no-hw: without it, if wardend does not require it
	uv      bool
	device  string
}

// hwFlags: --hw (on by default) and --no-hw for approve and watch. The device key on a laptop is
// software, a process of the same user can read it; a YubiKey touch cannot be forged. The boundary
// is still on the server: without a require_hardware rule wardend accepts allow without the key.
func hwFlags(fs *flag.FlagSet, o *decideOpts) {
	fs.BoolVar(&o.forceHW, "hw", true, "allow with a YubiKey touch even if wardend does not require it (default yes)")
	fs.BoolVar(&o.noHW, "no-hw", false, "allow without a YubiKey if wardend does not require it: the device key decides alone")
}

// decide: sign the ticket (and, if needed, get a YubiKey assertion) and send it.
func (a *app) decide(ctx context.Context, s *session, c Card, decision string, o decideOpts) (*DecideResp, error) {
	if c.Err != nil {
		return nil, fmt.Errorf("the card failed verification (%v): it must not be signed", c.Err)
	}
	needHW := decision == "allow" && (c.hwNeeded() || (o.forceHW && !o.noHW))
	if needHW {
		if err := hwReady(s.st.HW, c); err != nil {
			return nil, err
		}
	}
	body, cdj, err := signTicket(s.priv, s.st.SupervisorID, c.ID, c.Digest, decision, a.now().UnixMilli(), envelope.NewNonce())
	if err != nil {
		return nil, err
	}
	if needHW {
		asr, err := hwAssert(s.st.HW, o.device, o.uv, cdj, a.stderr)
		if err != nil {
			return nil, err
		}
		body.HW = asr
	}
	return s.cl.Decide(ctx, body)
}

// hwReady: whether an allow with a YubiKey touch can go through: this build has YubiKey support,
// a key is bound here (hw) and, if the card meta lists the keys of wardend, it is one of them.
func hwReady(hw *HWCred, c Card) error {
	if !feature.HWKey { // then only a card from a wardend built with the hwkey tag needs the key
		return errors.New("the card requires a YubiKey touch, and this wardenctl build has no YubiKey support: " + feature.HWKeyOff)
	}
	if hw == nil && !c.hwNeeded() {
		return errors.New(noHWBound)
	}
	h := c.Meta.Hardware
	if hw == nil {
		why := "a YubiKey is required"
		if h != nil && h.Rule != "" {
			why += " (rule " + h.Rule + ")"
		}
		return errors.New(why + ", but none is bound: wardenctl hw-register")
	}
	if h == nil {
		return nil
	}
	if len(h.Credentials) == 0 {
		return errors.New("no key is registered in wardend: wardend hw-register and a wardend restart")
	}
	for _, cr := range h.Credentials {
		if cr.ID == hw.CredentialID {
			return nil
		}
	}
	return errors.New("wardend does not know the bound YubiKey: run the command from wardenctl hw-register on the server and restart wardend")
}

// signTicket: an exec ticket for the pinned supervisor (device signature) and the clientDataJSON
// for the second signature of the same ticket (signDecision + assertionRequest in the app; the CLI
// does not sign risk).
func signTicket(priv ed25519.PrivateKey, supervisorID, id, digest, decision string, tsMs int64, nonce string) (envelope.DecisionBody, []byte, error) {
	p := envelope.ExecPayload(supervisorID, id, digest, decision, tsMs, nonce)
	body := envelope.SignPayload(priv, p)
	ch, err := envelope.HWChallenge(body.DeviceID, p)
	if err != nil {
		return body, nil, err
	}
	return body, hwkey.ClientDataJSON("webauthn.get", ch), nil
}

func decisionWord(d string) string {
	if d == "allow" {
		return "Allowed"
	}
	return "Denied"
}

// noHWBound: allow uses a YubiKey by default, but none is bound.
const noHWBound = "an allow from wardenctl uses a YubiKey touch by default, but none is bound: wardenctl hw-register, or explicitly without the key: --no-hw"

// minUnpromptedID: without a prompt (--yes or stdin is not a terminal) approve takes only an id of
// at least 12 hex characters: a short prefix in a script easily hits the wrong card.
const minUnpromptedID = 12

func (a *app) cmdDecide(ctx context.Context, decision string, args []string) int {
	name := "deny"
	if decision == "allow" {
		name = "approve"
	}
	fs := a.flags(name)
	var o decideOpts
	yes := false
	if decision == "allow" {
		if feature.HWKey {
			hwFlags(fs, &o)
			fs.BoolVar(&o.uv, "uv", false, "PIN YubiKey (user verification)")
			fs.StringVar(&o.device, "device", "", "FIDO device (otherwise the only one from fido2-token -L)")
		}
		fs.BoolVar(&yes, "yes", false, "do not show the card or ask (scripts; the id needs at least 12 characters)")
	}
	pos, code, ok := a.parseCmd(fs, args, cmdSpec{guarded: true, json: true, maxArgs: 1})
	if !ok {
		return code
	}
	if len(pos) != 1 {
		return a.errf("a card id is required")
	}
	ask := decision == "allow" && !yes && a.interactive()
	if decision == "allow" && !ask && len(cardHex(pos[0])) < minUnpromptedID {
		return a.errf("without a prompt (--yes or stdin is not a terminal) approve needs an id of at least %d characters, not %q: wardenctl pending shows the full one", minUnpromptedID, pos[0])
	}
	s, err := a.open(ctx)
	if err != nil {
		return a.errf("%v", err)
	}
	defer s.cl.Close()
	pr, cards, err := s.cards(ctx)
	if err != nil {
		return a.errf("%v", err)
	}
	c, err := findCard(cards, pos[0])
	if err != nil {
		return a.errf("%v", err)
	}
	if ask && !a.confirmAllow(c, pr.Now) {
		return 1
	}
	r, err := a.decide(ctx, s, c, decision, o)
	if err != nil {
		return a.errf("%v", err)
	}
	if !r.OK {
		msg := reasonHuman(r.Reason)
		if r.HardwareRule != "" {
			msg += ", rule " + r.HardwareRule
		}
		return a.errf("wardend rejected the decision on %s: %s", c.ID, msg)
	}
	if a.json {
		return a.writeJSON(decisionJSON{OK: true, ID: c.ID, Digest: c.Digest, Decision: decision, HardwareRule: r.HardwareRule})
	}
	fmt.Fprintf(a.stdout, "%s: %s  (%s)\n", decisionWord(decision), clip(sanitize(displayCommand(c.Env)), 200), c.ID)
	return 0
}

// confirmAllow: approve in a terminal first shows the card and waits for an answer, like watch:
// y (yes) allows a regular card, only the word allow in full allows a dangerous one. There is no
// default answer: an empty line or anything else cancels, and no decision is sent. With --json
// the card and the question go to stderr, stdout stays for JSON.
func (a *app) confirmAllow(c Card, serverNow int64) bool {
	w := a.stdout
	if a.json {
		w = a.stderr
	}
	printCard(w, c, serverNow, false)
	danger, _ := dangerOf(c)
	if danger {
		fmt.Fprintf(w, "Dangerous card %s. Only the word allow in full allows it (Enter cancels): ", c.ID)
	} else {
		fmt.Fprintf(w, "Allow %s? [y/N] ", c.ID)
	}
	line, _ := readLine(a.stdin)
	switch watchAnswer(line, danger) {
	case watchAllow:
		return true
	case watchNeedAllowWord:
		fmt.Fprintln(w, "Not allowed: the card is dangerous, only the word allow in full allows it. No decision sent.")
	default:
		fmt.Fprintln(w, "Cancelled, no decision sent.")
	}
	return false
}
