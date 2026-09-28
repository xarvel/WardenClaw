// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// A paired session, and the commands that only read the queue: pending and show.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/relaylink"
)

type session struct {
	st     *State
	cl     *Client
	priv   ed25519.PrivateKey
	pinned ed25519.PublicKey
}

func (a *app) open(ctx context.Context) (*session, error) {
	st, err := loadState(a.dir)
	if err != nil {
		return nil, err
	}
	pinned, err := envelope.DecodeKey(st.SupervisorKey)
	if err != nil {
		return nil, fmt.Errorf("server.json: supervisor key: %v", err)
	}
	if envelope.DeviceID(pinned) != st.SupervisorID {
		return nil, errors.New("server.json: supervisorId does not match the key")
	}
	if st.KeyStore == "keychain" && st.KeychainACL == "" {
		if err := a.reprotectKeychain(st); err != nil {
			return nil, err
		}
	}
	supEnc, err := relaylink.ParseEncKey(st.SupervisorEnc)
	if err != nil {
		return nil, fmt.Errorf("server.json: supervisor encryption key: %v", err)
	}
	priv, enc, err := deviceKey(a.dir, st)
	if err != nil {
		return nil, err
	}
	s := &session{st: st, cl: newClient(st.Relay, st.SupervisorID, supEnc, priv, enc), priv: priv, pinned: pinned}
	if st.PairStatus != "approved" {
		if st.PairStatus == "rejected" {
			return nil, errors.New("pairing was rejected: wardenctl forget and start over")
		}
		if err := s.finishPairing(ctx, a); err != nil {
			s.cl.Close()
			return nil, err
		}
	}
	return s, nil
}

// finishPairing: where a pairing that was not approved when pair stopped waiting stands now.
// wardend answers a status.req of a trusted device only, so a status is the approval; a
// rejection is in the pair.status the relay kept for this device.
func (s *session) finishPairing(ctx context.Context, a *app) error {
	st := s.st
	if _, err := s.cl.Status(ctx); err == nil {
		a.pairDone(st)
		return nil
	} else if !isReason(err, "not_trusted") {
		return fmt.Errorf("pairing is not finished yet, no status: %w", err)
	}
	if err := s.cl.Resume(ctx); err == nil {
		if ps, err := s.cl.PairStatus(ctx, st.PairRe, pairResumeWait); err == nil {
			if done, _ := a.applyPairStatus(st, ps.Status); done {
				if ps.Status == "approved" {
					return nil
				}
				return errors.New("pairing failed")
			}
		}
	}
	return fmt.Errorf("pairing is not approved yet: on the server wardend pair approve %s (fingerprint %s)", st.PairID, envelope.Fingerprint(st.DeviceID))
}

// pairResumeWait: how long open waits for a pair.status the relay may have kept.
const pairResumeWait = 2 * time.Second

func (s *session) cards(ctx context.Context) (*PendingResp, []Card, error) {
	r, err := s.cl.Status(ctx)
	if err != nil {
		return nil, nil, err
	}
	return &r.Queue, s.check(&r.Queue), nil
}

// check: every card as it may be shown: the supervisor of the pairing link signed its identity
// (id, digest, lifetime), and the envelope under that digest is the one shown.
func (s *session) check(r *PendingResp) []Card {
	cs := make([]Card, 0, len(r.Pending))
	for _, it := range r.Pending {
		c := checkItem(it, s.st.SupervisorID)
		if msg, err := relaylink.CardSigningString(it.ID, it.Digest, it.CreatedAt, it.ExpiresAt); c.Err == nil && (err != nil || !envelope.VerifySig(s.pinned, msg, it.SupervisorSig)) {
			c.Err = errors.New("the card is not signed by the supervisor key from the pairing link")
		}
		cs = append(cs, c)
	}
	return cs
}

// ---- pending / show ----

func (a *app) cmdPending(ctx context.Context, args []string) int {
	if _, code, ok := a.parseCmd(a.flags("pending"), args, cmdSpec{guarded: true, json: true}); !ok {
		return code
	}
	s, err := a.open(ctx)
	if err != nil {
		return a.errf("%v", err)
	}
	defer s.cl.Close()
	r, cards, err := s.cards(ctx)
	if err != nil {
		return a.errf("%v", err)
	}
	if a.json {
		out := pendingJSON{OK: true, Host: r.Host, Mode: r.Mode, Seq: r.Seq, Now: r.Now, Pending: make([]cardJSON, 0, len(cards))}
		for _, c := range cards {
			out.Pending = append(out.Pending, newCardJSON(c))
		}
		return a.writeJSON(out)
	}
	fmt.Fprintf(a.stdout, "%s: mode %s, cards: %d\n", sanitize(r.Host), r.Mode, len(cards))
	for _, c := range cards {
		printShort(a.stdout, c, r.Now)
	}
	if r.Mode != "ticket" && len(cards) == 0 {
		fmt.Fprintf(a.stdout, "  (in %s mode wardend creates no cards)\n", r.Mode)
	}
	return 0
}

func (a *app) cmdShow(ctx context.Context, args []string) int {
	pos, code, ok := a.parseCmd(a.flags("show"), args, cmdSpec{guarded: true, json: true, maxArgs: 1})
	if !ok {
		return code
	}
	if len(pos) != 1 {
		return a.errf("an id is required: wardenctl show <id>")
	}
	s, err := a.open(ctx)
	if err != nil {
		return a.errf("%v", err)
	}
	defer s.cl.Close()
	r, cards, err := s.cards(ctx)
	if err != nil {
		return a.errf("%v", err)
	}
	c, err := findCard(cards, pos[0])
	if err != nil {
		return a.errf("%v", err)
	}
	if a.json {
		return a.writeJSON(showJSON{OK: true, Host: r.Host, Mode: r.Mode, Now: r.Now, Card: newCardJSON(c)})
	}
	printCard(a.stdout, c, r.Now, true)
	return 0
}
