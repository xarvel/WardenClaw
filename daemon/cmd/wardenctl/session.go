// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// A paired session, and the commands that only read the queue: pending and show.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

type session struct {
	st   *State
	cl   *Client
	priv ed25519.PrivateKey
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
	priv, err := deviceKey(a.dir, st)
	if err != nil {
		return nil, err
	}
	s := &session{st: st, cl: newClient(st.URL, pinned, priv), priv: priv}
	if st.PairStatus != "approved" {
		if st.PairStatus == "rejected" {
			return nil, errors.New("pairing was rejected: wardenctl forget and start over")
		}
		ps, err := s.cl.PairStatus(ctx, st.PairID)
		if err != nil {
			return nil, fmt.Errorf("pairing is not finished yet, no status: %v", err)
		}
		if ps.Status != "approved" {
			if done, _ := a.applyPairStatus(st, ps.Status); done {
				return nil, errors.New("pairing failed")
			}
			return nil, fmt.Errorf("pairing is not approved yet: on the server wardend pair approve %s (fingerprint %s)", st.PairID, envelope.Fingerprint(st.DeviceID))
		}
		a.pairDone(st)
	}
	return s, nil
}

func (s *session) cards(ctx context.Context) (*PendingResp, []Card, error) {
	r, err := s.cl.Pending(ctx, 0, 0)
	if err != nil {
		return nil, nil, err
	}
	return r, s.check(r), nil
}

func (s *session) check(r *PendingResp) []Card {
	cs := make([]Card, 0, len(r.Pending))
	for _, it := range r.Pending {
		cs = append(cs, checkItem(it, s.st.SupervisorID))
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
