// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// wardenctl watch: one connection to the relay, the cards in the terminal one at a time:
//
//	y: allow (with a YubiKey touch; with --no-hw only if wardend requires it), n: deny,
//	d: details, empty input (Enter): do nothing, the card stays in the queue
//	(the phone can decide it, otherwise it expires by TTL and the exec gets EPERM).
//
// A dangerous card (rule, flag, delegating launch: the same as "!!! DANGEROUS") is allowed only by
// the word allow in full, like the hold on the phone and the watch: y, yes and other short
// answers do not allow it, so that a habitual key does not approve something dangerous.
//
// There is no default answer. If the card leaves the queue while you are thinking (decided by
// another device, expired), the question is withdrawn. Input is read only when a question is
// asked: while fido2-assert asks for the PIN, nobody intercepts the terminal.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/xarvel/WardenClaw/daemon/feature"
)

type lineResult struct {
	line string
	err  error
}

// lineReader: a stdin line on request (ask), the result in C.
type lineReader struct {
	req     chan struct{}
	C       chan lineResult
	pending bool
	closed  bool
}

func newLineReader(r io.Reader) *lineReader {
	lr := &lineReader{req: make(chan struct{}), C: make(chan lineResult, 1)}
	br := bufio.NewReader(r)
	go func() {
		for range lr.req {
			s, err := br.ReadString('\n')
			lr.C <- lineResult{strings.TrimSpace(s), err}
			if err != nil {
				return
			}
		}
	}()
	return lr
}

func (lr *lineReader) ask() {
	if !lr.pending && !lr.closed {
		lr.req <- struct{}{}
		lr.pending = true
	}
}

// snapshot: the queue after one change, as the follower knows it.
type snapshot struct {
	resp *PendingResp
	err  error
}

// followRetry: how long the follower waits before it dials the relay again.
const followRetry = 5 * time.Second

// followQueue keeps one connection to the relay until ctx ends and holds the queue: a status is
// the whole state, a card adds one, a card.done removes one. After every (re)connect it takes
// what the relay kept (resume) and asks for a status, so nothing depends on the relay's queue
// alone. snaps holds only the latest state: an older snapshot nobody has read yet is dropped.
func followQueue(ctx context.Context, cl *Client, snaps chan snapshot) {
	put := func(sn snapshot) {
		select {
		case <-snaps:
		default:
		}
		snaps <- sn
	}
	for ctx.Err() == nil {
		err := followOnce(ctx, cl, put)
		if ctx.Err() != nil {
			return
		}
		put(snapshot{nil, err})
		cl.Close()
		select {
		case <-ctx.Done():
		case <-time.After(followRetry):
		}
	}
}

func followOnce(ctx context.Context, cl *Client, put func(snapshot)) error {
	if err := cl.Resume(ctx); err != nil {
		return err
	}
	sr, err := cl.Status(ctx)
	if err != nil {
		return err
	}
	q := sr.Queue
	put(snapshot{resp: &q})
	s, in, err := cl.connect(ctx)
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case m, ok := <-in:
			if !ok {
				return fmt.Errorf("the connection to the relay ended: %v", s.Err())
			}
			next := q
			switch m.Kind {
			case "status":
				r, err := parseStatus(m.Body)
				if err != nil {
					return err
				}
				next = r.Queue
			case "card":
				var it Item
				if json.Unmarshal(m.Body, &it) != nil || slices.ContainsFunc(q.Pending, func(x Item) bool { return x.ID == it.ID }) {
					continue
				}
				next.Pending = append(slices.Clone(q.Pending), it)
			case "card.done":
				var d struct {
					ID string `json:"id"`
				}
				if json.Unmarshal(m.Body, &d) != nil {
					continue
				}
				next.Pending = slices.DeleteFunc(slices.Clone(q.Pending), func(x Item) bool { return x.ID == d.ID })
			default:
				continue
			}
			q = next
			out := q
			put(snapshot{resp: &out})
		}
	}
}

// retryableRejection: a wardend rejection after which watch asks about the same card again:
// YubiKey problems (hw_*, hardware_required) and clock skew (stale_timestamp).
func retryableRejection(reason string) bool {
	return strings.HasPrefix(reason, "hw_") || reason == "hardware_required" || reason == "stale_timestamp"
}

// watchAction: what to do with the answer to a card question.
type watchAction int

const (
	watchUnknown watchAction = iota
	watchSkip
	watchDetails
	watchAllow
	watchDeny
	// y on a dangerous card: not allowed, the word allow in full is needed
	watchNeedAllowWord
)

// watchAnswer parses the answer. allow allows any card; y (yes) only a non-dangerous one.
func watchAnswer(line string, dangerous bool) watchAction {
	switch ans := strings.ToLower(strings.TrimSpace(line)); {
	case ans == "":
		return watchSkip
	case ans == "d" || ans == "?":
		return watchDetails
	case ans == "n" || ans == "no":
		return watchDeny
	case ans == "allow":
		return watchAllow
	case isYes(ans):
		if dangerous {
			return watchNeedAllowWord
		}
		return watchAllow
	}
	return watchUnknown
}

func (a *app) cmdWatch(ctx context.Context, args []string) int {
	fs := a.flags("watch")
	var o decideOpts
	if feature.HWKey {
		hwFlags(fs, &o)
		fs.BoolVar(&o.uv, "uv", false, "YubiKey PIN on touch")
		fs.StringVar(&o.device, "device", "", "FIDO device")
	}
	if _, code, ok := a.parseCmd(fs, args, cmdSpec{guarded: true}); !ok {
		return code
	}
	// Without a bound YubiKey every "y" would end in an error: say so before the first card.
	if st, err := loadState(a.dir); err == nil && st.HW == nil && o.forceHW && !o.noHW {
		return a.errf("%s (wardenctl watch --no-hw)", noHWBound)
	}
	s, err := a.open(ctx)
	if err != nil {
		return a.errf("%v", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	snaps := make(chan snapshot, 1)
	defer s.cl.Close()
	go followQueue(ctx, s.cl, snaps)

	out := a.stdout
	fmt.Fprintf(out, "Watching %s (%s). y: allow, n: deny, d: details, Enter: do nothing. Ctrl-C: quit.\n", s.st.Host, s.st.Relay)
	fmt.Fprintf(out, "A dangerous card is allowed only by the word allow in full.\n")
	lr := newLineReader(a.stdin)
	seen := map[string]bool{}
	var queue []Card
	var cur *Card
	curDanger := false
	var serverNow int64
	var lastErr string
	online := false

	prompt := func() {
		if lr.closed {
			return
		}
		if curDanger {
			fmt.Fprintf(out, "Dangerous card %s. Only the word allow in full allows it; n denies, d shows details, Enter skips: ", cur.ID)
		} else {
			fmt.Fprintf(out, "Allow %s? [y/n/d, Enter: skip] ", cur.ID)
		}
		lr.ask()
	}
	next := func() {
		cur = nil
		for len(queue) > 0 && cur == nil {
			c := queue[0]
			queue = queue[1:]
			fmt.Fprintln(out)
			printCard(out, c, serverNow, false)
			if c.Err != nil || lr.closed {
				continue // must not be signed or nobody can answer: only shown
			}
			cur = &c
			curDanger, _ = dangerOf(c)
			if len(queue) > 0 {
				fmt.Fprintf(out, "  (%d more in the queue)\n", len(queue))
			}
			prompt()
		}
	}

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(out)
			return 0
		case sn := <-snaps:
			if sn.err != nil {
				if msg := sn.err.Error(); msg != lastErr || online {
					fmt.Fprintf(a.stderr, "\nno connection: %v (retrying every 5 s)\n", sn.err)
					lastErr = msg
				}
				online = false
				if isReason(sn.err, "not_trusted") {
					return 1
				}
				continue
			}
			if !online && lastErr != "" {
				fmt.Fprintln(a.stderr, "connection restored")
			}
			online, lastErr = true, ""
			serverNow = sn.resp.Now
			present := map[string]bool{}
			for _, c := range s.check(sn.resp) {
				present[c.ID] = true
				if !seen[c.ID] {
					seen[c.ID] = true
					queue = append(queue, c)
				}
			}
			kept := queue[:0]
			for _, c := range queue {
				if present[c.ID] {
					kept = append(kept, c)
				}
			}
			queue = kept
			if cur != nil && !present[cur.ID] {
				fmt.Fprintf(out, "\nCard %s withdrawn: decided by another device or expired.\n", cur.ID)
				cur = nil
			}
			if cur == nil {
				next()
			}
		case in := <-lr.C:
			lr.pending = false
			if in.err != nil {
				lr.closed = true // the reader goroutine has finished
				if in.line == "" {
					fmt.Fprintln(out, "\ninput closed: from now on only showing cards, not sending decisions")
					next()
					continue
				}
			}
			if cur == nil {
				continue // the question is already withdrawn
			}
			switch act := watchAnswer(in.line, curDanger); act {
			case watchSkip:
				fmt.Fprintf(out, "Skipped: no decision sent, %s stays in the queue.\n", cur.ID)
				next()
			case watchDetails:
				printCard(out, *cur, serverNow, true)
				prompt()
			case watchNeedAllowWord:
				fmt.Fprintf(out, "Not allowed: the card is dangerous, only the word allow in full allows it. n denies.\n")
				prompt()
			case watchAllow, watchDeny:
				decision := "deny"
				if act == watchAllow {
					decision = "allow"
				}
				r, err := a.decide(ctx, s, *cur, decision, o)
				switch {
				case err != nil:
					fmt.Fprintf(out, "Not sent: %v\n", err)
					prompt()
					continue
				case !r.OK && retryableRejection(r.Reason):
					fmt.Fprintf(out, "wardend rejected: %s; you can try again.\n", reasonHuman(r.Reason))
					prompt()
					continue
				case !r.OK:
					fmt.Fprintf(out, "wardend rejected: %s\n", reasonHuman(r.Reason))
				default:
					fmt.Fprintf(out, "%s: %s\n", decisionWord(decision), clip(sanitize(displayCommand(cur.Env)), 120))
				}
				next()
			default:
				if curDanger {
					fmt.Fprintln(out, "Not understood. To allow: allow (the whole word); n denies, d shows details, Enter does nothing.")
				} else {
					fmt.Fprintln(out, "Not understood. y: allow, n: deny, d: details, Enter: do nothing.")
				}
				prompt()
			}
		}
	}
}
